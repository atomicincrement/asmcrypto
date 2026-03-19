//! Timing benchmark: `fp_mul_x8` (8-wide AVX-512 field multiply) vs 8 × `scalar_fp_mul`.
//!
//! Usage:
//!   cargo build --example perf_fp_mul --release
//!   target/release/examples/perf_fp_mul
//!
//!   # With perf:
//!   perf record -g --call-graph dwarf -F 997 -- target/release/examples/perf_fp_mul
//!   perf report --stdio -n

use asmcrypto::ecdsa::bench_fp_mul;
use asmcrypto::ecdsa_batch::x8::{fp_mul_x8, load, store};
use std::time::Instant;

// p-1 (maximally large secp256k1 field element)
const P_MINUS_1: [u64; 4] = [
    0xFFFFFFFEFFFFFC2E,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
];

// x-coordinate of the generator G
const G_X: [u64; 4] = [
    0x59F2815B16F81798,
    0x029BFCDB2DCE28D9,
    0x55A06295CE870B07,
    0x79BE667EF9DCBBAC,
];

fn main() {
    const N: usize = 500_000;

    // ── Verify correctness first ──────────────────────────────────────────────
    let expected_scalar = bench_fp_mul(G_X, P_MINUS_1);

    let have_avx512 = is_x86_feature_detected!("avx512f") && is_x86_feature_detected!("avx512ifma");

    if have_avx512 {
        let a8 = unsafe { load(&[G_X; 8]) };
        let b8 = unsafe { load(&[P_MINUS_1; 8]) };
        let c8 = unsafe { fp_mul_x8(a8, b8) };
        let got = unsafe { store(c8) };
        for lane in 0..8 {
            assert_eq!(
                got[lane], expected_scalar,
                "fp_mul_x8 lane {lane} mismatch! Correctness check failed."
            );
        }
        eprintln!("correctness check passed.");
    } else {
        eprintln!("AVX-512F/IFMA not available; skipping vector path.");
    }

    // ── Warm-up ───────────────────────────────────────────────────────────────
    for _ in 0..10_000 {
        let _ = bench_fp_mul(G_X, P_MINUS_1);
        if have_avx512 {
            let a8 = unsafe { load(&[G_X; 8]) };
            let b8 = unsafe { load(&[P_MINUS_1; 8]) };
            let _ = unsafe { fp_mul_x8(a8, b8) };
        }
    }

    // ── Scalar 8× loop ────────────────────────────────────────────────────────
    let mut sink_s = [[0u64; 4]; 8];
    let t0 = Instant::now();
    for _ in 0..N {
        for lane in 0..8 {
            sink_s[lane] = bench_fp_mul(G_X, P_MINUS_1);
        }
    }
    let scalar_8x_ns = t0.elapsed().as_nanos() as f64 / N as f64;
    println!(
        "8 × scalar fp_mul  : {:7.1} ns total  ({:.1} ns/mul)",
        scalar_8x_ns,
        scalar_8x_ns / 8.0
    );

    // ── AVX-512 8-wide loop ───────────────────────────────────────────────────
    if have_avx512 {
        let a8 = unsafe { load(&[G_X; 8]) };
        let b8 = unsafe { load(&[P_MINUS_1; 8]) };

        let mut sink_v = unsafe { fp_mul_x8(a8, b8) };
        let t1 = Instant::now();
        for _ in 0..N {
            // Chain: c = a*b, then c*b to keep the CPU busy
            sink_v = unsafe { fp_mul_x8(sink_v, b8) };
        }
        let simd_ns = t1.elapsed().as_nanos() as f64 / N as f64;
        println!(
            "fp_mul_x8 (8 lanes): {:7.1} ns total  ({:.1} ns/mul)  {:.2}× speedup",
            simd_ns,
            simd_ns / 8.0,
            scalar_8x_ns / simd_ns
        );
        // Prevent dead-code elimination.
        let s = unsafe { store(sink_v) };
        if s[0][0] == 0xdeadbeef {
            eprintln!("(should not print)");
        }
    }

    // Prevent dead-code elimination.
    if sink_s[0][0] == 0xdeadbeef {
        eprintln!("(should not print)");
    }
}
