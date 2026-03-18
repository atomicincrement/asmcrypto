/// Tight loop for perf profiling of fp_mul and fn_mul in isolation.
///
/// Usage:
///   cargo build --example perf_mul --release
///   perf record -g --call-graph dwarf -F 997 -- target/release/examples/perf_mul
///   perf report --stdio -n
use asmcrypto::ecdsa::{bench_fn_mul, bench_fp_mul};

fn main() {
    // fp_mul inputs: p-1  (maximally large field element)
    // p-1 = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2E
    let p_minus_1: [u64; 4] = [
        0xFFFFFFFEFFFFFC2E,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
    ];

    // fn_mul inputs: n-1  (maximally large scalar)
    // n-1 = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140
    let n_minus_1: [u64; 4] = [
        0xBFD25E8CD0364140,
        0xBAAEDCE6AF48A03B,
        0xFFFFFFFFFFFFFFFE,
        0xFFFFFFFFFFFFFFFF,
    ];

    // Warm up.
    for _ in 0..10_000 {
        let _ = bench_fp_mul(p_minus_1, p_minus_1);
        let _ = bench_fn_mul(n_minus_1, n_minus_1);
    }

    let n = 300_000_000usize;

    // ── fp_mul profiling loop ─────────────────────────────────────────────────
    let mut sink_fp = [0u64; 4];
    for _ in 0..n {
        sink_fp = bench_fp_mul(p_minus_1, p_minus_1);
    }

    // ── fn_mul profiling loop ─────────────────────────────────────────────────
    let mut sink_fn = [0u64; 4];
    for _ in 0..n {
        sink_fn = bench_fn_mul(n_minus_1, n_minus_1);
    }

    // Prevent dead-code elimination.
    if sink_fp[0] == 0xdeadbeef || sink_fn[0] == 0xdeadbeef {
        eprintln!("(should not print)");
    }
}
