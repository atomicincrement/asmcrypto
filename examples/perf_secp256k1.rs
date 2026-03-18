/// Tight loop for perf profiling of the C-backed secp256k1 ECDSA recovery.
///
/// Uses the same test vector as perf_ecdsa so timings are directly comparable.
///
/// Usage:
///   cargo build --example perf_secp256k1 --release
///   perf record -g --call-graph dwarf -F 997 -- target/release/examples/perf_secp256k1
///   perf report --stdio -n
use secp256k1::{
    SECP256K1,
    ecdsa::{RecoverableSignature, RecoveryId},
};
use std::time::Instant;

fn main() {
    // Same test vector as perf_ecdsa / the ecrecover precompile test.
    let hash: [u8; 32] = [
        0x18, 0xc5, 0x47, 0xe4, 0xf7, 0xb0, 0xf3, 0x25, 0xad, 0x1e, 0x56, 0xf5, 0x7e, 0x26, 0xc7,
        0x45, 0xb0, 0x9a, 0x3e, 0x50, 0x3d, 0x86, 0xe0, 0x0e, 0x52, 0x55, 0xff, 0x7f, 0x71, 0x5d,
        0x3d, 0x1c,
    ];
    let r: [u8; 32] = [
        0x73, 0xb1, 0x69, 0x38, 0x92, 0x21, 0x9d, 0x73, 0x6c, 0xab, 0xa5, 0x5b, 0xdb, 0x67, 0x21,
        0x6e, 0x48, 0x55, 0x57, 0xea, 0x6b, 0x6a, 0xf7, 0x5f, 0x37, 0x09, 0x6c, 0x9a, 0xa6, 0xa5,
        0xa7, 0x5f,
    ];
    let s: [u8; 32] = [
        0xee, 0xb9, 0x40, 0xb1, 0xd0, 0x3b, 0x21, 0xe3, 0x6b, 0x0e, 0x47, 0xe7, 0x97, 0x69, 0xf0,
        0x95, 0xfe, 0x2a, 0xb8, 0x55, 0xbd, 0x91, 0xe3, 0xa3, 0x87, 0x56, 0xb7, 0xd7, 0x5a, 0x9c,
        0x45, 0x49,
    ];
    let v = 1u8;

    let msg = secp256k1::Message::from_digest(hash);
    let recid = RecoveryId::from_i32(v as i32).expect("recovery id");
    let mut compact = [0u8; 64];
    compact[..32].copy_from_slice(&r);
    compact[32..].copy_from_slice(&s);
    let sig = RecoverableSignature::from_compact(&compact, recid).expect("sig");

    // Warm up.
    for _ in 0..200 {
        let _ = SECP256K1.recover_ecdsa(&msg, &sig);
    }

    // Profile loop.
    let n = 50_000usize;
    let mut sink = [0u8; 65];
    let t0 = Instant::now();
    for _ in 0..n {
        sink = SECP256K1
            .recover_ecdsa(&msg, &sig)
            .expect("recovery")
            .serialize_uncompressed();
    }
    let us = t0.elapsed().as_nanos() as f64 / n as f64 / 1_000.0;
    println!("secp256k1 recover_pubkey: {us:.2} µs/call  ({n} iters)");

    // Prevent dead-code elimination.
    if sink[0] == 0x00 {
        eprintln!("(should not print)");
    }
}
