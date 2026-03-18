/// Tight loop for perf profiling of ECDSA recovery.
/// Usage:
///   cargo build --example perf_ecdsa --release
///   perf record -g --call-graph dwarf -F 997 -- target/release/examples/perf_ecdsa
///   perf report --stdio -n

fn main() {
    // hash / r / s / v from the standard ecrecover precompile test vector
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

    // Build sig65 for ecdsa_clone: r || s || v
    let mut sig65 = [0u8; 65];
    sig65[0..32].copy_from_slice(&r);
    sig65[32..64].copy_from_slice(&s);
    sig65[64] = v;

    let n = 50_000usize;
    let mut sink = [0u8; 20];

    // ── ecdsa (4×64-bit Solinas) ──────────────────────────────────────────────
    for _ in 0..200 {
        let _ = asmcrypto::ecdsa::recover_address(&hash, &r, &s, v);
    }
    let t0 = std::time::Instant::now();
    for _ in 0..n {
        sink = asmcrypto::ecdsa::recover_address(&hash, &r, &s, v).unwrap_or([0u8; 20]);
    }
    let us_orig = t0.elapsed().as_nanos() as f64 / n as f64 / 1_000.0;
    println!(
        "ecdsa  (4×64 Solinas)  recover_address: {us_orig:.2} µs/call  ({n} iters)  addr={}",
        hex(&sink)
    );

    // ── ecdsa_clone (5×52-bit, libsecp256k1 translation) ─────────────────────
    for _ in 0..200 {
        let _ = asmcrypto::ecdsa_clone::recover_address(&hash, &sig65);
    }
    let t1 = std::time::Instant::now();
    for _ in 0..n {
        sink = asmcrypto::ecdsa_clone::recover_address(&hash, &sig65).unwrap_or([0u8; 20]);
    }
    let us_clone = t1.elapsed().as_nanos() as f64 / n as f64 / 1_000.0;
    println!(
        "ecdsa_clone (5×52 clone) recover_address: {us_clone:.2} µs/call  ({n} iters)  addr={}",
        hex(&sink)
    );

    println!("ratio clone/orig: {:.3}", us_clone / us_orig);

    // Prevent dead-code elimination
    if sink[0] == 0xff {
        eprintln!("(should not print)");
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
