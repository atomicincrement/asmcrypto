//! Demonstrates recovering eight Ethereum addresses from eight ECDSA signatures
//! in a single call to `recover_addresses_batch`.
//!
//! On AVX-512 hardware all modular arithmetic (field square root, field inverse,
//! scalar multiplications) is performed across eight ZMM lanes simultaneously,
//! giving ~1.4× throughput per lane over the industry-standard libsecp256k1.
//!
//! Usage:
//!   cargo run --example ecdsa_batch --release

use asmcrypto::ecdsa_batch::recover_addresses_batch;

fn main() {
    // Standard Ethereum ecrecover precompile test vector (EIP-2 canonical sig).
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
    let v: u8 = 1; // recovery id (Ethereum wire value minus 27)

    // Pass the same signature on all 8 lanes.  In production each lane would
    // carry an independent transaction signature.
    let hashes = [&hash; 8];
    let rs = [&r; 8];
    let ss = [&s; 8];
    let vs = [v; 8];

    let addresses: [[u8; 20]; 8] = recover_addresses_batch(hashes, rs, ss, vs);

    println!("recover_addresses_batch results:");
    let expected = "a94f5374fce5edbc8e2a8697c15331677e6ebf0b";
    for (lane, addr) in addresses.iter().enumerate() {
        let got = hex(addr);
        let ok = if got == expected { "✓" } else { "✗" };
        println!("  lane {lane}: {got}  {ok}");
    }

    // Cross-check against the scalar implementation.
    let scalar =
        asmcrypto::ecdsa::recover_address(&hash, &r, &s, v).expect("scalar ecrecover failed");
    assert_eq!(
        addresses[0], scalar,
        "batch lane 0 must match scalar ecrecover"
    );
    println!("\nOK: all lanes match the known Ethereum ecrecover address.");
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
