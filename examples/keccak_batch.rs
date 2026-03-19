//! Demonstrates hashing eight messages simultaneously with `keccak256_batch`.
//!
//! On AVX-512 hardware the eight Keccak-256 permutations are interleaved
//! inside a single set of ZMM registers, giving ~6× throughput over eight
//! sequential scalar calls.
//!
//! Usage:
//!   cargo run --example keccak_batch --release

use asmcrypto::keccak_batch::keccak256_batch;

fn main() {
    // Eight arbitrary messages (variable length is fully supported).
    let messages: [&[u8]; 8] = [
        b"hello, world",
        b"Ethereum",
        b"secp256k1",
        b"keccak-256",
        b"AVX-512",
        b"batch hashing",
        b"register-parallel",
        b"asmcrypto",
    ];

    let hashes: [[u8; 32]; 8] = keccak256_batch(messages);

    println!("keccak256_batch results:");
    for (i, (msg, hash)) in messages.iter().zip(hashes.iter()).enumerate() {
        println!(
            "  [{}] {:20} => {}",
            i,
            String::from_utf8_lossy(msg),
            hex(hash)
        );
    }

    // Cross-check one lane against the scalar implementation.
    let scalar = asmcrypto::keccak::keccak256(messages[0]);
    assert_eq!(
        hashes[0], scalar,
        "batch lane 0 must match scalar keccak256"
    );
    println!("\nOK: lane 0 matches scalar keccak256.");
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
