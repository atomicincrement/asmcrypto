//! AsmCrypto — register-parallel cryptographic primitives.
//!
//! Modules:
//! * [`keccak`]       — Keccak-256 (Ethereum variant, padding byte `0x01`).
//! * [`ecdsa`]        — secp256k1 ECDSA public-key and address recovery (4×64-bit field).
//! * [`ecdsa_clone`]  — Exact Rust translation of the C secp256k1 library (5×52-bit field).

pub mod ecdsa;
pub mod ecdsa_clone;
pub mod keccak;
