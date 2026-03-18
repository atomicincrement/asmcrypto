//! AsmCrypto — register-parallel cryptographic primitives.
//!
//! Modules:
//! * [`keccak`] — Keccak-256 (Ethereum variant, padding byte `0x01`).
//! * [`ecdsa`]  — secp256k1 ECDSA public-key and address recovery.

pub mod ecdsa;
pub mod keccak;
