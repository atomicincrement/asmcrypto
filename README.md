# asmcrypto

[![CI](https://github.com/andy-thomason/asmcrypto/actions/workflows/ci.yml/badge.svg)](https://github.com/andy-thomason/asmcrypto/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/asmcrypto.svg)](https://crates.io/crates/asmcrypto)
[![docs.rs](https://img.shields.io/docsrs/asmcrypto)](https://docs.rs/asmcrypto)
[![license](https://img.shields.io/crates/l/asmcrypto.svg)](LICENSE-MIT)

Register-parallel cryptographic primitives for Ethereum node infrastructure,
written in Rust with AVX-512 intrinsics.

## What is this?

ECDSA public-key recovery and Keccak-256 hashing are two of the largest
bottlenecks for Ethereum nodes wanting to exceed 50 000 TPS.  `asmcrypto`
attacks both bottlenecks by running **eight independent operations in parallel
across a single set of 512-bit ZMM registers** — one AVX-512 instruction does
the work of eight scalar instructions, with no cross-lane dependencies.

Two core APIs are provided:

| Function | Description |
|---|---|
| `keccak_batch::keccak256_batch` | 8 × Keccak-256 in one AVX-512 permutation pass |
| `ecdsa_batch::recover_addresses_batch` | 8 × secp256k1 ecrecover → Ethereum address |

## Performance

> Benchmarks run on a single core (Zen 4 / AVX-512, `RUSTFLAGS="-C target-cpu=native"`).

### ECDSA batch address recovery (8 lanes)

| Implementation | ns / 8-batch | µs / lane | krecov/s |
|---|---|---|---|
| **asmcrypto batch × 8 (this crate)** | **~125 000** | **~15.6** | **~64** |
| secp256k1 C library × 8 (sequential) | ~174 000 | ~21.8 | ~46 |
| asmcrypto scalar × 8 (sequential) | ~421 000 | ~52.6 | ~19 |

The AVX-512 batch path is **~1.4× faster per lane** than the highly-tuned
libsecp256k1 C library, and **~3.4× faster** than eight sequential scalar
recoveries.

The entire computation — field square root (lifting `r` to the curve),
modular inverse (computing `r⁻¹ mod n`), scalar multiplications (`u₁·G`
and `u₂·R`), Jacobian addition, batch affine conversion, and Keccak-256
hashing — is performed over ZMM registers across all eight lanes
simultaneously.

### Keccak-256 batch (8 lanes)

| Implementation | µs / 8-batch | ns / hash |
|---|---|---|
| **asmcrypto batch × 8 (this crate)** | **~0.24** | **~30** |
| scalar keccak256 × 8 (sequential) | ~1.46 | ~182 |

**6× throughput** over eight sequential hashes on identical hardware.

### Why it will keep getting better

The current implementation uses Rust `core::arch` AVX-512 intrinsics.
Future iterations will replace the two innermost hot loops — the
Montgomery field multiplier (`fp_mul_x8`) and the scalar multiplier
(`scalar_mul_g_x8`, `scalar_mul_affine_x8`) — with hand-written assembly
that can exploit micro-architectural details (instruction scheduling, register
pressure, port utilisation) that LLVM cannot currently model for AVX-512IFMA.
A 1.5–2× additional speedup is achievable, which would push throughput well
above 100 krecov/s per core and past the 50 000 TPS threshold for a
single-threaded validator.

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
asmcrypto = "0.1"
```

The AVX-512 fast paths are selected automatically at runtime via
`is_x86_feature_detected!`.  On machines without AVX-512 the crate falls back
to a correct scalar implementation.

### Batch ECDSA address recovery

```rust
use asmcrypto::ecdsa_batch::recover_addresses_batch;

let addresses: [[u8; 20]; 8] = recover_addresses_batch(
    [&hash; 8],  // 8 × 32-byte message hashes
    [&r; 8],     // 8 × 32-byte signature r components (big-endian)
    [&s; 8],     // 8 × 32-byte signature s components (big-endian)
    [v; 8],      // 8 recovery ids (0 or 1; Ethereum wire value − 27)
);
```

See [`examples/ecdsa_batch.rs`](examples/ecdsa_batch.rs) for a complete
runnable example.

### Batch Keccak-256

```rust
use asmcrypto::keccak_batch::keccak256_batch;

let hashes: [[u8; 32]; 8] = keccak256_batch([
    b"message 0".as_slice(),
    b"message 1".as_slice(),
    // ...
    b"message 7".as_slice(),
]);
```

See [`examples/keccak_batch.rs`](examples/keccak_batch.rs) for a complete
runnable example.

## Running benchmarks

```bash
RUSTFLAGS="-C target-cpu=native" cargo bench
RUSTFLAGS="-C target-cpu=native" cargo run --example perf_ecdsa_batch --release
RUSTFLAGS="-C target-cpu=native" cargo run --example perf_keccak_batch --release
```

## Requirements

- Rust stable ≥ 1.85 (edition 2024)
- For the AVX-512 fast path: x86-64 with `avx512f`, `avx512bw`, `avx512dq`,
  `avx512ifma` (Intel Skylake-X / Ice Lake or AMD Zen 4 and later)

## Internals

See [`doc/internals.md`](doc/internals.md) for a description of the
algorithms: the Keccak-256 sponge construction, the AVX-512 batch
interleaving strategy, secp256k1 ECDSA recovery, GLV endomorphism, wNAF
scalar multiplication, and the Phase 1a / Phase 1b vectorisation design.

## License

Licensed under either of

 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
 * MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
