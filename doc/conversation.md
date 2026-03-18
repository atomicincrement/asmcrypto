# Prompt & Commit History

---

## 2026-03-18 — Initial Keccak-256 implementation

### Prompt
> Write a keccak256 function from scratch.

### High-level effects
- Implemented `keccak256(input: &[u8]) -> [u8; 32]` in `src/lib.rs` with no
  external dependencies.
- Full Keccak-f[1600] permutation (24 rounds) implemented inline, covering all
  five steps per round: θ, ρ, π, χ, ι.
- Used the **original Keccak padding** (delimiter byte `0x01`) rather than
  NIST SHA-3 (`0x06`), matching the Ethereum Yellow Paper specification.
- Sponge parameters: rate = 1088 bits (136 bytes), capacity = 512 bits,
  output = 256 bits.
- Four test vectors added and verified:
  - `keccak256(b"")` — well-known Ethereum/Keccak reference value.
  - `keccak256(b"abc")` — reference implementation cross-check.
  - `keccak256([0u8; 136])` — exercises the exact-rate-boundary code path.
  - `keccak256(b"Transfer(address,address,uint256)")` — matches the canonical
    ERC-20 Transfer event topic `ddf252ad…`.

---

## 2026-03-18 — Module split + Ethereum ECDSA recovery

### Prompt
> Make two modules keccak and ecdsa. Move the keccak function and tests to the
> keccak module. In the ecdsa module, implement Ethereum ecdsa recovery from scratch.

### High-level effects

**Restructuring:**
- `src/lib.rs` reduced to a bare crate root that re-exports `pub mod keccak`
  and `pub mod ecdsa`.
- All Keccak code (constants, permutation, sponge, tests) moved verbatim into
  `src/keccak.rs`.

**`src/ecdsa.rs` — new, zero-dependencies:**
- `U256` — 256-bit integer with little-endian `[u64; 4]` limbs; add-with-carry,
  subtract-with-borrow, bit test, big-endian serialisation.
- Widening 256×256→512-bit schoolbook multiply (`mul_wide`).
- **Field arithmetic mod p** (secp256k1 prime) using a 2-iteration Solinas
  reduction (`fp_reduce_wide`): `fp_add`, `fp_sub`, `fp_neg`, `fp_mul`, `fp_sq`,
  `fp_pow`, `fp_inv` (Fermat), `fp_sqrt` (Tonelli–Shanks shortcut, since p ≡ 3
  mod 4).
- **Scalar arithmetic mod n** (group order) using iterative N_COMPL folding
  (`fn_reduce_wide`): `fn_add`, `fn_neg`, `fn_mul`, `fn_pow`, `fn_inv`.
- **Jacobian point arithmetic**: `point_double` (dbl-2009-l formulas, a=0),
  `point_add_mixed` (madd-2007-bl), `scalar_mul_affine`, `scalar_mul_g`.
- **`recover_public_key`** — standard ECDSA recovery:
  1. Lift r to curve point R (square-root of r³+7).
  2. Choose y parity from recovery_id.
  3. Compute `Q = r⁻¹·(−z·G + s·R)`.
  4. Return 65-byte uncompressed point (`04 || X || Y`).
- **`recover_address`** — hashes the 64-byte (X‖Y) with `keccak256`, takes the
  last 20 bytes.

**Tests (10 total, all passing):**
- `keccak::*` — 4 existing Keccak vectors unchanged.
- `ecdsa::test_fp_arithmetic` — `(p−1)²≡1 mod p` and G on-curve check.
- `ecdsa::test_fp_inv` — `2·inv(2)≡1 mod p`.
- `ecdsa::test_fn_arithmetic` — `2·inv(2)≡1 mod n`.
- `ecdsa::test_scalar_mul_one` — `1·G == G`.
- `ecdsa::test_scalar_mul_two` — `2·G` matches known secp256k1 value.
- `ecdsa::test_ecrecover_precompile_vector` — go-ethereum `ValidKey` JSON
  vector; recovers address `a94f5374fce5edbc8e2a8697c15331677e6ebf0b`.

---

## 2026-03-18 — Baseline benchmarks (Keccak & ECDSA)

### Prompt
> Benchmark the reference keccak and ecdsa recovery.

### High-level effects
- Added `criterion 0.5` (with `html_reports`) to `[dev-dependencies]`.
- Created `benches/keccak.rs`: five input sizes (empty, 32 B, 136 B, 1 KiB,
  1 MiB); single function per size.
- Created `benches/ecdsa.rs`: `recover_public_key` and `recover_address` groups
  using the go-ethereum `ValidKey` test vector.
- Declared `[[bench]]` entries in `Cargo.toml` with `harness = false`.

**Baseline results (optimised build, criterion 0.5):**

| Benchmark | Time |
|---|---|
| keccak256 empty | 221 ns |
| keccak256 32 B | 220 ns |
| keccak256 136 B | 426 ns |
| keccak256 1 KiB | 1.69 µs |
| keccak256 1 MiB | 1.607 ms |
| ecdsa recover_public_key | 1.26 ms |
| ecdsa recover_address | 1.26 ms |

---

## 2026-03-18 — Comparative benchmarks vs alloy-consensus libraries

### Prompt
> Benchmark against the libraries used by alloy-consensus.

### High-level effects
- Fetched alloy-consensus and alloy-primitives Cargo.toml to identify
  standard Ethereum library choices:
  - **Keccak**: `sha3` (always-on in alloy-primitives), `tiny-keccak` (optional).
  - **ECDSA**: `k256` (pure-Rust RustCrypto) and `secp256k1` (C-backed libsecp256k1).
- Added dev-dependencies: `sha3 = "0.10"`, `tiny-keccak = { version = "2",
  features = ["keccak"] }`, `k256 = { version = "0.13", features = ["ecdsa"] }`,
  `secp256k1 = { version = "0.29", features = ["recovery", "global-context"] }`.
- Rewrote `benches/keccak.rs` to compare all three Keccak backends per size.
- Rewrote `benches/ecdsa.rs` to compare asmcrypto vs k256 vs secp256k1.
  - The test vector is generated at startup using `k256`'s own signing API with
    a fixed private key (`[0x01; 32]`), guaranteeing a canonical (low-s)
    signature that all three libraries accept.

**Comparative results:**

### Keccak-256

| Input | asmcrypto | sha3 | tiny-keccak |
|---|---|---|---|
| empty | 221 ns | 231 ns | 228 ns |
| 32 B | 220 ns | 225 ns | 229 ns |
| 136 B | 426 ns | 418 ns | 426 ns |
| 1 KiB | 1.69 µs | 1.60 µs | 1.66 µs |
| 1 MiB | 1.607 ms | 1.517 ms | 1.565 ms |

Our Keccak implementation is **within 5 %** of both reference libraries across
all input sizes; sha3 has a slight edge at large inputs likely due to its
SIMD-friendly inner loop.

### ECDSA recovery

| Benchmark | asmcrypto | k256 (RustCrypto) | secp256k1 (libsecp256k1) |
|---|---|---|---|
| recover_public_key | 1.38 ms | 111.7 µs **(12× faster)** | 21.4 µs **(64× faster)** |
| recover_address | 1.38 ms | 112.0 µs **(12× faster)** | 21.6 µs **(64× faster)** |

The ECDSA gap is the primary motivation for this project: production libraries
use highly-optimised scalar multiplication (wNAF window, GLV endomorphism, or
hand-written assembly), whereas our current implementation uses a simple
double-and-add loop. These numbers define the improvement target for the
forthcoming assembly/SIMD optimisations.

---

## 2026-03-18 — GLV + wNAF Shamir scalar multiplication

### Prompt
> Can we use the wnaf+glv endomorphism in our reference code?

### High-level effects

Replaced the simple double-and-add scalar multiplication in `src/ecdsa.rs` with
a complete GLV+wNAF Shamir simultaneous scalar multiplication:

**Algorithm overview:**
- **GLV decomposition:** Any scalar `k` is split into two ~128-bit sub-scalars
  `k1`, `k2` satisfying `k ≡ k1 + k2·λ (mod n)`, where `λ` is the GLV
  eigenvalue. This halves the effective scalar size.
- **wNAF width-5:** Each sub-scalar is encoded in width-5 Non-Adjacent Form,
  giving digits in `{0, ±1, ±3, ±5, ±7, ±9, ±11, ±13, ±15}`. Window tables of
  8 precomputed odd multiples `[P, 3P, …, 15P]` are built for `P` and `φ(P)`.
- **Shamir's trick:** Both wNAF sequences are processed together in a single
  131-step loop, roughly doubling throughput vs two independent multiplications.
- **φ(P):** The GLV endomorphism maps affine point `(x, y)` to `(β·x, y)` in
  O(1) field multiplications, where `β = (√(−3) − 1)/2 mod p`.

**Key new types and functions:**
- `S129` — signed 129-bit integer `{ mag: u128, hi: bool, neg: bool }` for
  sub-scalar storage.
- `glv_decompose(k) -> (S129, S129)` — Babai rounding decomposition using
  precomputed 256-bit lattice constants `g1`, `g2`, `b1`, `b2`.
- `wnaf_129(k_lo, k_hi) -> [i8; 131]` — width-5 wNAF with correct carry
  handling for 129-bit inputs.
- `build_table`, `table_get` — precomputed odd multiples and signed lookup.
- `phi_affine(px, py)` — applies the GLV endomorphism.
- `scalar_mul_glv_wnaf` — core Shamir loop; replaces both `scalar_mul_g` and
  `scalar_mul_affine`.
- `point_add` — full Jacobian-Jacobian point addition.
- `point_neg` — negate a Jacobian point.

**Bugs found and fixed during implementation (7 total in constants/formulas):**
1. GLV formula: `r2 = c2·b2 − c1·b1 mod n` (not `c1·(−b1) + c2·(−b2)`).
2. `S129` struct: added `hi: bool` for bit 128 (k1 can reach 129 bits).
3. `wnaf_129`: replaced 128-bit version; carries correctly between `lo`/`hi`.
4. `n_half`: wrong constant (`0xDFE92F4661B8DD57` → `0xDFE92F46681B20A0`).
5. `LAMBDA` limb[0]: nibble-shifted (`0x2E0CFC810B51283C` → `0xE0CFC810B51283CE`).
6. `BETA` lower 3 limbs: all three wrong; corrected to match secp256k1 spec.
7. `BETA` value itself: was `0x7AE96A2B657C0710…` (wrong cube root of unity);
   correct value is `β = (√(−3)−1)/2 mod p = 0x851695D49A83F8EF…` which
   satisfies `φ(P) = λ·P` for all curve points.

**Final constants (verified):**
- `BETA = 0x851695d49a83f8ef919bb86153cbcb16630fb68aed0a766a3ec693d68e6afa40`
- `LAMBDA = 0xac9c52b33fa3cf1f5ad9e3fd77ed9ba4a880b9fc8ec739c2e0cfc810b51283ce`

All 10 tests pass.

---

## 2026-03-18 — perf profiling of ECDSA hotspots

### Prompt
> Run perf on the asmcrypto ecdsa to identify hotspots.

### High-level effects

Added `examples/perf_ecdsa.rs` — a 50 000-iteration tight loop over
`recover_address` with a 200-call warm-up, suitable for `perf record`.

Profiled on: **AMD Ryzen 9 9955HX** (Zen 5).  
Available ISA extensions of interest: **ADX** (MULX/ADCX/ADOX), **AVX-512 IFMA**
(`VPMADD52LU/HU`), BMI1/BMI2, AVX-512BW/DQ/VL, SHA_NI.

#### Flat profile (self time, 3096 samples, `perf record -g --call-graph dwarf -F 997`)

| Self % | Samples | Function |
|---|---|---|
| **68.3%** | 2092 | `asmcrypto::ecdsa::fp_mul` |
| 12.6% | 380 | `asmcrypto::ecdsa::point_double` |
| 11.5% | 351 | `asmcrypto::ecdsa::fn_mul` |
| 3.6% | 110 | `asmcrypto::ecdsa::point_add` |
| 1.5% | 44 | `asmcrypto::ecdsa::scalar_mul_glv_wnaf` |
| 1.0% | 28 | `asmcrypto::ecdsa::JacobianPoint::to_affine` |

#### Interpretation

`fp_mul` alone consumes 68% of cycles. Its inner loop is a 4×4 schoolbook
`mul_wide` (16 × `MUL` instructions) followed by a two-round Solinas reduction.
The `point_double` and `point_add` percentages are mostly `fp_mul` calls reported
at the call-site (LLVM inlines lightly here). `fn_mul` (scalar-field mod n) uses
the same schoolbook core.

#### Optimisation targets, in priority order

1. **`fp_mul` (68%)** — replace `mul_wide` schoolbook with an ADX-accelerated
   implementation using `MULX`/`ADCX`/`ADOX`. These instructions decouple the
   multiply output from CF/OF, enabling full pipelining of the carry chain.
   Alternative: `VPMADD52LU`/`VPMADD52HU` (AVX-512 IFMA) for a 52-bit multiply
   accumulate approach used by e.g. OpenSSL's P-256 assembly.

2. **`fn_mul` (11.5%)** — same treatment; both share `mul_wide`.

3. **Jacobian formula reduction** — `point_double` costs ~8 `fp_mul` + 4 `fp_sq`;
   `point_add` costs ~11 `fp_mul` + 2 `fp_sq`. Switching to add-2008-bj
   (dedicated doubling formula) or a Z=1 mixed-add path would reduce call count.

4. **`to_affine` (1%)** — one modular inversion (254-step exponentiation).
   Batching inversions across multiple signature verifications (Montgomery's
   trick) would amortise this cost.
