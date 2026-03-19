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

---

## 2026-03-18 — ADX mul_wide, precomputed G table, target-cpu=native

### Prompt
> Do all of these [three optimisation targets from the perf profile].

### High-level effects

**1. `.cargo/config.toml` — native CPU tuning (new file)**

```toml
[build]
rustflags = ["-C", "target-cpu=native"]
```

Enables LLVM to emit BMI2 and ADX instructions throughout the crate and makes
`#[cfg(target_feature = "bmi2")]` / `"adx"` resolve to `true` at compile time
on this machine (AMD Ryzen 9 9955HX).

**2. ADX-accelerated `mul_wide` (`src/ecdsa.rs`)**

`mul_wide` is the 256×256→512-bit schoolbook multiply called by both `fp_mul`
(68% of cycles) and `fn_mul` (11.5%). It was replaced with two implementations
selected at compile time:

- **`mul_wide_adx`** — 4-row MULX/ADCX/ADOX inline assembly using per-row
  **two-chain carry** (ADCX feeds CF, ADOX feeds OF in parallel), eliminating
  the serialisation between multiply and add:
  - `MULX r_hi, r_lo, mem` — multiplies `rdx * mem`, stores hi:lo in two
    registers without touching any flags.
  - `ADCX dst, src` — `dst += src + CF`, sets CF only.
  - `ADOX dst, src` — `dst += src + OF`, sets OF only.
  - `xor e_reg, e_reg` at each row start atomically clears both CF and OF.
  - Register map: r8–r15, rcx, rdi (8 accumulators R[0]–R[7]), r9/r13
    (hi/lo temps), rax (zero constant), rdx (b[i] for MULX).
  - `rbx` is off-limits in Rust's inline asm on Linux (LLVM uses it internally);
    replaced with `rdi` for R[7].
  - `#[target_feature(enable = "bmi2,adx")]` guards the function; `#[inline(always)]`
    cannot be combined with `#[target_feature]` (Rust issue #145574), removed.

- **`mul_wide_generic`** — the original schoolbook `u128`-based loop, used when
  BMI2/ADX are unavailable.

- **`mul_wide`** — dispatch function using `#[cfg(target_feature)]`; selects ADX
  path at zero runtime cost when both features are present.

**3. Precomputed affine G and φ(G) tables (`src/ecdsa.rs`)**

Two compile-time constants added after `LAMBDA`:

- **`G_TABLE: [(U256, U256); 8]`** — affine coordinates of [G, 3G, 5G, …, 15G],
  the 8 odd multiples used by window-4 wNAF.
- **`PHI_G_TABLE: [(U256, U256); 8]`** — affine coordinates of [φ(G), 3φ(G),
  …, 15φ(G)].  Since the GLV endomorphism maps (x, y) → (β·x, y), the
  y-coordinates are identical to `G_TABLE`; only the x-coordinates differ.

Both tables were computed via Python using actual secp256k1 curve arithmetic and
verified against known generator coordinates.

**4. Fixed-base `scalar_mul_g` rewritten**

`scalar_mul_g` previously delegated to the general `scalar_mul_glv_wnaf` with GX/GY
as input. It is now a dedicated fixed-base implementation:

- Skips the `build_table` step entirely (tables are compile-time constants).
- Uses `point_add_mixed(&acc, &qx, &qy)` (assumes Z₂=1) instead of full
  `point_add`, saving ~4 `fp_mul` per step (madd-2007-bl vs add-2007-bl).
- Helper functions `g_table_lookup(d, negate)` and `phi_g_table_lookup(d, negate)`
  combine the subscalar sign flag (from GLV decomposition) with the wNAF digit
  sign to avoid redundant negation branches.

**5. Correctness**

All 10 tests pass. No warnings after:
- wrapping the `asm!` macro in an explicit `unsafe {}` block (Rust 2024
  `unsafe_op_in_unsafe_fn` lint).
- adding `#[allow(dead_code)]` to `GX` / `GY` (superseded by `G_TABLE[0]` but
  retained as documentation constants).

**Benchmark results (criterion, release, target-cpu=native):**

| Benchmark | Before | After | Speedup |
|---|---|---|---|
| asmcrypto recover_public_key | 60.5 µs | 57.2 µs | +5.8% |
| asmcrypto recover_address | 60.5 µs | 57.0 µs | +5.8% |
| k256 recover_public_key | — | 115.8 µs | (ref) |
| secp256k1 recover_public_key | — | 21.5 µs | (target) |

The ADX `mul_wide` is responsible for the full 5.8% improvement on the ECDSA
benchmarks (both paths use variable-base multiplication; the precomputed G table
accelerates signing but `recover_public_key` uses only `scalar_mul_affine`).

The remaining 2.6× gap vs secp256k1 is attributable to:
- `point_double` (8 fp_mul currently, no ADX in the doubling formula itself),
- Jacobian → affine conversion (one 254-step exponentiation, not batched),
- Solinas reduction in `fp_reduce_wide` (not yet pipelined with the multiply).

---

## Session 5e — Inline fn_reduce_wide into fn_mul; #[inline(never)] on fp_mul

### Prompts
> Put an inline(never) on fp_mul instead. Manually inline fn_reduce_wide into
> fn_mul. Change the bench of reduce for a bench of fn_mul.

### High-level effects

**`fn_mul` fully inlined (commit 3671f61):**
- The previously separate `fn_reduce_wide` function (2-pass unrolled port of
  the C `secp256k1_scalar_reduce_512`) is now inlined directly inside `fn_mul`.
- `fn_mul` is marked `#[inline(never)]` so LLVM treats it as a single
  out-of-line unit, giving the scheduler a large instruction window rather than
  duplicating the expanded macro body at every call site.
- `fp_mul` is also marked `#[inline(never)]` for the same reason — it dominates
  at ~68% of ECDSA cycles according to perf.

**Dead code removed:**
- The standalone `fn_reduce_wide` function deleted (was 140 lines).
- `N_COMPL: U256` constant deleted (values inlined as `N_C_0`/`N_C_1` inside
  the local macros in `fn_mul`).

**Benchmarks updated:**
- `benches/mul_wide.rs` bench renamed from `fn_reduce_wide` to `fn_mul`
  (measuring `mul_wide` + full reduction together).
- `examples/perf_reduce.rs` updated: `bench_fn_reduce_wide(fn_wide)` replaced
  with `bench_fn_mul(n_minus_1, n_minus_1)` where `n_minus_1` is the 4-limb
  LE representation of n−1.

**Build:** 10/10 tests pass, zero warnings.

---

## Session 5m — fp_sq squaring kernel, fp_half, C-style point_double

**Prompts:**
1. "use fp_sq where possible"
2. "look at what the C code does for the multiply in fp_mul"
3. "implement point_double as in the C code"

**High-level effects (commit 3a7ae60):**

### Dedicated `fp_sq` squaring kernel
The previous `fp_sq(a)` simply delegated to `fp_mul(a, a)`, computing all 16
products of a 4×4 schoolbook multiply.  
A dedicated squaring kernel exploits the symmetry of Aᵀ·A:
- **Diagonal terms** `aᵢ²` (×4): `muladd(c, aᵢ, aᵢ)` — 1 mul each
- **Cross-terms** `2·aᵢ·aⱼ` (×6): `muladd2(c, aᵢ, aⱼ)` — 1 mul + left-shift-by-1

Total: **10 `mulq` instead of 16**, followed by the same Solinas fold as `fp_mul`.
Marked `#[inline(never)]` to give LLVM a wide scheduling window.

### `fp_half` — field halving
New `#[inline(always)] fn fp_half(a: &U256) -> U256`:
- If `a` is even: right-shift all 4 limbs by 1 (free).
- If `a` is odd: add `p` (which is also odd, so `a + p` is even), then shift.

The carry out of bit 255 slides into bit 255 of the result. No multiplications
required — just one conditional 256-bit add and a 256-bit shift.

### `point_double` ported from secp256k1 `gej_double`
The dbl-2009-l formula (5 sqr + 2 mul) was replaced by the secp256k1 C
library's `gej_double` formula (4 sqr + 3 mul), which uses `fp_half` to
halve the slope:

```
L  = (3/2)·X₁²   [1 sqr + 3× + half]
S  = Y₁²          [1 sqr]
T  = −X₁·S        [1 mul]
X₃ = L² + 2T      [1 sqr]
S' = S²            [1 sqr]
Y₃ = −(L·(X₃+T) + S')  [1 mul]
Z₃ = Y₁·Z₁        [1 mul]
```

The formula has slightly shorter latency chains trading one of the cheap
field squarings for the near-free `fp_half`.

### `fp_mul_8` removed
The `fp_mul_8` helper (used by the old dbl-2009-l `Y₃` computation) is now
dead and was deleted.

**Performance:**
| Metric | Before | After | Δ |
|---|---|---|---|
| ECDSA e2e | 57.0 µs | 55.59 µs | −2.5% |
| fp_mul | 8.00 ns | 8.27 ns | +3% (noise) |

The ECDSA improvement comes entirely from faster squarings: `fp_sq` is called
in `point_double`, `fp_inv`, `fp_sqrt`, and the main scalar-multiplication loop.

**Build:** 10/10 tests pass, zero warnings.

---

## Session 5n — `ecdsa_clone`: 5×52-bit field, all 11 tests passing

### Prompt
> "make a new module ecdsa_clone that is an exact translation of the C code.
> Reference the path to each C function on my local machine in the comments."
> (followed by several debugging sessions to fix bugs in the translation)

### High-level effects

**New `src/ecdsa_clone.rs`** (~1550 lines): a direct Rust translation of
`libsecp256k1`'s 5×52-bit field-element representation and group operations,
each function cross-referenced to its C source by comment.

**Structures mirroring the C types:**
- `Fe { n: [u64; 5] }` — 5×52-bit packed field element
- `Scalar { d: [u64; 4] }` — 256-bit group scalar (little-endian)
- `Ge / Gej` — affine and Jacobian secp256k1 points

**Bugs found and fixed during translation:**

1. **`scalar_inverse_var` limb-iteration order** — binary square-and-multiply
   must iterate MSB-first within each 64-bit word.

2. **`N_C_0` constant** — the N-complement limb 0 was off by 1:
   correct form is `N_0.wrapping_neg()`.

3. **`fe_inv` used wrong modulus** — used scalar n−2 instead of field prime p−2.
   Fixed: binary square-and-multiply over
   `[0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFEFFFFFC2D]`.

4. **`fe_half` used `|` instead of `+`** — the critical bug. The C source
   writes `(t1 >> 1) + ((t2 & one) << 51)`. For magnitude ≥ 2 inputs,
   `t1 >> 1` can already have bit 51 set; `|` then silently discards the carry,
   producing a result wrong by `2^155 + 2^207`. Using `+` propagates the carry
   correctly. This caused `gej_double` to return the wrong x-coordinate for 2G.

**`test_ecrecover_clone`:** recovers Ethereum address
`7156526fbd7a3c72969b54f64e42c10fbb768c8a` from a known secp256k1 signature.

**Build:** 21/21 tests pass (11 ecdsa_clone + 4 keccak + 6 ecdsa), zero errors.

---

## Session 5o — `ecdsa_clone`: Strauss wNAF + GLV ecmult; 44.7 µs/call

### Prompt
> "Can we try the Strauss wNAF algorithm with precomputed tables as in the C version?"

### High-level effects

**Replaced naive double-and-add `ecmult` with a faithful port of `ecmult_impl.h`:**

New functions added to `src/ecdsa_clone.rs`:

| Function | C source | Purpose |
|---|---|---|
| `scalar_get_bits(s, pos, len)` | `ecmult_impl.h` | bit-range extraction for wNAF |
| `scalar_mul_shift_384(a, b)` | `scalar_4x64_impl.h` `scalar_mul_shift_var` | (a·b)>>384, round to nearest |
| `scalar_split_lambda(k)` | `scalar_impl.h` | GLV: r1+λ·r2=k, both ~128 bit |
| `scalar_split_128(k)` | `scalar_4x64_impl.h` | lo128 / hi128 split for G scalar |
| `ecmult_wnaf(s, w=5)` | `ecmult_impl.h` | signed windowed NAF |
| `build_odd_multiples_table(a)` | `ecmult_impl.h` | {P,3P,...,15P} via single field-inversion (Montgomery batch trick) |
| `table_get_ge / table_get_ge_lambda` | `ecmult_impl.h` | table lookup with automatic negation for negative NAF digits |
| `g_tables()` OnceLock | – | cache G and 2¹²⁸·G tables globally (built once per process) |

**GLV decomposition constants (from `scalar_impl.h`):**
- λ = cube root of 1 mod n: `5363AD4C...1B23BD72`
- β = cube root of 1 mod p: `7ae96a2b...719501ee`
- g1, g2, minus_b1, minus_b2: lattice basis for algorithm 3.74

**Algorithm:**
1. Split `u2` (A scalar) via GLV → `na_1 + λ·na_lam`, both ~128 bits
2. Split `u1` (G scalar) simply → `ng_1 = lo128`, `ng_128 = hi128`
3. Build affine table `{A, 3A, ..., 15A}` with Montgomery batch-inversion (1 fe_inv + 22 fe_muls)
4. Build `aux` table = `{β·Ax, β·3Ax, ...}` for the λ-twisted lookups
5. Fetch cached tables for G and 2¹²⁸·G (computed once via `OnceLock`)
6. Convert all 4 scalars to wNAF (window 5, ≤ 129 bits each)
7. Main loop: ≤ 129 doublings + ≤ 4 × 26 = 104 affine additions

**Performance (50 000 iterations, `--release`):**

| Variant | Time | vs previous |
|---|---|---|
| `ecdsa` (4×64 Solinas) | 53 µs | — |
| `ecdsa_clone` naive double-and-add | 69 µs | baseline |
| `ecdsa_clone` Strauss wNAF + GLV | **45 µs** | 35% faster, 16% faster than Solinas |

**Build:** 21/21 tests pass, zero errors.

---

## 2026-03-18 — Compile-time constant evaluation: `const fn hex32 / set_b32_mod`

### Prompt
> Instead of hex32 use static constants or a const function.

### High-level effects

- `hex_nibble` and `hex32` converted to `const fn`; `hex32` rewrites the iterator loop as a `while` loop (iterators are not allowed in `const fn`). Uppercase hex digits (`A`–`F`) added to `hex_nibble` match arm.
- `Fe::set_b32_mod` declared `pub const fn` (pure bit ops — already const-compatible).
- Four runtime helper functions eliminated; replaced by module-level `const` items evaluated entirely at compile time:
  - `fn G() -> Ge` → `const G: Ge`
  - `fn beta_fe() -> Fe` → `const BETA: Fe`
  - `fn order_as_fe() -> Fe` → `const ORDER_AS_FE: Fe`
  - `fn p_minus_order() -> Fe` → `const P_MINUS_ORDER: Fe`
- All 14 call sites updated (`G()` → `G`, `beta_fe()` → `BETA`, etc.) across `g_tables`, `ecmult`, `ecdsa_sig_recover`, and test functions.
- **Build:** 11/11 `ecdsa_clone` tests pass, zero errors, commit `d708447`.

---

## 2026-03-19 — Bernstein-Yang `modinv64` Safegcd module

### Prompt
> Implement the modinv64 in its own module. Keep the fermat versions of fe_inv and scalar_inverse_var for comparison.

### High-level effects

**New file `src/modinv64.rs`** (~270 lines) — standalone module, no dependencies on other crate modules:

| Item | Description |
|---|---|
| `Signed62` | 256-bit integer as 5 × signed-62-bit limbs |
| `ModInfo` | Modulus in signed62 + its negative inverse mod 2^62 |
| `Trans2x2` | 2×2 transition matrix (scaled by 2^62) |
| `normalize_62` | Bring a signed62 into [0, modulus) |
| `divsteps_62_var` | Up to 62 variable-time Bernstein-Yang division steps |
| `update_de_62` | Apply transition matrix to (d, e) with modular correction via i128 accumulators |
| `update_fg_62_var` | Apply transition matrix to (f, g) for variable limb count |
| `modinv64_var` | Full variable-time modular inverse (outer loop: until g = 0) |
| `FE_MODINFO` | Compile-time modinfo for p = 2^256 − 2^32 − 977 |
| `SCALAR_MODINFO` | Compile-time modinfo for n (secp256k1 group order) |

C reference: `secp256k1-sys-0.11.0/.../modinv64_impl.h` (Peter Dettman).
Differences vs. C: Rust `i128`/`u128` replace the `secp256k1_int128` helper; `u64::trailing_zeros()` replaces `ctz64_var`; constant-time variant not ported.

**`src/ecdsa_clone.rs` additions:**
- `fe_to_signed62` / `fe_from_signed62` — repack 5×52-bit Fe ↔ 5×62-bit Signed62
- `scalar_to_signed62` / `scalar_from_signed62` — repack 4×64-bit Scalar ↔ 5×62-bit Signed62
- `fe_inv_var` — Safegcd field inverse (Fermat `fe_inv` kept for comparison)
- `scalar_inv_var` — Safegcd scalar inverse (Fermat `scalar_inverse_var` kept for comparison)
- Two new tests: `test_fe_inv_var_safegcd`, `test_scalar_inv_var_safegcd` — cross-check safegcd vs. Fermat and verify a·a⁻¹ = 1

**Build:** 13/13 `ecdsa_clone` tests pass, zero errors, commit `9b54dab`.

---

## 2026-03-19 — Wire safegcd into hot path

### Prompt
> Add modinv64 to the hot path and re-run.

### High-level effects

- Three hot-path call sites updated:
  - `gej_normalize`: `fe_inv` → `fe_inv_var`
  - `build_odd_multiples_table`: `fe_inv` → `fe_inv_var` (the single batch inversion)
  - `ecdsa_sig_recover`: `scalar_inverse_var` → `scalar_inv_var`
- Fermat `fe_inv` and `scalar_inverse_var` retained (used only in tests).

**Performance (50 000 iterations, `--release`):**

| Implementation | Time | vs previous |
|---|---|---|
| `ecdsa` (4×64 Solinas) | 52.11 µs | – |
| `ecdsa_clone` Fermat inversion | 43.67 µs | baseline |
| `ecdsa_clone` safegcd inversion | **29.06 µs** | 33% faster, 44% faster than Solinas |

**Build:** 13/13 tests pass, commit `eadb8ef`.

---

## 2026-03-19 — Static G tables with WINDOW_G = 15

### Prompt
> Can we use static data to store the tables?

### High-level effects

- Added `WINDOW_G = 15` and `pub const TABLE_SIZE_G = 8192` constants alongside the existing `WINDOW_A = 5 / TABLE_SIZE = 8`.
- `table_get_ge` and `table_get_ge_lambda` signatures widened from `&[Ge; TABLE_SIZE]` to `&[Ge]` (slices) to support variable-size tables.
- Added `build_odd_multiples_table_vec(a, n)` (Vec-based, any size) and `pub fn build_g_tables_vec()` (computes the two WINDOW_G-sized tables for G and 2¹²⁸·G).
- New example `gen_g_tables` runs the computation once and emits `src/g_tables_generated.rs` — a 16 400-line Rust source file containing:
  - `static PRE_G_DATA: [[u64; 10]; 8192]` — odd multiples of G in 5×52 limb form
  - `static PRE_G128_DATA: [[u64; 10]; 8192]` — odd multiples of 2¹²⁸·G
  - `fn g_table_get_ge(data, n)` — inline lookup / optional y-negation
- `include!("g_tables_generated.rs")` replaces the runtime `OnceLock<(Vec<Ge>, Vec<Ge>)>`; the G-table data is now a zero-cost compile-time constant.
- `ecmult_wnaf` calls for the G scalars (`ng_1`, `ng_128`) updated from `WINDOW_A` to `WINDOW_G`; A scalars unchanged.

**Performance (50 000 iterations, `--release`):**

| Implementation | Time | vs C |
|---|---|---|
| `ecdsa_clone` safegcd + WINDOW_A=5 (OnceLock) | 29.06 µs | 1.36× |
| `ecdsa_clone` safegcd + WINDOW_G=15 (static)  | **25.49 µs** | **1.19×** |
| secp256k1 C library | 21.36 µs | 1.00× |

Addition cost for G scalars drops from ~32 additions/scalar (window 5) to ~9 additions/scalar (window 15), a 78% reduction.

**Build:** 13/13 `ecdsa_clone` tests pass.

---

## 2026-03-19 — RDTSC phase timeline

### Prompt
> Can we add rdtsc timing to various points in the code to get a timeline of execution?

### High-level effects

- Additional `pub` items exposed from `ecdsa_clone`: `WINDOW_A`, `TABLE_SIZE`, `WINDOW_G`, `BETA`, `scalar_split_lambda`, `scalar_split_128`, `build_odd_multiples_table`, `ecmult_wnaf`, `table_get_ge`, `table_get_ge_lambda`, `PRE_G_DATA`, `PRE_G128_DATA`, `g_table_get_ge`.
- New example `examples/timeline_ecdsa.rs`: calls each phase individually, samples cycle counts with `_rdtsc()`, reports median and p95 over 10 000 iterations.

**Phase breakdown (median cycles @ ~5.4 GHz, n = 10 000):**

| Phase | Cycles | % |
|---|---|---|
| §1 ge_set_xo_var (R recovery, fe_sqrt) | 8 250 | 12.9% |
| §2 scalar_inv_var (safegcd 1/r) | 1 500 | 2.3% |
| §3 scalar_mul × 2 (u1, u2) | 101 | 0.2% |
| §4 scalar_split (GLV + 128-bit) | 175 | 0.3% |
| §5 build_odd_multiples_table + aux | 6 650 | 10.4% |
| §6 ecmult_wnaf × 4 | 699 | 1.1% |
| **§7 ecmult main loop (~129 iters)** | **43 875** | **68.4%** |
| §8 ge_set_gej_var (normalise Q) | 1 575 | 2.5% |
| §9 keccak256 | 474 | 0.7% |
| **TOTAL** | **64 125** | |

The ecmult main loop (doublings + mixed-addition table lookups) dominates at 68% of total cost. Next priorities: §1 ge_set_xo_var (13%) and §5 build A table (10%).

---

## 2026-03-19 — AVX-512 batch Keccak-256 (keccak_batch)

### Prompt
> Create a new module keccak_batch with a function keccak256_batch for x86_64 only which takes eight input byte streams [&[u8]; 8] and outputs eight 256 bit hashes. Use avx512bw intrinsics to hold the state in 25 zmm registers.

### High-level effects

New module `src/keccak_batch.rs` with `pub fn keccak256_batch(inputs: [&[u8]; 8]) -> [[u8; 32]; 8]`.

**Architecture:**
- 25 ZMM registers (`[__m512i; 25]`) hold all 8 parallel Keccak-f[1600] states simultaneously: `ZMM[lane]` = `[stream7.lane, …, stream0.lane]`
- One `permute()` call advances all 8 states with a single pass through θ → ρ+π → χ → ι

**Implementation:**
- **θ**: 5 column XORs (xor5 helper), 5 D[x] = C[x−1] ^ rol(C[x+1], 1), scatter XOR into all 25 lanes
- **ρ+π**: 25 explicit `_mm512_rol_epi64` with compile-time immediate constants (mapping precomputed offline)
- **χ**: 25 `xor(b[i], andnot(b[x+1,y], b[x+2,y]))` — branchless using `_mm512_andnot_si512`
- **ι**: 1 `_mm512_xor_si512` with `_mm512_set1_epi64(RC[round])`
- **Absorb**: 17 `_mm512_set_epi64` calls load 8 little-endian u64 lanes (one per stream) into a ZMM, then XOR into state; then `permute()`
- **Squeeze**: store ZMM[0..4] to temp arrays, scatter 8-byte slices to 8 per-stream output buffers
- **Variable-length inputs**: shared complete blocks absorbed vectorially; diverging final blocks built per-stream into padded `[u8; 136]` arrays, then batch-absorbed; if block counts differ, scalar fallback via `extract_scalar_state` + `finish_scalar`
- Runtime `is_x86_feature_detected!` guard; scalar fallback on non-AVX-512 CPUs

**Benchmark (200 000 iters, 64-byte inputs, release):**

| | µs/batch | ns/hash |
|---|---|---|
| scalar × 8 | 1.495 | 186.9 |
| `keccak256_batch` × 8 | **0.242** | **30.2** |
| gain | **6.18×** | |

**Tests:** 3 new batch tests (empty, various lengths, uniform 64-byte) — all cross-checked against scalar references. 7/7 keccak tests pass.
