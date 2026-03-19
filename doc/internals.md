# asmcrypto Internals

This document describes the algorithms implemented in `asmcrypto` and the
design decisions behind the AVX-512 vectorisation strategy.

---

## 1. Keccak-256

### 1.1 Sponge construction

Keccak-256 is a sponge function operating over a 1600-bit (200-byte) state
organised as a 5×5 array of 64-bit lanes.  It has:

- **Rate** (r) = 1088 bits (136 bytes) — the portion of the state that absorbs
  input and squeezes output.
- **Capacity** (c) = 512 bits — the opaque portion that provides security.

Padding appends a single `0x01` byte (multi-rate padding) followed by zeros
and a `0x80` byte at the end of the last block.  Each 136-byte block is XORed
into the rate portion of the state, then the 24-round Keccak-f[1600]
permutation is applied.  The first 32 bytes of the state after the final
permutation are the 256-bit digest.

### 1.2 Keccak-f[1600]: the 24 rounds

Each round applies five step mappings in sequence:

| Step | Symbol | Operation |
|---|---|---|
| Theta (θ) | Θ | XOR each lane with the parity of two neighbouring columns |
| Rho (ρ)   | ρ | Rotate each of the 25 lanes by a fixed offset |
| Pi (π)    | π | Permute lanes within the 5×5 plane |
| Chi (χ)   | χ | Bitwise `a ^= (~b & c)` per row (the only nonlinear step) |
| Iota (ι)  | ι | XOR the (0,0) lane with a round constant |

### 1.3 Scalar implementation (`keccak` module)

The scalar implementation follows the compact reference design: the 5×5 state
is stored as a flat `[u64; 25]`, the five step mappings are applied in order,
and the round constants are a compile-time `[u64; 24]` array.

### 1.4 AVX-512 batch implementation (`keccak_batch` module)

**Goal**: hash 8 independent messages simultaneously without any communication
between lanes.

**Interleaving strategy**: the 1600-bit Keccak state (25 lanes of u64) is
replicated across eight ZMM registers.  A single `__m512i` (512 bits = 8 ×
64-bit lanes) holds the same state position from all eight input streams.
Thus the 5×5 state becomes 25 ZMM registers, and one AVX-512 instruction
(e.g. `VPTERNLOGQ` for Chi, `VPXORQ` for XOR-based steps) operates on all
eight streams in parallel.

```
ZMM[0]  = [state[0][stream0], state[0][stream1], …, state[0][stream7]]
ZMM[1]  = [state[1][stream0], state[1][stream1], …, state[1][stream7]]
…
ZMM[24] = [state[24][stream0], …, state[24][stream7]]
```

The rotation offsets for Rho are implemented with `VPROLVQ` (variable-rotate
of 64-bit lanes within a ZMM register, which is free when all 8 lanes rotate
by the same amount since a single broadcast scalar can drive the rotate count).

The Chi nonlinear layer uses:

```asm
VPTERNLOGQ z_out, a, b, c   ; computes out = a ^ (~b & c) with imm8 = 0xD2
```

This replaces three instructions per element with one, giving Chi a cost of
only 5 ZMM instructions for each row of 5 lanes across all 8 streams.

**Throughput**: 6× over 8 sequential scalar hashes on Zen 4.

---

## 2. secp256k1 ECDSA address recovery

### 2.1 Mathematical background

Given a message hash `z`, a signature `(r, s)`, and a recovery id `v`, the
algorithm recovers the signer's public key as an affine point `Q = (Qx, Qy)`:

1. Treat `r` as the x-coordinate of a curve point `R = (r_x, r_y)` where
   `r_y` is lifted from the curve equation `y² = x³ + 7 (mod p)` and its
   parity is chosen to match `v`.
2. Compute `r⁻¹ mod n` (Fermat: `r^(n−2) mod n`).
3. Compute scalars `u₁ = −z·r⁻¹ mod n` and `u₂ = s·r⁻¹ mod n`.
4. Compute `Q = u₁·G + u₂·R` (two scalar multiplications and a point
   addition).
5. The Ethereum address is `keccak256(Qx ‖ Qy)[12..]`.

### 2.2 Field arithmetic

All arithmetic is modular over the secp256k1 prime `p = 2²⁵⁶ − 2³² − 977`.

**Scalar basis (`ecdsa` module)**: 4 × 64-bit limbs (standard 256-bit
Montgomery form).  Field multiplication uses schoolbook 4×4 with an inline
Montgomery reduction exploiting the sparse structure of `p`.

**IFMA basis (`x8` module)**: 5 × 52-bit limbs (the AVX-512IFMA representation
introduced by Gueron and Krasnov).  The field multiplier `fp_mul_x8` uses
`VPMADD52LO/HI` to perform a schoolbook 5×5 product (50 fused-multiply-add
instructions) followed by Solinas reduction exploiting `p + 2³² + 977 = 2²⁵⁶`.

The 52-bit representation is chosen because `VPMADD52` operates on 52-bit
inputs exactly, avoiding all overflow bookkeeping.

### 2.3 GLV endomorphism

secp256k1 has an efficiently computable endomorphism φ: (x, y) → (β·x, y)
where β = 2²¹⁴ + 2¹⁰⁷ + … (the cube root of unity mod p) and accordingly for
the scalar λ mod n.

For a scalar `k`, we decompose `k = k₁ + k₂·λ (mod n)` where both `|k₁|` and
`|k₂|` are at most `⌈√n⌉ ≈ 2¹²⁸`.  Then `k·P = k₁·P + k₂·φ(P)`.  The two
128-bit sub-scalars can be processed simultaneously by an interleaved wNAF
loop, halving the number of point-double steps from ~256 to ~128.

### 2.4 Window NAF scalar multiplication

Non-Adjacent Form (NAF) is a signed-digit representation where no two
consecutive digits are non-zero.  The width-w NAF (wNAF) uses digits in
`{0, ±1, ±3, …, ±(2^(w−1)−1)}`, reducing the average digit density to
≈ 1/(w+1).

For the generator multiplications `u₁·G` (`scalar_mul_g_x8`), a precomputed
table of odd multiples of `G` is itted into cache.  For variable-base
(`u₂·R`, `scalar_mul_affine_x8`), a small 4-bit window table is built on the
fly per lane (using point doubling in Jacobian coordinates).

The main loop alternates between doublings (`pt_double_x8`) and mixed
additions (`pt_add_mixed_x8`, cheaper than full `pt_add_x8` because one
operand is affine, eliminating Z-coordinate multiplications).

### 2.5 Batch affine conversion (`to_affine_x8`)

Converting Jacobian `(X : Y : Z)` to affine `(X/Z², Y/Z³)` requires one
field inversion per point.  With eight points, the classic Montgomery
batch-inversion trick reduces this to one scalar field inversion plus 21
field multiplications:

1. Compute prefix products: `P[0] = Z₀`, `P[k] = P[k−1]·Zₖ`.
2. Invert the full product: `inv = 1 / P[7]`.
3. Unroll suffixes: for `i = 7..0`, `inv_z[i] = inv·P[i−1]`,
   `inv = inv·Zᵢ`.
4. Apply: `aff_x[i] = X[i]·inv_z[i]²`, `aff_y[i] = Y[i]·inv_z[i]³`.

### 2.6 Phase 1a / Phase 1b vectorisation design

`recover_addresses_avx512` is split into two phases:

#### Phase 1a (vectorised, all 8 lanes simultaneously)

| Step | AVX-512 operation |
|---|---|
| Validate r, s ∈ \[1, n−1\] | 8 scalar comparisons (branchless bitmask) |
| rhs = r³ + 7 mod p | `fp_sq_x8` + `fp_mul_x8` + `fp_add_x8` |
| r_y = √rhs mod p | `fp_sqrt_x8` (a^((p+1)/4), 253-squaring addition chain) |
| sqrt validity check | `fp_sq_x8` + `store` + compare |
| parity select | `fp_neg_x8` + 8-bit mask + `blend_x8` |
| r⁻¹ mod n | `fn_inv_x8` (a^(n−2), 254-squaring addition chain in ZMM) |
| u₁ = −z·r⁻¹ mod n | `fn_mul_x8` + `fn_neg_x8` |
| u₂ = s·r⁻¹ mod n | `fn_mul_x8` |

Previously, Phase 1a ran sequentially over 8 lanes using scalar arithmetic.
The 254-squaring Fermat inverse was the dominant bottleneck (8 independent
invocations each requiring ~254 IFMA squarings).  Replacing all 8 with one
`fn_inv_x8` call reduces the cost by the full 8× lane factor.

#### Phase 1b (vectorised, all 8 lanes simultaneously)

```
p₁    = scalar_mul_g_x8(u₁s)           // 8 lanes: u₁·G
p₂    = scalar_mul_affine_x8(u₂s, R)   // 8 lanes: u₂·R
Q     = pt_add_x8(p₁, p₂)              // 8 lanes: Jacobian + Jacobian
       [Z=0 guard: mark infinity lanes invalid, replace Z with 1]
(x,y) = to_affine_x8(Q)               // batch inversion: 1 fp_inv + 21 fp_mul
```

#### Phase 2 (Keccak, vectorised)

`keccak256_batch` hashes all 8 64-byte `(Qx ‖ Qy)` buffers simultaneously
using the interleaved ZMM strategy described in §1.4.

#### Phase 3 (scalar)

Extract `addr[i] = keccak_hash[i][12..]`, zero invalid lanes.

### 2.7 Invalid-lane handling

Lanes where validation fails (r or s out of range, rhs not a quadratic
residue, or Q = ∞) are given dummy values `u₁=1, u₂=2, R=(Gx,Gy)` so that
`1·G + 2·G = 3·G ≠ ∞`, keeping all vector ops in a well-defined state.  Their
output entries are zeroed in Phase 3.

---

## 3. Planned assembler optimisations

The current bottleneck is the throughput of `fp_mul_x8` (the 52-bit IFMA
Montgomery multiplier).  LLVM produces correct but not optimal code: it
over-uses the stack for register spills and does not schedule `VPMADD52`
instructions to hide the ~4-cycle latency of the FMA unit.

Hand-written x86-64 assembly (using `.s` files included via `global_asm!`)
will:

1. Eliminate all stack spills by colouring the 5 input + 10 product + 5 carry
   limbs across 20 ZMM registers (28 ZMM registers are available in the kernel
   after saving Windows x64 / SysV registers).
2. Interleave independent multiply-accumulate chains to keep both FMA ports
   (p0 and p1 on Zen 4) saturated at all times.
3. Reduce the `fn_inv_x8` squaring loop by interleaving the multiply-squarings
   with subsequent independent multiplications from the assembly chain.

A conservative estimate for the resulting improvement is 1.5–2×, which would
push ECDSA batch recovery above 100 krecov/s per core.
