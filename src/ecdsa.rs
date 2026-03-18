//! Ethereum ECDSA public-key and address recovery on the secp256k1 curve.
//!
//! Implements the ecrecover primitive: given a message hash and a signature
//! `(r, s, v)` recover the signer's uncompressed public key and Ethereum address.
//!
//! All arithmetic is implemented from scratch — no external crates are used.

use crate::keccak::keccak256;

// ─────────────────────────────────────────────────────────────────────────────
// secp256k1 domain parameters
// ─────────────────────────────────────────────────────────────────────────────

// Field prime  p = 2^256 − 2^32 − 977
// In little-endian u64 limbs (limbs[0] = least-significant 64 bits):
//   p = FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF FFFFFFFEFFFFFC2F
const P: U256 = U256([
    0xFFFFFFFEFFFFFC2F,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
]);

// Group order  n = 2^256 − 0x14551231950B75FC4402DA1732FC9BEBF
// n = FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFE BAAEDCE6AF48A03B BFD25E8CD0364141
const N: U256 = U256([
    0xBFD25E8CD0364141,
    0xBAAEDCE6AF48A03B,
    0xFFFFFFFFFFFFFFFE,
    0xFFFFFFFFFFFFFFFF,
]);

// 2^256 − p  =  K_P  =  2^32 + 977  =  0x1_0000_03D1
// This is the Solinas "correction term" used for fast reduction mod p.
const K_P: u64 = (1u64 << 32) + 977; // = 4_295_000_977

// 2^256 − n  =  N_COMPL
// N_COMPL = [0x402DA1732FC9BEBF, 0x4551231950B75FC4, 0x0000000000000001, 0]
const N_COMPL: U256 = U256([
    0x402DA1732FC9BEBF,
    0x4551231950B75FC4,
    0x0000000000000001,
    0x0000000000000000,
]);

// (p + 1) / 4 — used for square-root extraction (since p ≡ 3 mod 4).
const P_PLUS_ONE_DIV_4: U256 = U256([
    0xFFFFFFFFBFFFFF0C,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0x3FFFFFFFFFFFFFFF,
]);

// Generator point G  (affine coordinates, uncompressed).
const GX: U256 = U256([
    0x59F2815B16F81798,
    0x029BFCDB2DCE28D9,
    0x55A06295CE870B07,
    0x79BE667EF9DCBBAC,
]);
const GY: U256 = U256([
    0x9C47D08FFB10D4B8,
    0xFD17B448A6855419,
    0x5DA4FBFC0E1108A8,
    0x483ADA7726A3C465,
]);

// ─────────────────────────────────────────────────────────────────────────────
// U256 — 256-bit unsigned integer
// ─────────────────────────────────────────────────────────────────────────────

/// 256-bit unsigned integer stored as four `u64` limbs in **little-endian** order:
/// `self.0[0]` holds bits 0–63 (least significant), `self.0[3]` holds bits 192–255.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct U256(pub [u64; 4]);

impl U256 {
    const ZERO: U256 = U256([0, 0, 0, 0]);
    const ONE: U256 = U256([1, 0, 0, 0]);

    /// Construct from a 32-byte big-endian slice.
    fn from_be_bytes(b: &[u8; 32]) -> Self {
        U256([
            u64::from_be_bytes(b[24..32].try_into().unwrap()),
            u64::from_be_bytes(b[16..24].try_into().unwrap()),
            u64::from_be_bytes(b[8..16].try_into().unwrap()),
            u64::from_be_bytes(b[0..8].try_into().unwrap()),
        ])
    }

    /// Serialize to big-endian bytes.
    fn to_be_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[0..8].copy_from_slice(&self.0[3].to_be_bytes());
        out[8..16].copy_from_slice(&self.0[2].to_be_bytes());
        out[16..24].copy_from_slice(&self.0[1].to_be_bytes());
        out[24..32].copy_from_slice(&self.0[0].to_be_bytes());
        out
    }

    fn is_zero(&self) -> bool {
        self.0 == [0, 0, 0, 0]
    }

    /// Return (self + rhs, carry).
    fn adc(&self, rhs: &U256) -> (U256, u64) {
        let mut limbs = [0u64; 4];
        let mut carry = 0u128;
        for i in 0..4 {
            carry = self.0[i] as u128 + rhs.0[i] as u128 + (carry >> 64);
            limbs[i] = carry as u64;
        }
        (U256(limbs), (carry >> 64) as u64)
    }

    /// Return (self - rhs, borrow).
    fn sbb(&self, rhs: &U256) -> (U256, u64) {
        let mut limbs = [0u64; 4];
        let mut borrow = 0i128;
        for i in 0..4 {
            let diff = self.0[i] as i128 - rhs.0[i] as i128 + borrow;
            limbs[i] = diff as u64;
            borrow = diff >> 64;
        }
        (U256(limbs), (-borrow) as u64)
    }

    /// Lexicographic (magnitude) compare: `true` if `self >= rhs`.
    fn ge(&self, rhs: &U256) -> bool {
        for i in (0..4).rev() {
            if self.0[i] > rhs.0[i] {
                return true;
            }
            if self.0[i] < rhs.0[i] {
                return false;
            }
        }
        true // equal
    }

    /// Test bit `i` (0 = least significant).
    fn bit(&self, i: usize) -> bool {
        (self.0[i / 64] >> (i % 64)) & 1 == 1
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Widening 256×256 → 512-bit multiply
// ─────────────────────────────────────────────────────────────────────────────

/// Schoolbook multiplication producing an 8-limb (512-bit) result.
fn mul_wide(a: &U256, b: &U256) -> [u64; 8] {
    let mut r = [0u64; 8];
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            carry += r[i + j] as u128 + a.0[i] as u128 * b.0[j] as u128;
            r[i + j] = carry as u64;
            carry >>= 64;
        }
        r[i + 4] += carry as u64;
    }
    r
}

// ─────────────────────────────────────────────────────────────────────────────
// Field arithmetic — mod p  (Fp)
// ─────────────────────────────────────────────────────────────────────────────

/// Add two field elements mod p.
fn fp_add(a: &U256, b: &U256) -> U256 {
    let (s, c) = a.adc(b);
    // If carry OR result >= p, subtract p.
    let (s2, b2) = s.sbb(&P);
    if c == 1 || b2 == 0 { s2 } else { s }
}

/// Subtract two field elements mod p.
fn fp_sub(a: &U256, b: &U256) -> U256 {
    let (d, borrow) = a.sbb(b);
    if borrow == 1 {
        let (d2, _) = d.adc(&P);
        d2
    } else {
        d
    }
}

/// Negate a field element: return `(p - a) mod p`.
fn fp_neg(a: &U256) -> U256 {
    if a.is_zero() { U256::ZERO } else { P.sbb(a).0 }
}

/// Multiply two field elements mod p using Solinas reduction.
///
/// p = 2^256 − K_P where K_P = 2^32 + 977.
/// Given wide = lo + hi·2^256, we reduce by replacing hi·2^256 with hi·K_P.
fn fp_mul(a: &U256, b: &U256) -> U256 {
    let wide = mul_wide(a, b);
    fp_reduce_wide(&wide)
}

/// Reduce an 8-limb (512-bit) number modulo p using the Solinas trick.
fn fp_reduce_wide(w: &[u64; 8]) -> U256 {
    // Step 1: accumulate lo[0..3] + hi[4..7] * K_P
    // Use u128 limbs to catch carries naturally.
    let mut acc = [0u128; 5];
    for i in 0..4 {
        acc[i] = w[i] as u128;
    }
    for i in 0..4 {
        acc[i] += w[i + 4] as u128 * K_P as u128;
    }
    // Propagate carries through the 5 limbs.
    for i in 0..4 {
        acc[i + 1] += acc[i] >> 64;
        acc[i] &= 0xFFFF_FFFF_FFFF_FFFF;
    }

    // Step 2: acc[4] still holds an overflow; multiply it by K_P and fold in.
    let extra = acc[4] * K_P as u128;
    acc[0] += extra & 0xFFFF_FFFF_FFFF_FFFF;
    acc[1] += extra >> 64;
    acc[4] = 0;

    // Propagate again.
    for i in 0..4 {
        acc[i + 1] += acc[i] >> 64;
        acc[i] &= 0xFFFF_FFFF_FFFF_FFFF;
    }

    let mut r = U256([acc[0] as u64, acc[1] as u64, acc[2] as u64, acc[3] as u64]);
    // At most two subtractions needed.
    if r.ge(&P) {
        r = r.sbb(&P).0;
    }
    if r.ge(&P) {
        r = r.sbb(&P).0;
    }
    r
}

/// Square a field element mod p.
fn fp_sq(a: &U256) -> U256 {
    fp_mul(a, a)
}

/// Raise `a` to the power `exp` (mod p) via square-and-multiply.
fn fp_pow(a: &U256, exp: &U256) -> U256 {
    let mut result = U256::ONE;
    let mut base = *a;
    for i in 0..256 {
        if exp.bit(i) {
            result = fp_mul(&result, &base);
        }
        base = fp_sq(&base);
    }
    result
}

/// Compute the modular inverse of `a` mod p via Fermat's little theorem:
/// a^(p−2) mod p.  Returns `None` if `a == 0`.
fn fp_inv(a: &U256) -> Option<U256> {
    if a.is_zero() {
        return None;
    }
    // p − 2 in little-endian:
    let p_minus_2 = U256([
        0xFFFFFFFEFFFFFC2D,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
    ]);
    Some(fp_pow(a, &p_minus_2))
}

/// Compute a square root of `a` mod p.  Since p ≡ 3 (mod 4), we have
/// sqrt(a) = a^((p+1)/4) mod p.  Returns `None` if `a` is not a QR.
fn fp_sqrt(a: &U256) -> Option<U256> {
    if a.is_zero() {
        return Some(U256::ZERO);
    }
    let root = fp_pow(a, &P_PLUS_ONE_DIV_4);
    // Verify: root^2 == a
    if fp_sq(&root) == *a { Some(root) } else { None }
}

// ─────────────────────────────────────────────────────────────────────────────
// Scalar arithmetic — mod n  (Fn)
// ─────────────────────────────────────────────────────────────────────────────

/// Add two scalars mod n.
#[allow(dead_code)]
fn fn_add(a: &U256, b: &U256) -> U256 {
    let (s, c) = a.adc(b);
    let (s2, b2) = s.sbb(&N);
    if c == 1 || b2 == 0 { s2 } else { s }
}

/// Negate a scalar: return `(n - a) mod n`.
fn fn_neg(a: &U256) -> U256 {
    if a.is_zero() { U256::ZERO } else { N.sbb(a).0 }
}

/// Multiply two scalars mod n.
///
/// Uses the N_COMPL reduction: since n·N_COMPL = 2^256·N_COMPL − N_COMPL·N_COMPL,
/// replacing 2^256 with N_COMPL gives convergence in three passes.
fn fn_mul(a: &U256, b: &U256) -> U256 {
    let wide = mul_wide(a, b);
    fn_reduce_wide(&wide)
}

/// Reduce an 8-limb (512-bit) number modulo n via iterated N_COMPL folding.
fn fn_reduce_wide(w: &[u64; 8]) -> U256 {
    // Start with the low 256 bits.
    let mut lo = U256([w[0], w[1], w[2], w[3]]);
    let mut hi = U256([w[4], w[5], w[6], w[7]]);

    // Iteration 1: lo += hi * N_COMPL  (produces up to ~385-bit result)
    // We compute hi * N_COMPL as a 512-bit product and split off the new hi/lo.
    for _iter in 0..3 {
        if hi.is_zero() {
            break;
        }
        let prod = mul_wide(&hi, &N_COMPL);
        // lo += prod_low (256 bits), accumulating into a 5-limb value
        let mut acc = [0u128; 5];
        for i in 0..4 {
            acc[i] = lo.0[i] as u128 + prod[i] as u128;
        }
        // The upper half of prod becomes the new hi.
        // But first fold the carry from the lower production.
        for i in 0..4 {
            acc[i + 1] += acc[i] >> 64;
            acc[i] &= 0xFFFF_FFFF_FFFF_FFFF;
        }
        // acc[4] contains the carry; add it to prod[4..7] to form new hi.
        let mut hi_acc = [0u128; 4];
        hi_acc[0] = prod[4] as u128 + acc[4];
        for i in 1..4 {
            hi_acc[0 + i] = prod[4 + i] as u128;
        }
        for i in 0..3 {
            hi_acc[i + 1] += hi_acc[i] >> 64;
            hi_acc[i] &= 0xFFFF_FFFF_FFFF_FFFF;
        }
        lo = U256([acc[0] as u64, acc[1] as u64, acc[2] as u64, acc[3] as u64]);
        hi = U256([
            hi_acc[0] as u64,
            hi_acc[1] as u64,
            hi_acc[2] as u64,
            hi_acc[3] as u64,
        ]);
    }

    // At this point lo should be < 2·n.  Apply at most two conditional subtracts.
    if lo.ge(&N) {
        lo = lo.sbb(&N).0;
    }
    if lo.ge(&N) {
        lo = lo.sbb(&N).0;
    }
    lo
}

/// Raise `a` to the power `exp` (mod n) via square-and-multiply.
fn fn_pow(a: &U256, exp: &U256) -> U256 {
    let mut result = U256::ONE;
    let mut base = *a;
    for i in 0..256 {
        if exp.bit(i) {
            result = fn_mul(&result, &base);
        }
        base = fn_mul(&base, &base);
    }
    result
}

/// Invert a scalar mod n via Fermat's little theorem (n is prime).
fn fn_inv(a: &U256) -> Option<U256> {
    if a.is_zero() {
        return None;
    }
    // n − 2
    let n_minus_2 = U256([
        0xBFD25E8CD036413F,
        0xBAAEDCE6AF48A03B,
        0xFFFFFFFFFFFFFFFE,
        0xFFFFFFFFFFFFFFFF,
    ]);
    Some(fn_pow(a, &n_minus_2))
}

// ─────────────────────────────────────────────────────────────────────────────
// Elliptic curve point arithmetic — secp256k1 in Jacobian coordinates
// ─────────────────────────────────────────────────────────────────────────────
//
// Affine point (X/Z², Y/Z³).  The point at infinity is represented by Z = 0.

#[derive(Clone, Copy, Debug)]
struct JacobianPoint {
    x: U256,
    y: U256,
    z: U256,
}

impl JacobianPoint {
    fn infinity() -> Self {
        JacobianPoint {
            x: U256::ONE,
            y: U256::ONE,
            z: U256::ZERO,
        }
    }

    fn is_infinity(&self) -> bool {
        self.z.is_zero()
    }

    /// Construct from affine coordinates (assumes the point is on the curve).
    fn from_affine(x: U256, y: U256) -> Self {
        JacobianPoint { x, y, z: U256::ONE }
    }

    /// Convert back to affine coordinates.  Returns `None` for the point at infinity.
    fn to_affine(&self) -> Option<(U256, U256)> {
        if self.is_infinity() {
            return None;
        }
        let z_inv = fp_inv(&self.z)?;
        let z_inv2 = fp_sq(&z_inv);
        let z_inv3 = fp_mul(&z_inv2, &z_inv);
        let ax = fp_mul(&self.x, &z_inv2);
        let ay = fp_mul(&self.y, &z_inv3);
        Some((ax, ay))
    }
}

/// Point doubling in Jacobian coordinates.
/// Uses the formulas from https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l
/// (a = 0 for secp256k1).
fn point_double(p: &JacobianPoint) -> JacobianPoint {
    if p.is_infinity() {
        return *p;
    }
    // A = X1^2, B = Y1^2, C = B^2
    let a = fp_sq(&p.x);
    let b = fp_sq(&p.y);
    let c = fp_sq(&b);

    // D = 2*((X1+B)^2 - A - C)
    let x1_plus_b = fp_add(&p.x, &b);
    let d = fp_mul_2(&fp_sub(&fp_sub(&fp_sq(&x1_plus_b), &a), &c));

    // E = 3*A  (since a_coeff = 0)
    let e = fp_add(&fp_mul_2(&a), &a); // 3A

    // F = E^2
    let f = fp_sq(&e);

    // X3 = F - 2*D
    let x3 = fp_sub(&f, &fp_mul_2(&d));

    // Y3 = E*(D - X3) - 8*C
    let y3 = fp_sub(&fp_mul(&e, &fp_sub(&d, &x3)), &fp_mul_8(&c));

    // Z3 = 2*Y1*Z1
    let z3 = fp_mul(&fp_mul_2(&p.y), &p.z);

    JacobianPoint {
        x: x3,
        y: y3,
        z: z3,
    }
}

/// Mixed addition: Jacobian `p` + affine `q`.
/// Uses the formulas from https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-madd-2007-bl
fn point_add_mixed(p: &JacobianPoint, qx: &U256, qy: &U256) -> JacobianPoint {
    if p.is_infinity() {
        return JacobianPoint::from_affine(*qx, *qy);
    }

    // Z1^2, Z1^3
    let z1sq = fp_sq(&p.z);
    let z1cu = fp_mul(&z1sq, &p.z);

    // U2 = QX * Z1^2,  S2 = QY * Z1^3
    let u2 = fp_mul(qx, &z1sq);
    let s2 = fp_mul(qy, &z1cu);

    // H = U2 - X1,  R = S2 - Y1
    let h = fp_sub(&u2, &p.x);
    let r = fp_sub(&s2, &p.y);

    // Point at infinity if H=0 and R=0 (i.e., p == q in affine) → double instead.
    if h.is_zero() && r.is_zero() {
        return point_double(&JacobianPoint::from_affine(*qx, *qy));
    }
    // Point at infinity if H=0 and R≠0 (p == -q).
    if h.is_zero() {
        return JacobianPoint::infinity();
    }

    let h2 = fp_sq(&h);
    let h3 = fp_mul(&h, &h2);

    // I = 4*H^2 (not used here — direct formula below)
    // X3 = R^2 - H^3 - 2*X1*H^2
    let x1h2 = fp_mul(&p.x, &h2);
    let x3 = fp_sub(&fp_sub(&fp_sq(&r), &h3), &fp_mul_2(&x1h2));

    // Y3 = R*(X1*H^2 - X3) - Y1*H^3
    let y3 = fp_sub(&fp_mul(&r, &fp_sub(&x1h2, &x3)), &fp_mul(&p.y, &h3));

    // Z3 = Z1 * H
    let z3 = fp_mul(&p.z, &h);

    JacobianPoint {
        x: x3,
        y: y3,
        z: z3,
    }
}

/// Scalar multiplication: `scalar * G` using the affine generator.
fn scalar_mul_g(scalar: &U256) -> JacobianPoint {
    scalar_mul_affine(scalar, &GX, &GY)
}

/// Scalar multiplication: `scalar * (px, py)` using double-and-add.
fn scalar_mul_affine(scalar: &U256, px: &U256, py: &U256) -> JacobianPoint {
    let mut acc = JacobianPoint::infinity();
    let mut addend = JacobianPoint::from_affine(*px, *py);
    for i in 0..256 {
        if scalar.bit(i) {
            if acc.is_infinity() {
                acc = addend;
            } else if addend.z == U256::ONE {
                // addend is still in affine form (z=1).
                acc = point_add_mixed(&acc, &addend.x, &addend.y);
            } else {
                // After first doubling addend is in Jacobian form.
                let (ax, ay) = match addend.to_affine() {
                    Some(v) => v,
                    None => return JacobianPoint::infinity(),
                };
                acc = point_add_mixed(&acc, &ax, &ay);
            }
        }
        addend = point_double(&addend);
    }
    acc
}

// ─────────────────────────────────────────────────────────────────────────────
// Fp convenience helpers
// ─────────────────────────────────────────────────────────────────────────────

#[inline(always)]
fn fp_mul_2(a: &U256) -> U256 {
    fp_add(a, a)
}

#[inline(always)]
fn fp_mul_8(a: &U256) -> U256 {
    fp_mul_2(&fp_mul_2(&fp_mul_2(a)))
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Recover the uncompressed secp256k1 public key (65 bytes: `04 || X || Y`) from an
/// Ethereum-style ECDSA signature.
///
/// # Parameters
/// * `hash`  — 32-byte Keccak-256 message hash.
/// * `r`, `s` — signature components (32-byte big-endian).
/// * `v`      — recovery id, either `0` or `1` (Ethereum uses `27` / `28`; subtract `27` first).
///
/// # Returns
/// `Some([u8; 65])` containing the uncompressed public key, or `None` on failure.
pub fn recover_public_key(hash: &[u8; 32], r: &[u8; 32], s: &[u8; 32], v: u8) -> Option<[u8; 65]> {
    let r_u = U256::from_be_bytes(r);
    let s_u = U256::from_be_bytes(s);
    let z = U256::from_be_bytes(hash);

    // Validate r and s are in [1, n-1].
    if r_u.is_zero() || !r_u.ge(&U256::ONE) || r_u.ge(&N) {
        return None;
    }
    if s_u.is_zero() || !s_u.ge(&U256::ONE) || s_u.ge(&N) {
        return None;
    }

    // Lift r to a curve point R = (r_x, r_y).
    // For secp256k1, r + n > p always, so we only consider R.x = r (not r + n).
    let r_x = r_u;

    // Recover r_y from the curve equation  y² = x³ + 7  (secp256k1, a=0, b=7).
    let r_x3 = fp_mul(&fp_sq(&r_x), &r_x); // x³
    let b7 = U256([7, 0, 0, 0]);
    let rhs = fp_add(&r_x3, &b7); // x³ + 7
    let mut r_y = fp_sqrt(&rhs)?;

    // Choose the correct y parity: v bit 0 must match the least-significant bit of r_y.
    let y_parity = (v & 1) as u64;
    if (r_y.0[0] & 1) != y_parity {
        r_y = fp_neg(&r_y);
    }

    // Compute r_inv = r^(-1) mod n.
    let r_inv = fn_inv(&r_u)?;

    // u1 = -(z * r_inv) mod n
    let u1 = fn_neg(&fn_mul(&z, &r_inv));
    // u2 = s * r_inv mod n
    let u2 = fn_mul(&s_u, &r_inv);

    // Q = u1·G + u2·R
    let p1 = scalar_mul_g(&u1);
    let p2 = scalar_mul_affine(&u2, &r_x, &r_y);

    let q = if p1.is_infinity() {
        p2
    } else if p2.is_infinity() {
        p1
    } else {
        let (p1x, p1y) = p1.to_affine()?;
        point_add_mixed(&p2, &p1x, &p1y)
    };

    let (qx, qy) = q.to_affine()?;

    let mut pubkey = [0u8; 65];
    pubkey[0] = 0x04;
    pubkey[1..33].copy_from_slice(&qx.to_be_bytes());
    pubkey[33..65].copy_from_slice(&qy.to_be_bytes());
    Some(pubkey)
}

/// Recover the Ethereum address from a signature.
///
/// Computes `Keccak-256(pubkey_x || pubkey_y)[12..]` — the rightmost 20 bytes.
///
/// `v` should be `0` or `1` (subtract `27` from the Ethereum wire encoding first).
pub fn recover_address(hash: &[u8; 32], r: &[u8; 32], s: &[u8; 32], v: u8) -> Option<[u8; 20]> {
    let pubkey = recover_public_key(hash, r, s, v)?;
    // Hash the 64-byte (X, Y) portion (skip the 0x04 prefix byte).
    let h = keccak256(&pubkey[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&h[12..]);
    Some(addr)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn unhex32(s: &str) -> [u8; 32] {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        bytes.try_into().unwrap()
    }

    /// Well-known ecrecover test vector from the go-ethereum ecRecover precompile JSON test suite.
    /// Source: go-ethereum core/vm/testdata/precompiles/ecRecover.json "ValidKey" entry.
    ///
    /// hash = 18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c
    /// v    = 0x1c = 28  →  recovery_id = 1
    /// r    = 73b1693892219d736caba55bdb67216e485557ea6b6af75f37096c9aa6a5a75f
    /// s    = eeb940b1d03b21e36b0e47e79769f095fe2ab855bd91e3a38756b7d75a9c4549
    /// expected address = a94f5374fce5edbc8e2a8697c15331677e6ebf0b
    #[test]
    fn test_ecrecover_precompile_vector() {
        let hash = unhex32("18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c");
        let r = unhex32("73b1693892219d736caba55bdb67216e485557ea6b6af75f37096c9aa6a5a75f");
        let s = unhex32("eeb940b1d03b21e36b0e47e79769f095fe2ab855bd91e3a38756b7d75a9c4549");
        let v = 28u8 - 27; // recovery_id = 1

        let addr = recover_address(&hash, &r, &s, v).expect("recovery failed");
        assert_eq!(hex(&addr), "a94f5374fce5edbc8e2a8697c15331677e6ebf0b");
    }

    /// Verify that generator-point arithmetic is self-consistent:
    /// multiplying G by 1 should give G, and multiplying by 2 should give 2G.
    #[test]
    fn test_scalar_mul_one() {
        let g1 = scalar_mul_g(&U256::ONE);
        let (x, y) = g1.to_affine().unwrap();
        assert_eq!(x, GX, "G×1 x mismatch");
        assert_eq!(y, GY, "G×1 y mismatch");
    }

    /// Verify basic field arithmetic: on-curve check for G and (p-1)^2 mod p == 1.
    #[test]
    fn test_fp_arithmetic() {
        // (p-1)^2 mod p == 1
        let pm1 = P.sbb(&U256::ONE).0;
        let sq = fp_sq(&pm1);
        assert_eq!(sq, U256::ONE, "(p-1)^2 mod p should be 1");

        // G is on the curve: Gy^2 == Gx^3 + 7  mod p
        let b7 = U256([7, 0, 0, 0]);
        let gx3 = fp_mul(&fp_sq(&GX), &GX);
        let rhs = fp_add(&gx3, &b7);
        let lhs = fp_sq(&GY);
        assert_eq!(lhs, rhs, "G should be on secp256k1 curve");
    }

    /// Regression: fp_inv(2) * 2 == 1 mod p.
    #[test]
    fn test_fp_inv() {
        let two = U256([2, 0, 0, 0]);
        let inv2 = fp_inv(&two).unwrap();
        let product = fp_mul(&two, &inv2);
        assert_eq!(product, U256::ONE, "2 * inv(2) should be 1 mod p");
    }

    /// Regression: fn_inv(2) * 2 == 1 mod n.
    #[test]
    fn test_fn_arithmetic() {
        let two = U256([2, 0, 0, 0]);
        let inv2 = fn_inv(&two).unwrap();
        let product = fn_mul(&two, &inv2);
        assert_eq!(product, U256::ONE, "2 * inv(2) should be 1 mod n");
    }

    /// Known 2G for secp256k1.
    /// 2G.x = 0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5
    /// 2G.y computed by Python: 0x1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a
    #[test]
    fn test_scalar_mul_two() {
        let two = U256([2, 0, 0, 0]);
        let g2 = scalar_mul_g(&two);
        let (x, y) = g2.to_affine().unwrap();
        let expected_x = U256::from_be_bytes(&unhex32(
            "C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5",
        ));
        let expected_y = U256::from_be_bytes(&unhex32(
            "1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a",
        ));
        assert_eq!(x, expected_x, "2G x mismatch");
        assert_eq!(y, expected_y, "2G y mismatch");
    }
}
