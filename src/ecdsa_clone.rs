//! Exact Rust translation of the secp256k1 C library.
//!
//! Each function carries a `// C:` comment giving the absolute path on this
//! machine to the C source that was translated.
//!
//! C source base:
//!   /home/amy/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/secp256k1-sys-0.10.1/depend/secp256k1/src/
//! (abbreviated below as `$BASE`)
//!
//! Deviations from an exact translation:
//!  - `fe_inv` and `scalar_inverse_var` use an addition-chain Fermat inversion
//!    (x^(m-2) mod m) instead of the Safegcd-based `modinv64` algorithm used by
//!    the C library, because translating modinv64_impl.h (~700 lines) is out of
//!    scope.  The mathematical result is identical; only the performance differs.
//!  - `ecmult` implements Strauss wNAF (w=5) with GLV endomorphism, matching
//!    the C algorithm.  The precomputed G / 2¹²⁸·G tables are cached in a
//!    `OnceLock` so the 128-doubling setup cost is paid only on the first call.
//!    The C library uses a much larger static window (WINDOW_G≈15); here we use
//!    the same WINDOW_A=5 for G, trading table size for simplicity.
//!  - VERIFY_CHECK / VERIFY_BITS / magnitude tracking are omitted (they are
//!    debug-only assertions in the C library).

#![allow(dead_code, clippy::many_single_char_names)]

use std::sync::OnceLock;

// ─────────────────────────────────────────────────────────────────────────────
// § 1  Field element  (5 × 52-bit limbs, C: secp256k1_fe)
//
//   C: $BASE/field_5x52_impl.h
//   C: $BASE/field_5x52_int128_impl.h
// ─────────────────────────────────────────────────────────────────────────────

// 52-bit mask used throughout field arithmetic.
// C: field_5x52_int128_impl.h – `const uint64_t M = 0xFFFFFFFFFFFFFULL`
const M52: u64 = 0x000F_FFFF_FFFF_FFFF;

// Reduction constant: 2^260 ≡ R (mod p), where p = 2^256 − 2^32 − 977.
// R = 2^4 × 0x1000003D1 = 0x1000003D10.
// C: field_5x52_int128_impl.h – `const uint64_t R = 0x1000003D10ULL`
const R52: u64 = 0x1000003D10;

/// secp256k1 field element in 5×52-bit LE representation.
///
/// C: $BASE/field_5x52.h – `typedef struct { uint64_t n[5]; } secp256k1_fe;`
#[derive(Clone, Copy, Debug)]
pub struct Fe {
    /// Little-endian limbs.  n[0] is the least significant 52 bits.
    /// After normalization: n[0..3] < 2^52, n[4] < 2^48.
    pub n: [u64; 5],
}

// Normalised prime p in 5×52 limbs (used only for cmp).
// C: field_5x52_impl.h – literal values in fe_impl_normalize
const P52: Fe = Fe {
    n: [
        0xFFFFEFFFFFC2F,
        0xFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFF,
        0x0FFFFFFFFFFFF,
    ],
};

impl Fe {
    pub const fn zero() -> Self {
        Fe { n: [0; 5] }
    }
    pub fn set_int(v: u32) -> Self {
        // C: $BASE/field_5x52_impl.h – `fe_impl_set_int`
        Fe {
            n: [v as u64, 0, 0, 0, 0],
        }
    }
    pub const fn set_b32_mod(b: &[u8; 32]) -> Self {
        // C: $BASE/field_5x52_impl.h – `fe_impl_set_b32_mod`
        Fe {
            n: [
                (b[31] as u64)
                    | ((b[30] as u64) << 8)
                    | ((b[29] as u64) << 16)
                    | ((b[28] as u64) << 24)
                    | ((b[27] as u64) << 32)
                    | ((b[26] as u64) << 40)
                    | (((b[25] & 0xF) as u64) << 48),
                (((b[25] >> 4) & 0xF) as u64)
                    | ((b[24] as u64) << 4)
                    | ((b[23] as u64) << 12)
                    | ((b[22] as u64) << 20)
                    | ((b[21] as u64) << 28)
                    | ((b[20] as u64) << 36)
                    | ((b[19] as u64) << 44),
                (b[18] as u64)
                    | ((b[17] as u64) << 8)
                    | ((b[16] as u64) << 16)
                    | ((b[15] as u64) << 24)
                    | ((b[14] as u64) << 32)
                    | ((b[13] as u64) << 40)
                    | (((b[12] & 0xF) as u64) << 48),
                (((b[12] >> 4) & 0xF) as u64)
                    | ((b[11] as u64) << 4)
                    | ((b[10] as u64) << 12)
                    | ((b[9] as u64) << 20)
                    | ((b[8] as u64) << 28)
                    | ((b[7] as u64) << 36)
                    | ((b[6] as u64) << 44),
                (b[5] as u64)
                    | ((b[4] as u64) << 8)
                    | ((b[3] as u64) << 16)
                    | ((b[2] as u64) << 24)
                    | ((b[1] as u64) << 32)
                    | ((b[0] as u64) << 40),
            ],
        }
    }
    /// Returns (self, true) if self < p, else (self mod p, false).
    // C: $BASE/field_5x52_impl.h – `fe_impl_set_b32_limit`
    pub fn set_b32_limit(b: &[u8; 32]) -> (Self, bool) {
        let r = Self::set_b32_mod(b);
        let in_range = !((r.n[4] == 0x0FFFFFFFFFFFF)
            & ((r.n[3] & r.n[2] & r.n[1]) == 0xFFFFFFFFFFFFF)
            & (r.n[0] >= 0xFFFFEFFFFFC2F));
        (r, in_range)
    }
    // C: $BASE/field_5x52_impl.h – `fe_impl_get_b32`
    pub fn get_b32(&self) -> [u8; 32] {
        let n = &self.n;
        let mut r = [0u8; 32];
        r[0] = ((n[4] >> 40) & 0xFF) as u8;
        r[1] = ((n[4] >> 32) & 0xFF) as u8;
        r[2] = ((n[4] >> 24) & 0xFF) as u8;
        r[3] = ((n[4] >> 16) & 0xFF) as u8;
        r[4] = ((n[4] >> 8) & 0xFF) as u8;
        r[5] = (n[4] & 0xFF) as u8;
        r[6] = ((n[3] >> 44) & 0xFF) as u8;
        r[7] = ((n[3] >> 36) & 0xFF) as u8;
        r[8] = ((n[3] >> 28) & 0xFF) as u8;
        r[9] = ((n[3] >> 20) & 0xFF) as u8;
        r[10] = ((n[3] >> 12) & 0xFF) as u8;
        r[11] = ((n[3] >> 4) & 0xFF) as u8;
        r[12] = (((n[2] >> 48) & 0xF) | ((n[3] & 0xF) << 4)) as u8;
        r[13] = ((n[2] >> 40) & 0xFF) as u8;
        r[14] = ((n[2] >> 32) & 0xFF) as u8;
        r[15] = ((n[2] >> 24) & 0xFF) as u8;
        r[16] = ((n[2] >> 16) & 0xFF) as u8;
        r[17] = ((n[2] >> 8) & 0xFF) as u8;
        r[18] = (n[2] & 0xFF) as u8;
        r[19] = ((n[1] >> 44) & 0xFF) as u8;
        r[20] = ((n[1] >> 36) & 0xFF) as u8;
        r[21] = ((n[1] >> 28) & 0xFF) as u8;
        r[22] = ((n[1] >> 20) & 0xFF) as u8;
        r[23] = ((n[1] >> 12) & 0xFF) as u8;
        r[24] = ((n[1] >> 4) & 0xFF) as u8;
        r[25] = (((n[0] >> 48) & 0xF) | ((n[1] & 0xF) << 4)) as u8;
        r[26] = ((n[0] >> 40) & 0xFF) as u8;
        r[27] = ((n[0] >> 32) & 0xFF) as u8;
        r[28] = ((n[0] >> 24) & 0xFF) as u8;
        r[29] = ((n[0] >> 16) & 0xFF) as u8;
        r[30] = ((n[0] >> 8) & 0xFF) as u8;
        r[31] = (n[0] & 0xFF) as u8;
        r
    }
    // C: $BASE/field_5x52_impl.h – `fe_impl_is_zero`
    pub fn is_zero(&self) -> bool {
        (self.n[0] | self.n[1] | self.n[2] | self.n[3] | self.n[4]) == 0
    }
    // C: $BASE/field_5x52_impl.h – `fe_impl_is_odd`
    pub fn is_odd(&self) -> bool {
        self.n[0] & 1 != 0
    }
    // C: $BASE/field_5x52_impl.h – `fe_impl_normalize`
    pub fn normalize(&mut self) {
        let (t0, t1, t2, t3, mut t4) = (self.n[0], self.n[1], self.n[2], self.n[3], self.n[4]);
        let x = t4 >> 48;
        t4 &= 0x0FFFFFFFFFFFF;
        let t0 = t0 + x * 0x1000003D1;
        let t1 = t1 + (t0 >> 52);
        let t0 = t0 & M52;
        let t2 = t2 + (t1 >> 52);
        let t1 = t1 & M52;
        let m = t1;
        let t3 = t3 + (t2 >> 52);
        let t2 = t2 & M52;
        let m = m & t2;
        t4 = t4 + (t3 >> 52);
        let t3 = t3 & M52;
        let m = m & t3;
        let x = (t4 >> 48)
            | (((t4 == 0x0FFFFFFFFFFFF) & (m == 0xFFFFFFFFFFFFF) & (t0 >= 0xFFFFEFFFFFC2F)) as u64);
        let t0 = t0 + x * 0x1000003D1;
        let t1 = t1 + (t0 >> 52);
        let t0 = t0 & M52;
        let t2 = t2 + (t1 >> 52);
        let t1 = t1 & M52;
        let t3 = t3 + (t2 >> 52);
        let t2 = t2 & M52;
        let t4 = t4 + (t3 >> 52);
        let t3 = t3 & M52;
        let t4 = t4 & 0x0FFFFFFFFFFFF;
        self.n = [t0, t1, t2, t3, t4];
    }
    // C: $BASE/field_5x52_impl.h – `fe_impl_normalize_weak`
    pub fn normalize_weak(&mut self) {
        let (t0, t1, t2, t3, mut t4) = (self.n[0], self.n[1], self.n[2], self.n[3], self.n[4]);
        let x = t4 >> 48;
        t4 &= 0x0FFFFFFFFFFFF;
        let t0 = t0 + x * 0x1000003D1;
        let t1 = t1 + (t0 >> 52);
        let t0 = t0 & M52;
        let t2 = t2 + (t1 >> 52);
        let t1 = t1 & M52;
        let t3 = t3 + (t2 >> 52);
        let t2 = t2 & M52;
        let t4 = t4 + (t3 >> 52);
        let t3 = t3 & M52;
        self.n = [t0, t1, t2, t3, t4];
    }
    // C: $BASE/field_5x52_impl.h – `fe_impl_normalize_var`   (non-constant-time)
    pub fn normalize_var(&mut self) {
        let (t0, t1, t2, t3, mut t4) = (self.n[0], self.n[1], self.n[2], self.n[3], self.n[4]);
        let x = t4 >> 48;
        t4 &= 0x0FFFFFFFFFFFF;
        let t0 = t0 + x * 0x1000003D1;
        let t1 = t1 + (t0 >> 52);
        let t0 = t0 & M52;
        let m = t1;
        let t2 = t2 + (t1 >> 52);
        let t1 = t1 & M52;
        let m = m & t2;
        let t3 = t3 + (t2 >> 52);
        let t2 = t2 & M52;
        let m = m & t3;
        t4 += t3 >> 52;
        let t3 = t3 & M52;
        let m = m & t3;
        let x = (t4 >> 48)
            | (((t4 == 0x0FFFFFFFFFFFF) & (m == 0xFFFFFFFFFFFFF) & (t0 >= 0xFFFFEFFFFFC2F)) as u64);
        if x != 0 {
            let t0 = t0 + 0x1000003D1;
            let t1 = t1 + (t0 >> 52);
            let t0 = t0 & M52;
            let t2 = t2 + (t1 >> 52);
            let t1 = t1 & M52;
            let t3 = t3 + (t2 >> 52);
            let t2 = t2 & M52;
            t4 += t3 >> 52;
            let t3 = t3 & M52;
            let t4 = t4 & 0x0FFFFFFFFFFFF;
            self.n = [t0, t1, t2, t3, t4];
        } else {
            self.n = [t0, t1, t2, t3, t4];
        }
    }
    // C: $BASE/field_5x52_impl.h – `fe_impl_normalizes_to_zero`
    pub fn normalizes_to_zero(&self) -> bool {
        let (t0, t1, t2, t3, t4) = (self.n[0], self.n[1], self.n[2], self.n[3], self.n[4]);
        let x = t4 >> 48;
        let t4 = t4 & 0x0FFFFFFFFFFFF;
        let t0 = t0 + x * 0x1000003D1;
        let z0 = t0 & M52;
        let z1 = z0 ^ 0x1000003D0;
        let t1 = t1 + (t0 >> 52);
        let z0 = z0 | (t1 & M52);
        let z1 = z1 & (t1 & M52);
        let t2 = t2 + (t1 >> 52);
        let z0 = z0 | (t2 & M52);
        let z1 = z1 & (t2 & M52);
        let t3 = t3 + (t2 >> 52);
        let z0 = z0 | (t3 & M52);
        let z1 = z1 & (t3 & M52);
        let t4 = t4 + (t3 >> 52);
        let z0 = z0 | t4;
        let z1 = z1 & (t4 ^ 0xF000000000000);
        (z0 == 0) | (z1 == 0xFFFFFFFFFFFFF)
    }
    // C: $BASE/field_impl.h – `fe_equal`
    pub fn equal(&self, b: &Fe) -> bool {
        let mut na = fe_negate(self, 1);
        fe_add(&mut na, b);
        na.normalizes_to_zero()
    }
    // C: $BASE/field_5x52_impl.h – `fe_impl_cmp_var`
    pub fn cmp_var(&self, b: &Fe) -> i32 {
        for i in (0..5).rev() {
            if self.n[i] > b.n[i] {
                return 1;
            }
            if self.n[i] < b.n[i] {
                return -1;
            }
        }
        0
    }
    // C: $BASE/field_5x52_impl.h – `fe_impl_cmov`  (constant-time select)
    pub fn cmov(&mut self, a: &Fe, flag: bool) {
        let mask0 = if flag { 0u64 } else { !0u64 };
        let mask1 = !mask0;
        for i in 0..5 {
            self.n[i] = (self.n[i] & mask0) | (a.n[i] & mask1);
        }
    }
}

// C: $BASE/field_5x52_impl.h – `fe_impl_negate_unchecked`
// m is the magnitude bound of `a` (used by C for bounds checking; unused here).
pub fn fe_negate(a: &Fe, m: u64) -> Fe {
    Fe {
        n: [
            0xFFFFEFFFFFC2F * 2 * (m + 1) - a.n[0],
            0xFFFFFFFFFFFFF * 2 * (m + 1) - a.n[1],
            0xFFFFFFFFFFFFF * 2 * (m + 1) - a.n[2],
            0xFFFFFFFFFFFFF * 2 * (m + 1) - a.n[3],
            0x0FFFFFFFFFFFF * 2 * (m + 1) - a.n[4],
        ],
    }
}

// C: $BASE/field_5x52_impl.h – `fe_impl_add`
pub fn fe_add(r: &mut Fe, a: &Fe) {
    r.n[0] += a.n[0];
    r.n[1] += a.n[1];
    r.n[2] += a.n[2];
    r.n[3] += a.n[3];
    r.n[4] += a.n[4];
}

// C: $BASE/field_5x52_impl.h – `fe_impl_add_int`
pub fn fe_add_int(r: &mut Fe, a: i32) {
    r.n[0] = r.n[0].wrapping_add(a as i64 as u64);
}

// C: $BASE/field_5x52_impl.h – `fe_impl_mul_int_unchecked`
pub fn fe_mul_int(r: &mut Fe, a: u32) {
    let a = a as u64;
    r.n[0] *= a;
    r.n[1] *= a;
    r.n[2] *= a;
    r.n[3] *= a;
    r.n[4] *= a;
}

// C: $BASE/field_5x52_impl.h – `fe_impl_half`
// C: $BASE/field_5x52_impl.h line ~310
pub fn fe_half(r: &mut Fe) {
    let (t0, t1, t2, t3, t4) = (r.n[0], r.n[1], r.n[2], r.n[3], r.n[4]);
    // mask = 0 if even, all-ones if odd
    let mask = u64::wrapping_neg(t0 & 1) >> 12;
    let t0 = t0 + (0xFFFFEFFFFFC2F & mask);
    let t1 = t1 + mask;
    let t2 = t2 + mask;
    let t3 = t3 + mask;
    let t4 = t4 + (mask >> 4);
    // Use + not | : when (tN >> 1) has bit 51 set (magnitude >= 2 input),
    // | would silently discard the carry from the next limb, giving wrong result.
    // C uses + throughout: (t0 >> 1) + ((t1 & one) << 51), etc.
    r.n[0] = (t0 >> 1) + ((t1 & 1) << 51);
    r.n[1] = (t1 >> 1) + ((t2 & 1) << 51);
    r.n[2] = (t2 >> 1) + ((t3 & 1) << 51);
    r.n[3] = (t3 >> 1) + ((t4 & 1) << 51);
    r.n[4] = t4 >> 1;
}

// ── fe_mul_inner ──────────────────────────────────────────────────────────────
// C: $BASE/field_5x52_int128_impl.h – `fe_mul_inner`
#[inline(never)]
pub fn fe_mul_inner(r: &mut [u64; 5], a: &[u64; 5], b: &[u64; 5]) {
    let (a0, a1, a2, a3, a4) = (a[0], a[1], a[2], a[3], a[4]);

    // d  accumulates products that go into limbs r[3] and r[4].
    // c  accumulates products that go into limbs r[0]..r[2].
    // t3, t4 are temporaries and tx, u0 help with the carry between limbs 4 and 0.

    let mut d: u128 = (a0 as u128) * (b[3] as u128)
        + (a1 as u128) * (b[2] as u128)
        + (a2 as u128) * (b[1] as u128)
        + (a3 as u128) * (b[0] as u128);
    let mut c: u128 = (a4 as u128) * (b[4] as u128);

    d += (R52 as u128) * (c as u64 as u128);
    c >>= 64;
    let t3 = (d as u64) & M52;
    d >>= 52;

    d += (a0 as u128) * (b[4] as u128)
        + (a1 as u128) * (b[3] as u128)
        + (a2 as u128) * (b[2] as u128)
        + (a3 as u128) * (b[1] as u128)
        + (a4 as u128) * (b[0] as u128);
    d += ((R52 << 12) as u128) * (c as u64 as u128);
    let t4 = (d as u64) & M52;
    d >>= 52;
    let tx = t4 >> 48;
    let t4 = t4 & (M52 >> 4);

    c = (a0 as u128) * (b[0] as u128);
    d += (a1 as u128) * (b[4] as u128)
        + (a2 as u128) * (b[3] as u128)
        + (a3 as u128) * (b[2] as u128)
        + (a4 as u128) * (b[1] as u128);
    let u0 = (d as u64) & M52;
    d >>= 52;
    let u0 = (u0 << 4) | tx;
    c += (u0 as u128) * ((R52 >> 4) as u128);
    r[0] = (c as u64) & M52;
    c >>= 52;

    c += (a0 as u128) * (b[1] as u128) + (a1 as u128) * (b[0] as u128);
    d += (a2 as u128) * (b[4] as u128)
        + (a3 as u128) * (b[3] as u128)
        + (a4 as u128) * (b[2] as u128);
    c += (R52 as u128) * ((d as u64 & M52) as u128);
    d >>= 52;
    r[1] = (c as u64) & M52;
    c >>= 52;

    c += (a0 as u128) * (b[2] as u128)
        + (a1 as u128) * (b[1] as u128)
        + (a2 as u128) * (b[0] as u128);
    d += (a3 as u128) * (b[4] as u128) + (a4 as u128) * (b[3] as u128);
    c += (R52 as u128) * (d as u64 as u128);
    d >>= 64;
    r[2] = (c as u64) & M52;
    c >>= 52;

    c += ((R52 << 12) as u128) * (d as u64 as u128) + t3 as u128;
    r[3] = (c as u64) & M52;
    c >>= 52;

    r[4] = (c as u64) + t4;
}

// C: $BASE/field_5x52_impl.h – `fe_impl_mul`
pub fn fe_mul(a: &Fe, b: &Fe) -> Fe {
    let mut r = Fe { n: [0; 5] };
    fe_mul_inner(&mut r.n, &a.n, &b.n);
    r
}

// ── fe_sqr_inner ──────────────────────────────────────────────────────────────
// C: $BASE/field_5x52_int128_impl.h – `fe_sqr_inner`
#[inline(never)]
pub fn fe_sqr_inner(r: &mut [u64; 5], a: &[u64; 5]) {
    let (a0, a1, a2, mut a3, mut a4) = (a[0], a[1], a[2], a[3], a[4]);

    let mut d: u128 = (a0 * 2) as u128 * a3 as u128 + (a1 * 2) as u128 * a2 as u128;
    let mut c: u128 = a4 as u128 * a4 as u128;

    d += (R52 as u128) * (c as u64 as u128);
    c >>= 64;
    let t3 = (d as u64) & M52;
    d >>= 52;

    a4 *= 2;
    d += a0 as u128 * a4 as u128 + (a1 * 2) as u128 * a3 as u128 + a2 as u128 * a2 as u128;
    d += ((R52 << 12) as u128) * (c as u64 as u128);
    let t4 = (d as u64) & M52;
    d >>= 52;
    let tx = t4 >> 48;
    let t4 = t4 & (M52 >> 4);

    c = a0 as u128 * a0 as u128;
    d += a1 as u128 * a4 as u128 + (a2 * 2) as u128 * a3 as u128;
    let u0 = (d as u64) & M52;
    d >>= 52;
    let u0 = (u0 << 4) | tx;
    c += (u0 as u128) * ((R52 >> 4) as u128);
    r[0] = (c as u64) & M52;
    c >>= 52;

    a3 = (a[3]) as u64; // restore (a3 wasn't mutated)
    let a0d = a0 * 2;
    c += a0d as u128 * a1 as u128;
    d += a2 as u128 * a4 as u128 + a3 as u128 * a3 as u128;
    c += (R52 as u128) * ((d as u64 & M52) as u128);
    d >>= 52;
    r[1] = (c as u64) & M52;
    c >>= 52;

    c += a0d as u128 * a2 as u128 + a1 as u128 * a1 as u128;
    d += a3 as u128 * a4 as u128;
    c += (R52 as u128) * (d as u64 as u128);
    d >>= 64;
    r[2] = (c as u64) & M52;
    c >>= 52;

    c += ((R52 << 12) as u128) * (d as u64 as u128) + t3 as u128;
    r[3] = (c as u64) & M52;
    c >>= 52;

    r[4] = (c as u64) + t4;
}

// C: $BASE/field_5x52_impl.h – `fe_impl_sqr`
pub fn fe_sqr(a: &Fe) -> Fe {
    let mut r = Fe { n: [0; 5] };
    fe_sqr_inner(&mut r.n, &a.n);
    r
}

// C: $BASE/field_impl.h – `fe_sqrt`
// Uses the (p+1)/4 addition chain since p ≡ 3 (mod 4).
// Returns (sqrt, true) if a is a QR, (junk, false) otherwise.
pub fn fe_sqrt(a: &Fe) -> (Fe, bool) {
    macro_rules! mul_into {
        ($dst:expr, $src:expr) => {{
            let t = $dst.n;
            fe_mul_inner(&mut $dst.n, &t, &$src.n);
        }};
    }
    let mut x2 = fe_sqr(a);
    {
        let t = x2.n;
        fe_mul_inner(&mut x2.n, &t, &a.n);
    }
    let mut x3 = fe_sqr(&x2);
    {
        let t = x3.n;
        fe_mul_inner(&mut x3.n, &t, &a.n);
    }
    let mut x6 = x3;
    for _ in 0..3 {
        x6 = fe_sqr(&x6);
    }
    mul_into!(x6, x3);
    let mut x9 = x6;
    for _ in 0..3 {
        x9 = fe_sqr(&x9);
    }
    mul_into!(x9, x3);
    let mut x11 = x9;
    for _ in 0..2 {
        x11 = fe_sqr(&x11);
    }
    mul_into!(x11, x2);
    let mut x22 = x11;
    for _ in 0..11 {
        x22 = fe_sqr(&x22);
    }
    mul_into!(x22, x11);
    let mut x44 = x22;
    for _ in 0..22 {
        x44 = fe_sqr(&x44);
    }
    mul_into!(x44, x22);
    let mut x88 = x44;
    for _ in 0..44 {
        x88 = fe_sqr(&x88);
    }
    mul_into!(x88, x44);
    let mut x176 = x88;
    for _ in 0..88 {
        x176 = fe_sqr(&x176);
    }
    mul_into!(x176, x88);
    let mut x220 = x176;
    for _ in 0..44 {
        x220 = fe_sqr(&x220);
    }
    mul_into!(x220, x44);
    let mut x223 = x220;
    for _ in 0..3 {
        x223 = fe_sqr(&x223);
    }
    mul_into!(x223, x3);
    let mut t1 = x223;
    for _ in 0..23 {
        t1 = fe_sqr(&t1);
    }
    mul_into!(t1, x22);
    for _ in 0..6 {
        t1 = fe_sqr(&t1);
    }
    mul_into!(t1, x2);
    t1 = fe_sqr(&t1);
    let r = fe_sqr(&t1);
    let ok = fe_sqr(&r).equal(a);
    (r, ok)
}

// C: $BASE/field_5x52_impl.h – `fe_impl_inv`
// Deviation: C uses modinv64 (Safegcd); we use Fermat: a^(p-2) mod p.
//
// p-2 in bits (256 total, MSB first):
//   bits 255..33 = all 1 (223 ones, covered by x223 prefix chain)
//   bit  32      = 0
//   bits 31..10  = all 1 (22 ones, covered by mul x22 after 22 sqrs)
//   bits 9..6    = 0 0 0 0  (4 squarings)
//   bit  5       = 1  (sqr + mul a)
//   bit  4       = 0  (sqr)
//   bits 3,2     = 1 1  (sqr + mul a, sqr + mul a)
//   bit  1       = 0  (sqr)
//   bit  0       = 1  (sqr + mul a)
//
// Verified: (2^223-1)*2^1 start, 22 more squares + x22, then 4+1+1+1+1+1+1 = 10 more.
// Final exponent = 2^256 - 2^32 - 979 = p - 2. ✓
pub fn fe_inv(a: &Fe) -> Fe {
    macro_rules! mul_into {
        ($dst:expr, $src:expr) => {{
            let t = $dst.n;
            fe_mul_inner(&mut $dst.n, &t, &$src.n);
        }};
    }
    let mut a_norm = *a;
    a_norm.normalize();

    // Build x223 using the shared addition chain prefix (same as fe_sqrt).
    let mut x2 = fe_sqr(&a_norm);
    {
        let t = x2.n;
        fe_mul_inner(&mut x2.n, &t, &a_norm.n);
    }
    let mut x3 = fe_sqr(&x2);
    {
        let t = x3.n;
        fe_mul_inner(&mut x3.n, &t, &a_norm.n);
    }
    let mut x6 = x3;
    for _ in 0..3 {
        x6 = fe_sqr(&x6);
    }
    mul_into!(x6, x3);
    let mut x9 = x6;
    for _ in 0..3 {
        x9 = fe_sqr(&x9);
    }
    mul_into!(x9, x3);
    let mut x11 = x9;
    for _ in 0..2 {
        x11 = fe_sqr(&x11);
    }
    mul_into!(x11, x2);
    let mut x22 = x11;
    for _ in 0..11 {
        x22 = fe_sqr(&x22);
    }
    mul_into!(x22, x11);
    let mut x44 = x22;
    for _ in 0..22 {
        x44 = fe_sqr(&x44);
    }
    mul_into!(x44, x22);
    let mut x88 = x44;
    for _ in 0..44 {
        x88 = fe_sqr(&x88);
    }
    mul_into!(x88, x44);
    let mut x176 = x88;
    for _ in 0..88 {
        x176 = fe_sqr(&x176);
    }
    mul_into!(x176, x88);
    let mut x220 = x176;
    for _ in 0..44 {
        x220 = fe_sqr(&x220);
    }
    mul_into!(x220, x44);
    let mut x223 = x220;
    for _ in 0..3 {
        x223 = fe_sqr(&x223);
    }
    mul_into!(x223, x3);

    // Tail for p-2 (33 remaining bits after x223).
    let mut t = x223;
    t = fe_sqr(&t); // bit 32 = 0
    for _ in 0..22 {
        t = fe_sqr(&t);
    }
    mul_into!(t, x22); // bits 31..10 = 22 ones
    for _ in 0..4 {
        t = fe_sqr(&t);
    } // bits 9..6 = 0
    t = fe_sqr(&t);
    {
        let tn = t.n;
        fe_mul_inner(&mut t.n, &tn, &a_norm.n);
    } // bit 5 = 1
    t = fe_sqr(&t); // bit 4 = 0
    t = fe_sqr(&t);
    {
        let tn = t.n;
        fe_mul_inner(&mut t.n, &tn, &a_norm.n);
    } // bit 3 = 1
    t = fe_sqr(&t);
    {
        let tn = t.n;
        fe_mul_inner(&mut t.n, &tn, &a_norm.n);
    } // bit 2 = 1
    t = fe_sqr(&t); // bit 1 = 0
    t = fe_sqr(&t);
    {
        let tn = t.n;
        fe_mul_inner(&mut t.n, &tn, &a_norm.n);
    } // bit 0 = 1
    t
}

// ─────────────────────────────────────────────────────────────────────────────
// § 2  Scalar  (4 × 64-bit limbs, C: secp256k1_scalar)
//
//   C: $BASE/scalar_4x64_impl.h
// ─────────────────────────────────────────────────────────────────────────────

// Limbs of n (secp256k1 group order).
// C: $BASE/scalar_4x64_impl.h – SECP256K1_N_[0123]
const N_0: u64 = 0xBFD25E8CD0364141;
const N_1: u64 = 0xBAAEDCE6AF48A03B;
const N_2: u64 = 0xFFFFFFFFFFFFFFFE;
const N_3: u64 = 0xFFFFFFFFFFFFFFFF;

// Limbs of 2^256 - n.
// C: $BASE/scalar_4x64_impl.h – SECP256K1_N_C_[012]
// N_C_0 = ~N_0 + 1 = 2^64 - N_0 = wrapping_neg(N_0)
const N_C_0: u64 = N_0.wrapping_neg(); // !N_0 + 1
const N_C_1: u64 = !N_1;
const N_C_2: u64 = 1u64;

// Limbs of n/2.
// C: $BASE/scalar_4x64_impl.h – SECP256K1_N_H_[0123]
const N_H_0: u64 = 0xDFE92F46681B20A0;
const N_H_1: u64 = 0x5D576E7357A4501D;
const N_H_2: u64 = 0xFFFFFFFFFFFFFFFF;
const N_H_3: u64 = 0x7FFFFFFFFFFFFFFF;

/// secp256k1 scalar (reduced mod n) in 4×64-bit LE representation.
///
/// C: $BASE/scalar_4x64.h – `typedef struct { uint64_t d[4]; } secp256k1_scalar;`
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scalar {
    /// Little-endian 64-bit limbs.  d[0] is least significant.
    pub d: [u64; 4],
}

impl Scalar {
    pub const ZERO: Self = Scalar { d: [0; 4] };
    // C: $BASE/scalar_4x64_impl.h – `scalar_set_int`
    pub fn from_u32(v: u32) -> Self {
        Scalar {
            d: [v as u64, 0, 0, 0],
        }
    }
    // C: $BASE/scalar_4x64_impl.h – `scalar_is_zero`
    pub fn is_zero(&self) -> bool {
        (self.d[0] | self.d[1] | self.d[2] | self.d[3]) == 0
    }
    // C: $BASE/scalar_4x64_impl.h – `scalar_is_high`
    pub fn is_high(&self) -> bool {
        let mut yes = false;
        let mut no = false;
        no |= self.d[3] < N_H_3;
        yes |= (self.d[3] > N_H_3) & !no;
        no |= (self.d[2] < N_H_2) & !yes;
        no |= (self.d[1] < N_H_1) & !yes;
        yes |= (self.d[1] > N_H_1) & !no;
        yes |= (self.d[0] > N_H_0) & !no;
        yes
    }
    // C: $BASE/scalar_4x64_impl.h – `scalar_is_even`
    pub fn is_even(&self) -> bool {
        self.d[0] & 1 == 0
    }
    // C: $BASE/scalar_4x64_impl.h – `scalar_get_bits`
    pub fn get_bits(&self, offset: u32, count: u32) -> u32 {
        ((self.d[(offset >> 6) as usize] >> (offset & 0x3F)) & (((1u64) << count) - 1)) as u32
    }
    // C: $BASE/scalar_4x64_impl.h – `scalar_get_bits_var`
    pub fn get_bits_var(&self, offset: u32, count: u32) -> u32 {
        if (offset + count - 1) >> 6 == offset >> 6 {
            self.get_bits(offset, count)
        } else {
            let lo = self.d[(offset >> 6) as usize] >> (offset & 0x3F);
            let hi = self.d[((offset >> 6) + 1) as usize] << (64 - (offset & 0x3F));
            ((lo | hi) & (((1u64) << count) - 1)) as u32
        }
    }
    // C: $BASE/scalar_4x64_impl.h – `scalar_check_overflow`
    pub fn check_overflow(&self) -> bool {
        let mut yes = false;
        let mut no = false;
        no |= self.d[3] < N_3;
        no |= self.d[2] < N_2;
        yes |= (self.d[2] > N_2) & !no;
        no |= self.d[1] < N_1;
        yes |= (self.d[1] > N_1) & !no;
        yes |= (self.d[0] >= N_0) & !no;
        yes
    }
    // C: $BASE/scalar_4x64_impl.h – `scalar_reduce`
    pub fn reduce(&mut self, overflow: u64) -> bool {
        let ov = overflow as u128;
        let mut t = self.d[0] as u128 + ov * N_C_0 as u128;
        self.d[0] = t as u64;
        t >>= 64;
        t += self.d[1] as u128 + ov * N_C_1 as u128;
        self.d[1] = t as u64;
        t >>= 64;
        t += self.d[2] as u128 + ov * N_C_2 as u128;
        self.d[2] = t as u64;
        t >>= 64;
        t += self.d[3] as u128;
        self.d[3] = t as u64;
        overflow != 0
    }
    // C: $BASE/scalar_4x64_impl.h – `scalar_set_b32`
    pub fn set_b32(b: &[u8; 32]) -> (Self, bool) {
        let mut s = Scalar {
            d: [
                u64::from_be_bytes(b[24..32].try_into().unwrap()),
                u64::from_be_bytes(b[16..24].try_into().unwrap()),
                u64::from_be_bytes(b[8..16].try_into().unwrap()),
                u64::from_be_bytes(b[0..8].try_into().unwrap()),
            ],
        };
        let over = s.check_overflow();
        let overflowed = s.reduce(over as u64);
        (s, overflowed)
    }
    // C: $BASE/scalar_4x64_impl.h – `scalar_get_b32`
    pub fn get_b32(&self) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[0..8].copy_from_slice(&self.d[3].to_be_bytes());
        b[8..16].copy_from_slice(&self.d[2].to_be_bytes());
        b[16..24].copy_from_slice(&self.d[1].to_be_bytes());
        b[24..32].copy_from_slice(&self.d[0].to_be_bytes());
        b
    }
    // C: $BASE/scalar_4x64_impl.h – `scalar_add`
    pub fn add(&mut self, b: &Scalar) -> bool {
        let mut t = self.d[0] as u128 + b.d[0] as u128;
        self.d[0] = t as u64;
        t >>= 64;
        t += self.d[1] as u128 + b.d[1] as u128;
        self.d[1] = t as u64;
        t >>= 64;
        t += self.d[2] as u128 + b.d[2] as u128;
        self.d[2] = t as u64;
        t >>= 64;
        t += self.d[3] as u128 + b.d[3] as u128;
        self.d[3] = t as u64;
        t >>= 64;
        let overflow = (t as u64) + self.check_overflow() as u64;
        self.reduce(overflow)
    }
    // C: $BASE/scalar_4x64_impl.h – `scalar_negate`
    pub fn negate(&self) -> Scalar {
        let nonzero = if self.is_zero() { 0u64 } else { !0u64 };
        let mut t = !self.d[0] as u128 + (N_0 + 1) as u128;
        let d0 = (t as u64) & nonzero;
        t >>= 64;
        t += !self.d[1] as u128 + N_1 as u128;
        let d1 = (t as u64) & nonzero;
        t >>= 64;
        t += !self.d[2] as u128 + N_2 as u128;
        let d2 = (t as u64) & nonzero;
        t >>= 64;
        t += !self.d[3] as u128 + N_3 as u128;
        let d3 = (t as u64) & nonzero;
        Scalar {
            d: [d0, d1, d2, d3],
        }
    }
    // C: $BASE/scalar_4x64_impl.h – `scalar_cond_negate`
    pub fn cond_negate(&mut self, flag: bool) -> i32 {
        let mask = if flag { !0u64 } else { 0u64 };
        let nonzero = if self.is_zero() { 0u64 } else { !0u64 };
        let mut t = (self.d[0] ^ mask) as u128 + ((N_0 + 1) & mask) as u128;
        self.d[0] = (t as u64) & nonzero;
        t >>= 64;
        t += (self.d[1] ^ mask) as u128 + (N_1 & mask) as u128;
        self.d[1] = (t as u64) & nonzero;
        t >>= 64;
        t += (self.d[2] ^ mask) as u128 + (N_2 & mask) as u128;
        self.d[2] = (t as u64) & nonzero;
        t >>= 64;
        t += (self.d[3] ^ mask) as u128 + (N_3 & mask) as u128;
        self.d[3] = (t as u64) & nonzero;
        if flag { -1 } else { 1 }
    }
    // C: $BASE/scalar_4x64_impl.h – `scalar_half`
    pub fn half(&self) -> Scalar {
        let mask = u64::wrapping_neg(self.d[0] & 1);
        let mut t: u128 =
            ((self.d[0] >> 1) | (self.d[1] << 63)) as u128 + ((N_H_0 + 1) & mask) as u128;
        let d0 = t as u64;
        t >>= 64;
        t += ((self.d[1] >> 1) | (self.d[2] << 63)) as u128 + (N_H_1 & mask) as u128;
        let d1 = t as u64;
        t >>= 64;
        t += ((self.d[2] >> 1) | (self.d[3] << 63)) as u128 + (N_H_2 & mask) as u128;
        let d2 = t as u64;
        let d3 = (t >> 64) as u64 + (self.d[3] >> 1) + (N_H_3 & mask);
        Scalar {
            d: [d0, d1, d2, d3],
        }
    }
    // C: $BASE/scalar_4x64_impl.h – `scalar_cmov`
    pub fn cmov(&mut self, a: &Scalar, flag: bool) {
        let mask0 = if flag { 0u64 } else { !0u64 };
        let mask1 = !mask0;
        self.d[0] = (self.d[0] & mask0) | (a.d[0] & mask1);
        self.d[1] = (self.d[1] & mask0) | (a.d[1] & mask1);
        self.d[2] = (self.d[2] & mask0) | (a.d[2] & mask1);
        self.d[3] = (self.d[3] & mask0) | (a.d[3] & mask1);
    }
}

// C: $BASE/scalar_4x64_impl.h – `scalar_mul_512`  (only the non-ASM `#else` path)
fn scalar_mul_512(a: &Scalar, b: &Scalar) -> [u64; 8] {
    // 160-bit accumulator (c0, c1, c2).
    // muladd!(c, x, y) → (c0,c1,c2) += x*y
    macro_rules! muladd {
        ($c0:expr, $c1:expr, $c2:expr, $x:expr, $y:expr) => {{
            let t = $x as u128 * $y as u128;
            let tl = t as u64;
            let th = (t >> 64) as u64;
            let (x, ov1) = $c0.overflowing_add(tl);
            $c0 = x;
            let th = th + ov1 as u64;
            let (y, ov2) = $c1.overflowing_add(th);
            $c1 = y;
            $c2 += ov2 as u32;
        }};
    }
    macro_rules! extract {
        ($l:expr, $c0:expr, $c1:expr, $c2:expr) => {{
            $l = $c0;
            $c0 = $c1;
            $c1 = $c2 as u64;
            $c2 = 0;
        }};
    }
    let (mut c0, mut c1, mut c2): (u64, u64, u32) = (0, 0, 0);
    let mut l = [0u64; 8];
    muladd!(c0, c1, c2, a.d[0], b.d[0]);
    extract!(l[0], c0, c1, c2);
    muladd!(c0, c1, c2, a.d[0], b.d[1]);
    muladd!(c0, c1, c2, a.d[1], b.d[0]);
    extract!(l[1], c0, c1, c2);
    muladd!(c0, c1, c2, a.d[0], b.d[2]);
    muladd!(c0, c1, c2, a.d[1], b.d[1]);
    muladd!(c0, c1, c2, a.d[2], b.d[0]);
    extract!(l[2], c0, c1, c2);
    muladd!(c0, c1, c2, a.d[0], b.d[3]);
    muladd!(c0, c1, c2, a.d[1], b.d[2]);
    muladd!(c0, c1, c2, a.d[2], b.d[1]);
    muladd!(c0, c1, c2, a.d[3], b.d[0]);
    extract!(l[3], c0, c1, c2);
    muladd!(c0, c1, c2, a.d[1], b.d[3]);
    muladd!(c0, c1, c2, a.d[2], b.d[2]);
    muladd!(c0, c1, c2, a.d[3], b.d[1]);
    extract!(l[4], c0, c1, c2);
    muladd!(c0, c1, c2, a.d[2], b.d[3]);
    muladd!(c0, c1, c2, a.d[3], b.d[2]);
    extract!(l[5], c0, c1, c2);
    muladd!(c0, c1, c2, a.d[3], b.d[3]);
    extract!(l[6], c0, c1, c2);
    l[7] = c0;
    l
}

// C: $BASE/scalar_4x64_impl.h – `scalar_reduce_512`  (only the non-ASM `#else` path)
fn scalar_reduce_512(r: &mut Scalar, l: &[u64; 8]) {
    // Reduce 512→385 via m[0..6] = l[0..3] + l[4..7] * N_C
    macro_rules! muladd {
        ($c0:expr, $c1:expr, $c2:expr, $x:expr, $y:expr) => {{
            let t = $x as u128 * $y as u128;
            let tl = t as u64;
            let th = (t >> 64) as u64;
            let (x, o1) = $c0.overflowing_add(tl);
            $c0 = x;
            let th = th + o1 as u64;
            let (y, o2) = $c1.overflowing_add(th);
            $c1 = y;
            $c2 = $c2.wrapping_add(o2 as u32);
        }};
    }
    macro_rules! sumadd {
        ($c0:expr, $c1:expr, $c2:expr, $a:expr) => {{
            let (x, o) = $c0.overflowing_add($a);
            $c0 = x;
            let (y, o2) = $c1.overflowing_add(o as u64);
            $c1 = y;
            $c2 += o2 as u32;
        }};
    }
    macro_rules! extract {
        ($m:expr, $c0:expr, $c1:expr, $c2:expr) => {{
            $m = $c0;
            $c0 = $c1;
            $c1 = $c2 as u64;
            $c2 = 0;
        }};
    }

    let (n0, n1, n2, n3) = (l[4], l[5], l[6], l[7]);
    let (mut c0, mut c1, mut c2): (u64, u64, u32) = (0, 0, 0);
    let (mut m0, mut m1, mut m2, mut m3, mut m4, mut m5): (u64, u64, u64, u64, u64, u64);
    let m6: u32;

    c0 = l[0];
    muladd!(c0, c1, c2, n0, N_C_0);
    extract!(m0, c0, c1, c2);
    sumadd!(c0, c1, c2, l[1]);
    muladd!(c0, c1, c2, n1, N_C_0);
    muladd!(c0, c1, c2, n0, N_C_1);
    extract!(m1, c0, c1, c2);
    sumadd!(c0, c1, c2, l[2]);
    muladd!(c0, c1, c2, n2, N_C_0);
    muladd!(c0, c1, c2, n1, N_C_1);
    sumadd!(c0, c1, c2, n0);
    extract!(m2, c0, c1, c2);
    sumadd!(c0, c1, c2, l[3]);
    muladd!(c0, c1, c2, n3, N_C_0);
    muladd!(c0, c1, c2, n2, N_C_1);
    sumadd!(c0, c1, c2, n1);
    extract!(m3, c0, c1, c2);
    muladd!(c0, c1, c2, n3, N_C_1);
    sumadd!(c0, c1, c2, n2);
    extract!(m4, c0, c1, c2);
    sumadd!(c0, c1, c2, n3);
    extract!(m5, c0, c1, c2);
    m6 = c0 as u32;

    // Reduce 385→258 via p[0..4] = m[0..3] + m[4..6] * N_C
    let (mut p0, mut p1, mut p2, mut p3): (u64, u64, u64, u64);
    let p4: u32;
    c0 = m0;
    c1 = 0;
    c2 = 0;
    muladd!(c0, c1, c2, m4, N_C_0);
    extract!(p0, c0, c1, c2);
    sumadd!(c0, c1, c2, m1);
    muladd!(c0, c1, c2, m5, N_C_0);
    muladd!(c0, c1, c2, m4, N_C_1);
    extract!(p1, c0, c1, c2);
    sumadd!(c0, c1, c2, m2);
    muladd!(c0, c1, c2, m6 as u64, N_C_0);
    muladd!(c0, c1, c2, m5, N_C_1);
    sumadd!(c0, c1, c2, m4);
    extract!(p2, c0, c1, c2);
    sumadd!(c0, c1, c2, m3);
    muladd!(c0, c1, c2, m6 as u64, N_C_1);
    sumadd!(c0, c1, c2, m5);
    extract!(p3, c0, c1, c2);
    p4 = (c0 as u32).wrapping_add(m6);

    // Reduce 258→256: r[0..3] = p[0..3] + p4 * N_C
    let mut t = p0 as u128 + p4 as u128 * N_C_0 as u128;
    r.d[0] = t as u64;
    t >>= 64;
    t += p1 as u128 + p4 as u128 * N_C_1 as u128;
    r.d[1] = t as u64;
    t >>= 64;
    t += p2 as u128 + p4 as u128 * N_C_2 as u128;
    r.d[2] = t as u64;
    t >>= 64;
    t += p3 as u128;
    r.d[3] = t as u64;
    let c = (t >> 64) as u64;

    // Final reduction.
    r.reduce(c + r.check_overflow() as u64);
}

// C: $BASE/scalar_4x64_impl.h – `scalar_mul`
pub fn scalar_mul(a: &Scalar, b: &Scalar) -> Scalar {
    let l = scalar_mul_512(a, b);
    let mut r = Scalar::ZERO;
    scalar_reduce_512(&mut r, &l);
    r
}

// C: $BASE/scalar_4x64_impl.h – `scalar_inverse` / `scalar_inverse_var`
// Deviation: uses Fermat (x^(n-2) mod n) instead of modinv64.
pub fn scalar_inverse_var(x: &Scalar) -> Scalar {
    // n-2 addition chain (standard secp256k1 SCA-resistant chain via binary
    // exponentiation with precomputed rungs).
    // We use a simple square-and-multiply loop for correctness.
    let mut r = Scalar::from_u32(1);
    // Exponent = n-2 in big-endian bits
    // big-endian limb order: index 0 = most-significant (N_3), index 3 = N_0-2
    let n_minus_2 = [N_3, N_2, N_1, N_0.wrapping_sub(2)];
    for limb_idx in 0..4 {
        let limb = n_minus_2[limb_idx];
        for bit in (0..64).rev() {
            r = scalar_mul(&r, &r); // square
            if (limb >> bit) & 1 != 0 {
                r = scalar_mul(&r, x); // multiply
            }
        }
    }
    r
}

// ─────────────────────────────────────────────────────────────────────────────
// § 3  Group elements
//
//   C: $BASE/group_impl.h
// ─────────────────────────────────────────────────────────────────────────────

/// Affine (non-Jacobian) point.  C: secp256k1_ge
#[derive(Clone, Copy, Debug)]
pub struct Ge {
    pub x: Fe,
    pub y: Fe,
    pub infinity: bool,
}

/// Jacobian point.  C: secp256k1_gej
#[derive(Clone, Copy, Debug)]
pub struct Gej {
    pub x: Fe,
    pub y: Fe,
    pub z: Fe,
    pub infinity: bool,
}

// secp256k1 curve constant B=7.
// C: $BASE/group_impl.h – `#define SECP256K1_B 7`
const SECP256K1_B: i32 = 7;

// Generator point G.
// C: $BASE/group_impl.h – `static const rustsecp256k1_v0_10_0_ge rustsecp256k1_v0_10_0_ge_const_g = SECP256K1_G;`
// The constant is given in big-endian 32-bit words.
const G: Ge = Ge {
    x: Fe::set_b32_mod(&hex32(
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    )),
    y: Fe::set_b32_mod(&hex32(
        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
    )),
    infinity: false,
};
const fn hex32(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (hex_nibble(b[2 * i]) << 4) | hex_nibble(b[2 * i + 1]);
        i += 1;
    }
    out
}
const fn hex_nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("bad hex char"),
    }
}

impl Ge {
    pub fn infinity() -> Self {
        Ge {
            x: Fe::zero(),
            y: Fe::zero(),
            infinity: true,
        }
    }
    // C: $BASE/group_impl.h – `ge_set_xy`
    pub fn set_xy(x: Fe, y: Fe) -> Self {
        Ge {
            x,
            y,
            infinity: false,
        }
    }
    // C: $BASE/group_impl.h – `ge_neg`
    pub fn neg(&self) -> Ge {
        let mut r = *self;
        r.y.normalize_weak();
        r.y = fe_negate(&r.y, 1);
        r
    }
}

impl Gej {
    pub fn infinity() -> Self {
        Gej {
            x: Fe::zero(),
            y: Fe::zero(),
            z: Fe::zero(),
            infinity: true,
        }
    }
    // C: $BASE/group_impl.h – `gej_is_infinity`
    pub fn is_infinity(&self) -> bool {
        self.infinity
    }
    // C: $BASE/group_impl.h – `gej_neg`
    pub fn neg(&self) -> Gej {
        let mut r = *self;
        r.y.normalize_weak();
        r.y = fe_negate(&r.y, 1);
        r
    }
    // C: $BASE/group_impl.h – `gej_set_ge`
    pub fn set_ge(a: &Ge) -> Self {
        Gej {
            infinity: a.infinity,
            x: a.x,
            y: a.y,
            z: Fe::set_int(1),
        }
    }
}

// C: $BASE/group_impl.h – `gej_eq_x_var`
// Returns true if `x * r.z^2 ≡ r.x (mod p)`, i.e. the affine X of r equals x.
pub fn gej_eq_x_var(x: &Fe, a: &Gej) -> bool {
    let z2 = fe_sqr(&a.z);
    let r = fe_mul(&z2, x);
    r.equal(&a.x)
}

// C: $BASE/group_impl.h – `ge_set_gej_var`  (converts Jacobian to affine, variable-time)
pub fn ge_set_gej_var(a: &Gej) -> Ge {
    if a.infinity {
        return Ge::infinity();
    }
    let zi = fe_inv(&a.z);
    let zi2 = fe_sqr(&zi);
    let zi3 = fe_mul(&zi2, &zi);
    Ge {
        x: fe_mul(&a.x, &zi2),
        y: fe_mul(&a.y, &zi3),
        infinity: false,
    }
}

// C: $BASE/group_impl.h – `ge_set_xo_var`
// Given x, compute y such that y^2 = x^3+7 and y has the given parity.
pub fn ge_set_xo_var(x: &Fe, odd: bool) -> Option<Ge> {
    let x2 = fe_sqr(x);
    let mut x3 = fe_mul(x, &x2);
    fe_add_int(&mut x3, SECP256K1_B);
    let (mut y, ok) = fe_sqrt(&x3);
    if !ok {
        return None;
    }
    y.normalize_var();
    if y.is_odd() != odd {
        y = fe_negate(&y, 1);
    }
    Some(Ge {
        x: *x,
        y,
        infinity: false,
    })
}

// C: $BASE/group_impl.h – `gej_double`
// Operations: 3 mul, 4 sqr, 8 add/half/mul_int/negate
#[inline(never)]
pub fn gej_double(a: &Gej) -> Gej {
    if a.infinity {
        return *a;
    }
    // Z3 = Y1 * Z1
    let z3 = fe_mul(&a.z, &a.y);
    // S = Y1^2
    let s = fe_sqr(&a.y);
    // L = X1^2
    let mut l = fe_sqr(&a.x);
    // L = 3 * X1^2
    fe_mul_int(&mut l, 3);
    // L = (3/2) * X1^2
    fe_half(&mut l);
    // T = -S
    let mut t = fe_negate(&s, 1);
    // T = -X1*S
    t = fe_mul(&t, &a.x);
    // X3 = L^2
    let mut x3 = fe_sqr(&l);
    // X3 = L^2 + T
    fe_add(&mut x3, &t);
    // X3 = L^2 + 2T
    fe_add(&mut x3, &t);
    // S' = S^2
    let ss = fe_sqr(&s);
    // T' = X3 + T
    let mut tp = x3;
    fe_add(&mut tp, &t);
    // Y3 = L * (X3 + T)
    let mut y3 = fe_mul(&tp, &l);
    // Y3 = L*(X3+T) + S^2
    fe_add(&mut y3, &ss);
    // Y3 = -(L*(X3+T) + S^2)
    y3 = fe_negate(&y3, 2);

    Gej {
        x: x3,
        y: y3,
        z: z3,
        infinity: false,
    }
}

// C: $BASE/group_impl.h – `gej_add_var`   (12 mul, 4 sqr)
pub fn gej_add_var(a: &Gej, b: &Gej) -> Gej {
    if a.infinity {
        return *b;
    }
    if b.infinity {
        return *a;
    }

    let z22 = fe_sqr(&b.z);
    let z12 = fe_sqr(&a.z);
    let u1 = fe_mul(&a.x, &z22);
    let u2 = fe_mul(&b.x, &z12);
    let mut s1 = fe_mul(&a.y, &z22);
    s1 = fe_mul(&s1, &b.z);
    let mut s2 = fe_mul(&b.y, &z12);
    s2 = fe_mul(&s2, &a.z);

    let mut h = fe_negate(&u1, 1);
    fe_add(&mut h, &u2);
    let mut i = fe_negate(&s2, 1);
    fe_add(&mut i, &s1);

    if h.normalizes_to_zero() {
        if i.normalizes_to_zero() {
            return gej_double(a);
        } else {
            return Gej::infinity();
        }
    }

    let mut rz = fe_mul(&h, &b.z);
    let z3 = fe_mul(&a.z, &rz);

    let mut h2 = fe_sqr(&h);
    h2 = fe_negate(&h2, 1);
    let h3 = fe_mul(&h2, &h);
    let mut t = fe_mul(&u1, &h2);

    let mut x3 = fe_sqr(&i);
    fe_add(&mut x3, &h3);
    fe_add(&mut x3, &t);
    fe_add(&mut x3, &t);

    let mut tp = t;
    fe_add(&mut tp, &x3);
    let mut y3 = fe_mul(&tp, &i);
    let h3s1 = fe_mul(&h3, &s1);
    fe_add(&mut y3, &h3s1);

    Gej {
        x: x3,
        y: y3,
        z: z3,
        infinity: false,
    }
}

// C: $BASE/group_impl.h – `gej_add_ge_var`  (8 mul, 3 sqr)
pub fn gej_add_ge_var(a: &Gej, b: &Ge) -> Gej {
    if a.infinity {
        return Gej::set_ge(b);
    }
    if b.infinity {
        return *a;
    }

    let z12 = fe_sqr(&a.z);
    let u1 = a.x;
    let u2 = fe_mul(&b.x, &z12);
    let s1 = a.y;
    let mut s2 = fe_mul(&b.y, &z12);
    s2 = fe_mul(&s2, &a.z);

    let mut h = fe_negate(&u1, 6); // magnitude max for gej.x is 8; use conservative bound
    fe_add(&mut h, &u2);
    let mut i = fe_negate(&s2, 1);
    fe_add(&mut i, &s1);

    if h.normalizes_to_zero() {
        if i.normalizes_to_zero() {
            return gej_double(a);
        } else {
            return Gej::infinity();
        }
    }

    let z3 = fe_mul(&a.z, &h);

    let mut h2 = fe_sqr(&h);
    h2 = fe_negate(&h2, 1);
    let h3 = fe_mul(&h2, &h);
    let mut t = fe_mul(&u1, &h2);

    let mut x3 = fe_sqr(&i);
    fe_add(&mut x3, &h3);
    fe_add(&mut x3, &t);
    fe_add(&mut x3, &t);

    let mut tp = t;
    fe_add(&mut tp, &x3);
    let mut y3 = fe_mul(&tp, &i);
    let h3s1 = fe_mul(&h3, &s1);
    fe_add(&mut y3, &h3s1);

    Gej {
        x: x3,
        y: y3,
        z: z3,
        infinity: false,
    }
}

// C: $BASE/group_impl.h – `gej_add_ge`  (unified, constant-time; 7 mul, 5 sqr)
pub fn gej_add_ge(a: &Gej, b: &Ge) -> Gej {
    // Brier-Joye unified formula (handles both addition and doubling).
    let zz = fe_sqr(&a.z);
    let u1 = a.x;
    let u2 = fe_mul(&b.x, &zz);
    let s1 = a.y;
    let mut s2 = fe_mul(&b.y, &zz);
    s2 = fe_mul(&s2, &a.z);
    let mut t = u1;
    fe_add(&mut t, &u2); // T = U1+U2
    let mut m = s1;
    fe_add(&mut m, &s2); // M = S1+S2
    let mut rr = fe_sqr(&t); // rr = T^2
    let mut m_alt = fe_negate(&u2, 1);
    let tt = fe_mul(&u1, &m_alt);
    fe_add(&mut rr, &tt); // rr = R = T^2 - U1*U2

    let degenerate = m.normalizes_to_zero();

    let mut rr_alt = s1;
    fe_mul_int(&mut rr_alt, 2); // 2*(S1+S2−S2) = 2*S1 → Numerator
    fe_add(&mut m_alt, &u1); // Malt = X1−X2 → Denominator

    rr_alt.cmov(&rr, !degenerate);
    m_alt.cmov(&m, !degenerate);

    let mut n = fe_sqr(&m_alt); // n = Malt^2
    let mut q = fe_negate(&t, 9); // q = -T  (magnitude bound)
    q = fe_mul(&q, &n); // q = Q = -T*Malt^2

    n = fe_sqr(&n); // n = Malt^4
    n.cmov(&m, degenerate); // n = M^3*Malt

    let mut tx = fe_sqr(&rr_alt); // t = Ralt^2
    let z3 = fe_mul(&a.z, &m_alt); // Z3 = Malt*Z
    fe_add(&mut tx, &q); // t = X3 = Ralt^2+Q
    let x3 = tx;
    fe_mul_int(&mut tx, 2);
    fe_add(&mut tx, &q); // t = 2*X3+Q
    let mut ty = fe_mul(&tx, &rr_alt); // t = Ralt*(2*X3+Q)
    fe_add(&mut ty, &n); // t = Ralt*(2*X3+Q)+M^3*Malt
    ty = fe_negate(&ty, 9);
    fe_half(&mut ty); // Y3

    let mut r = Gej {
        x: x3,
        y: ty,
        z: z3,
        infinity: false,
    };
    r.x.cmov(&b.x, a.infinity);
    r.y.cmov(&b.y, a.infinity);
    r.z.cmov(&Fe::set_int(1), a.infinity);
    r.infinity = r.z.normalizes_to_zero();
    r
}

// ─────────────────────────────────────────────────────────────────────────────
// § 4  Strauss wNAF ecmult  (matches C library algorithm)
//
//   C: $BASE/ecmult_impl.h  – `ecmult`, `ecmult_strauss_wnaf`,
//      `ecmult_odd_multiples_table`, `ecmult_wnaf`, `ecmult_table_get_ge`
//   C: $BASE/scalar_impl.h  – `scalar_split_lambda`
//   C: $BASE/scalar_4x64_impl.h – `scalar_split_128`, `scalar_mul_shift_var`
//   C: $BASE/field.h        – `const_beta`
//
// GLV endomorphism: for secp256k1, φ(x,y) = (β·x, y) satisfies λ·φ(P) = P
// where λ³ ≡ 1 (mod n) and β³ ≡ 1 (mod p).  Splitting a 256-bit scalar into
// two ~128-bit halves via scalar_split_lambda halves the main-loop length.
//
// G is additionally split at bit-128 (ng_1 + ng_128·2¹²⁸) so all four wNAFs
// are ≤ 129 bits.  Two per-call tables of size 8 are built for A and for G
// (and two more for λ·A and 2¹²⁸·G) using Montgomery's batch-inversion trick.
// ─────────────────────────────────────────────────────────────────────────────

/// Window size for Strauss wNAF — matches C's WINDOW_A.
const WINDOW_A: usize = 5;
/// Number of table entries per scalar: 2^(w-2) = 8 → {1,3,…,15}·P.
const TABLE_SIZE: usize = 1 << (WINDOW_A - 2);

// ── GLV constants ─────────────────────────────────────────────────────────────
// C: $BASE/scalar_impl.h
// λ: scalar cube-root of unity,  λ·G = φ(G) = (β·Gx, Gy).
// SECP256K1_SCALAR_CONST is big-endian; d[] is little-endian 64-bit.
const LAMBDA: Scalar = Scalar {
    d: [
        0xDF02967C_1B23BD72,
        0x122E22EA_20816678,
        0xA5261C02_8812645A,
        0x5363AD4C_C05C30E0,
    ],
};
// minus_b1,  minus_b2,  g1,  g2  — for algorithm 3.74 (GLV decomposition)
const MINUS_B1: Scalar = Scalar {
    d: [0x6F547FA9_0ABFE4C3, 0xE4437ED6_010E8828, 0, 0],
};
const MINUS_B2: Scalar = Scalar {
    d: [
        0xD765CDA8_3DB1562C,
        0x8A280AC5_0774346D,
        0xFFFFFFFF_FFFFFFFE,
        0xFFFFFFFF_FFFFFFFF,
    ],
};
const G1_GLV: Scalar = Scalar {
    d: [
        0xE893209A_45DBB031,
        0x3DAA8A14_71E8CA7F,
        0xE86C90E4_9284EB15,
        0x3086D221_A7D46BCD,
    ],
};
const G2_GLV: Scalar = Scalar {
    d: [
        0x1571B4AE_8AC47F71,
        0x221208AC_9DF506C6,
        0x6F547FA9_0ABFE4C4,
        0xE4437ED6_010E8828,
    ],
};
// β: field cube-root of unity,  β³ ≡ 1 (mod p).
// C: $BASE/field.h  `const_beta`
// SECP256K1_FE_CONST: 0x7ae96a2b 657c0710 6e64479e ac3434e9 9cf04975 12f58995 c1396c28 719501ee
const BETA: Fe = Fe::set_b32_mod(&hex32(
    "7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee",
));

// ── Scalar helpers ────────────────────────────────────────────────────────────

/// Extract `len` consecutive bits of `s` starting at bit `pos`.
/// Precondition: 1 ≤ len ≤ 32 (wNAF window), pos < 256.
/// — C: `scalar_get_bits` / `scalar_get_bits_var`
#[inline(always)]
fn scalar_get_bits(s: &Scalar, pos: usize, len: usize) -> u64 {
    let limb = pos >> 6;
    let off = pos & 63;
    let lo = s.d[limb] >> off;
    let val = if off + len > 64 && limb + 1 < 4 {
        lo | (s.d[limb + 1] << (64 - off))
    } else {
        lo
    };
    val & ((1u64 << len).wrapping_sub(1))
}

/// Compute `(a * b) >> 384`, rounding to nearest.
/// Used by scalar_split_lambda (shift is always 384 so specialised here).
/// — C: $BASE/scalar_4x64_impl.h  `scalar_mul_shift_var` (shift=384)
fn scalar_mul_shift_384(a: &Scalar, b: &Scalar) -> Scalar {
    let l = scalar_mul_512(a, b);
    // shift=384: shiftlimbs=6, shiftlow=0
    // d[0] = l[6], d[1] = l[7], d[2]=d[3]=0.
    let mut r = Scalar {
        d: [l[6], l[7], 0, 0],
    };
    // Round: if MSB of l[5] (bit 383) is set, add 1 to d[0].
    // C: scalar_cadd_bit(r, 0, (l[5] >> 63) & 1)
    if (l[5] >> 63) & 1 != 0 {
        let (v, carry) = r.d[0].overflowing_add(1);
        r.d[0] = v;
        if carry {
            let (v, carry) = r.d[1].overflowing_add(1);
            r.d[1] = v;
            if carry {
                r.d[2] = r.d[2].wrapping_add(1);
            }
        }
    }
    r
}

/// Split `k` into `(r1, r2)` with `r1 + λ·r2 ≡ k (mod n)`, both ~128 bits.
/// — C: $BASE/scalar_impl.h  `scalar_split_lambda`  (algorithm 3.74)
fn scalar_split_lambda(k: &Scalar) -> (Scalar, Scalar) {
    let c1 = scalar_mul_shift_384(k, &G1_GLV);
    let c2 = scalar_mul_shift_384(k, &G2_GLV);
    let c1 = scalar_mul(&c1, &MINUS_B1);
    let c2 = scalar_mul(&c2, &MINUS_B2);
    let mut r2 = c1;
    r2.add(&c2);
    // r1 = k - r2 * λ
    let mut r1 = scalar_mul(&r2, &LAMBDA);
    r1 = r1.negate();
    r1.add(k);
    (r1, r2)
}

/// Split `k` into `(lo128, hi128)`: lo128 = k mod 2¹²⁸, hi128 = k >> 128.
/// — C: $BASE/scalar_4x64_impl.h  `scalar_split_128`
#[inline]
fn scalar_split_128(k: &Scalar) -> (Scalar, Scalar) {
    (
        Scalar {
            d: [k.d[0], k.d[1], 0, 0],
        },
        Scalar {
            d: [k.d[2], k.d[3], 0, 0],
        },
    )
}

// ── wNAF ─────────────────────────────────────────────────────────────────────

/// Convert scalar `s` to signed wNAF with window `w`.
/// Returns `(wnaf[257], useful_length)`.
/// Each non-zero wnaf[i] is odd and in `[-(2^(w-1)−1), 2^(w-1)−1]`.
/// — C: $BASE/ecmult_impl.h  `ecmult_wnaf`
fn ecmult_wnaf(s: &Scalar, w: usize) -> ([i32; 257], usize) {
    let mut wnaf = [0i32; 257];
    let mut s = *s;
    let mut sign = 1i32;
    let mut carry = 0i32;
    let mut last_set = 0usize;

    // Work with positive scalar (wNAF of −s is the negation of wNAF of s).
    if scalar_get_bits(&s, 255, 1) != 0 {
        s = s.negate();
        sign = -1;
    }

    let mut bit = 0usize;
    while bit < 256 {
        if scalar_get_bits(&s, bit, 1) as i32 == carry {
            bit += 1;
            continue;
        }
        let now = w.min(256 - bit);
        let word = scalar_get_bits(&s, bit, now) as i32 + carry;
        carry = (word >> (w as i32 - 1)) & 1;
        let word = word - (carry << w as i32);
        wnaf[bit] = sign * word;
        last_set = bit;
        bit += now;
    }
    (wnaf, last_set + 1)
}

// ── Table building ────────────────────────────────────────────────────────────

/// Build affine table `[P, 3P, 5P, …, (2·TABLE_SIZE−1)·P]`
/// using one field inversion (Montgomery batch-inverse trick).
/// — C: $BASE/ecmult_impl.h  `ecmult_odd_multiples_table` (simplified)
fn build_odd_multiples_table(a: &Gej) -> [Ge; TABLE_SIZE] {
    // Compute odd multiples in Jacobian.
    let two_a = gej_double(a);
    let mut jac = [*a; TABLE_SIZE];
    for i in 1..TABLE_SIZE {
        jac[i] = gej_add_var(&jac[i - 1], &two_a);
    }

    // Forward pass: products[i] = z[0]·z[1]·…·z[i].
    let mut products = [Fe { n: [1, 0, 0, 0, 0] }; TABLE_SIZE];
    products[0] = jac[0].z;
    for i in 1..TABLE_SIZE {
        products[i] = fe_mul(&products[i - 1], &jac[i].z);
    }

    // One inversion of the full product.
    let mut run_inv = fe_inv(&products[TABLE_SIZE - 1]);
    run_inv.normalize();

    // Backward pass: derive each z⁻¹ and convert to affine.
    let inf_ge = Ge {
        x: Fe { n: [0; 5] },
        y: Fe { n: [0; 5] },
        infinity: true,
    };
    let mut pre = [inf_ge; TABLE_SIZE];
    for i in (0..TABLE_SIZE).rev() {
        let zi = if i > 0 {
            let zi = fe_mul(&run_inv, &products[i - 1]);
            run_inv = fe_mul(&run_inv, &jac[i].z);
            zi
        } else {
            run_inv
        };
        let zi2 = fe_mul(&zi, &zi);
        let zi3 = fe_mul(&zi2, &zi);
        let mut x = fe_mul(&jac[i].x, &zi2);
        let mut y = fe_mul(&jac[i].y, &zi3);
        x.normalize_weak();
        y.normalize_weak();
        pre[i] = Ge {
            x,
            y,
            infinity: false,
        };
    }
    pre
}

/// Table lookup: return the entry for odd index `n` (negate y if n < 0).
/// — C: $BASE/ecmult_impl.h  `ecmult_table_get_ge`
#[inline(always)]
fn table_get_ge(pre: &[Ge; TABLE_SIZE], n: i32) -> Ge {
    debug_assert!(n != 0 && (n & 1) != 0);
    if n > 0 {
        pre[((n - 1) / 2) as usize]
    } else {
        let idx = ((-n - 1) / 2) as usize;
        Ge {
            x: pre[idx].x,
            y: fe_negate(&pre[idx].y, 1),
            infinity: false,
        }
    }
}

/// λ-twisted table lookup: x from `aux` (= β·x of pre), y from `pre`.
/// — C: $BASE/ecmult_impl.h  `ecmult_table_get_ge_lambda`
#[inline(always)]
fn table_get_ge_lambda(pre: &[Ge; TABLE_SIZE], aux: &[Fe; TABLE_SIZE], n: i32) -> Ge {
    debug_assert!(n != 0 && (n & 1) != 0);
    if n > 0 {
        let idx = ((n - 1) / 2) as usize;
        Ge {
            x: aux[idx],
            y: pre[idx].y,
            infinity: false,
        }
    } else {
        let idx = ((-n - 1) / 2) as usize;
        Ge {
            x: aux[idx],
            y: fe_negate(&pre[idx].y, 1),
            infinity: false,
        }
    }
}

// ── Main Strauss wNAF ecmult ──────────────────────────────────────────────────

/// One-time initialisation: compute pre_g and pre_g128 tables, cached globally.
/// In the C library these are huge static arrays computed at compile time.
/// Here we build them once on first call and store in a global OnceLock.
/// C: $BASE/ecmult_impl.h — `ecmult_odd_multiples_table` over G / 2¹²⁸·G
fn g_tables() -> &'static ([Ge; TABLE_SIZE], [Ge; TABLE_SIZE]) {
    static CACHE: OnceLock<([Ge; TABLE_SIZE], [Ge; TABLE_SIZE])> = OnceLock::new();
    CACHE.get_or_init(|| {
        let g_jac = Gej::set_ge(&G);
        let pre_g = build_odd_multiples_table(&g_jac);
        let g128_jac = (0..128u32).fold(g_jac, |acc, _| gej_double(&acc));
        let pre_g128 = build_odd_multiples_table(&g128_jac);
        (pre_g, pre_g128)
    })
}

/// Compute `u1·G + u2·a` using Strauss wNAF with GLV endomorphism.
///
/// Both scalars are decomposed into ~128-bit halves so the main loop runs
/// ≤ 129 iterations instead of 256, cutting doublings in half.
///
/// — C: $BASE/ecmult_impl.h  `ecmult` / `ecmult_strauss_wnaf`
pub fn ecmult(a: &Gej, u2: &Scalar, u1: &Scalar) -> Gej {
    // ── GLV split of u2 (the variable-base scalar for A) ───────────────────
    // na_1 + λ·na_lam ≡ u2 (mod n);  both ≤ 128 bits.
    let (na_1, na_lam) = scalar_split_lambda(u2);

    // ── Simple split of u1 (the fixed-base scalar for G) ───────────────────
    // u1 = ng_1 + 2¹²⁸·ng_128;  exact 128-bit halves.
    let (ng_1, ng_128) = scalar_split_128(u1);

    // ── Build affine tables for A (8 entries each) ──────────────────────────
    // pre_a[i] = (2i+1)·A   (affine)
    // aux[i]   = β · pre_a[i].x  (for the λ·A endomorphism points)
    let pre_a = build_odd_multiples_table(a);
    let beta = BETA;
    let mut aux = [Fe { n: [0; 5] }; TABLE_SIZE];
    for i in 0..TABLE_SIZE {
        aux[i] = fe_mul(&pre_a[i].x, &beta);
        aux[i].normalize_weak();
    }

    // ── Fetch cached affine tables for G and 2¹²⁸·G ─────────────────────────
    // The G tables are constant (G is the secp256k1 generator) and expensive to
    // build (128 doublings + 1 batch-inversion each), so cache them globally.
    let (pre_g, pre_g128) = g_tables();

    // ── wNAF for all four ~128-bit scalars ──────────────────────────────────
    let (wnaf_na1, bits_na1) = ecmult_wnaf(&na_1, WINDOW_A);
    let (wnaf_nalm, bits_nalm) = ecmult_wnaf(&na_lam, WINDOW_A);
    let (wnaf_ng1, bits_ng1) = ecmult_wnaf(&ng_1, WINDOW_A);
    let (wnaf_ng128, bits_ng128) = ecmult_wnaf(&ng_128, WINDOW_A);

    let bits = bits_na1.max(bits_nalm).max(bits_ng1).max(bits_ng128);

    // ── Main loop (high-to-low, ≤ 129 iterations) ──────────────────────────
    let mut r = Gej::infinity();
    for i in (0..bits).rev() {
        r = gej_double(&r);

        if i < bits_na1 {
            let n = wnaf_na1[i];
            if n != 0 {
                r = gej_add_ge_var(&r, &table_get_ge(&pre_a, n));
            }
        }
        if i < bits_nalm {
            let n = wnaf_nalm[i];
            if n != 0 {
                r = gej_add_ge_var(&r, &table_get_ge_lambda(&pre_a, &aux, n));
            }
        }
        if i < bits_ng1 {
            let n = wnaf_ng1[i];
            if n != 0 {
                r = gej_add_ge_var(&r, &table_get_ge(&pre_g, n));
            }
        }
        if i < bits_ng128 {
            let n = wnaf_ng128[i];
            if n != 0 {
                r = gej_add_ge_var(&r, &table_get_ge(&pre_g128, n));
            }
        }
    }
    r
}

// ─────────────────────────────────────────────────────────────────────────────
// § 5  ECDSA recovery
//
//   C: $BASE/ecdsa_impl.h
//   C: $BASE/modules/recovery/main_impl.h
// ─────────────────────────────────────────────────────────────────────────────

// C: $BASE/ecdsa_impl.h – group order n expressed as field element
// `static const secp256k1_fe secp256k1_ecdsa_const_order_as_fe`
const ORDER_AS_FE: Fe = Fe::set_b32_mod(&hex32(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
));
// C: $BASE/ecdsa_impl.h – `static const secp256k1_fe secp256k1_ecdsa_const_p_minus_order`
// p - n = 0x14551231950b75fc4402da1722fc9baee
const P_MINUS_ORDER: Fe = Fe::set_b32_mod(&hex32(
    "000000000000000000000000000000014551231950B75FC4402DA1722FC9BAEE",
));

/// Core ECDSA key recovery.
///
/// Recovers the public key `Q` such that `Q = (1/r)*(s*R - m*G)`.
/// Returns `Some(Q_affine)` on success, `None` if the signature is invalid.
///
/// C: $BASE/modules/recovery/main_impl.h – `ecdsa_sig_recover`
pub fn ecdsa_sig_recover(sigr: &Scalar, sigs: &Scalar, message: &Scalar, recid: u8) -> Option<Ge> {
    if sigr.is_zero() || sigs.is_zero() {
        return None;
    }

    // brx = r as a 32-byte big-endian array
    // C: $BASE/modules/recovery/main_impl.h line ~105: `scalar_get_b32(brx, sigr)`
    let brx = sigr.get_b32();
    let (mut fx, ok) = Fe::set_b32_limit(&brx);
    let _ = ok; // always valid since r < n < p+1

    // recid bit 1: r >= p-n means we add n to get fx
    // C: $BASE/modules/recovery/main_impl.h lines ~108-113
    if recid & 2 != 0 {
        if fx.cmp_var(&P_MINUS_ORDER) >= 0 {
            return None;
        }
        let mut order_fe = ORDER_AS_FE;
        fe_add(&mut fx, &order_fe);
    }

    // Recover the curve point X with the right Y parity.
    // C: $BASE/modules/recovery/main_impl.h line ~115: `ge_set_xo_var`
    let x = ge_set_xo_var(&fx, (recid & 1) != 0)?;
    let xj = Gej::set_ge(&x);

    // u1 = -m/r,  u2 = s/r
    // C: $BASE/modules/recovery/main_impl.h lines ~117-120
    let rn = scalar_inverse_var(sigr);
    let mut u1 = scalar_mul(&rn, message);
    u1 = u1.negate();
    let u2 = scalar_mul(&rn, sigs);

    // Q = u1*G + u2*X
    // C: $BASE/modules/recovery/main_impl.h line ~121: `ecmult(&qj, &xj, &u2, &u1)`
    let qj = ecmult(&xj, &u2, &u1);
    if qj.is_infinity() {
        return None;
    }
    Some(ge_set_gej_var(&qj))
}

// ─────────────────────────────────────────────────────────────────────────────
// § 6  Public API  (matching src/ecdsa.rs interface for easy benchmarking)
// ─────────────────────────────────────────────────────────────────────────────

/// Recover the Ethereum `address` (keccak160 of uncompressed pubkey) from a
/// compact (r,s,v) signature over a 32-byte message hash.
///
/// `sig65` = r (32 bytes) ‖ s (32 bytes) ‖ v (1 byte, 27/28 or 0/1).
pub fn recover_address(msg_hash: &[u8; 32], sig65: &[u8; 65]) -> Option<[u8; 20]> {
    let (sigr, _) = Scalar::set_b32(sig65[0..32].try_into().unwrap());
    let (sigs, _) = Scalar::set_b32(sig65[32..64].try_into().unwrap());
    let (message, _) = Scalar::set_b32(msg_hash);
    let recid = (sig65[64] % 27) & 1; // normalise EIP-155 v

    let pubkey = ecdsa_sig_recover(&sigr, &sigs, &message, recid)?;

    // Serialise uncompressed pubkey (64 bytes, no 0x04 prefix for keccak).
    let mut buf = [0u8; 64];
    let mut px = pubkey.x;
    let mut py = pubkey.y;
    px.normalize();
    py.normalize();
    buf[0..32].copy_from_slice(&px.get_b32());
    buf[32..64].copy_from_slice(&py.get_b32());

    // Keccak-256 of the 64-byte pubkey, then take last 20 bytes.
    let hash = crate::keccak::keccak256(&buf);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..32]);
    Some(addr)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    /// Same vector as test_ecrecover_precompile_vector in ecdsa.rs.
    #[test]
    fn test_ecrecover_clone() {
        let msg = hex32("456e9aea5e197a1f1af7a3e85a3212fa4049a3ba34c2289b4c860fc0b0c64ef3");
        let sig = {
            let r = hex32("9242685bf161793cc25603c231bc2f568eb630ea16aa137d2664ac8038825608");
            let s = hex32("4f8ae3bd7535248d0bd448298cc2e2071e56992d0774dc340c368ae950852ada");
            let v = 28u8;
            let mut sig65 = [0u8; 65];
            sig65[0..32].copy_from_slice(&r);
            sig65[32..64].copy_from_slice(&s);
            sig65[64] = v;
            sig65
        };
        let addr = recover_address(&msg, &sig).expect("recovery failed");
        let expected = hex20("7156526fbd7a3c72969b54f64e42c10fbb768c8a");
        assert_eq!(addr, expected, "address mismatch");
    }

    fn hex20(s: &str) -> [u8; 20] {
        let mut out = [0u8; 20];
        for (i, b) in out.iter_mut().enumerate() {
            let hi = s.as_bytes()[2 * i];
            let lo = s.as_bytes()[2 * i + 1];
            *b = (hex_nibble(hi) << 4) | hex_nibble(lo);
        }
        out
    }
}

#[cfg(test)]
mod debug_tests {
    use super::*;

    #[test]
    fn test_scalar_mul_basic() {
        let two = Scalar { d: [2, 0, 0, 0] };
        let three = Scalar { d: [3, 0, 0, 0] };
        let six = scalar_mul(&two, &three);
        assert_eq!(six.d, [6, 0, 0, 0], "2*3 should be 6");
    }

    #[test]
    fn test_scalar_inv_basic() {
        // r_inv * r should equal 1 mod n
        // use r = 2
        let two = Scalar { d: [2, 0, 0, 0] };
        let inv2 = scalar_inverse_var(&two);
        let product = scalar_mul(&two, &inv2);
        assert_eq!(product.d, [1, 0, 0, 0], "2 * 2^-1 should be 1 mod n");
    }

    #[test]
    fn test_fe_mul_basic() {
        // 2 * 3 = 6
        let two = Fe { n: [2, 0, 0, 0, 0] };
        let three = Fe { n: [3, 0, 0, 0, 0] };
        let six = fe_mul(&two, &three);
        let mut six_ref = six;
        six_ref.normalize();
        assert_eq!(six_ref.n, [6, 0, 0, 0, 0], "2*3 in Fe");
    }

    #[test]
    fn test_double_g_x() {
        // 2G x-coordinate = C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5
        let g_ge = G;
        let g_jac = Gej::set_ge(&g_ge);
        let g2 = gej_double(&g_jac);
        let g2_aff = ge_set_gej_var(&g2);
        let mut x = g2_aff.x;
        x.normalize();
        let xb = x.get_b32();
        let expected = hex32("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5");
        assert_eq!(xb, expected, "2G x mismatch");
    }

    #[test]
    fn test_g_on_curve() {
        let g = G;
        let x2 = fe_sqr(&g.x);
        let mut x3 = fe_mul(&x2, &g.x);
        fe_add_int(&mut x3, 7);
        let mut y2 = fe_sqr(&g.y);
        x3.normalize();
        y2.normalize();
        assert_eq!(x3.n, y2.n, "G not on curve y^2=x^3+7");
    }

    #[test]
    fn test_fe_sqr_vs_mul() {
        let g = G;
        let mut s1 = fe_sqr(&g.x);
        let mut s2 = fe_mul(&g.x, &g.x);
        s1.normalize();
        s2.normalize();
        assert_eq!(s1.n, s2.n, "fe_sqr(G.x) != fe_mul(G.x, G.x)");
    }

    #[test]
    fn test_fe_inv() {
        // a * fe_inv(a) == 1 mod p, using G.x
        let g = G;
        let inv_x = fe_inv(&g.x);
        let mut product = fe_mul(&g.x, &inv_x);
        product.normalize();
        assert_eq!(product.n, [1, 0, 0, 0, 0], "G.x * inv(G.x) != 1");
    }

    #[test]
    fn test_fe_half() {
        // half(2) == 1, and half(3) == (3 * inv(2)) mod p
        let two = Fe { n: [2, 0, 0, 0, 0] };
        let mut h = two;
        fe_half(&mut h);
        let mut one = Fe { n: [1, 0, 0, 0, 0] };
        h.normalize();
        one.normalize();
        assert_eq!(h.n, one.n, "half(2) != 1");
    }

    #[test]
    fn test_double_g_z() {
        // 2G.z = G.y + G.z = G.y (Jacobian: z3 = y1*z1 = G.y*1 = G.y)
        let g_ge = G;
        let g_jac = Gej::set_ge(&g_ge);
        let g2 = gej_double(&g_jac);
        // z3 = G.y * G.z = G.y * 1 = G.y (before normalization)
        // After normalizing g2.z, get_b32 and compare to G.y's bytes (they should match mod p)
        let mut z3 = g2.z;
        z3.normalize();
        let mut gy = g_ge.y;
        gy.normalize();
        assert_eq!(z3.n, gy.n, "2G.z != G.y (should equal G.y*1)");
    }

    #[test]
    fn test_scalar_mul_large() {
        // (n-1)^2 = n^2 - 2n + 1 ≡ 1 (mod n)
        let n_minus_1 = Scalar {
            d: [N_0.wrapping_sub(1), N_1, N_2, N_3],
        };
        let product = scalar_mul(&n_minus_1, &n_minus_1);
        assert_eq!(product.d, [1, 0, 0, 0], "(n-1)^2 mod n should be 1");
    }
}
