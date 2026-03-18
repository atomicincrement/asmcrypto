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

// (p + 1) / 4 — used for square-root extraction (since p ≡ 3 mod 4).
const P_PLUS_ONE_DIV_4: U256 = U256([
    0xFFFFFFFFBFFFFF0C,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0x3FFFFFFFFFFFFFFF,
]);

// Generator point G  (affine coordinates, uncompressed).
// Kept as named constants for clarity; also embedded in G_TABLE[0].
#[allow(dead_code)]
const GX: U256 = U256([
    0x59F2815B16F81798,
    0x029BFCDB2DCE28D9,
    0x55A06295CE870B07,
    0x79BE667EF9DCBBAC,
]);
#[allow(dead_code)]
const GY: U256 = U256([
    0x9C47D08FFB10D4B8,
    0xFD17B448A6855419,
    0x5DA4FBFC0E1108A8,
    0x483ADA7726A3C465,
]);

// ─────────────────────────────────────────────────────────────────────────────
// GLV endomorphism constants for secp256k1
// ─────────────────────────────────────────────────────────────────────────────
//
// secp256k1 has a degree-2 endomorphism φ: (x, y) ↦ (β·x, y)  where
//   β  = a primitive cube root of unity in Fp
//   λ  = the corresponding eigenvalue in Fn  (φ(P) = λ·P)
//
// For any scalar k we decompose k = k1 + k2·λ  with |k1|, |k2| ≈ 2^128,
// then compute  k·P = k1·P + k2·φ(P)  using Shamir's simultaneous mul,
// halving the effective scalar bitlength.
//
// Constants from the Bernstein–Hamburg paper and libsecp256k1 source:
//   β  = 0x7AE96A2B657C07106E64479EAC3434E99CF0497512F58995C1396C28719501EE
//   λ  = 0xAC9C52B33FA3CF1F5AD9E3FD77ED9BA4A880B9FC8EC739C2E0CFC810B51283CE
//
// For scalar decomposition we need four 128-bit scalars (Babai rounding):
//   a1 =  0x3086D221A7D46BCDE86C90E49284EB15
//   b1 = -0xE4437ED6010E88286F547FA90ABFE4C3  (negated)
//   a2 =  0x114CA50F7A8E2F3F657C1108D9D44CFD8
//   b2 =  0x3086D221A7D46BCDE86C90E49284EB15  (= a1)
//
// libsecp256k1 uses a slightly different (pre-rounded) form; we use the
// exact same constants so results match.

/// β: cube root of unity in Fp (the one satisfying φ(P) = λ·P).
/// β = (√(−3) − 1) / 2  mod p  =  0x851695d49a83f8ef919bb86153cbcb16630fb68aed0a766a3ec693d68e6afa40
const BETA: U256 = U256([
    0x3EC693D68E6AFA40,
    0x630FB68AED0A766A,
    0x919BB86153CBCB16,
    0x851695D49A83F8EF,
]);

/// λ: endomorphism eigenvalue in Fn  (φ(P) = λ·P).
const LAMBDA: U256 = U256([
    0xE0CFC810B51283CE,
    0xA880B9FC8EC739C2,
    0x5AD9E3FD77ED9BA4,
    0xAC9C52B33FA3CF1F,
]);

// ─────────────────────────────────────────────────────────────────────────────
// Precomputed affine tables for fixed-base G multiplication
// ─────────────────────────────────────────────────────────────────────────────
//
// Storing odd multiples [G, 3G, 5G, … 15G] and [φ(G), 3φ(G), … 15φ(G)] in
// affine form allows `point_add_mixed` (Z₂=1) in the Shamir loop for
// `scalar_mul_g`, saving 4 fp_mul per addition vs full Jacobian addition.
//
// Values verified against secp256k1 curve parameters via Python.

/// Odd multiples of the generator G in affine form: [G, 3G, 5G, … 15G].
const G_TABLE: [(U256, U256); 8] = [
    (
        // 1·G
        U256([
            0x59F2815B16F81798,
            0x029BFCDB2DCE28D9,
            0x55A06295CE870B07,
            0x79BE667EF9DCBBAC,
        ]),
        U256([
            0x9C47D08FFB10D4B8,
            0xFD17B448A6855419,
            0x5DA4FBFC0E1108A8,
            0x483ADA7726A3C465,
        ]),
    ),
    (
        // 3·G
        U256([
            0x8601F113BCE036F9,
            0xB531C845836F99B0,
            0x49344F85F89D5229,
            0xF9308A019258C310,
        ]),
        U256([
            0x6CB9FD7584B8E672,
            0x6500A99934C2231B,
            0x0FE337E62A37F356,
            0x388F7B0F632DE814,
        ]),
    ),
    (
        // 5·G
        U256([
            0xCBA8D569B240EFE4,
            0xE88B84BDDC619AB7,
            0x55B4A7250A5C5128,
            0x2F8BDE4D1A072093,
        ]),
        U256([
            0xDCA87D3AA6AC62D6,
            0xF788271BAB0D6840,
            0xD4DBA9DDA6C9C426,
            0xD8AC222636E5E3D6,
        ]),
    ),
    (
        // 7·G
        U256([
            0xE92BDDEDCAC4F9BC,
            0x3D419B7E0330E39C,
            0xA398F365F2EA7A0E,
            0x5CBDF0646E5DB4EA,
        ]),
        U256([
            0xA5082628087264DA,
            0xA813D0B813FDE7B5,
            0xA3178D6D861A54DB,
            0x6AEBCA40BA255960,
        ]),
    ),
    (
        // 9·G
        U256([
            0xC35F110DFC27CCBE,
            0xE09796974C57E714,
            0x09AD178A9F559ABD,
            0xACD484E2F0C7F653,
        ]),
        U256([
            0x05CC262AC64F9C37,
            0xADD888A4375F8E0F,
            0x64380971763B61E9,
            0xCC338921B0A7D9FD,
        ]),
    ),
    (
        // 11·G
        U256([
            0xBBEC17895DA008CB,
            0x5649980BE5C17891,
            0x5EF4246B70C65AAC,
            0x774AE7F858A9411E,
        ]),
        U256([
            0x301D74C9C953C61B,
            0x372DB1E2DFF9D6A8,
            0x0243DD56D7B7B365,
            0xD984A032EB6B5E19,
        ]),
    ),
    (
        // 13·G
        U256([
            0xDEEDDF8F19405AA8,
            0xB075FBC6610E58CD,
            0xC7D1D205C3748651,
            0xF28773C2D975288B,
        ]),
        U256([
            0x29B5CB52DB03ED81,
            0x3A1A06DA521FA91F,
            0x758212EB65CDAF47,
            0x0AB0902E8D880A89,
        ]),
    ),
    (
        // 15·G
        U256([
            0x44ADBCF8E27E080E,
            0x31E5946F3C85F79E,
            0x5A465AE3095FF411,
            0xD7924D4F7D43EA96,
        ]),
        U256([
            0xC504DC9FF6A26B58,
            0xEA40AF2BD896D3A5,
            0x83842EC228CC6DEF,
            0x581E2872A86C72A6,
        ]),
    ),
];

/// Odd multiples of φ(G) in affine form: [φ(G), 3φ(G), … 15φ(G)].
/// φ(P) = (β·Pₓ mod p, Pᵧ).  y-coordinates are identical to G_TABLE entries.
const PHI_G_TABLE: [(U256, U256); 8] = [
    (
        // 1·φ(G)
        U256([
            0xFE51DE5EE84F50FB,
            0x763BBF1E531BED98,
            0xFF5E9AB39AE8D1D3,
            0xC994B69768832BCB,
        ]),
        U256([
            0x9C47D08FFB10D4B8,
            0xFD17B448A6855419,
            0x5DA4FBFC0E1108A8,
            0x483ADA7726A3C465,
        ]),
    ),
    (
        // 3·φ(G)
        U256([
            0x820D9C5DCBFF5636,
            0xBFDC5797B5B3D832,
            0x28FE22AADD39B3A6,
            0x276096FAFA87A1A4,
        ]),
        U256([
            0x6CB9FD7584B8E672,
            0x6500A99934C2231B,
            0x0FE337E62A37F356,
            0x388F7B0F632DE814,
        ]),
    ),
    (
        // 5·φ(G)
        U256([
            0x20CAC14EB816D5E3,
            0x772F120342CDCD7C,
            0xB2AC03DF28EA6865,
            0x9CF8CECF391E958C,
        ]),
        U256([
            0xDCA87D3AA6AC62D6,
            0xF788271BAB0D6840,
            0xD4DBA9DDA6C9C426,
            0xD8AC222636E5E3D6,
        ]),
    ),
    (
        // 7·φ(G)
        U256([
            0xDB0FB9A2E6E745DF,
            0xB583439FED1FA1B8,
            0xB76847C84C7FC583,
            0x8F4FA12645B83F9D,
        ]),
        U256([
            0xA5082628087264DA,
            0xA813D0B813FDE7B5,
            0xA3178D6D861A54DB,
            0x6AEBCA40BA255960,
        ]),
    ),
    (
        // 9·φ(G)
        U256([
            0x1BD35DC19E42F14E,
            0x6A029B72C43AD40A,
            0x7AED8FC57451BA21,
            0xCB77771990F32193,
        ]),
        U256([
            0x05CC262AC64F9C37,
            0xADD888A4375F8E0F,
            0x64380971763B61E9,
            0xCC338921B0A7D9FD,
        ]),
    ),
    (
        // 11·φ(G)
        U256([
            0x7E14A540E73F567D,
            0x3030CC3D0EDE914D,
            0x13825F52D07A8B2D,
            0x36C04436903912C4,
        ]),
        U256([
            0x301D74C9C953C61B,
            0x372DB1E2DFF9D6A8,
            0x0243DD56D7B7B365,
            0xD984A032EB6B5E19,
        ]),
    ),
    (
        // 13·φ(G)
        U256([
            0xC06732049F5FE73E,
            0x1CF9856254B4A1CF,
            0x3129C1B4C38F0173,
            0x1C2B3405DAD246D2,
        ]),
        U256([
            0x29B5CB52DB03ED81,
            0x3A1A06DA521FA91F,
            0x758212EB65CDAF47,
            0x0AB0902E8D880A89,
        ]),
    ),
    (
        // 15·φ(G)
        U256([
            0x80919EF8ABD03C9C,
            0xC84E2FC701B96228,
            0x979E5CF7A574A2A6,
            0xA80EA1AA8CC2D01F,
        ]),
        U256([
            0xC504DC9FF6A26B58,
            0xEA40AF2BD896D3A5,
            0x83842EC228CC6DEF,
            0x581E2872A86C72A6,
        ]),
    ),
];

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

/// Schoolbook 256×256→512-bit multiply using `u128` limbs.
///
/// With `target-cpu=native` LLVM already emits MULX/ADCX/ADOX here, matching
/// or beating a hand-written ADX kernel (which cannot be `#[inline(always)]`
/// due to Rust issue #145574 and therefore carries call overhead).
#[inline(always)]
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
#[inline(never)]
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
/// Reduction ported verbatim from `secp256k1_scalar_reduce_512` (scalar_4x64_impl.h).
/// The fn_reduce_wide body is inlined here so LLVM can fuse mul_wide + reduction
/// into one optimised unit without a separate call boundary.
#[allow(unused_assignments)] // last extract! in each pass writes c1/c2 which are never re-read
#[inline(never)]
fn fn_mul(a: &U256, b: &U256) -> U256 {
    let wide = mul_wide(a, b);

    const N_C_0: u64 = 0x402DA1732FC9BEBF;
    const N_C_1: u64 = 0x4551231950B75FC4;

    macro_rules! muladd {
        ($c0:expr, $c1:expr, $c2:expr, $a:expr, $b:expr) => {{
            let t = $a as u128 * $b as u128;
            let tl = t as u64;
            let th = (t >> 64) as u64;
            let (x, ov1) = $c0.overflowing_add(tl);
            $c0 = x;
            let th = th + ov1 as u64;
            let (y, ov2) = $c1.overflowing_add(th);
            $c1 = y;
            $c2 += ov2 as u64;
        }};
    }
    macro_rules! sumadd {
        ($c0:expr, $c1:expr, $c2:expr, $a:expr) => {{
            let (x, ov) = $c0.overflowing_add($a);
            $c0 = x;
            let (y, ov2) = $c1.overflowing_add(ov as u64);
            $c1 = y;
            $c2 += ov2 as u64;
        }};
    }
    macro_rules! extract {
        ($c0:expr, $c1:expr, $c2:expr) => {{
            let n = $c0;
            $c0 = $c1;
            $c1 = $c2;
            $c2 = 0;
            n
        }};
    }

    let (n0, n1, n2, n3) = (wide[4], wide[5], wide[6], wide[7]);

    // Pass 1: 512 → 385 bits
    let (mut c0, mut c1, mut c2): (u64, u64, u64) = (wide[0], 0, 0);
    muladd!(c0, c1, c2, n0, N_C_0);
    let m0 = extract!(c0, c1, c2);
    sumadd!(c0, c1, c2, wide[1]);
    muladd!(c0, c1, c2, n1, N_C_0);
    muladd!(c0, c1, c2, n0, N_C_1);
    let m1 = extract!(c0, c1, c2);
    sumadd!(c0, c1, c2, wide[2]);
    muladd!(c0, c1, c2, n2, N_C_0);
    muladd!(c0, c1, c2, n1, N_C_1);
    sumadd!(c0, c1, c2, n0);
    let m2 = extract!(c0, c1, c2);
    sumadd!(c0, c1, c2, wide[3]);
    muladd!(c0, c1, c2, n3, N_C_0);
    muladd!(c0, c1, c2, n2, N_C_1);
    sumadd!(c0, c1, c2, n1);
    let m3 = extract!(c0, c1, c2);
    muladd!(c0, c1, c2, n3, N_C_1);
    sumadd!(c0, c1, c2, n2);
    let m4 = extract!(c0, c1, c2);
    sumadd!(c0, c1, c2, n3);
    let m5 = extract!(c0, c1, c2);
    let m6 = c0 as u32;
    debug_assert!(m6 <= 1);

    // Pass 2: 385 → 258 bits
    c0 = m0;
    c1 = 0;
    c2 = 0;
    muladd!(c0, c1, c2, m4, N_C_0);
    let p0 = extract!(c0, c1, c2);
    sumadd!(c0, c1, c2, m1);
    muladd!(c0, c1, c2, m5, N_C_0);
    muladd!(c0, c1, c2, m4, N_C_1);
    let p1 = extract!(c0, c1, c2);
    sumadd!(c0, c1, c2, m2);
    muladd!(c0, c1, c2, m6 as u64, N_C_0);
    muladd!(c0, c1, c2, m5, N_C_1);
    sumadd!(c0, c1, c2, m4);
    let p2 = extract!(c0, c1, c2);
    sumadd!(c0, c1, c2, m3);
    muladd!(c0, c1, c2, m6 as u64, N_C_1);
    sumadd!(c0, c1, c2, m5);
    let p3 = extract!(c0, c1, c2);
    let p4 = c0 as u32 + m6;
    debug_assert!(p4 <= 2);

    // Pass 3: 258 → 256 bits
    let mut t = p0 as u128 + N_C_0 as u128 * p4 as u128;
    let r0 = t as u64;
    t >>= 64;
    t += p1 as u128 + N_C_1 as u128 * p4 as u128;
    let r1 = t as u64;
    t >>= 64;
    t += p2 as u128 + p4 as u128;
    let r2 = t as u64;
    t >>= 64;
    t += p3 as u128;
    let r3 = t as u64;
    let carry = (t >> 64) as u64;

    let mut result = U256([r0, r1, r2, r3]);
    if carry != 0 || result.ge(&N) {
        result = result.sbb(&N).0;
    }
    result
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

// ─────────────────────────────────────────────────────────────────────────────
// Jacobian negation and full Jacobian-Jacobian addition
// ─────────────────────────────────────────────────────────────────────────────

/// Negate a Jacobian point: (X : Y : Z) ↦ (X : -Y : Z).
fn point_neg(p: &JacobianPoint) -> JacobianPoint {
    JacobianPoint {
        x: p.x,
        y: fp_neg(&p.y),
        z: p.z,
    }
}

/// Full Jacobian + Jacobian addition (both points may be in projective form).
/// add-2007-bl from https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-add-2007-bl
fn point_add(p: &JacobianPoint, q: &JacobianPoint) -> JacobianPoint {
    if p.is_infinity() {
        return *q;
    }
    if q.is_infinity() {
        return *p;
    }

    let z1sq = fp_sq(&p.z);
    let z2sq = fp_sq(&q.z);
    let u1 = fp_mul(&p.x, &z2sq); // U1 = X1·Z2²
    let u2 = fp_mul(&q.x, &z1sq); // U2 = X2·Z1²
    let s1 = fp_mul(&p.y, &fp_mul(&q.z, &z2sq)); // S1 = Y1·Z2³
    let s2 = fp_mul(&q.y, &fp_mul(&p.z, &z1sq)); // S2 = Y2·Z1³

    let h = fp_sub(&u2, &u1); // H = U2 - U1
    let r = fp_sub(&s2, &s1); // R = S2 - S1

    if h.is_zero() {
        return if r.is_zero() {
            // p == q → double
            point_double(p)
        } else {
            // p == -q → infinity
            JacobianPoint::infinity()
        };
    }

    let h2 = fp_sq(&h);
    let h3 = fp_mul(&h, &h2);
    let u1h2 = fp_mul(&u1, &h2);

    // X3 = R² - H³ - 2·U1·H²
    let x3 = fp_sub(&fp_sub(&fp_sq(&r), &h3), &fp_mul_2(&u1h2));
    // Y3 = R·(U1·H² - X3) - S1·H³
    let y3 = fp_sub(&fp_mul(&r, &fp_sub(&u1h2, &x3)), &fp_mul(&s1, &h3));
    // Z3 = H·Z1·Z2
    let z3 = fp_mul(&fp_mul(&h, &p.z), &q.z);

    JacobianPoint {
        x: x3,
        y: y3,
        z: z3,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GLV scalar decomposition
// ─────────────────────────────────────────────────────────────────────────────

/// Signed 129-bit integer used during GLV decomposition.
/// `neg=true` means the sub-scalar is negative; we negate the base point instead.
/// `mag` holds bits 0..127 and `hi` holds bit 128 of |value|.
/// GLV guarantees |k1| < √n < 2^129 and |k2| < √n < 2^129.
#[derive(Clone, Copy, Debug)]
struct S129 {
    mag: u128, // bits 0..127 of |value|
    hi: bool,  // bit 128 of |value| (set iff |value| >= 2^128)
    neg: bool, // true if the original signed value is negative
}

impl S129 {
    fn from_u256_signed(v: U256) -> Self {
        // v is a scalar mod n.  If v >= n/2 the "positive" form costs more bits;
        // use the negated form instead.
        // n_half = n >> 1 = (n-1)/2
        let n_half = U256([
            0xDFE92F46681B20A0,
            0x5D576E7357A4501D,
            0xFFFFFFFFFFFFFFFF,
            0x7FFFFFFFFFFFFFFF,
        ]);
        if v.ge(&n_half) {
            // neg: magnitude = n - v  (guaranteed < 2^129)
            let neg_v = N.sbb(&v).0;
            S129 {
                mag: neg_v.0[0] as u128 | ((neg_v.0[1] as u128) << 64),
                hi: neg_v.0[2] != 0,
                neg: true,
            }
        } else {
            // pos: magnitude = v  (guaranteed < 2^129)
            S129 {
                mag: v.0[0] as u128 | ((v.0[1] as u128) << 64),
                hi: v.0[2] != 0,
                neg: false,
            }
        }
    }
}

/// Decompose a 256-bit scalar `k` into two signed ~128-bit scalars `(k1, k2)`
/// such that `k ≡ k1 + k2·λ (mod n)`.
///
/// Uses the exact libsecp256k1 algorithm:
///   c1 = (k · g1) >> 384
///   c2 = (k · g2) >> 384
///   r2 = c1·(−b1) + c2·(−b2)  mod n
///   r1 = k − r2·λ  mod n
///
/// g1, g2 are pre-computed 256-bit round(2^384·b/d) constants.
fn glv_decompose(k: &U256) -> (S129, S129) {
    // Lattice constants for secp256k1 GLV decomposition.
    // Verified: k ≡ r1 + r2·λ (mod n) with min(r1, n-r1) < 2^129
    // and       min(r2, n-r2) < 2^128 for all k in [1, n).
    //
    // g1 = round(2^384 · b2 / n),  b2 = 0x3086D221A7D46BCDE86C90E49284EB15
    let g1 = U256([
        0xE893209A45DBB031,
        0x3DAA8A1471E8CA7F,
        0xE86C90E49284EB15,
        0x3086D221A7D46BCD,
    ]);
    // g2 = round(2^384 · b1 / n),  b1 = 0xE4437ED6010E88286F547FA90ABFE4C3
    // (note: the rounded value is b1+1 in the last bit, i.e. ends in ...C4)
    let g2 = U256([
        0x1571B4AE8AC47F71,
        0x221208AC9DF506C6,
        0x6F547FA90ABFE4C4,
        0xE4437ED6010E8828,
    ]);
    // b1 and b2 as positive 128-bit integers (both fit in 2 limbs).
    let b1 = U256([
        0x6F547FA90ABFE4C3,
        0xE4437ED6010E8828,
        0x0000000000000000,
        0x0000000000000000,
    ]);
    let b2 = U256([
        0xE86C90E49284EB15,
        0x3086D221A7D46BCD,
        0x0000000000000000,
        0x0000000000000000,
    ]);

    // c1 = floor(k · g1 / 2^384), c2 = floor(k · g2 / 2^384)
    // These are the Babai rounding coefficients.
    let c1 = mul256_top128(k, &g1);
    let c2 = mul256_top128(k, &g2);

    let c1_u = U256([c1 as u64, (c1 >> 64) as u64, 0, 0]);
    let c2_u = U256([c2 as u64, (c2 >> 64) as u64, 0, 0]);

    // r2 = c2·b2 − c1·b1  mod n
    // This gives min(r2, n-r2) < 2^128.
    let t1 = fn_mul(&c1_u, &b1);
    let t2 = fn_mul(&c2_u, &b2);
    let r2_raw = fn_sub(&t2, &t1);

    // r1 = k − r2·λ  mod n
    // This gives min(r1, n-r1) < 2^129.
    let r2_lam = fn_mul(&r2_raw, &LAMBDA);
    let r1_raw = fn_sub(k, &r2_lam);

    (
        S129::from_u256_signed(r1_raw),
        S129::from_u256_signed(r2_raw),
    )
}

/// Compute bits [384, 512) of (a · b) — i.e. the top 128 bits of the
/// 512-bit product, which equals floor(a·b / 2^384).
fn mul256_top128(a: &U256, b: &U256) -> u128 {
    // We need the 8-limb product; bits [384,512) are limbs [6] and [7].
    let wide = mul_wide(a, b);
    wide[6] as u128 | ((wide[7] as u128) << 64)
}

/// Subtract scalars mod n: (a - b) mod n.
fn fn_sub(a: &U256, b: &U256) -> U256 {
    let (d, borrow) = a.sbb(b);
    if borrow == 1 {
        // underflowed: add n
        let (d2, _) = d.adc(&N);
        d2
    } else {
        d
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// wNAF (width-5) scalar representation
// ─────────────────────────────────────────────────────────────────────────────

const WNAF_WIDTH: usize = 5;
const WNAF_WINDOW: i32 = 1 << WNAF_WIDTH; // 32
const WNAF_MASK: i32 = WNAF_WINDOW - 1; // 31

/// Compute the width-5 wNAF representation of a 129-bit scalar.
/// `k_lo` = bits 0..127, `k_hi` = bit 128 (the extra bit from GLV).
/// Returns an array of 131 signed digits in {0, ±1, ±3, ±5, ±7, ±9, ±11, ±13, ±15}.
fn wnaf_129(k_lo: u128, k_hi: bool) -> [i8; 131] {
    // Represent the 129-bit scalar as a two-word integer:
    // k = k_lo + k_hi * 2^128
    // We process it one bit at a time, borrowing from k_hi when k_lo underflows.
    let mut lo = k_lo;
    let mut hi = k_hi as u128; // 0 or 1
    let mut naf = [0i8; 131];
    let mut i = 0usize;
    while lo != 0 || hi != 0 {
        if lo & 1 == 1 {
            let mod_w = (lo as i32) & WNAF_MASK;
            let digit = if mod_w > WNAF_WINDOW / 2 {
                mod_w - WNAF_WINDOW
            } else {
                mod_w
            };
            naf[i] = digit as i8;
            if digit < 0 {
                // Adding |digit| — may carry into hi
                let (new_lo, carry) = lo.overflowing_add((-digit) as u128);
                lo = new_lo;
                hi += carry as u128;
            } else {
                // Subtracting digit — k is odd so digit <= k, no borrow from hi needed
                lo -= digit as u128;
            }
        }
        // Shift right by 1
        lo = (lo >> 1) | (hi << 127);
        hi >>= 1;
        i += 1;
    }
    naf
}

// ─────────────────────────────────────────────────────────────────────────────
// Scalar multiplication: GLV + wNAF + Shamir
// ─────────────────────────────────────────────────────────────────────────────

/// Build a table of the odd multiples  [P, 3P, 5P, … (2w−1)P]  in Jacobian coords.
/// `w = WNAF_WIDTH = 5`  ⟹  8 entries.
fn build_table(p: &JacobianPoint) -> [JacobianPoint; 8] {
    let p2 = point_double(p);
    let mut table = [JacobianPoint::infinity(); 8];
    table[0] = *p;
    for i in 1..8 {
        table[i] = point_add(&table[i - 1], &p2);
    }
    table
}

/// Lookup odd-multiple table: index `d` in [1,3,5,…,15] → table[(d-1)/2].
/// Negative `d` flips the y-coordinate.
fn table_get(table: &[JacobianPoint; 8], d: i8) -> JacobianPoint {
    let idx = (d.unsigned_abs() as usize - 1) / 2;
    let p = table[idx];
    if d < 0 { point_neg(&p) } else { p }
}

/// Apply the secp256k1 GLV endomorphism  φ(P) = (β·Px, Py)  to an affine point.
fn phi_affine(px: &U256, py: &U256) -> JacobianPoint {
    JacobianPoint::from_affine(fp_mul(px, &BETA), *py)
}

/// Fetch odd-multiple `d` of G from `G_TABLE`, accounting for the overall negation
/// flag `negate` (from GLV subscalar sign) and the signed wNAF digit `d`.
///
/// Returns `(x, y)` in affine coordinates on secp256k1.
#[inline(always)]
fn g_table_lookup(d: i8, negate: bool) -> (U256, U256) {
    // Combine scalar-level negation with digit sign.
    let d = if negate { -d } else { d };
    let idx = (d.unsigned_abs() as usize - 1) / 2;
    let (x, y) = G_TABLE[idx];
    if d < 0 { (x, fp_neg(&y)) } else { (x, y) }
}

/// Fetch odd-multiple `d` of φ(G) from `PHI_G_TABLE`, same convention as above.
#[inline(always)]
fn phi_g_table_lookup(d: i8, negate: bool) -> (U256, U256) {
    let d = if negate { -d } else { d };
    let idx = (d.unsigned_abs() as usize - 1) / 2;
    let (x, y) = PHI_G_TABLE[idx];
    if d < 0 { (x, fp_neg(&y)) } else { (x, y) }
}

/// Fixed-base scalar multiplication `scalar * G`.
///
/// Optimised over the general GLV+wNAF path by using precomputed affine tables
/// `G_TABLE` / `PHI_G_TABLE` (odd multiples [1..15]) so every addition can call
/// `point_add_mixed` (Z₂=1), saving ≈4 fp_mul per step compared to a full
/// Jacobian addition.
fn scalar_mul_g(scalar: &U256) -> JacobianPoint {
    // Step 1 – GLV decomposition
    let (k1, k2) = glv_decompose(scalar);

    // Step 2 – wNAF of |k1| and |k2|
    let naf1 = wnaf_129(k1.mag, k1.hi);
    let naf2 = wnaf_129(k2.mag, k2.hi);

    // Step 3 – Shamir double-and-add from MSB using mixed addition
    let mut acc = JacobianPoint::infinity();
    for i in (0..131usize).rev() {
        if !acc.is_infinity() {
            acc = point_double(&acc);
        }
        if naf1[i] != 0 {
            let (qx, qy) = g_table_lookup(naf1[i], k1.neg);
            acc = if acc.is_infinity() {
                JacobianPoint::from_affine(qx, qy)
            } else {
                point_add_mixed(&acc, &qx, &qy)
            };
        }
        if naf2[i] != 0 {
            let (qx, qy) = phi_g_table_lookup(naf2[i], k2.neg);
            acc = if acc.is_infinity() {
                JacobianPoint::from_affine(qx, qy)
            } else {
                point_add_mixed(&acc, &qx, &qy)
            };
        }
    }
    acc
}

/// Scalar multiplication: `scalar * (px, py)` using GLV + wNAF + Shamir's trick.
fn scalar_mul_affine(scalar: &U256, px: &U256, py: &U256) -> JacobianPoint {
    scalar_mul_glv_wnaf(scalar, px, py)
}

/// Core GLV + wNAF + Shamir scalar multiplication.
///
/// Given an affine base point P = (px, py) and scalar k:
///  1. Decompose  k = k1 + k2·λ  with |k1|, |k2| ≤ 2^128.
///  2. Build precomputed tables for P and φ(P).
///  3. Compute wNAF representations of k1 and k2.
///  4. Evaluate via simultaneous double-and-add (Shamir's trick).
fn scalar_mul_glv_wnaf(scalar: &U256, px: &U256, py: &U256) -> JacobianPoint {
    // Step 1 – GLV decomposition
    let (k1, k2) = glv_decompose(scalar);

    // Step 2 – build tables
    // P1 = ±P  (sign from k1)
    let p1_base = if k1.neg {
        JacobianPoint::from_affine(*px, fp_neg(py))
    } else {
        JacobianPoint::from_affine(*px, *py)
    };
    // P2 = ±φ(P)  (sign from k2)
    let phi_p = phi_affine(px, py);
    let p2_base = if k2.neg { point_neg(&phi_p) } else { phi_p };

    let table1 = build_table(&p1_base);
    let table2 = build_table(&p2_base);

    // Step 3 – wNAF of |k1| and |k2|
    let naf1 = wnaf_129(k1.mag, k1.hi);
    let naf2 = wnaf_129(k2.mag, k2.hi);

    // Step 4 – Shamir double-and-add from MSB
    let mut acc = JacobianPoint::infinity();
    let len = 131usize;
    for i in (0..len).rev() {
        if !acc.is_infinity() {
            acc = point_double(&acc);
        }
        if naf1[i] != 0 {
            let addend = table_get(&table1, naf1[i]);
            acc = if acc.is_infinity() {
                addend
            } else {
                point_add(&acc, &addend)
            };
        }
        if naf2[i] != 0 {
            let addend = table_get(&table2, naf2[i]);
            acc = if acc.is_infinity() {
                addend
            } else {
                point_add(&acc, &addend)
            };
        }
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
// Benchmark helpers
// ─────────────────────────────────────────────────────────────────────────────
// Thin public wrappers over the private multiply kernels so that the benches/
// crate can call them without U256 being part of the public API.

/// 256×256→512 schoolbook multiply.
#[doc(hidden)]
pub fn bench_mul_wide(a: [u64; 4], b: [u64; 4]) -> [u64; 8] {
    mul_wide(&U256(a), &U256(b))
}

/// Reduce a 512-bit wide product modulo the field prime p (Solinas reduction).
#[doc(hidden)]
pub fn bench_fp_reduce_wide(w: [u64; 8]) -> [u64; 4] {
    fp_reduce_wide(&w).0
}

/// Compute a field multiplication mod n (mul_wide + unrolled reduction).
#[doc(hidden)]
pub fn bench_fp_mul(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    fp_mul(&U256(a), &U256(b)).0
}

/// Compute a scalar multiplication mod n (mul_wide + unrolled reduction).
#[doc(hidden)]
pub fn bench_fn_mul(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    fn_mul(&U256(a), &U256(b)).0
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
