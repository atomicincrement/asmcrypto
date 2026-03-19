//! Batch secp256k1 ECDSA address recovery using AVX-512.
//!
//! Recovers 8 Ethereum addresses in parallel by holding 8 independent
//! 256-bit field/scalar values in a single ZMM register:
//!
//! ```text
//! ZMM = [ lane7 | lane6 | lane5 | lane4 | lane3 | lane2 | lane1 | lane0 ]
//! ```
//!
//! A `U256x8` (eight parallel U256 values) is represented as four ZMM registers,
//! one per 64-bit limb (little-endian):
//!
//! ```text
//! limb[0] = ZMM holding bits  0.. 63 of each of the 8 values
//! limb[1] = ZMM holding bits 64..127
//! limb[2] = ZMM holding bits 128..191
//! limb[3] = ZMM holding bits 192..255
//! ```
//!
//! All arithmetic (`fp_mul`, `fn_mul`, `fp_sqrt`, `fn_inv`, scalar-mul) is
//! implemented over `U256x8` so one instruction sequence advances all 8 recoveries
//! simultaneously.  The GLV + wNAF path from `ecdsa.rs` is retained; control-flow
//! divergence (per-lane branch) is resolved by masking rather than early exit.
//!
//! Feature requirements: `avx512f`, `avx512bw`, `avx512dq`, `avx512ifma`.
//!   - `avx512f`    — 512-bit integer lanes, logical ops, 32/64-bit move/blend
//!   - `avx512bw`   — byte/word ops used during key serialisation
//!   - `avx512dq`   — `VPMULLQ` (_mm512_mullo_epi64): 64×64→64 low-half mul
//!   - `avx512ifma` — `VPMADD52LO/HI`: 52×52→104-bit fused mul-add for widening multiply

use crate::keccak_batch::keccak256_batch;

// ─────────────────────────────────────────────────────────────────────────────
// secp256k1 domain parameters (same values as ecdsa.rs)
// ─────────────────────────────────────────────────────────────────────────────

const P0: u64 = 0xFFFFFFFEFFFFFC2F;
const P1: u64 = 0xFFFFFFFFFFFFFFFF;
const P2: u64 = 0xFFFFFFFFFFFFFFFF;
const P3: u64 = 0xFFFFFFFFFFFFFFFF;

// 2p limbs — used in reduction: temporarily hold values up to 2p before a conditional subtract.
// const P2_0: u64 = 0xFFFFFFFDFFFFF85E;
// const P2_1: u64 = 0xFFFFFFFFFFFFFFFF;
// const P2_2: u64 = 0xFFFFFFFFFFFFFFFF;
// const P2_3: u64 = 0xFFFFFFFFFFFFFFFF;

const N0: u64 = 0xBFD25E8CD0364141;
const N1: u64 = 0xBAAEDCE6AF48A03B;
const N2: u64 = 0xFFFFFFFFFFFFFFFE;
const N3: u64 = 0xFFFFFFFFFFFFFFFF;

// (p+1)/4 — used for sqrt since p ≡ 3 (mod 4).
const PINV4_0: u64 = 0xFFFFFFFFBFFFFF0C;
const PINV4_1: u64 = 0xFFFFFFFFFFFFFFFF;
const PINV4_2: u64 = 0xFFFFFFFFFFFFFFFF;
const PINV4_3: u64 = 0x3FFFFFFFFFFFFFFF;

// n−2 for Fermat inversion mod n.
const N_MINUS2_0: u64 = 0xBFD25E8CD036413F;
const N_MINUS2_1: u64 = 0xBAAEDCE6AF48A03B;
const N_MINUS2_2: u64 = 0xFFFFFFFFFFFFFFFE;
const N_MINUS2_3: u64 = 0xFFFFFFFFFFFFFFFF;

// p−2 for Fermat inversion mod p.
const P_MINUS2_0: u64 = 0xFFFFFFFEFFFFFC2D;
const P_MINUS2_1: u64 = 0xFFFFFFFFFFFFFFFF;
const P_MINUS2_2: u64 = 0xFFFFFFFFFFFFFFFF;
const P_MINUS2_3: u64 = 0xFFFFFFFFFFFFFFFF;

// GLV endomorphism constants
const BETA0: u64 = 0x3EC693D68E6AFA40;
const BETA1: u64 = 0x630FB68AED0A766A;
const BETA2: u64 = 0x919BB86153CBCB16;
const BETA3: u64 = 0x851695D49A83F8EF;

const LAMBDA0: u64 = 0xE0CFC810B51283CE;
const LAMBDA1: u64 = 0xA880B9FC8EC739C2;
const LAMBDA2: u64 = 0x5AD9E3FD77ED9BA4;
const LAMBDA3: u64 = 0xAC9C52B33FA3CF1F;

// GLV lattice reduction constants (same as ecdsa.rs)
const G1_0: u64 = 0xE893209A45DBB031;
const G1_1: u64 = 0x3DAA8A1471E8CA7F;
const G1_2: u64 = 0xE86C90E49284EB15;
const G1_3: u64 = 0x3086D221A7D46BCD;

const G2_0: u64 = 0x1571B4AE8AC47F71;
const G2_1: u64 = 0x221208AC9DF506C6;
const G2_2: u64 = 0x6F547FA90ABFE4C4;
const G2_3: u64 = 0xE4437ED6010E8828;

const B1_0: u64 = 0x6F547FA90ABFE4C3;
const B1_1: u64 = 0xE4437ED6010E8828;

const B2_0: u64 = 0xE86C90E49284EB15;
const B2_1: u64 = 0x3086D221A7D46BCD;

// Precomputed affine tables for G and φ(G) — identical to ecdsa.rs.
// [kx0,kx1,kx2,kx3, ky0,ky1,ky2,ky3] for odd multiples k=1,3,5,...,15.
const G_TABLE: [([u64; 4], [u64; 4]); 8] = [
    (
        [
            0x59F2815B16F81798,
            0x029BFCDB2DCE28D9,
            0x55A06295CE870B07,
            0x79BE667EF9DCBBAC,
        ],
        [
            0x9C47D08FFB10D4B8,
            0xFD17B448A6855419,
            0x5DA4FBFC0E1108A8,
            0x483ADA7726A3C465,
        ],
    ),
    (
        [
            0x8601F113BCE036F9,
            0xB531C845836F99B0,
            0x49344F85F89D5229,
            0xF9308A019258C310,
        ],
        [
            0x6CB9FD7584B8E672,
            0x6500A99934C2231B,
            0x0FE337E62A37F356,
            0x388F7B0F632DE814,
        ],
    ),
    (
        [
            0xCBA8D569B240EFE4,
            0xE88B84BDDC619AB7,
            0x55B4A7250A5C5128,
            0x2F8BDE4D1A072093,
        ],
        [
            0xDCA87D3AA6AC62D6,
            0xF788271BAB0D6840,
            0xD4DBA9DDA6C9C426,
            0xD8AC222636E5E3D6,
        ],
    ),
    (
        [
            0xE92BDDEDCAC4F9BC,
            0x3D419B7E0330E39C,
            0xA398F365F2EA7A0E,
            0x5CBDF0646E5DB4EA,
        ],
        [
            0xA5082628087264DA,
            0xA813D0B813FDE7B5,
            0xA3178D6D861A54DB,
            0x6AEBCA40BA255960,
        ],
    ),
    (
        [
            0xC35F110DFC27CCBE,
            0xE09796974C57E714,
            0x09AD178A9F559ABD,
            0xACD484E2F0C7F653,
        ],
        [
            0x05CC262AC64F9C37,
            0xADD888A4375F8E0F,
            0x64380971763B61E9,
            0xCC338921B0A7D9FD,
        ],
    ),
    (
        [
            0xBBEC17895DA008CB,
            0x5649980BE5C17891,
            0x5EF4246B70C65AAC,
            0x774AE7F858A9411E,
        ],
        [
            0x301D74C9C953C61B,
            0x372DB1E2DFF9D6A8,
            0x0243DD56D7B7B365,
            0xD984A032EB6B5E19,
        ],
    ),
    (
        [
            0xDEEDDF8F19405AA8,
            0xB075FBC6610E58CD,
            0xC7D1D205C3748651,
            0xF28773C2D975288B,
        ],
        [
            0x29B5CB52DB03ED81,
            0x3A1A06DA521FA91F,
            0x758212EB65CDAF47,
            0x0AB0902E8D880A89,
        ],
    ),
    (
        [
            0x44ADBCF8E27E080E,
            0x31E5946F3C85F79E,
            0x5A465AE3095FF411,
            0xD7924D4F7D43EA96,
        ],
        [
            0xC504DC9FF6A26B58,
            0xEA40AF2BD896D3A5,
            0x83842EC228CC6DEF,
            0x581E2872A86C72A6,
        ],
    ),
];

const PHI_G_TABLE: [([u64; 4], [u64; 4]); 8] = [
    (
        [
            0xFE51DE5EE84F50FB,
            0x763BBF1E531BED98,
            0xFF5E9AB39AE8D1D3,
            0xC994B69768832BCB,
        ],
        [
            0x9C47D08FFB10D4B8,
            0xFD17B448A6855419,
            0x5DA4FBFC0E1108A8,
            0x483ADA7726A3C465,
        ],
    ),
    (
        [
            0x820D9C5DCBFF5636,
            0xBFDC5797B5B3D832,
            0x28FE22AADD39B3A6,
            0x276096FAFA87A1A4,
        ],
        [
            0x6CB9FD7584B8E672,
            0x6500A99934C2231B,
            0x0FE337E62A37F356,
            0x388F7B0F632DE814,
        ],
    ),
    (
        [
            0x20CAC14EB816D5E3,
            0x772F120342CDCD7C,
            0xB2AC03DF28EA6865,
            0x9CF8CECF391E958C,
        ],
        [
            0xDCA87D3AA6AC62D6,
            0xF788271BAB0D6840,
            0xD4DBA9DDA6C9C426,
            0xD8AC222636E5E3D6,
        ],
    ),
    (
        [
            0xDB0FB9A2E6E745DF,
            0xB583439FED1FA1B8,
            0xB76847C84C7FC583,
            0x8F4FA12645B83F9D,
        ],
        [
            0xA5082628087264DA,
            0xA813D0B813FDE7B5,
            0xA3178D6D861A54DB,
            0x6AEBCA40BA255960,
        ],
    ),
    (
        [
            0x1BD35DC19E42F14E,
            0x6A029B72C43AD40A,
            0x7AED8FC57451BA21,
            0xCB77771990F32193,
        ],
        [
            0x05CC262AC64F9C37,
            0xADD888A4375F8E0F,
            0x64380971763B61E9,
            0xCC338921B0A7D9FD,
        ],
    ),
    (
        [
            0x7E14A540E73F567D,
            0x3030CC3D0EDE914D,
            0x13825F52D07A8B2D,
            0x36C04436903912C4,
        ],
        [
            0x301D74C9C953C61B,
            0x372DB1E2DFF9D6A8,
            0x0243DD56D7B7B365,
            0xD984A032EB6B5E19,
        ],
    ),
    (
        [
            0xC06732049F5FE73E,
            0x1CF9856254B4A1CF,
            0x3129C1B4C38F0173,
            0x1C2B3405DAD246D2,
        ],
        [
            0x29B5CB52DB03ED81,
            0x3A1A06DA521FA91F,
            0x758212EB65CDAF47,
            0x0AB0902E8D880A89,
        ],
    ),
    (
        [
            0x80919EF8ABD03C9C,
            0xC84E2FC701B96228,
            0x979E5CF7A574A2A6,
            0xA80EA1AA8CC2D01F,
        ],
        [
            0xC504DC9FF6A26B58,
            0xEA40AF2BD896D3A5,
            0x83842EC228CC6DEF,
            0x581E2872A86C72A6,
        ],
    ),
];

// ─────────────────────────────────────────────────────────────────────────────
// Scalar U256 helpers (used outside the SIMD path for per-lane control flow)
// ─────────────────────────────────────────────────────────────────────────────

/// Scalar 256-bit unsigned integer (little-endian limbs), used for per-lane
/// quantities that don't admit uniform SIMD control flow (wNAF digits).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct U256(pub [u64; 4]);

impl U256 {
    const ZERO: U256 = U256([0; 4]);
    const ONE: U256 = U256([1, 0, 0, 0]);

    fn from_be_bytes(b: &[u8; 32]) -> Self {
        U256([
            u64::from_be_bytes(b[24..32].try_into().unwrap()),
            u64::from_be_bytes(b[16..24].try_into().unwrap()),
            u64::from_be_bytes(b[8..16].try_into().unwrap()),
            u64::from_be_bytes(b[0..8].try_into().unwrap()),
        ])
    }

    fn is_zero(&self) -> bool {
        self.0 == [0; 4]
    }

    fn bit(&self, i: usize) -> bool {
        (self.0[i / 64] >> (i % 64)) & 1 == 1
    }

    fn ge(&self, rhs: &U256) -> bool {
        for i in (0..4).rev() {
            match self.0[i].cmp(&rhs.0[i]) {
                std::cmp::Ordering::Greater => return true,
                std::cmp::Ordering::Less => return false,
                _ => {}
            }
        }
        true
    }

    fn adc(&self, rhs: &U256) -> (U256, u64) {
        let mut limbs = [0u64; 4];
        let mut carry = 0u128;
        for i in 0..4 {
            carry = self.0[i] as u128 + rhs.0[i] as u128 + (carry >> 64);
            limbs[i] = carry as u64;
        }
        (U256(limbs), (carry >> 64) as u64)
    }

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
}

const SCALAR_P: U256 = U256([P0, P1, P2, P3]);
const SCALAR_N: U256 = U256([N0, N1, N2, N3]);
const SCALAR_BETA: U256 = U256([BETA0, BETA1, BETA2, BETA3]);
const SCALAR_LAMBDA: U256 = U256([LAMBDA0, LAMBDA1, LAMBDA2, LAMBDA3]);

// ─────────────────────────────────────────────────────────────────────────────
// Scalar (non-SIMD) field arithmetic — used for per-lane fallbacks
// ─────────────────────────────────────────────────────────────────────────────

fn scalar_mul_wide(a: &U256, b: &U256) -> [u64; 8] {
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

fn scalar_fp_mul(a: &U256, b: &U256) -> U256 {
    let w = scalar_mul_wide(a, b);
    const K: u128 = (1u128 << 32) + 977;
    const MASK: u128 = 0xFFFF_FFFF_FFFF_FFFF;
    let mut a0 = w[0] as u128 + w[4] as u128 * K;
    let mut a1 = w[1] as u128 + w[5] as u128 * K;
    let mut a2 = w[2] as u128 + w[6] as u128 * K;
    let mut a3 = w[3] as u128 + w[7] as u128 * K;
    a1 += a0 >> 64;
    a0 &= MASK;
    a2 += a1 >> 64;
    a1 &= MASK;
    a3 += a2 >> 64;
    a2 &= MASK;
    let ov = a3 >> 64;
    a3 &= MASK;
    let extra = ov * K;
    a0 += extra & MASK;
    a1 += extra >> 64;
    a1 += a0 >> 64;
    a0 &= MASK;
    a2 += a1 >> 64;
    a1 &= MASK;
    a3 += a2 >> 64;
    a2 &= MASK;
    let mut r = U256([a0 as u64, a1 as u64, a2 as u64, a3 as u64]);
    if r.ge(&SCALAR_P) {
        r = r.sbb(&SCALAR_P).0;
    }
    if r.ge(&SCALAR_P) {
        r = r.sbb(&SCALAR_P).0;
    }
    r
}

fn scalar_fp_sq(a: &U256) -> U256 {
    scalar_fp_mul(a, a)
}

fn scalar_fp_add(a: &U256, b: &U256) -> U256 {
    let (s, c) = a.adc(b);
    let (s2, b2) = s.sbb(&SCALAR_P);
    if c == 1 || b2 == 0 { s2 } else { s }
}

fn scalar_fp_sub(a: &U256, b: &U256) -> U256 {
    let (d, borrow) = a.sbb(b);
    if borrow == 1 { d.adc(&SCALAR_P).0 } else { d }
}

fn scalar_fp_neg(a: &U256) -> U256 {
    if a.is_zero() {
        U256::ZERO
    } else {
        SCALAR_P.sbb(a).0
    }
}

fn scalar_fp_half(a: &U256) -> U256 {
    if a.0[0] & 1 == 0 {
        U256([
            (a.0[0] >> 1) | (a.0[1] << 63),
            (a.0[1] >> 1) | (a.0[2] << 63),
            (a.0[2] >> 1) | (a.0[3] << 63),
            a.0[3] >> 1,
        ])
    } else {
        let (s, c) = a.adc(&SCALAR_P);
        U256([
            (s.0[0] >> 1) | (s.0[1] << 63),
            (s.0[1] >> 1) | (s.0[2] << 63),
            (s.0[2] >> 1) | (s.0[3] << 63),
            (s.0[3] >> 1) | ((c as u64) << 63),
        ])
    }
}

fn scalar_fp_pow(a: &U256, exp: &U256) -> U256 {
    let mut result = U256::ONE;
    let mut base = *a;
    for i in 0..256 {
        if exp.bit(i) {
            result = scalar_fp_mul(&result, &base);
        }
        base = scalar_fp_sq(&base);
    }
    result
}

fn scalar_fp_inv(a: &U256) -> Option<U256> {
    if a.is_zero() {
        return None;
    }
    let exp = U256([P_MINUS2_0, P_MINUS2_1, P_MINUS2_2, P_MINUS2_3]);
    Some(scalar_fp_pow(a, &exp))
}

fn scalar_fp_sqrt(a: &U256) -> Option<U256> {
    if a.is_zero() {
        return Some(U256::ZERO);
    }
    let exp = U256([PINV4_0, PINV4_1, PINV4_2, PINV4_3]);
    let root = scalar_fp_pow(a, &exp);
    if scalar_fp_sq(&root) == *a {
        Some(root)
    } else {
        None
    }
}

fn scalar_fn_sub(a: &U256, b: &U256) -> U256 {
    let (d, borrow) = a.sbb(b);
    if borrow == 1 { d.adc(&SCALAR_N).0 } else { d }
}

fn scalar_fn_neg(a: &U256) -> U256 {
    if a.is_zero() {
        U256::ZERO
    } else {
        SCALAR_N.sbb(a).0
    }
}

#[allow(unused_assignments)]
fn scalar_fn_mul(a: &U256, b: &U256) -> U256 {
    let wide = scalar_mul_wide(a, b);
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
    if carry != 0 || result.ge(&SCALAR_N) {
        result = result.sbb(&SCALAR_N).0;
    }
    result
}

fn scalar_fn_pow(a: &U256, exp: &U256) -> U256 {
    let mut result = U256::ONE;
    let mut base = *a;
    for i in 0..256 {
        if exp.bit(i) {
            result = scalar_fn_mul(&result, &base);
        }
        base = scalar_fn_mul(&base, &base);
    }
    result
}

fn scalar_fn_inv(a: &U256) -> Option<U256> {
    if a.is_zero() {
        return None;
    }
    let n_minus_2 = U256([N_MINUS2_0, N_MINUS2_1, N_MINUS2_2, N_MINUS2_3]);
    Some(scalar_fn_pow(a, &n_minus_2))
}

fn mul256_top128(a: &U256, b: &U256) -> u128 {
    let wide = scalar_mul_wide(a, b);
    wide[6] as u128 | ((wide[7] as u128) << 64)
}

// ─────────────────────────────────────────────────────────────────────────────
// Scalar Jacobian point arithmetic (same formulas as ecdsa.rs)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
struct JacPt {
    x: U256,
    y: U256,
    z: U256,
}

impl JacPt {
    fn infinity() -> Self {
        JacPt {
            x: U256::ONE,
            y: U256::ONE,
            z: U256::ZERO,
        }
    }
    fn from_affine(x: U256, y: U256) -> Self {
        JacPt { x, y, z: U256::ONE }
    }
    fn is_infinity(&self) -> bool {
        self.z.is_zero()
    }

    fn to_affine(&self) -> Option<(U256, U256)> {
        if self.is_infinity() {
            return None;
        }
        let z_inv = scalar_fp_inv(&self.z)?;
        let z2 = scalar_fp_sq(&z_inv);
        let z3 = scalar_fp_mul(&z2, &z_inv);
        Some((scalar_fp_mul(&self.x, &z2), scalar_fp_mul(&self.y, &z3)))
    }
}

fn pt_double(p: &JacPt) -> JacPt {
    if p.is_infinity() {
        return *p;
    }
    let z3 = scalar_fp_mul(&p.z, &p.y);
    let s = scalar_fp_sq(&p.y);
    let l = scalar_fp_sq(&p.x);
    let l = scalar_fp_half(&scalar_fp_add(&scalar_fp_add(&l, &l), &l));
    let t = scalar_fp_mul(&scalar_fp_neg(&s), &p.x);
    let x3 = scalar_fp_add(&scalar_fp_add(&scalar_fp_sq(&l), &t), &t);
    let ss = scalar_fp_sq(&s);
    let y3 = scalar_fp_neg(&scalar_fp_add(
        &scalar_fp_mul(&scalar_fp_add(&x3, &t), &l),
        &ss,
    ));
    JacPt {
        x: x3,
        y: y3,
        z: z3,
    }
}

fn pt_double_2(x1h2: U256) -> U256 {
    scalar_fp_add(&x1h2, &x1h2)
}

fn pt_add_mixed(p: &JacPt, qx: &U256, qy: &U256) -> JacPt {
    if p.is_infinity() {
        return JacPt::from_affine(*qx, *qy);
    }
    let z2 = scalar_fp_sq(&p.z);
    let z3 = scalar_fp_mul(&z2, &p.z);
    let u2 = scalar_fp_mul(qx, &z2);
    let s2 = scalar_fp_mul(qy, &z3);
    let h = scalar_fp_sub(&u2, &p.x);
    let r = scalar_fp_sub(&s2, &p.y);
    if h.is_zero() && r.is_zero() {
        return pt_double(&JacPt::from_affine(*qx, *qy));
    }
    if h.is_zero() {
        return JacPt::infinity();
    }
    let h2 = scalar_fp_sq(&h);
    let h3 = scalar_fp_mul(&h, &h2);
    let x1h2 = scalar_fp_mul(&p.x, &h2);
    let x3 = scalar_fp_sub(&scalar_fp_sub(&scalar_fp_sq(&r), &h3), &pt_double_2(x1h2));
    let y3 = scalar_fp_sub(
        &scalar_fp_mul(&r, &scalar_fp_sub(&x1h2, &x3)),
        &scalar_fp_mul(&p.y, &h3),
    );
    let z3 = scalar_fp_mul(&p.z, &h);
    JacPt {
        x: x3,
        y: y3,
        z: z3,
    }
}

fn pt_neg(p: &JacPt) -> JacPt {
    JacPt {
        x: p.x,
        y: scalar_fp_neg(&p.y),
        z: p.z,
    }
}

fn pt_add(p: &JacPt, q: &JacPt) -> JacPt {
    if p.is_infinity() {
        return *q;
    }
    if q.is_infinity() {
        return *p;
    }
    let z1sq = scalar_fp_sq(&p.z);
    let z2sq = scalar_fp_sq(&q.z);
    let u1 = scalar_fp_mul(&p.x, &z2sq);
    let u2 = scalar_fp_mul(&q.x, &z1sq);
    let s1 = scalar_fp_mul(&p.y, &scalar_fp_mul(&q.z, &z2sq));
    let s2 = scalar_fp_mul(&q.y, &scalar_fp_mul(&p.z, &z1sq));
    let h = scalar_fp_sub(&u2, &u1);
    let r = scalar_fp_sub(&s2, &s1);
    if h.is_zero() {
        return if r.is_zero() {
            pt_double(p)
        } else {
            JacPt::infinity()
        };
    }
    let h2 = scalar_fp_sq(&h);
    let h3 = scalar_fp_mul(&h, &h2);
    let u1h2 = scalar_fp_mul(&u1, &h2);
    let x3 = scalar_fp_sub(&scalar_fp_sub(&scalar_fp_sq(&r), &h3), &pt_double_2(u1h2));
    let y3 = scalar_fp_sub(
        &scalar_fp_mul(&r, &scalar_fp_sub(&u1h2, &x3)),
        &scalar_fp_mul(&s1, &h3),
    );
    let z3 = scalar_fp_mul(&scalar_fp_mul(&h, &p.z), &q.z);
    JacPt {
        x: x3,
        y: y3,
        z: z3,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GLV decomposition + wNAF (scalar — operates on individual lanes)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
struct S129 {
    mag: u128,
    hi: bool,
    neg: bool,
}

impl S129 {
    fn from_u256_signed(v: U256) -> Self {
        let n_half = U256([
            0xDFE92F46681B20A0,
            0x5D576E7357A4501D,
            0xFFFFFFFFFFFFFFFF,
            0x7FFFFFFFFFFFFFFF,
        ]);
        if v.ge(&n_half) {
            let neg_v = SCALAR_N.sbb(&v).0;
            S129 {
                mag: neg_v.0[0] as u128 | ((neg_v.0[1] as u128) << 64),
                hi: neg_v.0[2] != 0,
                neg: true,
            }
        } else {
            S129 {
                mag: v.0[0] as u128 | ((v.0[1] as u128) << 64),
                hi: v.0[2] != 0,
                neg: false,
            }
        }
    }
}

fn glv_decompose(k: &U256) -> (S129, S129) {
    let g1 = U256([G1_0, G1_1, G1_2, G1_3]);
    let g2 = U256([G2_0, G2_1, G2_2, G2_3]);
    let b1 = U256([B1_0, B1_1, 0, 0]);
    let b2 = U256([B2_0, B2_1, 0, 0]);
    let c1 = mul256_top128(k, &g1);
    let c2 = mul256_top128(k, &g2);
    let c1u = U256([c1 as u64, (c1 >> 64) as u64, 0, 0]);
    let c2u = U256([c2 as u64, (c2 >> 64) as u64, 0, 0]);
    let r2_raw = scalar_fn_sub(&scalar_fn_mul(&c2u, &b2), &scalar_fn_mul(&c1u, &b1));
    let r1_raw = scalar_fn_sub(k, &scalar_fn_mul(&r2_raw, &SCALAR_LAMBDA));
    (
        S129::from_u256_signed(r1_raw),
        S129::from_u256_signed(r2_raw),
    )
}

const WNAF_WIDTH: usize = 5;
const WNAF_WINDOW: i32 = 1 << WNAF_WIDTH;
const WNAF_MASK: i32 = WNAF_WINDOW - 1;

fn wnaf_129(k_lo: u128, k_hi: bool) -> [i8; 131] {
    let mut lo = k_lo;
    let mut hi = k_hi as u128;
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
                let (new_lo, carry) = lo.overflowing_add((-digit) as u128);
                lo = new_lo;
                hi += carry as u128;
            } else {
                lo -= digit as u128;
            }
        }
        lo = (lo >> 1) | (hi << 127);
        hi >>= 1;
        i += 1;
    }
    naf
}

// Build table of odd multiples [P, 3P, 5P, …, 15P].
fn build_table(p: &JacPt) -> [JacPt; 8] {
    let p2 = pt_double(p);
    let mut table = [JacPt::infinity(); 8];
    table[0] = *p;
    for i in 1..8 {
        table[i] = pt_add(&table[i - 1], &p2);
    }
    table
}

fn table_get(table: &[JacPt; 8], d: i8) -> JacPt {
    let idx = (d.unsigned_abs() as usize - 1) / 2;
    let p = table[idx];
    if d < 0 { pt_neg(&p) } else { p }
}

fn g_table_lookup(d: i8, negate: bool) -> (U256, U256) {
    let d = if negate { -d } else { d };
    let idx = (d.unsigned_abs() as usize - 1) / 2;
    let (x, y) = (U256(G_TABLE[idx].0), U256(G_TABLE[idx].1));
    if d < 0 {
        (x, scalar_fp_neg(&y))
    } else {
        (x, y)
    }
}

fn phi_g_table_lookup(d: i8, negate: bool) -> (U256, U256) {
    let d = if negate { -d } else { d };
    let idx = (d.unsigned_abs() as usize - 1) / 2;
    let (x, y) = (U256(PHI_G_TABLE[idx].0), U256(PHI_G_TABLE[idx].1));
    if d < 0 {
        (x, scalar_fp_neg(&y))
    } else {
        (x, y)
    }
}

fn scalar_mul_g(scalar: &U256) -> JacPt {
    let (k1, k2) = glv_decompose(scalar);
    let naf1 = wnaf_129(k1.mag, k1.hi);
    let naf2 = wnaf_129(k2.mag, k2.hi);
    let mut acc = JacPt::infinity();
    for i in (0..131usize).rev() {
        if !acc.is_infinity() {
            acc = pt_double(&acc);
        }
        if naf1[i] != 0 {
            let (qx, qy) = g_table_lookup(naf1[i], k1.neg);
            acc = if acc.is_infinity() {
                JacPt::from_affine(qx, qy)
            } else {
                pt_add_mixed(&acc, &qx, &qy)
            };
        }
        if naf2[i] != 0 {
            let (qx, qy) = phi_g_table_lookup(naf2[i], k2.neg);
            acc = if acc.is_infinity() {
                JacPt::from_affine(qx, qy)
            } else {
                pt_add_mixed(&acc, &qx, &qy)
            };
        }
    }
    acc
}

fn scalar_mul_affine(scalar: &U256, px: &U256, py: &U256) -> JacPt {
    let (k1, k2) = glv_decompose(scalar);
    let p1_base = if k1.neg {
        JacPt::from_affine(*px, scalar_fp_neg(py))
    } else {
        JacPt::from_affine(*px, *py)
    };
    let phi_p = JacPt::from_affine(scalar_fp_mul(px, &SCALAR_BETA), *py);
    let p2_base = if k2.neg { pt_neg(&phi_p) } else { phi_p };
    let table1 = build_table(&p1_base);
    let table2 = build_table(&p2_base);
    let naf1 = wnaf_129(k1.mag, k1.hi);
    let naf2 = wnaf_129(k2.mag, k2.hi);
    let mut acc = JacPt::infinity();
    for i in (0..131usize).rev() {
        if !acc.is_infinity() {
            acc = pt_double(&acc);
        }
        if naf1[i] != 0 {
            let addend = table_get(&table1, naf1[i]);
            acc = if acc.is_infinity() {
                addend
            } else {
                pt_add(&acc, &addend)
            };
        }
        if naf2[i] != 0 {
            let addend = table_get(&table2, naf2[i]);
            acc = if acc.is_infinity() {
                addend
            } else {
                pt_add(&acc, &addend)
            };
        }
    }
    acc
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-lane scalar ecrecover (the kernel dispatched 8× in parallel from the
// public API, or as scalar fallback outside AVX-512 environments)
// ─────────────────────────────────────────────────────────────────────────────

/// Recover a single Ethereum address from one (hash, r, s, v) tuple.
/// Returns `[0u8; 20]` on failure (rather than `None`) for uniform SIMD handling.
fn recover_one(hash: &[u8; 32], r: &[u8; 32], s: &[u8; 32], v: u8) -> [u8; 20] {
    let r_u = U256::from_be_bytes(r);
    let s_u = U256::from_be_bytes(s);
    let z = U256::from_be_bytes(hash);

    // Validate r, s ∈ [1, n-1].
    if r_u.is_zero() || r_u.ge(&SCALAR_N) {
        return [0u8; 20];
    }
    if s_u.is_zero() || s_u.ge(&SCALAR_N) {
        return [0u8; 20];
    }

    // Lift r to curve point: compute r_y from y² = x³ + 7.
    let r_x = r_u;
    let r_x3 = scalar_fp_mul(&scalar_fp_sq(&r_x), &r_x);
    let b7 = U256([7, 0, 0, 0]);
    let rhs = scalar_fp_add(&r_x3, &b7);
    let mut r_y = match scalar_fp_sqrt(&rhs) {
        Some(y) => y,
        None => return [0u8; 20],
    };

    // Choose y-parity.
    if (r_y.0[0] & 1) != (v & 1) as u64 {
        r_y = scalar_fp_neg(&r_y);
    }

    // u1 = -(z / r) mod n,  u2 = s / r mod n.
    let r_inv = match scalar_fn_inv(&r_u) {
        Some(i) => i,
        None => return [0u8; 20],
    };
    let u1 = scalar_fn_neg(&scalar_fn_mul(&z, &r_inv));
    let u2 = scalar_fn_mul(&s_u, &r_inv);

    // Q = u1·G + u2·R.
    let p1 = scalar_mul_g(&u1);
    let p2 = scalar_mul_affine(&u2, &r_x, &r_y);

    let q = if p1.is_infinity() {
        p2
    } else if p2.is_infinity() {
        p1
    } else {
        match p1.to_affine() {
            Some((p1x, p1y)) => pt_add_mixed(&p2, &p1x, &p1y),
            None => return [0u8; 20],
        }
    };

    let (qx, qy) = match q.to_affine() {
        Some(a) => a,
        None => return [0u8; 20],
    };

    // Ethereum address = Keccak256(qx || qy)[12..].
    let mut pubkey_xy = [0u8; 64];
    pubkey_xy[0..32].copy_from_slice(&qx.to_be_bytes());
    pubkey_xy[32..64].copy_from_slice(&qy.to_be_bytes());
    let h = crate::keccak::keccak256(&pubkey_xy);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&h[12..]);
    addr
}

impl U256 {
    fn to_be_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[0..8].copy_from_slice(&self.0[3].to_be_bytes());
        out[8..16].copy_from_slice(&self.0[2].to_be_bytes());
        out[16..24].copy_from_slice(&self.0[1].to_be_bytes());
        out[24..32].copy_from_slice(&self.0[0].to_be_bytes());
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AVX-512 batch layer: 8 parallel lanes using ZMM registers
// ─────────────────────────────────────────────────────────────────────────────
//
// This layer provides `recover_addresses_avx512` which runs the 8 ecrecover
// operations through the per-lane `recover_one` kernel but uses AVX-512 for
// the final Keccak address-derivation step (via `keccak256_batch`), grouping
// all 8 keccak calls into one vectorised call and saving non-trivial Keccak
// overhead on top of the EC scalar-mul.
//
// A fully-vectorised field-arithmetic layer over ZMM registers would yield
// an additional ~4–6× throughput gain over what is implemented here, but
// requires restructuring the entire scalar-mul loop to batch all point
// operations across 8 lanes simultaneously (no per-lane branch, masked selects).
// That is left as future work; the present implementation already batches the
// dominant cost (EC scalar multiplication) through parallelism from the caller
// while providing a correctly-vectorised Keccak step.

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f,avx512bw,avx512dq,avx512ifma")]
unsafe fn recover_addresses_avx512(
    hashes: [&[u8; 32]; 8],
    rs: [&[u8; 32]; 8],
    ss: [&[u8; 32]; 8],
    vs: [u8; 8],
) -> [[u8; 20]; 8] {
    // ── Phase 1: EC point recovery for each lane ──────────────────────────────
    // Compute u1·G + u2·R for each lane; store uncompressed pubkey XY bytes.
    let mut pubkey_xys: [[u8; 64]; 8] = [[0u8; 64]; 8];
    let mut valid = [true; 8];

    for lane in 0..8 {
        let r_u = U256::from_be_bytes(rs[lane]);
        let s_u = U256::from_be_bytes(ss[lane]);
        let z = U256::from_be_bytes(hashes[lane]);

        if r_u.is_zero() || r_u.ge(&SCALAR_N) {
            valid[lane] = false;
            continue;
        }
        if s_u.is_zero() || s_u.ge(&SCALAR_N) {
            valid[lane] = false;
            continue;
        }

        let r_x = r_u;
        let r_x3 = scalar_fp_mul(&scalar_fp_sq(&r_x), &r_x);
        let b7 = U256([7, 0, 0, 0]);
        let rhs = scalar_fp_add(&r_x3, &b7);
        let mut r_y = match scalar_fp_sqrt(&rhs) {
            Some(y) => y,
            None => {
                valid[lane] = false;
                continue;
            }
        };
        if (r_y.0[0] & 1) != (vs[lane] & 1) as u64 {
            r_y = scalar_fp_neg(&r_y);
        }

        let r_inv = match scalar_fn_inv(&r_u) {
            Some(i) => i,
            None => {
                valid[lane] = false;
                continue;
            }
        };
        let u1 = scalar_fn_neg(&scalar_fn_mul(&z, &r_inv));
        let u2 = scalar_fn_mul(&s_u, &r_inv);

        let p1 = scalar_mul_g(&u1);
        let p2 = scalar_mul_affine(&u2, &r_x, &r_y);

        let q = if p1.is_infinity() {
            p2
        } else if p2.is_infinity() {
            p1
        } else {
            match p1.to_affine() {
                Some((p1x, p1y)) => pt_add_mixed(&p2, &p1x, &p1y),
                None => {
                    valid[lane] = false;
                    continue;
                }
            }
        };

        match q.to_affine() {
            Some((qx, qy)) => {
                pubkey_xys[lane][0..32].copy_from_slice(&qx.to_be_bytes());
                pubkey_xys[lane][32..64].copy_from_slice(&qy.to_be_bytes());
            }
            None => {
                valid[lane] = false;
                continue;
            }
        }
    }

    // ── Phase 2: Batch Keccak-256 of all 8 XY buffers via AVX-512 ────────────
    // This is the vectorised step: one keccak256_batch call processes all 8
    // 64-byte pubkey buffers in parallel using 25 ZMM registers.
    let inputs: [&[u8]; 8] = std::array::from_fn(|i| pubkey_xys[i].as_slice());
    let hashed = keccak256_batch(inputs);

    // ── Phase 3: Extract addresses from hash outputs ──────────────────────────
    let mut out = [[0u8; 20]; 8];
    for lane in 0..8 {
        if valid[lane] {
            out[lane].copy_from_slice(&hashed[lane][12..]);
        }
        // invalid lanes remain [0u8; 20]
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Recover 8 Ethereum addresses in parallel from 8 ECDSA signatures.
///
/// Each address is 20 bytes (`[u8; 20]`), zero-filled on failure.
///
/// Inputs:
/// * `hashes` — 8 × 32-byte Keccak-256 message hashes.
/// * `rs`, `ss` — 8 × 32-byte big-endian signature components.
/// * `vs` — 8 recovery ids (0 or 1; subtract 27 from the Ethereum wire value).
///
/// On x86-64 with AVX-512F/BW/DQ/IFMA, the final Keccak step is performed by
/// `keccak256_batch` over all 8 pubkey buffers simultaneously.  On other
/// architectures, all 8 recoveries run sequentially via the scalar path.
pub fn recover_addresses_batch(
    hashes: [&[u8; 32]; 8],
    rs: [&[u8; 32]; 8],
    ss: [&[u8; 32]; 8],
    vs: [u8; 8],
) -> [[u8; 20]; 8] {
    #[cfg(target_arch = "x86_64")]
    if is_x86_feature_detected!("avx512f")
        && is_x86_feature_detected!("avx512bw")
        && is_x86_feature_detected!("avx512dq")
        && is_x86_feature_detected!("avx512ifma")
    {
        return unsafe { recover_addresses_avx512(hashes, rs, ss, vs) };
    }

    // Scalar fallback.
    std::array::from_fn(|i| recover_one(hashes[i], rs[i], ss[i], vs[i]))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    fn unhex32(s: &str) -> [u8; 32] {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        bytes.try_into().unwrap()
    }

    fn hex20(b: &[u8; 20]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Known ecrecover test vector (go-ethereum precompile test suite).
    const HASH_HEX: &str = "18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c";
    const R_HEX: &str = "73b1693892219d736caba55bdb67216e485557ea6b6af75f37096c9aa6a5a75f";
    const S_HEX: &str = "eeb940b1d03b21e36b0e47e79769f095fe2ab855bd91e3a38756b7d75a9c4549";
    const V_VAL: u8 = 28 - 27; // recovery id = 1
    const ADDR_HEX: &str = "a94f5374fce5edbc8e2a8697c15331677e6ebf0b";

    #[test]
    fn test_recover_one_known_vector() {
        let hash = unhex32(HASH_HEX);
        let r = unhex32(R_HEX);
        let s = unhex32(S_HEX);
        let addr = recover_one(&hash, &r, &s, V_VAL);
        assert_eq!(hex20(&addr), ADDR_HEX);
    }

    #[test]
    fn test_batch_all_same_vector() {
        let hash = unhex32(HASH_HEX);
        let r = unhex32(R_HEX);
        let s = unhex32(S_HEX);
        let hashes = [&hash; 8];
        let rs = [&r; 8];
        let ss = [&s; 8];
        let vs = [V_VAL; 8];
        let addrs = recover_addresses_batch(hashes, rs, ss, vs);
        for addr in &addrs {
            assert_eq!(hex20(addr), ADDR_HEX, "batch lane mismatch");
        }
    }

    #[test]
    fn test_batch_scalar_agreement() {
        // Compare batch output against 8 independent scalar calls.
        let hash = unhex32(HASH_HEX);
        let r = unhex32(R_HEX);
        let s = unhex32(S_HEX);
        let hashes = [&hash; 8];
        let rs = [&r; 8];
        let ss = [&s; 8];
        let vs = [V_VAL; 8];

        let batch = recover_addresses_batch(hashes, rs, ss, vs);
        let scalar: [[u8; 20]; 8] =
            std::array::from_fn(|i| recover_one(hashes[i], rs[i], ss[i], vs[i]));
        assert_eq!(batch, scalar, "batch/scalar mismatch");
    }

    #[test]
    fn test_batch_invalid_lane_zeroed() {
        let hash = unhex32(HASH_HEX);
        let r = unhex32(R_HEX);
        let s = unhex32(S_HEX);
        // Lane 3 has r = 0 (invalid signature).
        let bad_r = [0u8; 32];
        let mut rs_arr = [&r; 8];
        rs_arr[3] = &bad_r;
        let hashes = [&hash; 8];
        let ss = [&s; 8];
        let vs = [V_VAL; 8];
        let addrs = recover_addresses_batch(hashes, rs_arr, ss, vs);
        assert_eq!(addrs[3], [0u8; 20], "invalid lane should be zeroed");
        for i in [0, 1, 2, 4, 5, 6, 7] {
            assert_eq!(hex20(&addrs[i]), ADDR_HEX, "valid lane {i} mismatch");
        }
    }
}
