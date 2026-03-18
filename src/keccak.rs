//! Keccak-256 — the Ethereum variant of the Keccak sponge construction.
//!
//! Parameters:
//! * Rate       r = 1088 bits = 136 bytes
//! * Capacity   c = 512  bits =  64 bytes
//! * Output         256  bits =  32 bytes
//! * Padding delimiter byte = `0x01`  (Ethereum/original Keccak, **not** NIST SHA-3 `0x06`)

// ─────────────────────────────────────────────────────────────────────────────
// Keccak-f[1600] constants
// ─────────────────────────────────────────────────────────────────────────────

/// Round constants for the ι (iota) step, one per round.
const ROUND_CONSTANTS: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

/// Per-lane rotation offsets for the ρ (rho) step.
/// Indexed as `ROTATIONS[x + 5*y]`; lane (0,0) rotates by 0.
const ROTATIONS: [u32; 25] = [
    0, 1, 62, 28, 27, // y=0
    36, 44, 6, 55, 20, // y=1
    3, 10, 43, 25, 39, // y=2
    41, 45, 15, 21, 8, // y=3
    18, 2, 61, 56, 14, // y=4
];

// ─────────────────────────────────────────────────────────────────────────────
// Keccak-f[1600] permutation
// ─────────────────────────────────────────────────────────────────────────────

/// Apply one full Keccak-f[1600] permutation (24 rounds) to the 5×5 lane state.
///
/// `state[x + 5*y]` holds lane (x, y).  All arithmetic is over `u64` lanes.
fn keccak_f1600(state: &mut [u64; 25]) {
    for round in 0..24 {
        // ── θ (theta) ─────────────────────────────────────────────────────
        // C[x] = XOR of column x across all five rows.
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        // D[x] = C[x-1] ^ rot(C[x+1], 1);  then A[x,y] ^= D[x]
        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }
        for y in 0..5 {
            for x in 0..5 {
                state[x + 5 * y] ^= d[x];
            }
        }

        // ── ρ (rho) + π (pi) — combined in one pass ───────────────────────
        // B[y, (2x+3y) mod 5] = rot(A[x,y], off[x,y])
        let mut b = [0u64; 25];
        for y in 0..5usize {
            for x in 0..5usize {
                let x_prime = y;
                let y_prime = (2 * x + 3 * y) % 5;
                b[x_prime + 5 * y_prime] = state[x + 5 * y].rotate_left(ROTATIONS[x + 5 * y]);
            }
        }

        // ── χ (chi) ───────────────────────────────────────────────────────
        // A[x,y] = B[x,y] ^ ((~B[x+1,y]) & B[x+2,y])
        for y in 0..5 {
            for x in 0..5 {
                state[x + 5 * y] =
                    b[x + 5 * y] ^ ((!b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);
            }
        }

        // ── ι (iota) ──────────────────────────────────────────────────────
        state[0] ^= ROUND_CONSTANTS[round];
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Sponge construction
// ─────────────────────────────────────────────────────────────────────────────

const RATE_BYTES: usize = 136;

/// XOR a 136-byte block (as little-endian u64 lanes) into the sponge state,
/// then apply the Keccak-f[1600] permutation.
#[inline(always)]
fn absorb_block(state: &mut [u64; 25], block: &[u8; RATE_BYTES]) {
    for i in 0..(RATE_BYTES / 8) {
        let lane = u64::from_le_bytes(block[8 * i..8 * i + 8].try_into().unwrap());
        state[i] ^= lane;
    }
    keccak_f1600(state);
}

/// Compute Keccak-256 of arbitrary-length `input`.
///
/// Returns the 32-byte digest.  Uses Ethereum's original Keccak padding (`0x01`),
/// not the NIST SHA-3 padding (`0x06`).
pub fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut state = [0u64; 25];

    // ── Absorb phase ──────────────────────────────────────────────────────
    let mut buf = [0u8; RATE_BYTES];
    let mut offset = 0usize;

    for chunk in input.chunks(RATE_BYTES) {
        if chunk.len() == RATE_BYTES {
            let block: &[u8; RATE_BYTES] = chunk.try_into().unwrap();
            absorb_block(&mut state, block);
        } else {
            buf[offset..offset + chunk.len()].copy_from_slice(chunk);
            offset += chunk.len();
        }
    }

    // ── Padding ───────────────────────────────────────────────────────────
    buf[offset] = 0x01;
    for b in buf[offset + 1..RATE_BYTES - 1].iter_mut() {
        *b = 0;
    }
    buf[RATE_BYTES - 1] = 0x80;
    absorb_block(&mut state, &buf);

    // ── Squeeze phase ─────────────────────────────────────────────────────
    let mut digest = [0u8; 32];
    for i in 0..4 {
        digest[8 * i..8 * i + 8].copy_from_slice(&state[i].to_le_bytes());
    }
    digest
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

    /// Keccak-256("") from the Ethereum Yellow Paper / reference implementation.
    #[test]
    fn test_empty() {
        let digest = keccak256(b"");
        assert_eq!(
            hex(&digest),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        );
    }

    /// Keccak-256("abc")
    #[test]
    fn test_abc() {
        let digest = keccak256(b"abc");
        assert_eq!(
            hex(&digest),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
        );
    }

    /// Input exactly one rate block long (136 bytes of 0x00).
    #[test]
    fn test_one_full_block() {
        let input = [0u8; 136];
        let digest = keccak256(&input);
        assert_eq!(
            hex(&digest),
            "3a5912a7c5faa06ee4fe906253e339467a9ce87d533c65be3c15cb231cdb25f9",
        );
    }

    /// Keccak-256 of the canonical ERC-20 Transfer event signature.
    #[test]
    fn test_transfer_sig() {
        let digest = keccak256(b"Transfer(address,address,uint256)");
        assert_eq!(
            hex(&digest),
            "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
        );
    }
}
