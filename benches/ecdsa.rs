use asmcrypto::ecdsa::{
    recover_address as our_recover_address, recover_public_key as our_recover_pubkey,
};
use asmcrypto::ecdsa_batch::recover_addresses_batch;
use criterion::{Criterion, black_box, criterion_group, criterion_main};

// ─────────────────────────────────────────────────────────────────────────────
// Shared test vector
// ─────────────────────────────────────────────────────────────────────────────

struct TestVector {
    hash: [u8; 32],
    r: [u8; 32],
    s: [u8; 32],
    v: u8, // recovery_id: 0 or 1
}

/// Build a deterministic test vector by signing with k256 using a fixed private key.
///
/// k256 always produces canonical (low-s) signatures, so the same (r, s, v)
/// values work with all three libraries being compared.
fn make_test_vector() -> TestVector {
    use k256::ecdsa::{SigningKey, signature::hazmat::PrehashSigner};
    // Fixed 32-byte private key — not secret, benchmarking only.
    let sk = SigningKey::from_slice(&[0x01u8; 32]).expect("valid private key");
    let hash = [0x42u8; 32]; // arbitrary fixed prehash
    let (sig, recid): (k256::ecdsa::Signature, k256::ecdsa::RecoveryId) =
        PrehashSigner::sign_prehash(&sk, &hash).expect("signing failed");
    let r: [u8; 32] = sig.r().to_bytes().into();
    let s: [u8; 32] = sig.s().to_bytes().into();
    TestVector {
        hash,
        r,
        s,
        v: recid.to_byte(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// k256 (alloy-primitives / alloy-consensus, pure-Rust RustCrypto)
// ─────────────────────────────────────────────────────────────────────────────

mod bench_k256 {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

    pub fn recover_pubkey(hash: &[u8; 32], r: &[u8; 32], s: &[u8; 32], v: u8) -> [u8; 65] {
        let sig = Signature::from_scalars(k256::FieldBytes::from(*r), k256::FieldBytes::from(*s))
            .expect("k256 from_scalars");
        let recid = RecoveryId::try_from(v).expect("recovery id");
        let vk = VerifyingKey::recover_from_prehash(hash, &sig, recid).expect("k256 recovery");
        let ep = vk.to_encoded_point(false);
        ep.as_bytes().try_into().expect("65 bytes")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// secp256k1 (alloy-consensus, libsecp256k1 C-backed)
// ─────────────────────────────────────────────────────────────────────────────

mod bench_secp256k1 {
    use secp256k1::{
        SECP256K1,
        ecdsa::{RecoverableSignature, RecoveryId},
    };

    pub fn recover_pubkey(hash: &[u8; 32], r: &[u8; 32], s: &[u8; 32], v: u8) -> [u8; 65] {
        let msg = secp256k1::Message::from_digest(*hash);
        let recid = RecoveryId::from_i32(v as i32).expect("recovery id");
        let mut compact = [0u8; 64];
        compact[..32].copy_from_slice(r);
        compact[32..].copy_from_slice(s);
        let sig = RecoverableSignature::from_compact(&compact, recid).expect("secp256k1 sig");
        let pk = SECP256K1
            .recover_ecdsa(&msg, &sig)
            .expect("secp256k1 recovery");
        pk.serialize_uncompressed()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Benchmark groups
// ─────────────────────────────────────────────────────────────────────────────

fn bench_ecdsa(c: &mut Criterion) {
    let tv = make_test_vector();

    // ── recover_public_key ────────────────────────────────────────────────────
    {
        let mut g = c.benchmark_group("ecdsa/recover_public_key");

        g.bench_function("asmcrypto", |b| {
            b.iter(|| {
                our_recover_pubkey(
                    black_box(&tv.hash),
                    black_box(&tv.r),
                    black_box(&tv.s),
                    black_box(tv.v),
                )
            })
        });

        g.bench_function("k256", |b| {
            b.iter(|| {
                bench_k256::recover_pubkey(
                    black_box(&tv.hash),
                    black_box(&tv.r),
                    black_box(&tv.s),
                    black_box(tv.v),
                )
            })
        });

        g.bench_function("secp256k1", |b| {
            b.iter(|| {
                bench_secp256k1::recover_pubkey(
                    black_box(&tv.hash),
                    black_box(&tv.r),
                    black_box(&tv.s),
                    black_box(tv.v),
                )
            })
        });

        g.finish();
    }

    // ── recover_address (pubkey recovery + keccak-256) ────────────────────────
    {
        let mut g = c.benchmark_group("ecdsa/recover_address");

        g.bench_function("asmcrypto", |b| {
            b.iter(|| {
                our_recover_address(
                    black_box(&tv.hash),
                    black_box(&tv.r),
                    black_box(&tv.s),
                    black_box(tv.v),
                )
            })
        });

        // k256 + sha3 keccak (alloy-primitives default stack)
        g.bench_function("k256+sha3", |b| {
            b.iter(|| {
                use sha3::Digest as _;
                let pk = bench_k256::recover_pubkey(
                    black_box(&tv.hash),
                    black_box(&tv.r),
                    black_box(&tv.s),
                    black_box(tv.v),
                );
                let h: [u8; 32] = sha3::Keccak256::digest(&pk[1..]).into();
                let mut addr = [0u8; 20];
                addr.copy_from_slice(&h[12..]);
                addr
            })
        });

        // secp256k1 + sha3 keccak
        g.bench_function("secp256k1+sha3", |b| {
            b.iter(|| {
                use sha3::Digest as _;
                let pk = bench_secp256k1::recover_pubkey(
                    black_box(&tv.hash),
                    black_box(&tv.r),
                    black_box(&tv.s),
                    black_box(tv.v),
                );
                let h: [u8; 32] = sha3::Keccak256::digest(&pk[1..]).into();
                let mut addr = [0u8; 20];
                addr.copy_from_slice(&h[12..]);
                addr
            })
        });

        g.finish();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Batch benchmark: recover_addresses_batch (8 lanes) vs 8× scalar calls
// ─────────────────────────────────────────────────────────────────────────────

fn bench_ecdsa_batch(c: &mut Criterion) {
    let tv = make_test_vector();

    // Replicate the single vector across 8 lanes for a fair batch comparison.
    let hashes = [&tv.hash; 8];
    let rs = [&tv.r; 8];
    let ss = [&tv.s; 8];
    let vs = [tv.v; 8];

    let mut g = c.benchmark_group("ecdsa/recover_address_x8");

    // ── asmcrypto batch (our 8-lane AVX-512 path) ─────────────────────────────
    g.bench_function("asmcrypto-batch", |b| {
        b.iter(|| {
            recover_addresses_batch(
                black_box(hashes),
                black_box(rs),
                black_box(ss),
                black_box(vs),
            )
        })
    });

    // ── 8× asmcrypto scalar (our own baseline, no SIMD) ──────────────────────
    g.bench_function("asmcrypto-scalar-x8", |b| {
        b.iter(|| {
            std::array::from_fn::<[u8; 20], 8, _>(|i| {
                our_recover_address(
                    black_box(hashes[i]),
                    black_box(rs[i]),
                    black_box(ss[i]),
                    black_box(vs[i]),
                )
                .unwrap_or([0u8; 20])
            })
        })
    });

    // ── 8× secp256k1 C library + sha3 keccak ─────────────────────────────────
    g.bench_function("secp256k1-x8", |b| {
        b.iter(|| {
            std::array::from_fn::<[u8; 20], 8, _>(|i| {
                use sha3::Digest as _;
                let pk = bench_secp256k1::recover_pubkey(
                    black_box(hashes[i]),
                    black_box(rs[i]),
                    black_box(ss[i]),
                    black_box(vs[i]),
                );
                // Ethereum address = keccak256(uncompressed_pubkey[1..])[12..]
                let h: [u8; 32] = sha3::Keccak256::digest(&pk[1..]).into();
                let mut addr = [0u8; 20];
                addr.copy_from_slice(&h[12..]);
                addr
            })
        })
    });

    g.finish();
}

criterion_group!(benches, bench_ecdsa, bench_ecdsa_batch);
criterion_main!(benches);
