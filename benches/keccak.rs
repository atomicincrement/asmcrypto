use asmcrypto::keccak_batch::keccak256_batch;
use asmcrypto::keccak_scalar::keccak256 as our_keccak256;
use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use sha3::Digest as _;
use tiny_keccak::Hasher as _;

// ── sha3 crate (alloy-primitives default) ────────────────────────────────────
#[inline(never)]
fn sha3_keccak256(data: &[u8]) -> [u8; 32] {
    sha3::Keccak256::digest(data).into()
}

// ── tiny-keccak crate (alloy-primitives optional) ────────────────────────────
#[inline(never)]
fn tiny_keccak256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut h = tiny_keccak::Keccak::v256();
    h.update(data);
    h.finalize(&mut out);
    out
}

// ── our implementation ────────────────────────────────────────────────────────
#[inline(never)]
fn ours_keccak256(data: &[u8]) -> [u8; 32] {
    our_keccak256(data)
}

fn bench_keccak_size(c: &mut Criterion, label: &str, input: &[u8]) {
    let bytes = input.len() as u64;
    let mut g = c.benchmark_group(format!("keccak256/{label}"));
    g.throughput(if bytes == 0 {
        Throughput::Elements(1)
    } else {
        Throughput::Bytes(bytes)
    });

    g.bench_function("asmcrypto", |b| b.iter(|| ours_keccak256(black_box(input))));
    g.bench_function("sha3", |b| b.iter(|| sha3_keccak256(black_box(input))));
    g.bench_function("tiny-keccak", |b| {
        b.iter(|| tiny_keccak256(black_box(input)))
    });

    g.finish();
}

fn bench_keccak(c: &mut Criterion) {
    bench_keccak_size(c, "empty", b"");
    bench_keccak_size(c, "32B", &[0xABu8; 32]);
    bench_keccak_size(c, "136B (1 block)", &[0x42u8; 136]);

    let input1k = vec![0xDEu8; 1024];
    bench_keccak_size(c, "1KiB", &input1k);

    let input1m = vec![0xBEu8; 1024 * 1024];
    bench_keccak_size(c, "1MiB", &input1m);
}

/// Benchmark 8-stream batch hashing for a given fixed input length.
///
/// Compares:
///   - `keccak256_batch`: our AVX-512 implementation processing 8 streams in parallel.
///   - `tiny-keccak ×8`:  8 sequential `tiny_keccak::Keccak::v256()` calls (industry baseline).
///   - `asmcrypto ×8`:    8 sequential scalar calls from our own `keccak256`.
fn bench_batch_size(c: &mut Criterion, label: &str, len: usize) {
    // Build 8 distinct input buffers to avoid the branch predictor / prefetcher
    // trivially collapsing them into one.
    let bufs: Vec<Vec<u8>> = (0..8usize)
        .map(|i| vec![(i as u8).wrapping_add(1); len])
        .collect();

    let mut g = c.benchmark_group(format!("keccak256_batch/{label}"));
    g.throughput(Throughput::Elements(8)); // 8 hashes per iteration

    // Our AVX-512 path.
    g.bench_function("asmcrypto-batch", |b| {
        b.iter(|| {
            let inputs: [&[u8]; 8] = std::array::from_fn(|i| bufs[i].as_slice());
            keccak256_batch(black_box(inputs))
        })
    });

    // tiny-keccak sequential loop (the typical baseline in Ethereum tooling).
    g.bench_function("tiny-keccak ×8", |b| {
        b.iter(|| {
            std::array::from_fn::<[u8; 32], 8, _>(|i| {
                let mut out = [0u8; 32];
                let mut h = tiny_keccak::Keccak::v256();
                h.update(black_box(bufs[i].as_slice()));
                h.finalize(&mut out);
                out
            })
        })
    });

    // Our own scalar loop for a fair apples-to-apples baseline.
    g.bench_function("asmcrypto ×8", |b| {
        b.iter(|| {
            std::array::from_fn::<[u8; 32], 8, _>(|i| our_keccak256(black_box(bufs[i].as_slice())))
        })
    });

    g.finish();
}

fn bench_keccak_batch(c: &mut Criterion) {
    bench_batch_size(c, "32B", 32);
    bench_batch_size(c, "64B (pubkey)", 64);
    bench_batch_size(c, "136B (1 block)", 136);
    bench_batch_size(c, "272B (2 blocks)", 272);
}

criterion_group!(benches, bench_keccak, bench_keccak_batch);
criterion_main!(benches);
