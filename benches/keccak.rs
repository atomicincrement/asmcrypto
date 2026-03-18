use asmcrypto::keccak::keccak256 as our_keccak256;
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

criterion_group!(benches, bench_keccak);
criterion_main!(benches);
