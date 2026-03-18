use asmcrypto::ecdsa::bench_mul_wide_generic;
use criterion::{Criterion, black_box, criterion_group, criterion_main};

// Two non-trivial 256-bit operands (secp256k1 field prime - 1 and group order).
const A: [u64; 4] = [
    0xFFFFFFFEFFFFFC2E,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
];
const B: [u64; 4] = [
    0xBFD25E8CD0364141,
    0xBAAEDCE6AF48A03B,
    0xFFFFFFFFFFFFFFFE,
    0xFFFFFFFFFFFFFFFF,
];

fn bench_generic(c: &mut Criterion) {
    let mut g = c.benchmark_group("mul_wide");
    g.bench_function("generic", |b| {
        b.iter(|| bench_mul_wide_generic(black_box(A), black_box(B)))
    });

    #[cfg(all(
        target_arch = "x86_64",
        target_feature = "bmi2",
        target_feature = "adx"
    ))]
    {
        use asmcrypto::ecdsa::bench_mul_wide_adx;
        g.bench_function("adx", |b| {
            b.iter(|| bench_mul_wide_adx(black_box(A), black_box(B)))
        });
    }

    g.finish();
}

criterion_group!(benches, bench_generic);
criterion_main!(benches);
