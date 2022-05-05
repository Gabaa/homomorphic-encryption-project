use std::ops::Add;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use homomorphic_encryption_project::{
    encryption::{encrypt, generate_key_pair, mpc_secure_params, Parameters},
    poly::Polynomial,
    prob::sample_from_uniform,
};
use rug::Integer;

fn bench_poly_add(c: &mut Criterion) {
    let degree = Integer::from(1024);
    let p1 = sample_from_uniform(&degree, 12900);
    let p2 = sample_from_uniform(&degree, 12900);

    c.bench_function("poly add", |b| {
        b.iter(|| black_box(Polynomial::add(p1.clone(), p2.clone())))
    });
}

fn bench_poly_mul(c: &mut Criterion) {
    let degree = Integer::from(1024);
    let p1 = sample_from_uniform(&degree, 12900);
    let p2 = sample_from_uniform(&degree, 12900);

    c.bench_function("poly add", |b| {
        b.iter(|| black_box(p1.clone() * p2.clone()))
    });
}

fn bench_encrypt(c: &mut Criterion) {
    let params = mpc_secure_params();
    let m = sample_from_uniform(&Integer::from(1024), 12900);
    let (pk, _) = generate_key_pair(&params);

    c.bench_function("encrypt", |b| b.iter(|| encrypt(&params, m.clone(), &pk)));
}

criterion_group!(benches, bench_poly_add, bench_poly_mul, bench_encrypt);
criterion_main!(benches);
