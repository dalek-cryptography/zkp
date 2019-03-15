// -*- coding: utf-8; mode: rust; -*-
//
// To the extent possible under law, the authors have waived all
// copyright and related or neighboring rights to zkp,
// using the Creative Commons "CC0" public domain dedication.  See
// <http://creativecommons.org/publicdomain/zero/1.0/> for full
// details.
//
// Authors:
// - Henry de Valence <hdevalence@hdevalence.ca>

#![feature(test)]
#![allow(non_snake_case)]

extern crate bincode;
extern crate curve25519_dalek;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate sha2;
#[macro_use]
extern crate zkp;
extern crate rand;
extern crate test;
use test::Bencher;

use rand::{thread_rng, Rng};

use std::iter;

use self::sha2::Sha512;

use curve25519_dalek::constants as dalek_constants;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use zkp::Transcript;
use zkp::{CompactProof, Prover, SchnorrCS, Verifier};

#[allow(non_snake_case)]
fn cred_show_n<CS: SchnorrCS>(
    cs: &mut CS,
    minus_z_Q: CS::ScalarVar,
    m: &[CS::ScalarVar],
    z: &[CS::ScalarVar],
    C: &[CS::PointVar],
    X: &[CS::PointVar],
    A: CS::PointVar,
    B: CS::PointVar,
    P: CS::PointVar,
    Q: CS::PointVar,
    V: CS::PointVar,
) -> Result<(), &'static str> {
    let n = m.len();
    if n != z.len() || n != C.len() || n != X.len() {
        return Err("wrong arguments");
    }

    for i in 0..n {
        cs.constrain(C[i], vec![(m[i], P), (z[i], A)]);
    }

    cs.constrain(
        V,
        Iterator::zip(m.iter().cloned(), X.iter().cloned())
            .chain(iter::once((minus_z_Q, Q)))
            .collect(),
    );

    Ok(())
}

#[bench]
fn create_bogus_compact_cred_show_10(b: &mut Bencher) {
    // don't make a correct proof, just a bogus one, but proving is CT so
    let n = 10;
    let mut rng = thread_rng();
    let A = RistrettoPoint::random(&mut rng);
    let B = RistrettoPoint::random(&mut rng);
    let P = RistrettoPoint::random(&mut rng);
    let Q = RistrettoPoint::random(&mut rng);
    let V = RistrettoPoint::random(&mut rng);
    let C = (0..n)
        .map(|_| RistrettoPoint::random(&mut rng))
        .collect::<Vec<_>>();
    let X = (0..n)
        .map(|_| RistrettoPoint::random(&mut rng))
        .collect::<Vec<_>>();
    let m = (0..n).map(|_| Scalar::random(&mut rng)).collect::<Vec<_>>();
    let z = (0..n).map(|_| Scalar::random(&mut rng)).collect::<Vec<_>>();
    let minus_z_Q = Scalar::random(&mut rng);

    b.iter(|| {
        let mut transcript = Transcript::new(b"BogusCMZ13");
        let mut prover = Prover::new(b"CredShow10", &mut transcript);

        let (var_A, cmpr_A) = prover.allocate_point(b"A", A);
        let (var_B, cmpr_B) = prover.allocate_point(b"B", B);
        let (var_P, cmpr_P) = prover.allocate_point(b"P", P);
        let (var_Q, cmpr_Q) = prover.allocate_point(b"Q", Q);
        let (var_V, cmpr_V) = prover.allocate_point(b"V", V);
        let (var_C, cmpr_C): (Vec<_>, Vec<_>) = C
            .iter()
            .map(|&C_i| prover.allocate_point(b"C_i", C_i))
            .unzip();
        let (var_X, cmpr_X): (Vec<_>, Vec<_>) = X
            .iter()
            .map(|&X_i| prover.allocate_point(b"X_i", X_i))
            .unzip();
        let var_m = m
            .iter()
            .map(|&m_i| prover.allocate_scalar(b"m_i", m_i))
            .collect::<Vec<_>>();
        let var_z = z
            .iter()
            .map(|&z_i| prover.allocate_scalar(b"z_i", z_i))
            .collect::<Vec<_>>();
        let var_minus_z_Q = prover.allocate_scalar(b"minus_z_Q", minus_z_Q);

        cred_show_n(
            &mut prover,
            var_minus_z_Q,
            &var_m,
            &var_z,
            &var_C,
            &var_X,
            var_A,
            var_B,
            var_P,
            var_Q,
            var_V,
        )
        .unwrap();

        prover.prove_compact()
    });
}

#[bench]
fn verify_bogus_compact_cred_show_10(b: &mut Bencher) {
    // don't make a correct proof, just a plausible bogus one
    let n = 10;
    let mut rng = thread_rng();
    let A = RistrettoPoint::random(&mut rng);
    let B = RistrettoPoint::random(&mut rng);
    let P = RistrettoPoint::random(&mut rng);
    let Q = RistrettoPoint::random(&mut rng);
    let V = RistrettoPoint::random(&mut rng);
    let C = (0..n)
        .map(|_| RistrettoPoint::random(&mut rng))
        .collect::<Vec<_>>();
    let X = (0..n)
        .map(|_| RistrettoPoint::random(&mut rng))
        .collect::<Vec<_>>();
    let m = (0..n).map(|_| Scalar::random(&mut rng)).collect::<Vec<_>>();
    let z = (0..n).map(|_| Scalar::random(&mut rng)).collect::<Vec<_>>();
    let minus_z_Q = Scalar::random(&mut rng);

    let mut transcript = Transcript::new(b"BogusCMZ13");
    let mut prover = Prover::new(b"CredShow10", &mut transcript);

    let (var_A, cmpr_A) = prover.allocate_point(b"A", A);
    let (var_B, cmpr_B) = prover.allocate_point(b"B", B);
    let (var_P, cmpr_P) = prover.allocate_point(b"P", P);
    let (var_Q, cmpr_Q) = prover.allocate_point(b"Q", Q);
    let (var_V, cmpr_V) = prover.allocate_point(b"V", V);
    let (var_C, cmpr_C): (Vec<_>, Vec<_>) = C
        .iter()
        .map(|&C_i| prover.allocate_point(b"C_i", C_i))
        .unzip();
    let (var_X, cmpr_X): (Vec<_>, Vec<_>) = X
        .iter()
        .map(|&X_i| prover.allocate_point(b"X_i", X_i))
        .unzip();
    let var_m = m
        .iter()
        .map(|&m_i| prover.allocate_scalar(b"m_i", m_i))
        .collect::<Vec<_>>();
    let var_z = z
        .iter()
        .map(|&z_i| prover.allocate_scalar(b"z_i", z_i))
        .collect::<Vec<_>>();
    let var_minus_z_Q = prover.allocate_scalar(b"minus_z_Q", minus_z_Q);

    cred_show_n(
        &mut prover,
        var_minus_z_Q,
        &var_m,
        &var_z,
        &var_C,
        &var_X,
        var_A,
        var_B,
        var_P,
        var_Q,
        var_V,
    )
    .unwrap();

    let proof = prover.prove_compact();

    b.iter(|| {
        let mut transcript = Transcript::new(b"BogusCMZ13");
        let mut verifier = Verifier::new(b"CredShow10", &mut transcript);

        let var_A = verifier.allocate_point(b"A", cmpr_A);
        let var_B = verifier.allocate_point(b"B", cmpr_B);
        let var_P = verifier.allocate_point(b"P", cmpr_P);
        let var_Q = verifier.allocate_point(b"Q", cmpr_Q);
        let var_V = verifier.allocate_point(b"V", cmpr_V);
        let var_C = cmpr_C
            .iter()
            .map(|&cmpr_C_i| verifier.allocate_point(b"C_i", cmpr_C_i))
            .collect::<Vec<_>>();
        let var_X = cmpr_X
            .iter()
            .map(|&cmpr_X_i| verifier.allocate_point(b"X_i", cmpr_X_i))
            .collect::<Vec<_>>();
        let var_m = (0..n)
            .map(|_| verifier.allocate_scalar(b"m_i"))
            .collect::<Vec<_>>();
        let var_z = (0..n)
            .map(|_| verifier.allocate_scalar(b"z_i"))
            .collect::<Vec<_>>();
        let var_minus_z_Q = verifier.allocate_scalar(b"minus_z_Q");

        cred_show_n(
            &mut verifier,
            var_minus_z_Q,
            &var_m,
            &var_z,
            &var_C,
            &var_X,
            var_A,
            var_B,
            var_P,
            var_Q,
            var_V,
        )
        .unwrap();

        verifier.verify_compact(&proof);
    });
}

#[bench]
fn create_bogus_batchable_cred_show_10(b: &mut Bencher) {
    // don't make a correct proof, just a bogus one, but proving is CT so
    let n = 10;
    let mut rng = thread_rng();
    let A = RistrettoPoint::random(&mut rng);
    let B = RistrettoPoint::random(&mut rng);
    let P = RistrettoPoint::random(&mut rng);
    let Q = RistrettoPoint::random(&mut rng);
    let V = RistrettoPoint::random(&mut rng);
    let C = (0..n)
        .map(|_| RistrettoPoint::random(&mut rng))
        .collect::<Vec<_>>();
    let X = (0..n)
        .map(|_| RistrettoPoint::random(&mut rng))
        .collect::<Vec<_>>();
    let m = (0..n).map(|_| Scalar::random(&mut rng)).collect::<Vec<_>>();
    let z = (0..n).map(|_| Scalar::random(&mut rng)).collect::<Vec<_>>();
    let minus_z_Q = Scalar::random(&mut rng);

    b.iter(|| {
        let mut transcript = Transcript::new(b"BogusCMZ13");
        let mut prover = Prover::new(b"CredShow10", &mut transcript);

        let (var_A, cmpr_A) = prover.allocate_point(b"A", A);
        let (var_B, cmpr_B) = prover.allocate_point(b"B", B);
        let (var_P, cmpr_P) = prover.allocate_point(b"P", P);
        let (var_Q, cmpr_Q) = prover.allocate_point(b"Q", Q);
        let (var_V, cmpr_V) = prover.allocate_point(b"V", V);
        let (var_C, cmpr_C): (Vec<_>, Vec<_>) = C
            .iter()
            .map(|&C_i| prover.allocate_point(b"C_i", C_i))
            .unzip();
        let (var_X, cmpr_X): (Vec<_>, Vec<_>) = X
            .iter()
            .map(|&X_i| prover.allocate_point(b"X_i", X_i))
            .unzip();
        let var_m = m
            .iter()
            .map(|&m_i| prover.allocate_scalar(b"m_i", m_i))
            .collect::<Vec<_>>();
        let var_z = z
            .iter()
            .map(|&z_i| prover.allocate_scalar(b"z_i", z_i))
            .collect::<Vec<_>>();
        let var_minus_z_Q = prover.allocate_scalar(b"minus_z_Q", minus_z_Q);

        cred_show_n(
            &mut prover,
            var_minus_z_Q,
            &var_m,
            &var_z,
            &var_C,
            &var_X,
            var_A,
            var_B,
            var_P,
            var_Q,
            var_V,
        )
        .unwrap();

        prover.prove_batchable()
    });
}

#[bench]
fn verify_bogus_batchable_cred_show_10(b: &mut Bencher) {
    // don't make a correct proof, just a plausible bogus one
    let n = 10;
    let mut rng = thread_rng();
    let A = RistrettoPoint::random(&mut rng);
    let B = RistrettoPoint::random(&mut rng);
    let P = RistrettoPoint::random(&mut rng);
    let Q = RistrettoPoint::random(&mut rng);
    let V = RistrettoPoint::random(&mut rng);
    let C = (0..n)
        .map(|_| RistrettoPoint::random(&mut rng))
        .collect::<Vec<_>>();
    let X = (0..n)
        .map(|_| RistrettoPoint::random(&mut rng))
        .collect::<Vec<_>>();
    let m = (0..n).map(|_| Scalar::random(&mut rng)).collect::<Vec<_>>();
    let z = (0..n).map(|_| Scalar::random(&mut rng)).collect::<Vec<_>>();
    let minus_z_Q = Scalar::random(&mut rng);

    let mut transcript = Transcript::new(b"BogusCMZ13");
    let mut prover = Prover::new(b"CredShow10", &mut transcript);

    let (var_A, cmpr_A) = prover.allocate_point(b"A", A);
    let (var_B, cmpr_B) = prover.allocate_point(b"B", B);
    let (var_P, cmpr_P) = prover.allocate_point(b"P", P);
    let (var_Q, cmpr_Q) = prover.allocate_point(b"Q", Q);
    let (var_V, cmpr_V) = prover.allocate_point(b"V", V);
    let (var_C, cmpr_C): (Vec<_>, Vec<_>) = C
        .iter()
        .map(|&C_i| prover.allocate_point(b"C_i", C_i))
        .unzip();
    let (var_X, cmpr_X): (Vec<_>, Vec<_>) = X
        .iter()
        .map(|&X_i| prover.allocate_point(b"X_i", X_i))
        .unzip();
    let var_m = m
        .iter()
        .map(|&m_i| prover.allocate_scalar(b"m_i", m_i))
        .collect::<Vec<_>>();
    let var_z = z
        .iter()
        .map(|&z_i| prover.allocate_scalar(b"z_i", z_i))
        .collect::<Vec<_>>();
    let var_minus_z_Q = prover.allocate_scalar(b"minus_z_Q", minus_z_Q);

    cred_show_n(
        &mut prover,
        var_minus_z_Q,
        &var_m,
        &var_z,
        &var_C,
        &var_X,
        var_A,
        var_B,
        var_P,
        var_Q,
        var_V,
    )
    .unwrap();

    let proof = prover.prove_batchable();

    b.iter(|| {
        let mut transcript = Transcript::new(b"BogusCMZ13");
        let mut verifier = Verifier::new(b"CredShow10", &mut transcript);

        let var_A = verifier.allocate_point(b"A", cmpr_A);
        let var_B = verifier.allocate_point(b"B", cmpr_B);
        let var_P = verifier.allocate_point(b"P", cmpr_P);
        let var_Q = verifier.allocate_point(b"Q", cmpr_Q);
        let var_V = verifier.allocate_point(b"V", cmpr_V);
        let var_C = cmpr_C
            .iter()
            .map(|&cmpr_C_i| verifier.allocate_point(b"C_i", cmpr_C_i))
            .collect::<Vec<_>>();
        let var_X = cmpr_X
            .iter()
            .map(|&cmpr_X_i| verifier.allocate_point(b"X_i", cmpr_X_i))
            .collect::<Vec<_>>();
        let var_m = (0..n)
            .map(|_| verifier.allocate_scalar(b"m_i"))
            .collect::<Vec<_>>();
        let var_z = (0..n)
            .map(|_| verifier.allocate_scalar(b"z_i"))
            .collect::<Vec<_>>();
        let var_minus_z_Q = verifier.allocate_scalar(b"minus_z_Q");

        cred_show_n(
            &mut verifier,
            var_minus_z_Q,
            &var_m,
            &var_z,
            &var_C,
            &var_X,
            var_A,
            var_B,
            var_P,
            var_Q,
            var_V,
        )
        .unwrap();

        verifier.verify_batchable(&proof);
    });
}
