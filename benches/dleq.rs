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

extern crate bincode;
extern crate curve25519_dalek;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate sha2;
#[macro_use]
extern crate zkp;

extern crate test;
use test::Bencher;

use self::sha2::Sha512;

use curve25519_dalek::constants as dalek_constants;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use zkp::Transcript;
use zkp::{CompactProof, Prover, SchnorrCS, Verifier};

#[allow(non_snake_case)]
fn dleq_statement<CS: SchnorrCS>(
    cs: &mut CS,
    x: CS::ScalarVar,
    A: CS::PointVar,
    B: CS::PointVar,
    G: CS::PointVar,
    H: CS::PointVar,
) {
    cs.constrain(A, vec![(x, G)]);
    cs.constrain(B, vec![(x, H)]);
}

#[bench]
fn create_compact_dleq(b: &mut Bencher) {
    let G = dalek_constants::RISTRETTO_BASEPOINT_POINT;
    let H = RistrettoPoint::hash_from_bytes::<Sha512>(G.compress().as_bytes());

    let x = Scalar::from(89327492234u64);
    let A = G * x;
    let B = H * x;

    b.iter(|| {
        let mut transcript = Transcript::new(b"DLEQTest");
        let mut prover = Prover::new(b"DLEQProof", &mut transcript);

        let var_x = prover.allocate_scalar(b"x", x);
        let (var_G, _) = prover.allocate_point(b"G", G);
        let (var_H, _) = prover.allocate_point(b"H", H);
        let (var_A, cmpr_A) = prover.allocate_point(b"A", A);
        let (var_B, cmpr_B) = prover.allocate_point(b"B", B);

        dleq_statement(&mut prover, var_x, var_A, var_B, var_G, var_H);

        prover.prove_compact()
    });
}

#[bench]
fn verify_compact_dleq(b: &mut Bencher) {
    let G = dalek_constants::RISTRETTO_BASEPOINT_POINT;
    let H = RistrettoPoint::hash_from_bytes::<Sha512>(G.compress().as_bytes());

    let (proof, cmpr_A, cmpr_B) = {
        let x = Scalar::from(89327492234u64);

        let A = G * x;
        let B = H * x;

        let mut transcript = Transcript::new(b"DLEQTest");
        let mut prover = Prover::new(b"DLEQProof", &mut transcript);

        // XXX committing var names to transcript forces ordering (?)
        let var_x = prover.allocate_scalar(b"x", x);
        let (var_G, _) = prover.allocate_point(b"G", G);
        let (var_H, _) = prover.allocate_point(b"H", H);
        let (var_A, cmpr_A) = prover.allocate_point(b"A", A);
        let (var_B, cmpr_B) = prover.allocate_point(b"B", B);

        dleq_statement(&mut prover, var_x, var_A, var_B, var_G, var_H);

        (prover.prove_compact(), cmpr_A, cmpr_B)
    };

    b.iter(|| {
        let mut transcript = Transcript::new(b"DLEQTest");
        let mut verifier = Verifier::new(b"DLEQProof", &mut transcript);

        let var_x = verifier.allocate_scalar(b"x");
        let var_G = verifier.allocate_point(b"G", G.compress());
        let var_H = verifier.allocate_point(b"H", H.compress());
        let var_A = verifier.allocate_point(b"A", cmpr_A);
        let var_B = verifier.allocate_point(b"B", cmpr_B);

        dleq_statement(&mut verifier, var_x, var_A, var_B, var_G, var_H);

        verifier.verify_compact(&proof)
    });
}

#[bench]
fn create_batchable_dleq(b: &mut Bencher) {
    let G = dalek_constants::RISTRETTO_BASEPOINT_POINT;
    let H = RistrettoPoint::hash_from_bytes::<Sha512>(G.compress().as_bytes());

    let x = Scalar::from(89327492234u64);
    let A = G * x;
    let B = H * x;

    b.iter(|| {
        let mut transcript = Transcript::new(b"DLEQTest");
        let mut prover = Prover::new(b"DLEQProof", &mut transcript);

        let var_x = prover.allocate_scalar(b"x", x);
        let (var_G, _) = prover.allocate_point(b"G", G);
        let (var_H, _) = prover.allocate_point(b"H", H);
        let (var_A, cmpr_A) = prover.allocate_point(b"A", A);
        let (var_B, cmpr_B) = prover.allocate_point(b"B", B);

        dleq_statement(&mut prover, var_x, var_A, var_B, var_G, var_H);

        prover.prove_batchable()
    });
}

#[bench]
fn verify_batchable_dleq(b: &mut Bencher) {
    let G = dalek_constants::RISTRETTO_BASEPOINT_POINT;
    let H = RistrettoPoint::hash_from_bytes::<Sha512>(G.compress().as_bytes());

    let (proof, cmpr_A, cmpr_B) = {
        let x = Scalar::from(89327492234u64);

        let A = G * x;
        let B = H * x;

        let mut transcript = Transcript::new(b"DLEQTest");
        let mut prover = Prover::new(b"DLEQProof", &mut transcript);

        let var_x = prover.allocate_scalar(b"x", x);
        let (var_G, _) = prover.allocate_point(b"G", G);
        let (var_H, _) = prover.allocate_point(b"H", H);
        let (var_A, cmpr_A) = prover.allocate_point(b"A", A);
        let (var_B, cmpr_B) = prover.allocate_point(b"B", B);

        dleq_statement(&mut prover, var_x, var_A, var_B, var_G, var_H);

        (prover.prove_batchable(), cmpr_A, cmpr_B)
    };

    b.iter(|| {
        let mut transcript = Transcript::new(b"DLEQTest");
        let mut verifier = Verifier::new(b"DLEQProof", &mut transcript);

        let var_x = verifier.allocate_scalar(b"x");
        let var_G = verifier.allocate_point(b"G", G.compress());
        let var_H = verifier.allocate_point(b"H", H.compress());
        let var_A = verifier.allocate_point(b"A", cmpr_A);
        let var_B = verifier.allocate_point(b"B", cmpr_B);

        dleq_statement(&mut verifier, var_x, var_A, var_B, var_G, var_H);

        verifier.verify_batchable(&proof)
    });
}
