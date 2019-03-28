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
#![allow(non_snake_case)]

extern crate bincode;
extern crate curve25519_dalek;
extern crate serde;
extern crate sha2;
extern crate zkp;

use self::sha2::Sha512;

use curve25519_dalek::constants as dalek_constants;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use zkp::toolbox::{batch_verifier::BatchVerifier, prover::Prover, verifier::Verifier, SchnorrCS};
use zkp::Transcript;

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

#[test]
fn create_and_verify_compact_dleq() {
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

    let mut transcript = Transcript::new(b"DLEQTest");
    let mut verifier = Verifier::new(b"DLEQProof", &mut transcript);

    let var_x = verifier.allocate_scalar(b"x");
    let var_G = verifier.allocate_point(b"G", G.compress()).unwrap();
    let var_H = verifier.allocate_point(b"H", H.compress()).unwrap();
    let var_A = verifier.allocate_point(b"A", cmpr_A).unwrap();
    let var_B = verifier.allocate_point(b"B", cmpr_B).unwrap();

    dleq_statement(&mut verifier, var_x, var_A, var_B, var_G, var_H);

    assert!(verifier.verify_compact(&proof).is_ok());
}

#[test]
fn create_and_verify_batchable_dleq() {
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

        (prover.prove_batchable(), cmpr_A, cmpr_B)
    };

    let mut transcript = Transcript::new(b"DLEQTest");
    let mut verifier = Verifier::new(b"DLEQProof", &mut transcript);

    let var_x = verifier.allocate_scalar(b"x");
    let var_G = verifier.allocate_point(b"G", G.compress()).unwrap();
    let var_H = verifier.allocate_point(b"H", H.compress()).unwrap();
    let var_A = verifier.allocate_point(b"A", cmpr_A).unwrap();
    let var_B = verifier.allocate_point(b"B", cmpr_B).unwrap();

    dleq_statement(&mut verifier, var_x, var_A, var_B, var_G, var_H);

    assert!(verifier.verify_batchable(&proof).is_ok());
}

#[test]
fn create_and_batch_verify_batchable_dleq() {
    let G = dalek_constants::RISTRETTO_BASEPOINT_POINT;
    let H = RistrettoPoint::hash_from_bytes::<Sha512>(G.compress().as_bytes());

    let batch_size = 16;

    let mut proofs = Vec::new();
    let mut cmpr_As = Vec::new();
    let mut cmpr_Bs = Vec::new();

    for j in 0..batch_size {
        let (proof, cmpr_A, cmpr_B) = {
            let x = Scalar::from((j as u64) + 89327492234u64);

            let A = G * x;
            let B = H * x;

            let mut transcript = Transcript::new(b"DLEQBatchTest");
            let mut prover = Prover::new(b"DLEQProof", &mut transcript);

            // XXX committing var names to transcript forces ordering (?)
            let var_x = prover.allocate_scalar(b"x", x);
            let (var_G, _) = prover.allocate_point(b"G", G);
            let (var_H, _) = prover.allocate_point(b"H", H);
            let (var_A, cmpr_A) = prover.allocate_point(b"A", A);
            let (var_B, cmpr_B) = prover.allocate_point(b"B", B);

            dleq_statement(&mut prover, var_x, var_A, var_B, var_G, var_H);

            (prover.prove_batchable(), cmpr_A, cmpr_B)
        };
        proofs.push(proof);
        cmpr_As.push(cmpr_A);
        cmpr_Bs.push(cmpr_B);
    }

    let mut transcripts = vec![Transcript::new(b"DLEQBatchTest"); batch_size];
    let transcript_refs = transcripts.iter_mut().collect();
    let mut verifier = BatchVerifier::new(b"DLEQProof", batch_size, transcript_refs).unwrap();

    let var_x = verifier.allocate_scalar(b"x");
    let var_G = verifier.allocate_static_point(b"G", G.compress()).unwrap();
    let var_H = verifier.allocate_static_point(b"H", H.compress()).unwrap();
    let var_A = verifier.allocate_instance_point(b"A", cmpr_As).unwrap();
    let var_B = verifier.allocate_instance_point(b"B", cmpr_Bs).unwrap();

    dleq_statement(&mut verifier, var_x, var_A, var_B, var_G, var_H);

    assert!(verifier.verify_batchable(&proofs).is_ok());
}
