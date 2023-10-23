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
#[macro_use]
extern crate zkp;

use self::sha2::Sha512;

use curve25519_dalek::constants as dalek_constants;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use zkp::Transcript;

define_proof! {dleq, "DLEQ Example Proof", (x), (A, B, H), (G) : A = (x * G), B = (x * H) }

#[test]
fn create_and_verify_compact() {
    // Prover's scope
    let (proof, points) = {
        let H = RistrettoPoint::hash_from_bytes::<Sha512>(b"A VRF input, for instance");
        let x = Scalar::from(89327492234u64).invert();
        let A = &x * dalek_constants::RISTRETTO_BASEPOINT_TABLE;
        let B = &x * &H;

        let mut transcript = Transcript::new(b"DLEQTest");
        dleq::prove_compact(
            &mut transcript,
            dleq::ProveAssignments {
                x: &x,
                A: &A,
                B: &B,
                G: &dalek_constants::RISTRETTO_BASEPOINT_POINT,
                H: &H,
            },
        )
    };

    // Serialize and parse bincode representation
    let proof_bytes = bincode::serialize(&proof).unwrap();
    let parsed_proof: dleq::CompactProof = bincode::deserialize(&proof_bytes).unwrap();

    // Verifier logic
    let mut transcript = Transcript::new(b"DLEQTest");
    assert!(dleq::verify_compact(
        &parsed_proof,
        &mut transcript,
        dleq::VerifyAssignments {
            A: &points.A,
            B: &points.B,
            G: &dalek_constants::RISTRETTO_BASEPOINT_COMPRESSED,
            H: &RistrettoPoint::hash_from_bytes::<Sha512>(b"A VRF input, for instance").compress(),
        },
    )
    .is_ok());
}

#[test]
fn create_and_verify_batchable() {
    // identical to above but with batchable proofs

    // Prover's scope
    let (proof, points) = {
        let H = RistrettoPoint::hash_from_bytes::<Sha512>(b"A VRF input, for instance");
        let x = Scalar::from(89327492234u64).invert();
        let A = &x * dalek_constants::RISTRETTO_BASEPOINT_TABLE;
        let B = &x * &H;

        let mut transcript = Transcript::new(b"DLEQTest");
        dleq::prove_batchable(
            &mut transcript,
            dleq::ProveAssignments {
                x: &x,
                A: &A,
                B: &B,
                G: &dalek_constants::RISTRETTO_BASEPOINT_POINT,
                H: &H,
            },
        )
    };

    // Serialize and parse bincode representation
    let proof_bytes = bincode::serialize(&proof).unwrap();
    let parsed_proof: dleq::BatchableProof = bincode::deserialize(&proof_bytes).unwrap();

    // Verifier logic
    let mut transcript = Transcript::new(b"DLEQTest");
    assert!(dleq::verify_batchable(
        &parsed_proof,
        &mut transcript,
        dleq::VerifyAssignments {
            A: &points.A,
            B: &points.B,
            G: &dalek_constants::RISTRETTO_BASEPOINT_COMPRESSED,
            H: &RistrettoPoint::hash_from_bytes::<Sha512>(b"A VRF input, for instance").compress(),
        },
    )
    .is_ok());
}

#[test]
fn create_batch_and_batch_verify() {
    let messages = [
        "One message",
        "Another message",
        "A third message",
        "A fourth message",
    ];

    // Prover's scope
    let (proofs, pubkeys, vrf_outputs) = {
        let mut proofs = vec![];
        let mut pubkeys = vec![];
        let mut vrf_outputs = vec![];

        for (i, message) in messages.iter().enumerate() {
            let H = RistrettoPoint::hash_from_bytes::<Sha512>(message.as_bytes());
            let x = Scalar::from(89327492234u64) * Scalar::from((i + 1) as u64);
            let A = &x * dalek_constants::RISTRETTO_BASEPOINT_TABLE;
            let B = &x * &H;

            let mut transcript = Transcript::new(b"DLEQTest");
            let (proof, points) = dleq::prove_batchable(
                &mut transcript,
                dleq::ProveAssignments {
                    x: &x,
                    A: &A,
                    B: &B,
                    G: &dalek_constants::RISTRETTO_BASEPOINT_POINT,
                    H: &H,
                },
            );

            proofs.push(proof);
            pubkeys.push(points.A);
            vrf_outputs.push(points.B);
        }

        (proofs, pubkeys, vrf_outputs)
    };

    // Verifier logic
    let mut transcripts = vec![Transcript::new(b"DLEQTest"); messages.len()];

    assert!(dleq::batch_verify(
        &proofs,
        transcripts.iter_mut().collect(),
        dleq::BatchVerifyAssignments {
            A: pubkeys,
            B: vrf_outputs,
            H: messages
                .iter()
                .map(
                    |message| RistrettoPoint::hash_from_bytes::<Sha512>(message.as_bytes())
                        .compress()
                )
                .collect(),
            G: dalek_constants::RISTRETTO_BASEPOINT_COMPRESSED,
        },
    )
    .is_ok());
}
