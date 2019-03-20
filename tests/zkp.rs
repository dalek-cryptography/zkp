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
#[macro_use]
extern crate serde_derive;
extern crate sha2;
#[macro_use]
extern crate zkp;

use self::sha2::Sha512;

use curve25519_dalek::constants as dalek_constants;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use zkp::Transcript;

#[test]
fn create_and_verify_gen_dleq() {
    let G = &dalek_constants::RISTRETTO_BASEPOINT_POINT;
    let H = RistrettoPoint::hash_from_bytes::<Sha512>(G.compress().as_bytes());

    create_nipk! {dleq, (x), (A, B), (G, H) : A = (G * x), B = (H * x) }

    let basepoints = dleq::StaticAssignments { G: G, H: &H };

    let x = Scalar::from(89327492234u64);
    let A = G * &x;
    let B = &H * &x;

    let mut transcript = Transcript::new(b"DLEQTest");
    let proof = dleq::prove_compact(
        &mut transcript,
        dleq::SecretAssignments { x: &x },
        dleq::InstanceAssignments { A: &A, B: &B },
        basepoints,
    );

    // serialize to bincode representation
    let proof_bytes = bincode::serialize(&proof).unwrap();
    // parse bytes back to memory
    let parsed_proof: dleq::CompactProof = bincode::deserialize(&proof_bytes).unwrap();

    let mut transcript = Transcript::new(b"DLEQTest");
    assert!(dleq::verify_compact(
        &parsed_proof,
        &mut transcript,
        dleq::InstanceAssignments { A: &A, B: &B },
        basepoints,
    )
    .is_ok());
}
