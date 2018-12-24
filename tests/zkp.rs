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

mod cmz13 {
    // Proof statement for "credential presentation with 10 hidden attributes" from CMZ'13.
    create_nipk!{
        cred_show_10,
        (m_1, m_2, m_3, m_4, m_5, m_6, m_7, m_8, m_9, m_10,
         z_1, z_2, z_3, z_4, z_5, z_6, z_7, z_8, z_9, z_10, minus_z_Q),
        (C_1, C_2, C_3, C_4, C_5, C_6, C_7, C_8, C_9, C_10,
         X_1, X_2, X_3, X_4, X_5, X_6, X_7, X_8, X_9, X_10,
         P, Q, A, B, V)
        :
        C_1 = (P * m_1 + A * z_1), C_2 = (P * m_2 + A * z_2),
        C_3 = (P * m_3 + A * z_3), C_4 = (P * m_4 + A * z_4),
        C_5 = (P * m_5 + A * z_5), C_6 = (P * m_6 + A * z_6),
        C_7 = (P * m_7 + A * z_7), C_8 = (P * m_8 + A * z_8),
        C_9 = (P * m_9 + A * z_9), C_10 = (P * m_10 + A * z_10),
        V = (X_1*m_1 + X_2*m_2 + X_3*m_3 + X_4*m_4 + X_5*m_5 + X_6*m_6
             + X_7*m_7 + X_8*m_8 + X_9*m_9 + X_10*m_10 + Q*minus_z_Q)
    }
}

#[test]
fn create_and_verify_gen_dleq() {
    let G = &dalek_constants::RISTRETTO_BASEPOINT_POINT;
    let H = RistrettoPoint::hash_from_bytes::<Sha512>(G.compress().as_bytes());

    create_nipk!{dleq, (x), (A, B, G, H) : A = (G * x), B = (H * x) }

    let x = Scalar::from(89327492234u64);
    let A = G * &x;
    let B = &H * &x;

    let publics = dleq::Publics {
        A: &A,
        B: &B,
        G: G,
        H: &H,
    };
    let secrets = dleq::Secrets { x: &x };

    let mut transcript = Transcript::new(b"DLEQTest");
    let proof = dleq::Proof::create(&mut transcript, publics, secrets);
    // serialize to bincode representation
    let proof_bytes = bincode::serialize(&proof).unwrap();
    // parse bytes back to memory
    let parsed_proof: dleq::Proof = bincode::deserialize(&proof_bytes).unwrap();

    let mut transcript = Transcript::new(b"DLEQTest");
    assert!(parsed_proof.verify(&mut transcript, publics).is_ok());
}

#[cfg(all(feature = "bench", test))]
mod bench {
    use super::*;

    extern crate sha2;
    extern crate test;

    use self::sha2::Sha512;
    use self::test::Bencher;

    use curve25519_dalek::constants as dalek_constants;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use curve25519_dalek::scalar::Scalar;

    #[bench]
    fn create_gen_dleq(b: &mut Bencher) {
        let G = &dalek_constants::RISTRETTO_BASEPOINT_POINT;
        let H = RistrettoPoint::hash_from_bytes::<Sha512>(G.compress().as_bytes());

        create_nipk!{dleq, (x), (A, B, G, H) : A = (G * x), B = (H * x) }

        let x = Scalar::from(89327492234u64);
        let A = G * &x;
        let B = &H * &x;

        let publics = dleq::Publics {
            A: &A,
            B: &B,
            G: G,
            H: &H,
        };
        let secrets = dleq::Secrets { x: &x };

        b.iter(|| {
            let mut transcript = Transcript::new(b"DLEQBenchCreate");
            dleq::Proof::create(&mut transcript, publics, secrets)
        });
    }

    #[bench]
    fn verify_gen_dleq(b: &mut Bencher) {
        let G = &dalek_constants::RISTRETTO_BASEPOINT_POINT;
        let H = RistrettoPoint::hash_from_bytes::<Sha512>(G.compress().as_bytes());

        create_nipk!{dleq, (x), (A, B, G, H) : A = (G * x), B = (H * x) }

        let x = Scalar::from(89327492234u64);
        let A = G * &x;
        let B = &H * &x;

        let publics = dleq::Publics {
            A: &A,
            B: &B,
            G: G,
            H: &H,
        };
        let secrets = dleq::Secrets { x: &x };

        let mut transcript = Transcript::new(b"DLEQBenchVerify");
        let proof = dleq::Proof::create(&mut transcript, publics, secrets);
        b.iter(|| {
            let mut transcript = Transcript::new(b"DLEQBenchVerify");
            proof.verify(&mut transcript, publics).is_ok()
        });
    }
}
