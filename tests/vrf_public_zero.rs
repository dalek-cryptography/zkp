// We really want points to be capital letters and scalars to be
// lowercase letters
#![allow(non_snake_case)]

#[macro_use]
extern crate zkp;

use curve25519_dalek::constants as dalek_constants;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use zkp::Transcript;

define_proof! {
    testproof,
    "Test Proof",
    (s, a, b, c),
    (W, X, Y, Z),
    (B):
    Z = (s*B + a*W + b*X + c*Y)
}

// Test the generation and verification of the proof where (W,X,Y) =
// (w*B, x*B, y*B) and B is the Ristretto generator.  This situation
// comes up in the issuing protocol of CMZ14 credentials, where w, x,
// and y are the (public) attributes on the credential being issued.
pub fn test_issue(w: &Scalar, x: &Scalar, y: &Scalar) {
    let B: RistrettoPoint = dalek_constants::RISTRETTO_BASEPOINT_POINT;

    // Public points based on the public attributes
    let (W, X, Y) = (w*B, x*B, y*B);

    let mut rng = rand::thread_rng();
    // Private coefficients (the prover's MAC key)
    let a = Scalar::random(&mut rng);
    let b = Scalar::random(&mut rng);
    let c = Scalar::random(&mut rng);
    let s = Scalar::random(&mut rng);

    // (Part of the) public MAC
    let Z = s*B + a*W + b*X + c*Y;

    // Construct the proof
    let mut prv_transcript = Transcript::new(b"test transcript");
    let pi = testproof::prove_compact(
        &mut prv_transcript,
        testproof::ProveAssignments {
            B: &B,
            W: &W,
            X: &X,
            Y: &Y,
            Z: &Z,
            a: &a,
            b: &b,
            c: &c,
            s: &s,
        },
    )
    .0;

    // Send (Z, pi) to the verifier

    // The verifier will recompute W, Y, Z as above and then verify:

    let mut vrf_transcript = Transcript::new(b"test transcript");
    let result =  testproof::verify_compact(
        &pi,
        &mut vrf_transcript,
        testproof::VerifyAssignments {
            B: &B.compress(),
            W: &W.compress(),
            X: &X.compress(),
            Y: &Y.compress(),
            Z: &Z.compress(),
        },
    );

    assert!(result.is_ok());
}

#[test]
fn test_nozero() {
    let mut rng = rand::thread_rng();
    let w = Scalar::random(&mut rng);
    let x = Scalar::random(&mut rng);
    let y = Scalar::random(&mut rng);
    test_issue(&w, &x, &y);
}

#[test]
fn test_zero() {
    let mut rng = rand::thread_rng();
    let w = Scalar::random(&mut rng);
    let x = Scalar::ZERO;
    let y = Scalar::random(&mut rng);
    test_issue(&w, &x, &y);
}

