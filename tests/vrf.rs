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

extern crate rand;
use rand::{thread_rng, CryptoRng, RngCore};

extern crate curve25519_dalek;
use curve25519_dalek::constants as dalek_constants;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;

#[macro_use]
extern crate zkp;
pub use zkp::Transcript;

define_proof! {vrf_proof, "VRF", (x), (A, G, H), (B) : A = (x * B), G = (x * H) }

trait VrfTranscriptProtocol {
    fn append_message(&mut self, message: &[u8]);
    fn hash_to_group(self) -> RistrettoPoint;
}

impl VrfTranscriptProtocol for Transcript {
    fn append_message(&mut self, message: &[u8]) {
        self.commit_bytes(b"msg", message);
    }
    fn hash_to_group(mut self) -> RistrettoPoint {
        let mut bytes = [0u8; 64];
        self.challenge_bytes(b"output", &mut bytes);
        RistrettoPoint::from_uniform_bytes(&bytes)
    }
}

/// A VRF secret key.
#[derive(Clone)]
pub struct SecretKey(Scalar);

impl SecretKey {
    fn new<R: RngCore + CryptoRng>(rng: &mut R) -> SecretKey {
        SecretKey(Scalar::random(rng))
    }
}

/// A VRF public key.
#[derive(Copy, Clone)]
pub struct PublicKey(RistrettoPoint, CompressedRistretto);

impl<'a> From<&'a SecretKey> for PublicKey {
    fn from(sk: &'a SecretKey) -> PublicKey {
        let pk = &sk.0 * &dalek_constants::RISTRETTO_BASEPOINT_TABLE;
        PublicKey(pk, pk.compress())
    }
}

/// A VRF keypair.
pub struct KeyPair {
    sk: SecretKey,
    pk: PublicKey,
}

impl From<SecretKey> for KeyPair {
    fn from(sk: SecretKey) -> KeyPair {
        let pk = PublicKey::from(&sk);
        KeyPair { sk, pk }
    }
}

/// The output of a VRF.
pub struct VrfOutput(CompressedRistretto);

impl VrfOutput {
    fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

pub struct VrfProof(vrf_proof::CompactProof);

impl KeyPair {
    fn public_key(&self) -> PublicKey {
        self.pk
    }

    fn vrf(
        &self,
        mut function_transcript: Transcript,
        message: &[u8],
        proof_transcript: &mut Transcript,
    ) -> (VrfOutput, VrfProof) {
        // Use function_transcript to hash the message to a point H
        function_transcript.append_message(message);
        let H = function_transcript.hash_to_group();

        // Compute the VRF output G and form a proof
        let G = &H * &self.sk.0;
        let (proof, points) = vrf_proof::prove_compact(
            proof_transcript,
            vrf_proof::ProveAssignments {
                x: &self.sk.0,
                A: &self.pk.0,
                B: &dalek_constants::RISTRETTO_BASEPOINT_POINT,
                G: &G,
                H: &H,
            },
        );

        (VrfOutput(points.G), VrfProof(proof))
    }
}

impl VrfOutput {
    fn verify(
        &self,
        mut function_transcript: Transcript,
        message: &[u8],
        pubkey: &PublicKey,
        proof_transcript: &mut Transcript,
        proof: &VrfProof,
    ) -> Result<(), ()> {
        // Use function_transcript to hash the message to a point H
        function_transcript.append_message(message);
        let H = function_transcript.hash_to_group().compress();

        vrf_proof::verify_compact(
            &proof.0,
            proof_transcript,
            vrf_proof::VerifyAssignments {
                A: &pubkey.1,
                B: &dalek_constants::RISTRETTO_BASEPOINT_COMPRESSED,
                G: &self.0,
                H: &H,
            },
        )
    }
}

#[test]
fn create_and_verify_vrf() {
    let domain_sep = b"My VRF Application";
    let msg1 = b"Test Message 1";
    let msg2 = b"Test Message 2";

    let kp1 = KeyPair::from(SecretKey::new(&mut thread_rng()));
    let pk1 = kp1.public_key();
    let kp2 = KeyPair::from(SecretKey::new(&mut thread_rng()));
    let pk2 = kp2.public_key();

    let (output1, proof1) = kp1.vrf(
        Transcript::new(domain_sep),
        &msg1[..],
        &mut Transcript::new(domain_sep),
    );

    let (output2, proof2) = kp2.vrf(
        Transcript::new(domain_sep),
        &msg2[..],
        &mut Transcript::new(domain_sep),
    );

    // Check that each VRF output was correctly produced
    assert!(output1
        .verify(
            Transcript::new(domain_sep),
            msg1,
            &pk1,
            &mut Transcript::new(domain_sep),
            &proof1,
        )
        .is_ok());
    assert!(output2
        .verify(
            Transcript::new(domain_sep),
            msg2,
            &pk2,
            &mut Transcript::new(domain_sep),
            &proof2,
        )
        .is_ok());

    // Check that verification with the wrong pubkey fails
    assert!(output1
        .verify(
            Transcript::new(domain_sep),
            msg1,
            &pk2, // swap pubkey
            &mut Transcript::new(domain_sep),
            &proof1,
        )
        .is_err());
    assert!(output2
        .verify(
            Transcript::new(domain_sep),
            msg2,
            &pk1, // swap pubkey
            &mut Transcript::new(domain_sep),
            &proof2,
        )
        .is_err());

    // Check that verification with the wrong output fails
    assert!(output2 // swap output
        .verify(
            Transcript::new(domain_sep),
            msg1,
            &pk1,
            &mut Transcript::new(domain_sep),
            &proof1,
        )
        .is_err());
    assert!(output1 // swap output
        .verify(
            Transcript::new(domain_sep),
            msg2,
            &pk2,
            &mut Transcript::new(domain_sep),
            &proof2,
        )
        .is_err());

    // Check that verification with the wrong domain separator fails
    assert!(output1
        .verify(
            Transcript::new(domain_sep),
            msg1,
            &pk1,
            &mut Transcript::new(b"A different application"), // swap dom-sep
            &proof1,
        )
        .is_err());
    assert!(output2
        .verify(
            Transcript::new(domain_sep),
            msg2,
            &pk2,
            &mut Transcript::new(b"A different application"), // swap dom-sep
            &proof2,
        )
        .is_err());
}
