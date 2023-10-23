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

define_proof! {sig_proof, "Sig", (x), (A), (B) : A = (x * B) }
define_proof! {vrf_proof, "VRF", (x), (A, G, H), (B) : A = (x * B), G = (x * H) }

/// Defines how the construction interacts with the transcript.
trait TranscriptProtocol {
    fn append_message_example(&mut self, message: &[u8]);
    fn hash_to_group(self) -> RistrettoPoint;
}

impl TranscriptProtocol for Transcript {
    fn append_message_example(&mut self, message: &[u8]) {
        self.append_message(b"msg", message);
    }
    fn hash_to_group(mut self) -> RistrettoPoint {
        let mut bytes = [0u8; 64];
        self.challenge_bytes(b"output", &mut bytes);
        RistrettoPoint::from_uniform_bytes(&bytes)
    }
}

#[derive(Clone)]
pub struct SecretKey(Scalar);

impl SecretKey {
    fn new<R: RngCore + CryptoRng>(rng: &mut R) -> SecretKey {
        SecretKey(Scalar::random(rng))
    }
}

#[derive(Copy, Clone)]
pub struct PublicKey(RistrettoPoint, CompressedRistretto);

impl<'a> From<&'a SecretKey> for PublicKey {
    fn from(sk: &'a SecretKey) -> PublicKey {
        let pk = &sk.0 * dalek_constants::RISTRETTO_BASEPOINT_TABLE;
        PublicKey(pk, pk.compress())
    }
}

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

pub struct Signature(sig_proof::BatchableProof);

pub struct VrfOutput(CompressedRistretto);

pub struct VrfProof(vrf_proof::CompactProof);

impl KeyPair {
    fn public_key(&self) -> PublicKey {
        self.pk
    }

    fn sign(&self, message: &[u8], sig_transcript: &mut Transcript) -> Signature {
        sig_transcript.append_message_example(message);
        let (proof, _points) = sig_proof::prove_batchable(
            sig_transcript,
            sig_proof::ProveAssignments {
                x: &self.sk.0,
                A: &self.pk.0,
                B: &dalek_constants::RISTRETTO_BASEPOINT_POINT,
            },
        );

        Signature(proof)
    }

    #[allow(non_snake_case)]
    fn vrf(
        &self,
        mut function_transcript: Transcript,
        message: &[u8],
        proof_transcript: &mut Transcript,
    ) -> (VrfOutput, VrfProof) {
        // Use function_transcript to hash the message to a point H
        function_transcript.append_message_example(message);
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

impl Signature {
    fn verify(
        &self,
        message: &[u8],
        pubkey: &PublicKey,
        sig_transcript: &mut Transcript,
    ) -> Result<(), ()> {
        sig_transcript.append_message_example(message);
        sig_proof::verify_batchable(
            &self.0,
            sig_transcript,
            sig_proof::VerifyAssignments {
                A: &pubkey.1,
                B: &dalek_constants::RISTRETTO_BASEPOINT_COMPRESSED,
            },
        )
        .map_err(|_discard_error_info_in_test_code| ())
    }
}

impl VrfOutput {
    #[allow(non_snake_case)]
    fn verify(
        &self,
        mut function_transcript: Transcript,
        message: &[u8],
        pubkey: &PublicKey,
        proof_transcript: &mut Transcript,
        proof: &VrfProof,
    ) -> Result<(), ()> {
        // Use function_transcript to hash the message to a point H
        function_transcript.append_message_example(message);
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
        .map_err(|_discard_error_info_in_test_code| ())
    }
}

#[test]
fn create_and_verify_sig() {
    let domain_sep = b"My Sig Application";
    let msg1 = b"Test Message 1";
    let msg2 = b"Test Message 2";

    let kp1 = KeyPair::from(SecretKey::new(&mut thread_rng()));
    let pk1 = kp1.public_key();
    let kp2 = KeyPair::from(SecretKey::new(&mut thread_rng()));
    let pk2 = kp2.public_key();

    let sig1 = kp1.sign(&msg1[..], &mut Transcript::new(domain_sep));

    let sig2 = kp2.sign(&msg2[..], &mut Transcript::new(domain_sep));

    // Check that each signature verifies
    assert!(sig1
        .verify(msg1, &pk1, &mut Transcript::new(domain_sep),)
        .is_ok());
    assert!(sig2
        .verify(msg2, &pk2, &mut Transcript::new(domain_sep),)
        .is_ok());

    // Check that verification with the wrong pubkey fails
    assert!(sig1
        .verify(msg1, &pk2, &mut Transcript::new(domain_sep),)
        .is_err());
    assert!(sig2
        .verify(msg2, &pk1, &mut Transcript::new(domain_sep),)
        .is_err());

    // Check that verification with the wrong message fails
    assert!(sig1
        .verify(msg2, &pk1, &mut Transcript::new(domain_sep),)
        .is_err());
    assert!(sig2
        .verify(msg1, &pk2, &mut Transcript::new(domain_sep),)
        .is_err());

    // Check that verification with the wrong domain separator fails
    assert!(sig1
        .verify(msg1, &pk1, &mut Transcript::new(b"Wrong"),)
        .is_err());
    assert!(sig2
        .verify(msg2, &pk2, &mut Transcript::new(b"Wrong"),)
        .is_err());
}

#[test]
#[ignore]
fn create_and_verify_bigsig() {
    let domain_sep = b"My Sig Application";
    let mut large_msg = Vec::new();
    large_msg.resize((u32::max_value() as usize) + 250, 1u8);

    let kp = KeyPair::from(SecretKey::new(&mut thread_rng()));
    let pk = kp.public_key();

    let sig = kp.sign(&large_msg[..], &mut Transcript::new(domain_sep));

    // Check that the signature verifies (& doesn't panic inside Merlin)
    assert!(sig
        .verify(&large_msg[..], &pk, &mut Transcript::new(domain_sep),)
        .is_ok());
}

#[test]
fn counterparty_signature_chain() {
    let domain_sep = b"Counterparty Example";

    let msg1a = b"In this test, two counterparties exchange signatures.";
    let msg2a = b"However, the counterparties sign and verify messages";
    let msg1b = b"using stateful transcript objects.";
    let msg2b = b"When party 1 signs, the party 1 transcript changes;";
    let msg1c = b"when party 2 verifies, the party 2 transcript syncs.";
    let msg2c = b"In this way, the transcript states ratchet stateful signatures.";

    let kp1 = KeyPair::from(SecretKey::new(&mut thread_rng()));
    let pk1 = kp1.public_key();
    let kp2 = KeyPair::from(SecretKey::new(&mut thread_rng()));
    let pk2 = kp2.public_key();

    let mut trans1 = Transcript::new(domain_sep);
    let mut trans2 = Transcript::new(domain_sep);

    // Round a, Party 1 -----> Party 2
    let sig1a = kp1.sign(&msg1a[..], &mut trans1);
    assert!(sig1a.verify(msg1a, &pk1, &mut trans2).is_ok());
    // Round a, Party 2 -----> Party 1
    let sig2a = kp2.sign(&msg2a[..], &mut trans2);
    assert!(sig2a.verify(msg2a, &pk2, &mut trans1).is_ok());

    // Round b, Party 1 -----> Party 2
    let sig1b = kp1.sign(&msg1b[..], &mut trans1);
    assert!(sig1b.verify(msg1b, &pk1, &mut trans2).is_ok());
    // Round b, Party 2 -----> Party 1
    let sig2b = kp2.sign(&msg2b[..], &mut trans2);
    assert!(sig2b.verify(msg2b, &pk2, &mut trans1).is_ok());

    // Round c, Party 1 -----> Party 2
    let sig1c = kp1.sign(&msg1c[..], &mut trans1);
    assert!(sig1c.verify(msg1c, &pk1, &mut trans2).is_ok());
    // Round c, Party 2 -----> Party 1
    let sig2c = kp2.sign(&msg2c[..], &mut trans2);
    assert!(sig2c.verify(msg2c, &pk2, &mut trans1).is_ok());
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
