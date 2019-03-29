use rand::thread_rng;

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::MultiscalarMul;

use crate::{Transcript, CompactProof, BatchableProof};
use toolbox::{SchnorrCS, TranscriptProtocol};

/// Used to create proofs.
///
/// To use a [`Prover`], first construct one using [`Prover::new()`],
/// supplying a domain separation label, as well as the transcript to
/// operate on.
///
/// Then, allocate and assign secret ([`Prover::allocate_scalar`]) and
/// public ([`Prover::allocate_point`]) variables, and use those
/// variables to define the proof statements.
///
/// Finally, use [`Prover::prove_compact`] or
/// [`Prover::prove_batchable`] to consume the prover and produce a
/// proof.
pub struct Prover<'a> {
    transcript: &'a mut Transcript,
    scalars: Vec<Scalar>,
    points: Vec<RistrettoPoint>,
    point_labels: Vec<&'static [u8]>,
    constraints: Vec<(PointVar, Vec<(ScalarVar, PointVar)>)>,
}

/// A secret variable used during proving.
#[derive(Copy, Clone)]
pub struct ScalarVar(usize);
/// A public variable used during proving.
#[derive(Copy, Clone)]
pub struct PointVar(usize);

impl<'a> Prover<'a> {
    /// Construct a new prover.  The `proof_label` disambiguates proof
    /// statements.
    pub fn new(proof_label: &'static [u8], transcript: &'a mut Transcript) -> Self {
        transcript.domain_sep(proof_label);
        Prover {
            transcript,
            scalars: Vec::default(),
            points: Vec::default(),
            point_labels: Vec::default(),
            constraints: Vec::default(),
        }
    }

    /// Allocate and assign a secret variable with the given `label`.
    pub fn allocate_scalar(&mut self, label: &'static [u8], assignment: Scalar) -> ScalarVar {
        self.transcript.append_scalar_var(label);
        self.scalars.push(assignment);
        ScalarVar(self.scalars.len() - 1)
    }

    /// Allocate and assign a public variable with the given `label`.
    ///
    /// The point is compressed to be appended to the transcript, and
    /// the compressed point is returned to allow reusing the result
    /// of that computation; it can be safely discarded.
    pub fn allocate_point(
        &mut self,
        label: &'static [u8],
        assignment: RistrettoPoint,
    ) -> (PointVar, CompressedRistretto) {
        let compressed = self.transcript.append_point_var(label, &assignment);
        self.points.push(assignment);
        self.point_labels.push(label);
        (PointVar(self.points.len() - 1), compressed)
    }

    /// The compact and batchable proofs differ only by which data they store.
    fn prove_impl(self) -> (Scalar, Vec<Scalar>, Vec<CompressedRistretto>) {
        // Construct a TranscriptRng
        let mut rng_builder = self.transcript.build_rng();
        for scalar in &self.scalars {
            rng_builder = rng_builder.commit_witness_bytes(b"", scalar.as_bytes());
        }
        let mut transcript_rng = rng_builder.finalize(&mut thread_rng());

        // Generate a blinding factor for each secret variable
        let blindings = self
            .scalars
            .iter()
            .map(|_| Scalar::random(&mut transcript_rng))
            .collect::<Vec<Scalar>>();

        // Commit to each blinded LHS
        let mut commitments = Vec::with_capacity(self.constraints.len());
        for (lhs_var, rhs_lc) in &self.constraints {
            let commitment = RistrettoPoint::multiscalar_mul(
                rhs_lc.iter().map(|(sc_var, _pt_var)| blindings[sc_var.0]),
                rhs_lc.iter().map(|(_sc_var, pt_var)| self.points[pt_var.0]),
            );
            let encoding = self
                .transcript
                .append_blinding_commitment(self.point_labels[lhs_var.0], &commitment);

            commitments.push(encoding);
        }

        // Obtain a scalar challenge and compute responses
        let challenge = self.transcript.get_challenge(b"chal");
        let responses = Iterator::zip(self.scalars.iter(), blindings.iter())
            .map(|(s, b)| s * challenge + b)
            .collect::<Vec<Scalar>>();

        (challenge, responses, commitments)
    }

    /// Consume this prover to produce a compact proof.
    pub fn prove_compact(self) -> CompactProof {
        let (challenge, responses, _) = self.prove_impl();

        CompactProof {
            challenge,
            responses,
        }
    }

    /// Consume this prover to produce a batchable proof.
    pub fn prove_batchable(self) -> BatchableProof {
        let (_, responses, commitments) = self.prove_impl();

        BatchableProof {
            commitments,
            responses,
        }
    }
}

impl<'a> SchnorrCS for Prover<'a> {
    type ScalarVar = ScalarVar;
    type PointVar = PointVar;

    fn constrain(&mut self, lhs: PointVar, linear_combination: Vec<(ScalarVar, PointVar)>) {
        self.constraints.push((lhs, linear_combination));
    }
}
