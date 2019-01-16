use rand::thread_rng;

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::MultiscalarMul;

use crate::Transcript;

use super::constraints::*;
use super::proofs::*;

#[derive(Copy, Clone)]
pub struct ScalarVar(usize);
#[derive(Copy, Clone)]
pub struct PointVar(usize);

pub struct CommonProver {
    proof_label: &'static [u8],
    points: Vec<RistrettoPoint>,
    compressed_points: Vec<CompressedRistretto>,
    point_labels: Vec<&'static [u8]>,
}

pub struct ProverBuilder(CommonProver);

pub struct Prover<'a> {
    transcript: &'a mut Transcript,
    scalars: Vec<Scalar>,
    points: Vec<RistrettoPoint>,
    point_labels: Vec<&'static [u8]>,
    constraints: Vec<(PointVar, Vec<(ScalarVar, PointVar)>)>,
}

impl CommonProver {
    pub fn new(proof_label: &'static [u8]) -> CommonProver {
        CommonProver {
            proof_label,
            points: Vec::new(),
            compressed_points: Vec::new(),
            point_labels: Vec::new(),
        }
    }

    pub fn allocate_point(&mut self, label: &'static [u8], assignment: RistrettoPoint) -> PointVar {
        self.points.push(assignment);
        self.compressed_points.push(assignment.compress());
        self.point_labels.push(label);

        PointVar(self.points.len() - 1)
    }
}

impl From<CommonProver> for ProverBuilder {
    fn from(common: CommonProver) -> ProverBuilder {
        ProverBuilder(common)
    }
}

impl ProverBuilder {
    fn new_prover<'a>(self, transcript: &'a mut Transcript) -> Prover<'a> {
        transcript.domain_sep(self.0.proof_label);

        let it = Iterator::zip(self.0.point_labels.iter(), self.0.compressed_points.iter());
        for (label, point) in it {
            transcript.commit_point_var(label, point);
        }

        Prover {
            transcript,
            scalars: Vec::new(),
            points: self.0.points.clone(),
            point_labels: self.0.point_labels.clone(),
            constraints: Vec::new(),
        }
    }
}

impl<'a> Prover<'a> {
    pub fn new(proof_label: &'static [u8], transcript: &'a mut Transcript) -> Self {
        ProverBuilder::from(CommonProver::new(proof_label)).new_prover(transcript)
    }

    pub fn allocate_scalar(&mut self, label: &'static [u8], assignment: Scalar) -> ScalarVar {
        self.transcript.commit_scalar_var(label);
        self.scalars.push(assignment);
        ScalarVar(self.scalars.len() - 1)
    }

    pub fn allocate_point(
        &mut self,
        label: &'static [u8],
        assignment: RistrettoPoint,
    ) -> (PointVar, CompressedRistretto) {
        let compressed = assignment.compress();
        self.transcript.commit_point_var(label, &compressed);
        self.points.push(assignment);
        self.point_labels.push(label);
        (PointVar(self.points.len() - 1), compressed)
    }

    pub fn prove_compact(self) -> CompactProof {
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
        self.transcript.commit_bytes(b"commitments", b"");
        for (lhs_var, rhs_lc) in &self.constraints {
            let commitment = RistrettoPoint::multiscalar_mul(
                rhs_lc.iter().map(|(sc_var, _pt_var)| blindings[sc_var.0]),
                rhs_lc.iter().map(|(_sc_var, pt_var)| self.points[pt_var.0]),
            );
            self.transcript
                .commit_blinding_commitment(self.point_labels[lhs_var.0], &commitment.compress());
        }

        // Obtain a scalar challenge and compute responses
        let challenge = self.transcript.get_challenge(b"chal");
        let responses = Iterator::zip(self.scalars.iter(), blindings.iter())
            .map(|(s, b)| s * challenge + b)
            .collect::<Vec<Scalar>>();

        CompactProof {
            challenge,
            responses,
        }
    }

    pub fn prove_batchable(self) -> BatchableProof {
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
        self.transcript.commit_bytes(b"commitments", b"");

        let mut commitments = Vec::with_capacity(self.constraints.len());
        for (lhs_var, rhs_lc) in &self.constraints {
            let commitment = RistrettoPoint::multiscalar_mul(
                rhs_lc.iter().map(|(sc_var, _pt_var)| blindings[sc_var.0]),
                rhs_lc.iter().map(|(_sc_var, pt_var)| self.points[pt_var.0]),
            )
            .compress();

            self.transcript
                .commit_blinding_commitment(self.point_labels[lhs_var.0], &commitment);
            commitments.push(commitment);
        }

        // Obtain a scalar challenge and compute responses
        let challenge = self.transcript.get_challenge(b"chal");
        let responses = Iterator::zip(self.scalars.iter(), blindings.iter())
            .map(|(s, b)| s * challenge + b)
            .collect::<Vec<Scalar>>();

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
