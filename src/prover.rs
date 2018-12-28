use rand::thread_rng;

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::MultiscalarMul;

use crate::Transcript;

use super::constraints::*;
use super::proofs::*;

pub struct Prover<'a> {
    transcript: &'a mut Transcript,
    scalars: Vec<Scalar>,
    points: Vec<RistrettoPoint>,
    point_labels: Vec<&'static [u8]>,
    constraints: Vec<(PointVar, Vec<(ScalarVar, PointVar)>)>,
}

#[derive(Copy, Clone)]
pub struct ScalarVar(usize);
#[derive(Copy, Clone)]
pub struct PointVar(usize);

impl<'a> Prover<'a> {
    pub fn new(proof_label: &[u8], transcript: &'a mut Transcript) -> Self {
        transcript.domain_sep(proof_label);
        Prover {
            transcript,
            scalars: Vec::default(),
            points: Vec::default(),
            point_labels: Vec::default(),
            constraints: Vec::default(),
        }
    }

    pub fn allocate_scalar(&mut self, label: &'static [u8], assignment: Scalar) -> ScalarVar {
        // XXX not a good idea to commit to transcript? means all impls have to alloc in the same order
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

    pub fn prove_compact(mut self) -> CompactProof {
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
}

impl<'a> SchnorrCS for Prover<'a> {
    type ScalarVar = ScalarVar;
    type PointVar = PointVar;

    fn constrain(&mut self, lhs: PointVar, linear_combination: Vec<(ScalarVar, PointVar)>) {
        self.constraints.push((lhs, linear_combination));
    }
}
