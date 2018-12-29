use rand::thread_rng;
use std::iter;

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;

use crate::Transcript;

use super::constraints::*;
use super::proofs::*;

pub struct Verifier<'a> {
    transcript: &'a mut Transcript,
    num_scalars: usize,
    points: Vec<CompressedRistretto>,
    point_labels: Vec<&'static [u8]>,
    constraints: Vec<(PointVar, Vec<(ScalarVar, PointVar)>)>,
}

#[derive(Copy, Clone)]
pub struct ScalarVar(usize);
#[derive(Copy, Clone)]
pub struct PointVar(usize);

impl<'a> Verifier<'a> {
    pub fn new(proof_label: &[u8], transcript: &'a mut Transcript) -> Self {
        transcript.domain_sep(proof_label);
        Verifier {
            transcript,
            num_scalars: 0,
            points: Vec::default(),
            point_labels: Vec::default(),
            constraints: Vec::default(),
        }
    }

    pub fn allocate_scalar(&mut self, label: &'static [u8]) -> ScalarVar {
        self.transcript.commit_scalar_var(label);
        self.num_scalars += 1;
        ScalarVar(self.num_scalars - 1)
    }

    pub fn allocate_point(
        &mut self,
        label: &'static [u8],
        assignment: CompressedRistretto,
    ) -> PointVar {
        self.transcript.commit_point_var(label, &assignment);
        self.points.push(assignment);
        self.point_labels.push(label);
        PointVar(self.points.len() - 1)
    }

    pub fn verify_compact(self, proof: &CompactProof) -> Result<(), ()> {
        // Recompute the prover's commitments based on their claimed challenge value:
        let minus_c = -proof.challenge;

        self.transcript.commit_bytes(b"commitments", b"");
        for (lhs_var, rhs_lc) in &self.constraints {
            let commitment = RistrettoPoint::optional_multiscalar_mul(
                rhs_lc
                    .iter()
                    .map(|(sc_var, _pt_var)| proof.responses[sc_var.0])
                    .chain(iter::once(minus_c)),
                rhs_lc
                    .iter()
                    .map(|(_sc_var, pt_var)| self.points[pt_var.0].decompress())
                    .chain(iter::once(self.points[lhs_var.0].decompress())),
            )
            .ok_or(())?;
            self.transcript
                .commit_blinding_commitment(self.point_labels[lhs_var.0], &commitment.compress());
        }

        // Recompute the challenge and check if it's the claimed one
        let challenge = self.transcript.get_challenge(b"chal");

        if challenge == proof.challenge {
            Ok(())
        } else {
            Err(())
        }
    }

    pub fn verify_batchable(self, proof: &BatchableProof) -> Result<(), ()> {
        // Feed the prover's commitments into the transcript:
        self.transcript.commit_bytes(b"commitments", b"");
        for (i, commitment) in proof.commitments.iter().enumerate() {
            let (ref lhs_var, ref rhs_lc) = self.constraints[i];
            self.transcript
                .commit_blinding_commitment(self.point_labels[lhs_var.0], &commitment);
        }

        let minus_c = -self.transcript.get_challenge(b"chal");

        let points = self
            .points
            .iter()
            .map(|point| point.decompress().ok_or(()))
            .collect::<Result<Vec<_>, _>>()?;

        for (i, commitment) in proof.commitments.iter().enumerate() {
            let (ref lhs_var, ref rhs_lc) = self.constraints[i];
            let expected = commitment.decompress().ok_or(())?;
            let recomputed = RistrettoPoint::vartime_multiscalar_mul(
                rhs_lc
                    .iter()
                    .map(|(sc_var, _pt_var)| proof.responses[sc_var.0])
                    .chain(iter::once(minus_c)),
                rhs_lc
                    .iter()
                    .map(|(_sc_var, pt_var)| points[pt_var.0])
                    .chain(iter::once(points[lhs_var.0])),
            );

            if expected != recomputed {
                panic!();
                return Err(());
            }
        }
        Ok(())
    }
}

impl<'a> SchnorrCS for Verifier<'a> {
    type ScalarVar = ScalarVar;
    type PointVar = PointVar;

    fn constrain(&mut self, lhs: PointVar, linear_combination: Vec<(ScalarVar, PointVar)>) {
        self.constraints.push((lhs, linear_combination));
    }
}
