use rand::{thread_rng, Rng};
use std::iter;

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{IsIdentity, VartimeMultiscalarMul};

use crate::Transcript;

use super::constraints::*;
use super::proofs::*;

pub struct BatchVerifier<'a> {
    transcripts: Vec<&'a mut Transcript>,
    num_scalars: usize,

    shared_points: Vec<CompressedRistretto>,
    shared_point_labels: Vec<&'static [u8]>,

    perproof_points: Vec<Vec<CompressedRistretto>>,
    perproof_point_labels: Vec<&'static [u8]>,

    constraints: Vec<(PointVar, Vec<(ScalarVar, PointVar)>)>,
}

#[derive(Copy, Clone)]
pub struct ScalarVar(usize);

#[derive(Copy, Clone)]
pub enum PointVar {
    Shared(usize),
    PerProof(usize),
}

impl<'a> BatchVerifier<'a> {
    pub fn new(proof_label: &[u8], mut transcripts: Vec<&'a mut Transcript>) -> Self {
        for i in 0..transcripts.len() {
            transcripts[i].domain_sep(proof_label);
        }
        BatchVerifier {
            transcripts,
            num_scalars: 0,
            shared_points: Vec::default(),
            shared_point_labels: Vec::default(),
            perproof_points: Vec::default(),
            perproof_point_labels: Vec::default(),
            constraints: Vec::default(),
        }
    }

    pub fn allocate_scalar(&mut self, label: &'static [u8]) -> ScalarVar {
        for transcript in self.transcripts.iter_mut() {
            transcript.commit_scalar_var(label);
        }
        self.num_scalars += 1;
        ScalarVar(self.num_scalars - 1)
    }

    pub fn allocate_shared_point(
        &mut self,
        label: &'static [u8],
        assignment: CompressedRistretto,
    ) -> PointVar {
        for transcript in self.transcripts.iter_mut() {
            transcript.commit_point_var(label, &assignment);
        }
        self.shared_points.push(assignment);
        self.shared_point_labels.push(label);

        PointVar::Shared(self.shared_points.len() - 1)
    }

    pub fn allocate_perproof_point(
        &mut self,
        label: &'static [u8],
        assignments: Vec<CompressedRistretto>,
    ) -> PointVar {
        {
            // nll
            let it = Iterator::zip(self.transcripts.iter_mut(), assignments.iter());
            for (transcript, assignment) in it {
                transcript.commit_point_var(label, &assignment);
            }
        }
        self.perproof_points.push(assignments);
        self.perproof_point_labels.push(label);

        PointVar::PerProof(self.perproof_points.len() - 1)
    }

    pub fn verify_batchable(self, proofs: &[BatchableProof]) -> Result<(), ()> {
        unimplemented!();
    }
}

impl<'a> SchnorrCS for BatchVerifier<'a> {
    type ScalarVar = ScalarVar;
    type PointVar = PointVar;

    fn constrain(&mut self, lhs: PointVar, linear_combination: Vec<(ScalarVar, PointVar)>) {
        self.constraints.push((lhs, linear_combination));
    }
}
