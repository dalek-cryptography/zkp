use rand::{thread_rng, Rng};
use std::iter;

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{IsIdentity, VartimeMultiscalarMul};

use crate::Transcript;

use super::constraints::*;
use super::proofs::*;

use util::Matrix;

pub struct BatchVerifier<'a> {
    batch_size: usize,
    transcripts: Vec<&'a mut Transcript>,

    num_scalars: usize,

    static_points: Vec<CompressedRistretto>,
    static_point_labels: Vec<&'static [u8]>,

    instance_points: Vec<Vec<CompressedRistretto>>,
    instance_point_labels: Vec<&'static [u8]>,

    constraints: Vec<(PointVar, Vec<(ScalarVar, PointVar)>)>,
}

#[derive(Copy, Clone)]
pub struct ScalarVar(usize);

#[derive(Copy, Clone)]
pub enum PointVar {
    Static(usize),
    Instance(usize),
}

impl<'a> BatchVerifier<'a> {
    pub fn new(
        proof_label: &[u8],
        batch_size: usize,
        mut transcripts: Vec<&'a mut Transcript>,
    ) -> Result<Self, &'static str> {
        if transcripts.len() != batch_size {
            return Err("transcripts do not match batch size");
        }
        for i in 0..transcripts.len() {
            transcripts[i].domain_sep(proof_label);
        }
        Ok(BatchVerifier {
            batch_size,
            transcripts,
            num_scalars: 0,
            static_points: Vec::default(),
            static_point_labels: Vec::default(),
            instance_points: Vec::default(),
            instance_point_labels: Vec::default(),
            constraints: Vec::default(),
        })
    }

    pub fn allocate_scalar(&mut self, label: &'static [u8]) -> ScalarVar {
        for transcript in self.transcripts.iter_mut() {
            transcript.commit_scalar_var(label);
        }
        self.num_scalars += 1;
        ScalarVar(self.num_scalars - 1)
    }

    pub fn allocate_static_point(
        &mut self,
        label: &'static [u8],
        assignment: CompressedRistretto,
    ) -> PointVar {
        for transcript in self.transcripts.iter_mut() {
            transcript.commit_point_var(label, &assignment);
        }
        self.static_points.push(assignment);
        self.static_point_labels.push(label);

        PointVar::Static(self.static_points.len() - 1)
    }

    pub fn allocate_instance_point(
        &mut self,
        label: &'static [u8],
        assignments: Vec<CompressedRistretto>,
    ) -> Result<PointVar, &'static str> {
        if assignments.len() != self.batch_size {
            return Err("assignments len does not match batch size");
        }
        // nll
        {
            let it = Iterator::zip(self.transcripts.iter_mut(), assignments.iter());
            for (transcript, assignment) in it {
                transcript.commit_point_var(label, &assignment);
            }
        }
        self.instance_points.push(assignments);
        self.instance_point_labels.push(label);

        Ok(PointVar::Instance(self.instance_points.len() - 1))
    }

    pub fn verify_batchable(mut self, proofs: &[BatchableProof]) -> Result<(), &'static str> {
        if proofs.len() != self.batch_size {
            return Err("proofs len does not match batch size");
        }

        for proof in proofs {
            if proof.commitments.len() != self.constraints.len() {
                return Err("proof does not have correct num of commitments");
            }
            if proof.responses.len() != self.num_scalars {
                return Err("proof does not have correct num of responses");
            }
        }

        // Feed each prover's commitments into their respective transcript
        for j in 0..self.batch_size {
            self.transcripts[j].commit_bytes(b"commitments", b"");
            for (i, com) in proofs[j].commitments.iter().enumerate() {
                let label = match self.constraints[i].0 {
                    PointVar::Static(var_idx) => self.static_point_labels[var_idx],
                    PointVar::Instance(var_idx) => self.instance_point_labels[var_idx],
                };
                self.transcripts[j].commit_blinding_commitment(label, &com);
            }
        }

        // Compute the challenge value for each proof
        let minus_c = self
            .transcripts
            .iter_mut()
            .map(|trans| -trans.get_challenge(b"chal"))
            .collect::<Vec<_>>();

        let num_s = self.static_points.len();
        let num_i = self.instance_points.len();
        let num_c = self.constraints.len();

        let mut static_coeffs = vec![Scalar::zero(); num_s];
        let mut instance_coeffs = Matrix::<Scalar>::new(num_i + num_c, self.batch_size);

        for i in 0..num_c {
            let (ref lhs_var, ref rhs_lc) = self.constraints[i];
            for j in 0..self.batch_size {
                let random_factor = Scalar::from(thread_rng().gen::<u128>());

                // rand*( sum(P_i, resp_i) - c * Q - Q_com) == 0

                instance_coeffs[(num_i + i, j)] -= random_factor;

                match lhs_var {
                    PointVar::Static(var_idx) => {
                        static_coeffs[*var_idx] += random_factor * minus_c[j];
                    }
                    PointVar::Instance(var_idx) => {
                        instance_coeffs[(*var_idx, j)] += random_factor * minus_c[j];
                    }
                }

                for (sc_var, pt_var) in rhs_lc {
                    let resp = proofs[j].responses[sc_var.0];
                    match pt_var {
                        PointVar::Static(var_idx) => {
                            static_coeffs[*var_idx] += random_factor * resp;
                        }
                        PointVar::Instance(var_idx) => {
                            instance_coeffs[(*var_idx, j)] += random_factor * resp;
                        }
                    }
                }
            }
        }

        let mut instance_points = self.instance_points.clone();
        for i in 0..num_c {
            let ith_commitments = proofs.iter().map(|proof| proof.commitments[i]);
           instance_points.push(ith_commitments.collect());
        }

        let flat_instance_points = instance_points
            .iter()
            .flat_map(|inner| inner.iter().cloned())
            .collect::<Vec<CompressedRistretto>>();

        let check = RistrettoPoint::optional_multiscalar_mul(
            static_coeffs
                .iter()
                .chain(instance_coeffs.row_major_entries()),
            self.static_points
                .iter()
                .chain(flat_instance_points.iter())
                .map(|pt| pt.decompress()),
        )
        .ok_or("failed decompression in verify")?;

        if check.is_identity() {
            Ok(())
        } else {
            Err("bad verify")
        }
    }
}

impl<'a> SchnorrCS for BatchVerifier<'a> {
    type ScalarVar = ScalarVar;
    type PointVar = PointVar;

    fn constrain(&mut self, lhs: PointVar, linear_combination: Vec<(ScalarVar, PointVar)>) {
        self.constraints.push((lhs, linear_combination));
    }
}
