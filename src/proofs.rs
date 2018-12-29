use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::CompressedRistretto;

pub struct CompactProof {
    pub challenge: Scalar,
    pub responses: Vec<Scalar>,
}

pub struct BatchableProof {
    pub commitments: Vec<CompressedRistretto>,
    pub responses: Vec<Scalar>,
}
