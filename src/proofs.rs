use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;

/// A Schnorr proof in compact format.
#[derive(Clone, Serialize, Deserialize)]
pub struct CompactProof {
    pub challenge: Scalar,
    pub responses: Vec<Scalar>,
}

/// A Schnorr proof in batchable format.
#[derive(Clone, Serialize, Deserialize)]
pub struct BatchableProof {
    pub commitments: Vec<CompressedRistretto>,
    pub responses: Vec<Scalar>,
}
