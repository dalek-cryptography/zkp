use curve25519_dalek::scalar::Scalar;

pub struct CompactProof {
    pub challenge: Scalar,
    pub responses: Vec<Scalar>,
}
