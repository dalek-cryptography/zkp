use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;

use merlin::Transcript;

pub trait SchnorrCS {
    type ScalarVar: Copy;
    type PointVar: Copy;

    fn constrain(
        &mut self,
        lhs: Self::PointVar,
        linear_combination: Vec<(Self::ScalarVar, Self::PointVar)>,
    );
}

pub trait TranscriptProtocol {
    fn domain_sep(&mut self, label: &[u8]);
    fn commit_scalar_var(&mut self, label: &'static [u8]);
    fn commit_point_var(&mut self, label: &'static [u8], point: &CompressedRistretto);
    fn commit_blinding_commitment(&mut self, label: &'static [u8], point: &CompressedRistretto);
    fn get_challenge(&mut self, label: &[u8]) -> Scalar;
}

impl TranscriptProtocol for Transcript {
    fn domain_sep(&mut self, label: &[u8]) {
        self.commit_bytes(b"zkp dom-sep", label);
    }

    fn commit_scalar_var(&mut self, label: &'static [u8]) {
        self.commit_bytes(b"scvar", label);
    }

    fn commit_point_var(&mut self, label: &'static [u8], point: &CompressedRistretto) {
        self.commit_bytes(b"ptvar", label);
        self.commit_bytes(b"val", point.as_bytes());
    }

    fn commit_blinding_commitment(&mut self, label: &'static [u8], point: &CompressedRistretto) {
        self.commit_bytes(b"blinding", label);
        self.commit_bytes(b"val", point.as_bytes());
    }

    fn get_challenge(&mut self, label: &[u8]) -> Scalar {
        let mut bytes = [0; 64];
        self.challenge_bytes(b"chal", &mut bytes);
        Scalar::from_bytes_mod_order_wide(&bytes)
    }
}
