use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;

use merlin::Transcript;

use errors::ProofError;

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
    /// Appends `label` to the transcript as a domain separator.
    fn domain_sep(&mut self, label: &'static [u8]);

    /// Append the `label` for a scalar variable to the transcript.
    ///
    /// Note: this does not commit its assignment, which is secret,
    /// and only serves to bind the proof to the variable allocations.
    fn append_scalar_var(&mut self, label: &'static [u8]);

    /// Append a point variable to the transcript, for use by a prover.
    ///
    /// Returns the compressed point encoding to allow reusing the
    /// result of the encoding computation; the return value can be
    /// discarded if it's unused.
    fn append_point_var(
        &mut self,
        label: &'static [u8],
        point: &RistrettoPoint,
    ) -> CompressedRistretto;

    /// Check that point variable is not the identity and
    /// append it to the transcript, for use by a verifier.
    ///
    /// Returns `Ok(())` if the point is not the identity point (and
    /// therefore generates the full ristretto255 group).
    ///
    /// Using this function prevents small-subgroup attacks.
    fn validate_and_append_point_var(
        &mut self,
        label: &'static [u8],
        point: &CompressedRistretto,
    ) -> Result<(), ProofError>;

    /// Append a blinding factor commitment to the transcript, for use by
    /// a prover.
    ///
    /// Returns the compressed point encoding to allow reusing the
    /// result of the encoding computation; the return value can be
    /// discarded if it's unused.
    fn append_blinding_commitment(
        &mut self,
        label: &'static [u8],
        point: &RistrettoPoint,
    ) -> CompressedRistretto;

    /// Check that a blinding factor commitment is not the identity and
    /// commit it to the transcript, for use by a verifier.
    ///
    /// Returns `Ok(())` if the point is not the identity point (and
    /// therefore generates the full ristretto255 group).
    ///
    /// Using this function prevents small-subgroup attacks.
    fn validate_and_append_blinding_commitment(
        &mut self,
        label: &'static [u8],
        point: &CompressedRistretto,
    ) -> Result<(), ProofError>;

    /// Get a scalar challenge from the transcript.
    fn get_challenge(&mut self, label: &'static [u8]) -> Scalar;
}

impl TranscriptProtocol for Transcript {
    fn domain_sep(&mut self, label: &'static [u8]) {
        self.commit_bytes(b"dom-sep", b"schnorrzkp/1.0/ristretto255");
        self.commit_bytes(b"dom-sep", label);
    }

    fn append_scalar_var(&mut self, label: &'static [u8]) {
        self.commit_bytes(b"scvar", label);
    }

    fn append_point_var(
        &mut self,
        label: &'static [u8],
        point: &RistrettoPoint,
    ) -> CompressedRistretto {
        let encoding = point.compress();
        self.commit_bytes(b"ptvar", label);
        self.commit_bytes(b"val", encoding.as_bytes());
        encoding
    }

    fn validate_and_append_point_var(
        &mut self,
        label: &'static [u8],
        point: &CompressedRistretto,
    ) -> Result<(), ProofError> {
        if point.is_identity() {
            return Err(ProofError::VerificationFailure);
        }
        self.commit_bytes(b"ptvar", label);
        self.commit_bytes(b"val", point.as_bytes());
        Ok(())
    }

    fn append_blinding_commitment(
        &mut self,
        label: &'static [u8],
        point: &RistrettoPoint,
    ) -> CompressedRistretto {
        let encoding = point.compress();
        self.commit_bytes(b"blindcom", label);
        self.commit_bytes(b"val", encoding.as_bytes());
        encoding
    }

    fn validate_and_append_blinding_commitment(
        &mut self,
        label: &'static [u8],
        point: &CompressedRistretto,
    ) -> Result<(), ProofError> {
        if point.is_identity() {
            return Err(ProofError::VerificationFailure);
        }
        self.commit_bytes(b"blindcom", label);
        self.commit_bytes(b"val", point.as_bytes());
        Ok(())
    }

    fn get_challenge(&mut self, label: &'static [u8]) -> Scalar {
        let mut bytes = [0; 64];
        self.challenge_bytes(label, &mut bytes);
        Scalar::from_bytes_mod_order_wide(&bytes)
    }
}
