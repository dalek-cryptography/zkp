//! Contains lower-level tools that allow programmable specification
//! of proof statements.
//!
//! The higher-level [`define_proof`] macro allows declarative
//! specification of static proof statements, and expands into code
//! that uses this lower-level API.  This lower-level API can also be
//! used directly to perform imperative specification of proof
//! statements, allowing proof statements with runtime parameters
//! (e.g., an anonymous credential with a variable number of
//! attributes).
//!
//! The `SchnorrCS` trait defines the common constraint system API
//! used for specifying proof statements; it is implemented by the
//! `Prover`, `Verifier`, and `BatchVerifier` structs.
//!
//! Roughly speaking, the tools fit together in the following way:
//!
//! * Statements are defined as generic functions which take a
//! `SchnorrCS` implementation and some variables,
//! and add the proof statements to the constraint system;
//!
//! * To create a proof, construct a `Prover`,
//! allocate and assign variables, pass the prover and the variables
//! to the generic statement function, then consume the prover to
//! obtain a proof.
//!
//! * To verify a proof, construct a `Verifier`,
//! allocate and assign variables, pass the verifier and the variables
//! to the generic statement function, then consume the verifier to
//! obtain a verification result.
//!
//! Note that the expansion of the [`define_proof`] macro contains a
//! public `internal` module with the generated proof statement
//! function, making it possible to combine generated and hand-crafted
//! proof statements into the same constraint system.

/// Implements proof creation.
pub mod prover;
/// Implements proof verification of compact and batchable proofs.
pub mod verifier;
/// Implements batch verification of batchable proofs.
pub mod batch_verifier;

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;

use crate::{Transcript, ProofError};

/// An interface for specifying proof statements, common between
/// provers and verifiers.
///
/// The variables for the constraint system are provided as associated
/// types, allowing different implementations to have different point
/// and scalar types.  For instance, the batch verifier has two types
/// of point variables, one for points common to all proofs in the
/// batch, and one for points varying per-proof.
///
/// This is why variable allocation is *not* included in the trait, as
/// different roles may have different behaviour -- for instance, a
/// prover needs to supply assignments to the scalar variables, but
/// a verifier doesn't have access to the prover's secret scalars.
///
/// To specify a proof statement using this trait, write a generic
/// function that takes a constraint system as a parameter and adds
/// the statements.  For instance, to specify an equality of discrete
/// logarithms, one could write
/// ```rust,ignore
/// fn dleq_statement<CS: SchnorrCS>(
///     cs: &mut CS,
///     x: CS::ScalarVar,
///     A: CS::PointVar,
///     G: CS::PointVar,
///     B: CS::PointVar,
///     H: CS::PointVar,
/// ) {
///     cs.constrain(A, vec![(x, B)]);
///     cs.constrain(G, vec![(x, H)]);
/// }
/// ```
///
/// This means that multiple statements can be added to the same
/// proof, independently of the specification of the statement, by
/// constructing a constraint system and then passing it to multiple
/// statement functions.
pub trait SchnorrCS {
    /// A handle for a scalar variable in the constraint system.
    type ScalarVar: Copy;
    /// A handle for a point variable in the constraint system.
    type PointVar: Copy;

    /// Add a constraint of the form `lhs = linear_combination`.
    fn constrain(
        &mut self,
        lhs: Self::PointVar,
        linear_combination: Vec<(Self::ScalarVar, Self::PointVar)>,
    );
}

/// This trait defines the wire format for how the constraint system
/// interacts with the proof transcript.
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
