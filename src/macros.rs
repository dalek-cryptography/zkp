// -*- coding: utf-8; mode: rust; -*-
//
// To the extent possible under law, the authors have waived all
// copyright and related or neighboring rights to zkp,
// using the Creative Commons "CC0" public domain dedication.  See
// <http://creativecommons.org/publicdomain/zero/1.0/> for full
// details.
//
// Authors:
// - Henry de Valence <hdevalence@hdevalence.ca>

#[doc(hidden)]
#[macro_export]
macro_rules! __compute_formula_constraint {
    // Unbracket a statement
    (($public_vars:ident, $secret_vars:ident) ($($x:tt)*)) => {
        // Add a trailing +
        __compute_formula_constraint!(($public_vars,$secret_vars) $($x)* +)
    };
    // Inner part of the formula: give a list of &Scalars
    // Since there's a trailing +, we can just generate the list as normal...
    (($public_vars:ident, $secret_vars:ident)
     $( $scalar:ident * $point:ident +)+ ) => {
        vec![ $( ($secret_vars.$scalar , $public_vars.$point), )* ]
    };
}

/// Creates a module with code required to produce a non-interactive
/// zero-knowledge proof statement, to serialize it to wire format, to
/// parse from wire format, and to verify the proof or batch-verify
/// multiple proofs.
///
/// The statement is specified in an embedded DSL resembling
/// Camenisch-Stadler notation.  For instance, a proof of knowledge of
/// two equal discrete logarithms ("DLEQ") is specified as:
///
/// ```rust,ignore
/// define_proof! {dleq, "DLEQ Proof", (x), (A, B, H), (G) : A = (x * G), B = (x * H) }
/// ```
///
/// This creates a module `dleq` with code for proving knowledge of a
/// secret `x: Scalar` such that `A = x * G`, `B = x * H` for
/// per-proof public parameters `A, B, H: RistrettoPoint` and common
/// parameters `G: RistrettoPoint`; the UTF-8 string `"DLEQ Proof"` is
/// added to the transcript as a domain separator.
///
/// In general the syntax is
/// ```rust,ignore
/// define_proof!{
///     module_name,   // all generated code for this statement goes here
///     "Proof Label", // a UTF-8 domain separator unique to the statement
///     (x,y,z,...),   // secret variable labels (preferably lower-case)
///     (A,B,C,...),   // public per-proof parameter labels (upper-case)
///     (G,H,...)      // public common parameter labels (upper-case)
///     :
///     LHS = (x * A + y * B + z * C + ... ),  // comma-separated statements
///     ...
/// }
/// ```
///
/// Statements have the form `LHS = (A * x + B * y + C * z + ... )`,
/// where `LHS` is one of the points listed as a public parameter, and
/// the right-hand side is a sum of public points multiplied by secret
/// scalars.
///
/// Points which have the same assignment for all instances of the
/// proof statement (for instance, a basepoint) should be specified as
/// common public parameters, so that the generated implementation of
/// batch verification is more efficient.
///
/// Proof creation is done in constant time.  Proof verification uses
/// variable-time code.
#[macro_export]
macro_rules! define_proof {
    (
        $proof_module_name:ident // Name of the module to create
        ,
        $proof_label_string:expr // A string literal, used as a domain separator
        ,
        ( $($secret_var:ident),+ ) // Secret variables, sep by commas
        ,
        ( $($instance_var:ident),* ) // Public instance variables, separated by commas
        ,
        ( $($common_var:ident),* ) // Public common variables, separated by commas
        :
        // List of statements to prove
        // Format: LHS = ( ... RHS expr ... ),
        $($lhs:ident = $statement:tt),+
    ) => {
        /// An auto-generated Schnorr proof implementation.
        ///
        /// Proofs are created using `prove_compact` or
        /// `prove_batchable`, producing `CompactProof`s or
        /// `BatchableProof`s respectively.  These are verified
        /// using `verify_compact` and `verify_batchable`;
        /// `BatchableProofs` can also be batch-verified using
        /// `batch_verify`, but they have slightly larger proof
        /// sizes compared to `CompactProof`s.
        ///
        /// The internal details of the proof statement are accessible
        /// in the `internals` module.  While this is not necessary
        /// to create and verify proofs, the it can be used with the
        /// lower-level constraint system API to manually combine
        /// statements from different proofs.
        #[allow(non_snake_case)]
        pub mod $proof_module_name {
            use $crate::curve25519_dalek::scalar::Scalar;
            use $crate::curve25519_dalek::ristretto::RistrettoPoint;
            use $crate::curve25519_dalek::ristretto::CompressedRistretto;

            use $crate::toolbox::prover::Prover;
            use $crate::toolbox::verifier::Verifier;

            pub use $crate::merlin::Transcript;
            pub use $crate::{CompactProof, BatchableProof, ProofError};

            /// The generated [`internal`] module contains lower-level
            /// functions at the level of the Schnorr constraint
            /// system API.
            pub mod internal {
                use $crate::toolbox::SchnorrCS;

                /// The proof label committed to the transcript as a domain separator.
                pub const PROOF_LABEL: &'static str = $proof_label_string;

                /// A container type that holds transcript labels for secret variables.
                pub struct TranscriptLabels {
                    $( pub $secret_var: &'static str, )+
                    $( pub $instance_var: &'static str, )+
                    $( pub $common_var: &'static str, )+
                }

                /// The transcript labels used for each secret variable.
                pub const TRANSCRIPT_LABELS: TranscriptLabels = TranscriptLabels {
                    $( $secret_var: stringify!($secret_var), )+
                    $( $instance_var: stringify!($instance_var), )+
                    $( $common_var: stringify!($common_var), )+
                };

                /// A container type that simulates named parameters for [`proof_statement`].
                #[derive(Copy, Clone)]
                pub struct SecretVars<CS: SchnorrCS> {
                    $( pub $secret_var: CS::ScalarVar, )+
                }

                /// A container type that simulates named parameters for [`proof_statement`].
                #[derive(Copy, Clone)]
                pub struct PublicVars<CS: SchnorrCS> {
                    $( pub $instance_var: CS::PointVar, )+
                    $( pub $common_var: CS::PointVar, )+
                }

                /// The underlying proof statement generated by the macro invocation.
                ///
                /// This function exists separately from the proving
                /// and verification functions to allow composition of
                /// different proof statements with common variable
                /// assignments.
                pub fn proof_statement<CS: SchnorrCS>(
                    cs: &mut CS,
                    secrets: SecretVars<CS>,
                    publics: PublicVars<CS>,
                ) {
                    $(
                        cs.constrain(
                            publics.$lhs,
                            __compute_formula_constraint!( (publics, secrets) $statement ),
                        );
                    )+
                }
            }

            /// Named parameters for [`prove_compact`] and [`prove_batchable`].
            #[derive(Copy, Clone)]
            pub struct ProveAssignments<'a> {
                $(pub $secret_var: &'a Scalar,)+
                $(pub $instance_var: &'a RistrettoPoint,)+
                $(pub $common_var: &'a RistrettoPoint,)+
            }

            /// Named parameters for [`verify_compact`] and [`verify_batchable`].
            #[derive(Copy, Clone)]
            pub struct VerifyAssignments<'a> {
                $(pub $instance_var: &'a CompressedRistretto,)+
                $(pub $common_var: &'a CompressedRistretto,)+
            }

            /// Point encodings computed during proving and returned to allow reuse.
            ///
            /// This is used to allow a prover to avoid having to
            /// re-compress points used in the proof that may be
            /// necessary to supply to the verifier.
            #[derive(Copy, Clone)]
            pub struct CompressedPoints {
                $(pub $instance_var: CompressedRistretto,)+
                $(pub $common_var: CompressedRistretto,)+
            }

            /// Named parameters for [`batch_verify`].
            #[derive(Clone)]
            pub struct BatchVerifyAssignments {
                $(pub $instance_var: Vec<CompressedRistretto>,)+
                $(pub $common_var: CompressedRistretto,)+
            }

            fn build_prover<'a>(
                transcript: &'a mut Transcript,
                assignments: ProveAssignments,
            ) -> (Prover<'a>, CompressedPoints) {
                use self::internal::*;
                use $crate::toolbox::prover::*;

                let mut prover = Prover::new(PROOF_LABEL.as_bytes(), transcript);

                let secret_vars = SecretVars {
                    $(
                        $secret_var: prover.allocate_scalar(
                            TRANSCRIPT_LABELS.$secret_var.as_bytes(),
                            *assignments.$secret_var,
                        ),
                    )+
                };

                struct VarPointPairs {
                    $( pub $instance_var: (PointVar, CompressedRistretto), )+
                    $( pub $common_var: (PointVar, CompressedRistretto), )+
                }

                let pairs = VarPointPairs {
                    $(
                        $instance_var: prover.allocate_point(
                            TRANSCRIPT_LABELS.$instance_var.as_bytes(),
                            *assignments.$instance_var,
                        ),
                    )+
                    $(
                        $common_var: prover.allocate_point(
                            TRANSCRIPT_LABELS.$common_var.as_bytes(),
                            *assignments.$common_var,
                        ),
                    )+
                };

                // XXX return compressed points
                let public_vars = PublicVars {
                    $($instance_var: pairs.$instance_var.0,)+
                    $($common_var: pairs.$common_var.0,)+
                };

                let compressed = CompressedPoints {
                    $($instance_var: pairs.$instance_var.1,)+
                    $($common_var: pairs.$common_var.1,)+
                };

                proof_statement(&mut prover, secret_vars, public_vars);

                (prover, compressed)
            }

            /// Given a transcript and assignments to secret and public variables, produce a proof in compact format.
            pub fn prove_compact(
                transcript: &mut Transcript,
                assignments: ProveAssignments,
            ) -> (CompactProof, CompressedPoints) {
                let (prover, compressed) = build_prover(transcript, assignments);

                (prover.prove_compact(), compressed)
            }

            /// Given a transcript and assignments to secret and public variables, produce a proof in batchable format.
            pub fn prove_batchable(
                transcript: &mut Transcript,
                assignments: ProveAssignments,
            ) -> (BatchableProof, CompressedPoints) {
                let (prover, compressed) = build_prover(transcript, assignments);

                (prover.prove_batchable(), compressed)
            }

            fn build_verifier<'a>(
                transcript: &'a mut Transcript,
                assignments: VerifyAssignments,
            ) -> Result<Verifier<'a>, ProofError> {
                use self::internal::*;
                use $crate::toolbox::verifier::*;

                let mut verifier = Verifier::new(PROOF_LABEL.as_bytes(), transcript);

                let secret_vars = SecretVars {
                    $($secret_var: verifier.allocate_scalar(TRANSCRIPT_LABELS.$secret_var.as_bytes()),)+
                };

                let public_vars = PublicVars {
                    $(
                        $instance_var: verifier.allocate_public_point(
                            TRANSCRIPT_LABELS.$instance_var.as_bytes(),
                            *assignments.$instance_var,
                        )?,
                    )+
                    $(
                        $common_var: verifier.allocate_point(
                            TRANSCRIPT_LABELS.$common_var.as_bytes(),
                            *assignments.$common_var,
                        )?,
                    )+
                };

                proof_statement(&mut verifier, secret_vars, public_vars);

                Ok(verifier)
            }

            /// Given a transcript and assignments to public variables, verify a proof in compact format.
            pub fn verify_compact(
                proof: &CompactProof,
                transcript: &mut Transcript,
                assignments: VerifyAssignments,
            ) -> Result<(), ProofError> {
                let verifier = build_verifier(transcript, assignments)?;

                verifier.verify_compact(proof)
            }

            /// Given a transcript and assignments to public variables, verify a proof in batchable format.
            pub fn verify_batchable(
                proof: &BatchableProof,
                transcript: &mut Transcript,
                assignments: VerifyAssignments,
            ) -> Result<(), ProofError> {
                let verifier = build_verifier(transcript, assignments)?;

                verifier.verify_batchable(proof)
            }

            /// Verify a batch of proofs, given a batch of transcripts and a batch of assignments.
            pub fn batch_verify(
                proofs: &[BatchableProof],
                transcripts: Vec<&mut Transcript>,
                assignments: BatchVerifyAssignments,
            ) -> Result<(), ProofError> {
                use self::internal::*;
                use $crate::toolbox::batch_verifier::*;

                let batch_size = proofs.len();

                let mut verifier = BatchVerifier::new(PROOF_LABEL.as_bytes(), batch_size, transcripts)?;

                let secret_vars = SecretVars {
                    $($secret_var: verifier.allocate_scalar(TRANSCRIPT_LABELS.$secret_var.as_bytes()),)+
                };

                let public_vars = PublicVars {
                    $(
                        $instance_var: verifier.allocate_instance_point(
                            TRANSCRIPT_LABELS.$instance_var.as_bytes(),
                            assignments.$instance_var,
                        )?,
                    )+
                    $(
                        $common_var: verifier.allocate_static_point(
                            TRANSCRIPT_LABELS.$common_var.as_bytes(),
                            assignments.$common_var,
                        )?,
                    )+
                };

                proof_statement(&mut verifier, secret_vars, public_vars);

                verifier.verify_batchable(proofs)
            }

            #[cfg(all(feature = "bench", test))]
            mod bench {
                use super::*;
                use $crate::rand::thread_rng;

                extern crate test;
                use self::test::Bencher;

                #[bench]
                fn prove(b: &mut Bencher) {
                    let mut rng = thread_rng();

                    struct RandomAssignments {
                        $(pub $secret_var: Scalar,)+
                        $(pub $instance_var: RistrettoPoint,)+
                        $(pub $common_var: RistrettoPoint,)+
                    }

                    let assignments = RandomAssignments {
                        $($secret_var: Scalar::random(&mut rng),)+
                        $($instance_var: RistrettoPoint::random(&mut rng),)+
                        $($common_var: RistrettoPoint::random(&mut rng),)+
                    };

                    // Proving is constant time, so it shouldn't matter
                    // that the relation is not satisfied by random assignments.
                    b.iter(|| {
                        let mut trans = Transcript::new(b"Benchmark");
                        prove_compact(&mut trans, ProveAssignments {
                            $($secret_var: &assignments.$secret_var,)+
                            $($instance_var: &assignments.$instance_var,)+
                            $($common_var: &assignments.$common_var,)+
                        })
                    });
                }

                #[bench]
                fn verify_compact_proof(b: &mut Bencher) {
                    let mut rng = thread_rng();

                    struct RandomAssignments {
                        $(pub $secret_var: Scalar,)+
                        $(pub $instance_var: RistrettoPoint,)+
                        $(pub $common_var: RistrettoPoint,)+
                    }

                    let assignments = RandomAssignments {
                        $($secret_var: Scalar::random(&mut rng),)+
                        $($instance_var: RistrettoPoint::random(&mut rng),)+
                        $($common_var: RistrettoPoint::random(&mut rng),)+
                    };

                    let mut trans = Transcript::new(b"Benchmark");
                    let (proof, points) = prove_compact(&mut trans, ProveAssignments {
                        $($secret_var: &assignments.$secret_var,)+
                        $($instance_var: &assignments.$instance_var,)+
                        $($common_var: &assignments.$common_var,)+
                    });

                    // The proof is well-formed but invalid, so the
                    // compact verification should fall through to the
                    // final check on the recomputed challenge, and
                    // therefore verification failure should not affect
                    // timing.
                    b.iter(|| {
                        let mut trans = Transcript::new(b"Benchmark");
                        verify_compact(&proof, &mut trans, VerifyAssignments {
                            $($instance_var: &points.$instance_var,)+
                            $($common_var: &points.$common_var,)+
                        })
                    });
                }

                #[bench]
                fn verify_batchable_proof(b: &mut Bencher) {
                    let mut rng = thread_rng();

                    struct RandomAssignments {
                        $(pub $secret_var: Scalar,)+
                        $(pub $instance_var: RistrettoPoint,)+
                        $(pub $common_var: RistrettoPoint,)+
                    }

                    let assignments = RandomAssignments {
                        $($secret_var: Scalar::random(&mut rng),)+
                        $($instance_var: RistrettoPoint::random(&mut rng),)+
                        $($common_var: RistrettoPoint::random(&mut rng),)+
                    };

                    let mut trans = Transcript::new(b"Benchmark");
                    let (proof, points) = prove_batchable(&mut trans, ProveAssignments {
                        $($secret_var: &assignments.$secret_var,)+
                        $($instance_var: &assignments.$instance_var,)+
                        $($common_var: &assignments.$common_var,)+
                    });

                    // The proof is well-formed but invalid, so the
                    // batchable verification should perform the check and
                    // see a non-identity point.  So verification failure
                    // should not affect timing.
                    b.iter(|| {
                        let mut trans = Transcript::new(b"Benchmark");
                        verify_batchable(&proof, &mut trans, VerifyAssignments {
                            $($instance_var: &points.$instance_var,)+
                            $($common_var: &points.$common_var,)+
                        })
                    });
                }
            }
        }
    }
}
