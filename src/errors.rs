/// An error during proving or verification, such as a verification failure.
#[derive(Debug, Fail)]
pub enum ProofError {
    /// Something is wrong with the proof, causing a verification failure.
    #[fail(display = "Verification failed.")]
    VerificationFailure,
    /// Occurs during batch verification if the batch parameters are mis-sized.
    #[fail(display = "Mismatched parameter sizes for batch verification.")]
    BatchSizeMismatch,
}
