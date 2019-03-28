#[derive(Debug, Fail)]
pub enum ProofError {
    #[fail(display = "Verification failed.")]
    VerificationFailure,
    #[fail(display = "Mismatched parameter sizes for batch verification.")]
    BatchSizeMismatch,
}
