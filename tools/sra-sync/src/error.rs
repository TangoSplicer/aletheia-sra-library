#[derive(Error, Debug)]
pub enum SraError {
    // ... prior errors ...
    #[error("Identity Missing: Practitioner details are required for legal attestation")]
    IdentityMissing,

    #[error("Cryptographic Failure: {0}")]
    CryptoError(String),

    #[error("Signature Verification Failed: The verified manifest has been tampered with")]
    TamperDetected,
}
