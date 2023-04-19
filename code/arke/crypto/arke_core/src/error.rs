use aes_gcm::aes::cipher::InvalidLength;
use ark_relations::r1cs::SynthesisError;
use proof_essentials::error::CryptoError;
use thiserror::Error;

#[derive(Debug, Error)]
/// Error type
pub enum ARKEError {
    #[error("signature verification failed")]
    VerificationFailed,

    /// A hashing error
    #[error("hashing error {0}")]
    HashError(#[from] hash_functions::HashError),

    /// Error signalling that the threshold was not met
    #[error("Too few values were presented")]
    ThresholdNotMet,

    /// Error signalling that the threshold is greater than n/2
    #[error("Threshold value t is greater than n/2")]
    TooManyAdversaries,

    #[error("secret sharing error {0}")]
    SecretSharingError(#[from] secret_sharing::SSError),

    #[error("Serialization error {0}")]
    SerializationError(#[from] ark_serialize::SerializationError),

    #[error("this library is work in progress. Functionality yet to be implemented")]
    WIP,

    #[error("The credentials provided are not valid")]
    InvalidCredentials,

    #[error("Cannot compute a shared key for an ID and itself")]
    IdenticalIDs,

    #[error("Failed to build the circuit: missing {0}")]
    BuildError(String),

    #[error("Synthesis error {0}")]
    SynthesisError(#[from] SynthesisError),

    #[error("IoError: {0}")]
    IoError(String),

    #[error("Error using the ZKP library {0}")]
    ZKPError(#[from] CryptoError),

    #[error("AEAD Key length error {0}")]
    AEADKeyLengthError(String),

    #[error("AES-GCM Error {0}")]
    AESGCMError(String),
}

impl From<std::io::Error> for ARKEError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err.to_string())
    }
}

impl From<aes_gcm::Error> for ARKEError {
    fn from(err: aes_gcm::Error) -> Self {
        Self::AESGCMError(err.to_string())
    }
}

impl From<InvalidLength> for ARKEError {
    fn from(err: InvalidLength) -> Self {
        Self::AESGCMError(err.to_string())
    }
}
