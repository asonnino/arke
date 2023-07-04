use arke_core::ARKEError;
use fastcrypto::error::FastCryptoError;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{Digest, Epoch, PublicKey, Version};

#[macro_export]
macro_rules! bail {
    ($e:expr) => {
        return Err($e)
    };
}

#[macro_export(local_inner_macros)]
macro_rules! ensure {
    ($cond:expr, $e:expr) => {
        if !($cond) {
            bail!($e);
        }
    };
}

/// Convenient result wrappers.
pub type MessageResult<T> = Result<T, MessageError>;

/// Errors triggered when parsing and verifying protocol messages.
#[derive(Debug, Error, Serialize, Deserialize)]
pub enum MessageError {
    #[error("Malformed notification id {0:?}")]
    MalformedId(Digest),

    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("Message signed by unknown authority {0}")]
    UnknownAuthority(PublicKey),

    #[error("Authority {0} appears in quorum more than once")]
    AuthorityReuse(PublicKey),

    #[error("Received certificate without a quorum")]
    CertificateRequiresQuorum,

    #[error("Failed to deserialize message ({0})")]
    SerializationError(String),

    #[error("Crypto function has failed ({0})")]
    CryptoError(String),

    #[error("Not enough partial keys")]
    MissingPartialKeys,

    #[error("The message does not contain a Key proof")]
    MissingKeyProof,

    #[error("Could not add session info to the transcript: {0}")]
    TranscriptError(String),
}

impl From<signature::Error> for MessageError {
    fn from(error: signature::Error) -> Self {
        MessageError::InvalidSignature(error.to_string())
    }
}

impl From<FastCryptoError> for MessageError {
    fn from(error: FastCryptoError) -> Self {
        MessageError::InvalidSignature(error.to_string())
    }
}

impl From<eyre::Report> for MessageError {
    fn from(error: eyre::Report) -> Self {
        MessageError::InvalidSignature(error.to_string())
    }
}

impl From<Box<bincode::ErrorKind>> for MessageError {
    fn from(error: Box<bincode::ErrorKind>) -> Self {
        MessageError::SerializationError(error.to_string())
    }
}

impl From<ARKEError> for MessageError {
    fn from(error: ARKEError) -> Self {
        MessageError::CryptoError(error.to_string())
    }
}

impl From<std::io::Error> for MessageError {
    fn from(err: std::io::Error) -> Self {
        Self::TranscriptError(err.to_string())
    }
}

/// Convenient result wrappers.
pub type AuthorityResult<T> = Result<T, AuthorityError>;

/// Errors triggered when parsing and verifying protocol messages.
#[derive(Debug, Error, Serialize, Deserialize)]
pub enum AuthorityError {
    #[error(transparent)]
    MessageError(#[from] MessageError),

    #[error("Invalid transaction epoch: {received:} != {expected:}")]
    InvalidEpoch { received: Epoch, expected: Epoch },

    #[error("Invalid transaction version: {received:} != {expected:}")]
    InvalidVersion {
        received: Version,
        expected: Version,
    },

    #[error("Receiving transaction {received:} conflicting with {persisted:}")]
    ConflictingTransaction { received: Digest, persisted: Digest },

    #[error("Unknown registrar: {0:?}")]
    UnknownRegistrar(Vec<u8>),

    #[error("This authority does not support operation '{0}'")]
    UnsupportedOperation(String),
}
