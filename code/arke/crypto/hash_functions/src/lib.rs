use std::fmt::Debug;

use thiserror::Error;

mod blake2xs;
pub use blake2xs::Blake2Xs;

mod hash_to_curve;
pub use hash_to_curve::{HashToCurve, PoseidonTryAndIncrement, TryAndIncrement};

mod poseidonperm_x5_377_3;
pub use poseidonperm_x5_377_3::poseidon377_parameters;

pub mod proof_gadgets;

mod utils;
pub use utils::*;

/// Interface for a fixed-length hash, output length in specified in bytes.
pub trait FixedLengthHash {
    type Error: Debug;

    fn hash(
        domain: &[u8],
        message: &[u8],
        output_size_in_bytes: usize,
    ) -> Result<Vec<u8>, Self::Error>;
}

#[derive(Debug, Error)]
/// Error type
pub enum HashError {
    /// An IO error
    #[error("io error {0}")]
    IoError(#[from] std::io::Error),

    /// Error while hashing
    #[error("error in hasher {0}")]
    HashingError(#[from] Box<dyn std::error::Error>),

    /// Personalization string cannot be larger than 8 bytes
    #[error("domain length is too large: {0}")]
    DomainTooLarge(usize),

    /// Hashing to curve failed
    #[error("Could not hash to curve")]
    HashToCurveError,

    /// Serialization error in Zexe
    #[error(transparent)]
    SerializationError(#[from] ark_serialize::SerializationError),
}
