use std::fmt::Debug;

use ark_std::rand::Rng;
use thiserror::Error;

pub mod shamir_secret_sharing;
pub use shamir_secret_sharing::ShamirSecretSharing;

pub trait SecretSharingScheme {
    type Secret;
    type SecretShare;
    type Error: Debug;

    fn generate_shares<R: Rng>(
        secret: &Self::Secret,
        number_of_participants: usize,
        threshold: usize,
        rng: &mut R,
    ) -> Result<Vec<Self::SecretShare>, Self::Error>;

    fn combine_shares(
        shares: &[Self::SecretShare],
        threshold: usize,
    ) -> Result<Self::Secret, Self::Error>;
}

#[derive(Debug, Error)]
pub enum SSError {
    #[error("Unable to generate the secret shares")]
    ShareGenerationError,

    #[error("Not enough values provided")]
    ThresholdNotMet,

    #[error("Attempted to access a value outside of the range")]
    IndexOutOfRange,

    #[error("Tried to invert an element that has no inverse")]
    NoInverse,
}
