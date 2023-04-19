pub mod credentials;
pub mod error;
pub mod sync;
pub mod write;

pub use credentials::{CredentialsRequest, PartialCredentials};
pub use error::{AuthorityError, AuthorityResult, MessageError, MessageResult};
use serde::{Deserialize, Serialize};
pub use sync::{Certificate, Vote};
pub use write::WriteTransaction;

pub const DIGEST_LEN: usize = 32;
pub type Digest = fastcrypto::hash::Digest<DIGEST_LEN>;
pub type KeyPair = fastcrypto::ed25519::Ed25519KeyPair;
pub type PublicKey = fastcrypto::ed25519::Ed25519PublicKey;
pub type Signature = fastcrypto::ed25519::Ed25519Signature;

pub type Key = arke_core::StoreKey;
pub type Value = arke_core::StoreValue;
pub type Version = u64;
pub type Epoch = u64;

/// The message sent by the clients to the authorities.
#[derive(Serialize, Deserialize, Debug)]
pub enum ClientToAuthorityMessage {
    WriteTransaction(WriteTransaction),
    Certificate(Certificate),
    CredentialsRequest(CredentialsRequest),
}

/// The (reply) message sent by the authorities to the client.
#[derive(Serialize, Deserialize, Debug)]
pub enum AuthorityToClientMessage {
    Vote(AuthorityResult<Vote>),
    Acknowledgement(AuthorityResult<Digest>),
    CredentialsIssuance(AuthorityResult<PartialCredentials>),
}

impl From<AuthorityResult<Vote>> for AuthorityToClientMessage {
    fn from(result: AuthorityResult<Vote>) -> Self {
        Self::Vote(result)
    }
}

impl From<AuthorityResult<Digest>> for AuthorityToClientMessage {
    fn from(result: AuthorityResult<Digest>) -> Self {
        Self::Acknowledgement(result)
    }
}

impl From<AuthorityResult<PartialCredentials>> for AuthorityToClientMessage {
    fn from(result: AuthorityResult<PartialCredentials>) -> Self {
        Self::CredentialsIssuance(result)
    }
}
