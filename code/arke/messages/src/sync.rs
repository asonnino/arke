use std::collections::HashSet;

use config::Committee;
use fastcrypto::{
    hash::Hash,
    traits::{Signer, VerifyingKey},
    Verifier,
};
use serde::{Deserialize, Serialize};

use crate::{
    bail, ensure,
    error::{MessageError, MessageResult},
    write::WriteTransaction,
    Digest, Epoch, Key, KeyPair, PublicKey, Signature, Version,
};

/// A vote over a write transaction.
#[derive(Serialize, Deserialize, Clone)]
pub struct Vote {
    /// The write transaction.
    pub transaction: WriteTransaction,
    /// The author (signer) of the vote.
    pub author: PublicKey,
    /// The signature over the transaction
    pub signature: Option<Signature>,
}

impl std::fmt::Debug for Vote {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "{}: V{}({}, {})",
            self.id(),
            self.version(),
            self.author,
            self.transaction.key
        )
    }
}

impl Vote {
    /// Create a new vote.
    pub fn new(transaction: WriteTransaction, author: PublicKey) -> Self {
        Self {
            transaction,
            author,
            signature: None,
        }
    }

    /// Sign the vote.
    pub fn sign(mut self, keypair: &KeyPair) -> Self {
        self.signature = Some(keypair.sign(&self.transaction.id.digest));
        self
    }

    /// Verify the vote.
    pub fn verify(&self) -> MessageResult<()> {
        // Ensure the transaction's digest is correctly formed.
        ensure!(
            &self.transaction.digest() == self.id(),
            MessageError::MalformedId(self.transaction.id)
        );

        // Check the vote's signature.
        match &self.signature {
            Some(signature) => self.author.verify(self.id().as_ref(), signature)?,
            None => bail!(MessageError::InvalidSignature("Missing signature".into())),
        }

        Ok(())
    }
}

/// Accessor methods.
impl Vote {
    pub fn id(&self) -> &Digest {
        &self.transaction.id
    }

    pub fn version(&self) -> &Version {
        &self.transaction.version
    }

    pub fn key(&self) -> &Key {
        &self.transaction.key
    }
}

/// A certificate over a write transaction.
#[derive(Serialize, Deserialize, Clone)]
pub struct Certificate {
    /// The certified write transaction.
    transaction: WriteTransaction,
    /// The votes over the transaction.
    pub votes: Vec<(PublicKey, Signature)>,
}

impl std::fmt::Debug for Certificate {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "{}: C{}({})", self.id(), self.version(), self.key())
    }
}

impl std::fmt::Display for Certificate {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "C{}({})", self.version(), self.key())
    }
}

/// Assemble a vector of valid votes into a certificate. This function panics if the vector is empty
/// or some of the votes are unsigned.
impl<Votes> From<(WriteTransaction, Votes)> for Certificate
where
    Votes: IntoIterator<Item = Vote>,
{
    fn from(content: (WriteTransaction, Votes)) -> Self {
        let (tx, votes) = content;
        Self::new(
            tx,
            votes
                .into_iter()
                .map(|x| (x.author, x.signature.unwrap()))
                .collect(),
        )
    }
}

impl Certificate {
    /// Create a new certificate.
    pub fn new(transaction: WriteTransaction, votes: Vec<(PublicKey, Signature)>) -> Self {
        Self { transaction, votes }
    }

    /// Verify the certificate.
    pub fn verify(&self, committee: &Committee) -> MessageResult<()> {
        // Ensure the certificate has a quorum.
        let mut weight = 0;
        let mut used = HashSet::new();
        let mut names = Vec::new();
        let mut votes = Vec::new();
        for (name, vote) in &self.votes {
            ensure!(
                !used.contains(name),
                MessageError::AuthorityReuse(name.clone())
            );
            let voting_power = committee.voting_power(name);
            ensure!(
                voting_power > 0,
                MessageError::UnknownAuthority(name.clone())
            );
            used.insert(name.clone());
            weight += voting_power;

            names.push(name.clone());
            votes.push(vote.clone())
        }
        ensure!(
            weight >= committee.quorum_threshold(),
            MessageError::CertificateRequiresQuorum
        );

        // Check the signatures.
        VerifyingKey::verify_batch_empty_fail(self.id().as_ref(), &names, &votes)?;

        Ok(())
    }
}

/// Accessor methods.
impl Certificate {
    pub fn id(&self) -> &Digest {
        &self.transaction.id
    }

    pub fn version(&self) -> &Version {
        &self.transaction.version
    }

    pub fn epoch(&self) -> &Epoch {
        &self.transaction.epoch
    }

    pub fn key(&self) -> &Key {
        &self.transaction.key
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn verify_vote() {
        let vote = test_util::test_vote();
        assert!(vote.verify().is_ok())
    }

    #[test]
    fn verify_unsigned_vote() {
        let mut vote = test_util::test_vote();
        vote.signature = None;
        assert!(vote.verify().is_err())
    }

    #[test]
    fn verify_certificate() {
        let certificate = test_util::test_certificate();
        let committee = test_util::test_committee();
        assert!(certificate.verify(&committee).is_ok())
    }

    #[test]
    fn verify_certificate_without_quorum() {
        let mut certificate = test_util::test_certificate();
        certificate.votes = Vec::new();
        let committee = test_util::test_committee();
        assert!(certificate.verify(&committee).is_err())
    }
}
