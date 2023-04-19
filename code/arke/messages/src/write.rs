use ark_ec::ProjectiveCurve;
use ark_ff::{to_bytes, PrimeField, UniformRand};
use arke_core::{NIZKProof, TagExponent, UnlinkableHandshake};
use fastcrypto::hash::{Hash, HashFunction, Sha256};
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::{
    error::{MessageError, MessageResult},
    Digest, Epoch, Key, Value, Version,
};

/// A system-wide constant for the length of a `StoreValue`. Fixed length store values are necessary to achieve privacy.
pub const STORE_VALUE_LENGTH_IN_BYTES: usize = 8;

/// A write transaction updating a specific key-value of the store.
#[derive(Serialize, Deserialize, Clone)]
pub struct WriteTransaction {
    /// The store key to update.
    pub key: Key,
    /// The new store value.
    pub value: Value,
    /// The next expected version number.
    pub version: Version,
    /// The current epoch number.
    pub epoch: Epoch,
    /// The unique identifier of this transaction (digest).
    pub id: Digest,
    /// A signature over the transaction's fields.
    pub write_proof: Option<NIZKProof>,
}

impl Hash<{ crate::DIGEST_LEN }> for WriteTransaction {
    type TypedDigest = Digest;

    fn digest(&self) -> Self::TypedDigest {
        let mut hasher = Sha256::default();
        hasher.update(to_bytes!(self.key.point).unwrap());
        hasher.update(&self.value);
        hasher.update(self.version.to_le_bytes());
        hasher.update(self.epoch.to_le_bytes());
        hasher.finalize()
    }
}

impl std::fmt::Debug for WriteTransaction {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "{}: W{}({})", self.id, self.version, self.key)
    }
}

impl std::fmt::Display for WriteTransaction {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "W{}({})", self.version, self.key)
    }
}

impl WriteTransaction {
    /// Create a new write transaction.
    pub fn new(key: Key, value: Value, version: Version, epoch: Epoch) -> Self {
        let transaction = Self {
            key,
            value,
            version,
            epoch,
            id: Digest::new([0; 32]),
            write_proof: None,
        };
        Self {
            id: transaction.digest(),
            ..transaction
        }
    }

    /// Prove knowledge of the exponent of the Key that we want to write
    pub fn with_write_proof<R: Rng>(
        mut self,
        secret_exponent: &ark_bw6_761::Fr,
        rng: &mut R,
    ) -> MessageResult<Self> {
        let session_info = to_bytes!(
            &self.key.point,
            &self.value,
            &self.version,
            &self.epoch,
            &self.id.to_vec()
        )?;

        let proof = UnlinkableHandshake::prove_write_location(
            &self.key,
            secret_exponent,
            &session_info,
            rng,
        )?;

        self.write_proof = Some(proof);

        Ok(self)
    }

    /// Verify knowledge fo the exponent of the Key
    pub fn verify(&self) -> MessageResult<()> {
        let session_info = to_bytes!(
            &self.key.point,
            &self.value,
            &self.version,
            &self.epoch,
            &self.id.to_vec()
        )?;
        let proof = &self.write_proof.ok_or(MessageError::MissingKeyProof)?;
        UnlinkableHandshake::verify_write_location(&self.key, &proof, &session_info)?;
        Ok(())
    }

    /// Create a random write transaction
    pub fn rand<R: Rng>(
        version: Option<Version>,
        epoch: Option<Epoch>,
        size: usize,
        rng: &mut R,
    ) -> MessageResult<Self> {
        // Create a random exponent and StoreKey
        let exponent = TagExponent::rand(rng);
        let generator = ark_bw6_761::G1Projective::prime_subgroup_generator();
        let write_tag = Key::from(generator.mul(exponent.into_repr()));

        // Create some random bytes to be written
        let value = vec![1u8; size];

        // Use the provided version or default to 0
        let version = match version {
            Some(v) => v,
            None => 1,
        };

        // Use the provided epoch or default to 1
        let epoch = match epoch {
            Some(e) => e,
            None => 1,
        };

        // Create a transaction without a proof
        let mut transaction = Self {
            key: write_tag,
            value,
            version,
            epoch,
            id: Digest::new([0; 32]),
            write_proof: None,
        };

        // Compute the id
        transaction.id = transaction.digest();

        // Compute session info to prevent replay attacks
        let session_info = to_bytes!(
            transaction.key.point,
            transaction.value,
            transaction.version,
            transaction.epoch,
            transaction.id.to_vec()
        )?;

        // Compute a proof and add it to the transaction
        let proof = UnlinkableHandshake::prove_write_location(
            &transaction.key,
            &exponent,
            &session_info,
            rng,
        )?;
        transaction.write_proof = Some(proof);

        Ok(transaction)
    }
}

#[cfg(test)]
mod test {
    use rand::{rngs::ThreadRng, thread_rng};

    use crate::WriteTransaction;

    #[test]
    fn verify_transaction() {
        let transaction = test_util::test_write_transaction();
        assert!(transaction.verify().is_ok())
    }

    #[test]
    fn verify_unsigned_transaction() {
        let mut transaction = test_util::test_write_transaction();
        transaction.write_proof = None;
        assert!(transaction.verify().is_err())
    }

    #[test]
    fn random_write_transaction() {
        let mut rng = thread_rng();
        let size = 8;

        let random_transaction =
            WriteTransaction::rand::<ThreadRng>(None, None, size, &mut rng).unwrap();
        assert!(random_transaction.verify().is_ok())
    }
}
