use config::Committee;
use fastcrypto::traits::KeyPair as _;
use messages::{
    ensure, AuthorityError, AuthorityResult, Certificate, Digest, Epoch, Key, KeyPair, PublicKey,
    Vote, WriteTransaction,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{guard::Guard, metrics::AuthorityMetrics, Storage};

/// Represents a value persisted to storage.
#[derive(Serialize, Deserialize, Default)]
struct StoredValue {
    certificate: Option<Certificate>,
    vote: Option<Vote>,
}

/// The core state of the authority (shared among many tasks).
pub struct AuthorityState {
    /// The authority's public identifier.
    name: PublicKey,
    /// The (secret) keypair of the authority.
    keypair: KeyPair,
    /// The committee information.
    committee: Committee,
    /// The current epoch of the authority.
    epoch: Epoch,
    /// The persistent storage.
    storage: Storage,
    /// The authority's metrics.
    metrics: Option<AuthorityMetrics>,
    /// A lock table preventing race conditions on storage's keys.
    locks: Guard<Key>,
}

/// Process client messages.
impl AuthorityState {
    pub fn new(keypair: KeyPair, committee: Committee, epoch: Epoch, storage: Storage) -> Self {
        let name = keypair.public().clone();
        Self {
            name,
            keypair,
            committee,
            epoch,
            storage,
            metrics: None,
            locks: Default::default(),
        }
    }

    pub fn with_metrics(mut self, metrics: AuthorityMetrics) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Handle incoming write transactions.
    pub async fn handle_write_transaction(
        &self,
        transaction: WriteTransaction,
    ) -> AuthorityResult<Vote> {
        tracing::debug!("Processing {transaction:?}");

        // Check (1.1): check the transactions' validity.
        transaction.verify()?;
        tracing::debug!("Successfully checked validity of {transaction:?}");

        // Check (1.2): try to acquire a mutex over the specified storage's key.
        let _guard = self.locks.acquire_lock(&transaction.key).await;
        tracing::debug!("Obtained lock for {transaction:?}");

        // Check (1.3): ensure the transaction is for the current epoch.
        ensure!(
            transaction.epoch == self.epoch,
            AuthorityError::InvalidEpoch {
                received: transaction.epoch,
                expected: self.epoch
            }
        );
        tracing::debug!("Successfully checked epoch of {transaction:?}");

        // Check (1.4): check the transaction's version.
        let mut stored_value: StoredValue = self.load_from_storage(&transaction.key);
        let previous_version = stored_value
            .certificate
            .as_ref()
            .map_or_else(|| 0, |x| *x.version());
        let expected = previous_version + 1;
        ensure!(
            transaction.version == expected,
            AuthorityError::InvalidVersion {
                received: transaction.version,
                expected,
            }
        );
        tracing::debug!("Successfully checked version of {transaction:?}");

        // Check (1.5): only sign non-conflicting transactions.
        let vote = match stored_value.vote {
            None => {
                tracing::debug!("Store does not contain key {:?}", transaction.key);
                let vote = Vote::new(transaction, self.name.clone()).sign(&self.keypair);
                stored_value.vote = Some(vote.clone());
                self.persist(vote.key(), &stored_value);
                vote
            }
            Some(vote) => {
                let received = transaction.id;
                let persisted = vote.id();
                ensure!(
                    &received == persisted,
                    AuthorityError::ConflictingTransaction {
                        received,
                        persisted: *persisted
                    }
                );
                tracing::debug!("No conflicts found for {transaction:?}");
                vote
            }
        };

        self.metrics.as_ref().map(|x| x.transactions.inc());
        Ok(vote)
    }

    /// Handle incoming certificates.
    pub async fn handle_certificate(&self, certificate: Certificate) -> AuthorityResult<Digest> {
        tracing::debug!("Processing {certificate:?}");

        // Check (2.1): check the certificate's validity.
        certificate.verify(&self.committee)?;
        tracing::debug!("Successfully checked validity of {certificate:?}");

        // Check (2.2): try to acquire a mutex over the specified storage's key.
        let _guard = self.locks.acquire_lock(certificate.key()).await;
        tracing::debug!("Obtained lock for {certificate:?}");

        // Check (2.3): ensure the certificate is for the current epoch.
        ensure!(
            certificate.epoch() == &self.epoch,
            AuthorityError::InvalidEpoch {
                received: *certificate.epoch(),
                expected: self.epoch
            }
        );
        tracing::debug!("Successfully checked epoch of {certificate:?}");

        // Check (2.4): check the certificate's version number.
        let mut stored_value: StoredValue = self.load_from_storage(certificate.key());
        let previous_version = stored_value
            .certificate
            .as_ref()
            .map_or_else(|| &0, |x| x.version());
        ensure!(
            certificate.version() > previous_version,
            AuthorityError::InvalidVersion {
                received: *certificate.version(),
                expected: previous_version + 1,
            }
        );
        tracing::debug!("Successfully checked version of {certificate:?}");

        // Persist the new certificate.
        let key = certificate.key().clone();
        let id = certificate.id().clone();
        stored_value.certificate = Some(certificate);
        stored_value.vote = None;
        self.persist(&key, &stored_value);

        tracing::debug!("Persisted certificate {id}");
        self.metrics.as_ref().map(|x| x.certificates.inc());
        Ok(id)
    }
}

/// Facilities to load and persist values to storage.
impl AuthorityState {
    pub fn load_from_storage<K, V>(&self, key: &K) -> V
    where
        K: AsRef<[u8]>,
        V: DeserializeOwned + Default,
    {
        match self
            .storage
            .read(key.as_ref())
            .expect("Failed to read storage")
        {
            Some(bytes) => {
                bincode::deserialize(&bytes).expect("Failed to deserialize stored value")
            }
            None => Default::default(),
        }
    }

    pub fn persist<K, V>(&self, key: &K, value: &V)
    where
        K: AsRef<[u8]>,
        V: Serialize,
    {
        let bytes = bincode::serialize(value).expect("Failed to serialize stored value");
        self.storage
            .write(key.as_ref(), &bytes)
            .expect("Failed to write storage");
    }
}

#[cfg(test)]
mod test {
    use messages::{AuthorityError, WriteTransaction};
    use rand::{rngs::StdRng, SeedableRng};

    #[tokio::test(start_paused = true)]
    async fn persist_storage_value() {
        let key = vec![0u8; 32];
        let value = vec![1u8; 32];

        let authority = test_util::test_authority_state();
        authority.persist(&key, &value);
        let retrieved: Vec<u8> = authority.load_from_storage(&key);
        assert_eq!(retrieved, value);
    }

    #[tokio::test(start_paused = true)]
    async fn handle_write_transaction() {
        let transaction = test_util::test_write_transaction();
        let authority = test_util::test_authority_state();

        // Ensure the authority successfully processes the transaction.
        let result = authority.handle_write_transaction(transaction).await;
        assert!(result.is_ok());

        // Ensure the authority returns a valid vote.
        let vote = result.unwrap();
        assert!(vote.verify().is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn handle_invalid_write_transaction() {
        let mut tx = test_util::test_write_transaction();
        tx.write_proof = None;
        let authority = test_util::test_authority_state();

        // Ensure the authority rejects the invalid transaction.
        match authority.handle_write_transaction(tx).await {
            Err(AuthorityError::MessageError(_)) => (),
            x => panic!("Unexpected protocol message: {x:?}"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn handle_write_transaction_wrong_epoch() {
        let version = test_util::INITIAL_VERSION;
        let wrong_epoch = test_util::INITIAL_EPOCH + 1;
        let tx = test_util::test_write_transaction_with_version_and_epoch(version, wrong_epoch);
        let authority = test_util::test_authority_state();

        // Ensure the authority rejects the incorrect transaction.
        match authority.handle_write_transaction(tx).await {
            Err(AuthorityError::InvalidEpoch { received, expected }) => {
                assert_eq!(received, wrong_epoch);
                assert_eq!(expected, test_util::INITIAL_EPOCH);
            }
            x => panic!("Unexpected protocol message: {x:?}"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn handle_write_transaction_wrong_version() {
        let wrong_version = test_util::INITIAL_VERSION + 1;
        let epoch = test_util::INITIAL_EPOCH;
        let tx = test_util::test_write_transaction_with_version_and_epoch(wrong_version, epoch);
        let authority = test_util::test_authority_state();

        // Ensure the authority rejects the incorrect transaction.
        match authority.handle_write_transaction(tx).await {
            Err(AuthorityError::InvalidVersion { received, expected }) => {
                assert_eq!(received, wrong_version);
                assert_eq!(expected, test_util::INITIAL_VERSION);
            }
            x => panic!("Unexpected protocol message: {x:?}"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn handle_conflicting_write_transaction() {
        let mut csprng = StdRng::seed_from_u64(0);

        let store_key = messages::Key::default();
        let exp = ark_bw6_761::Fr::default();

        let tx_1 = {
            let value = vec![1u8; 32];
            let version = test_util::INITIAL_VERSION;
            let epoch = test_util::INITIAL_EPOCH;
            WriteTransaction::new(store_key.clone(), value, version, epoch)
                .with_write_proof(&exp, &mut csprng)
                .unwrap()
        };
        let tx_2 = {
            let value = vec![2u8; 32];
            let version = test_util::INITIAL_VERSION;
            let epoch = test_util::INITIAL_EPOCH;
            WriteTransaction::new(store_key, value, version, epoch)
                .with_write_proof(&exp, &mut csprng)
                .unwrap()
        };

        let authority = test_util::test_authority_state();

        // Ensure the authority successfully processes the first transaction.
        let result = authority.handle_write_transaction(tx_1.clone()).await;
        assert!(result.is_ok());

        // Ensure the authority rejects the invalid transaction.
        match authority.handle_write_transaction(tx_2.clone()).await {
            Err(AuthorityError::ConflictingTransaction {
                received,
                persisted,
            }) => {
                assert_eq!(received, tx_2.id);
                assert_eq!(persisted, tx_1.id);
            }
            x => panic!("Unexpected protocol message: {x:?}"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn handle_certificate() {
        let certificate = test_util::test_certificate();
        let authority = test_util::test_authority_state();
        let result = authority.handle_certificate(certificate).await;
        assert!(result.is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn handle_invalid_certificate() {
        let mut certificate = test_util::test_certificate();
        certificate.votes = Vec::new();
        let authority = test_util::test_authority_state();

        // Ensure the authority rejects the invalid certificate.
        match authority.handle_certificate(certificate).await {
            Err(AuthorityError::MessageError(_)) => (),
            x => panic!("Unexpected protocol message: {x:?}"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn handle_certificate_wrong_epoch() {
        let version = test_util::INITIAL_VERSION;
        let wrong_epoch = test_util::INITIAL_EPOCH + 1;
        let tx = test_util::test_write_transaction_with_version_and_epoch(version, wrong_epoch);
        let certificate = test_util::test_certificate_from_transaction(tx);

        let authority = test_util::test_authority_state();

        // Ensure the authority rejects the incorrect transaction.
        match authority.handle_certificate(certificate).await {
            Err(AuthorityError::InvalidEpoch { received, expected }) => {
                assert_eq!(received, wrong_epoch);
                assert_eq!(expected, test_util::INITIAL_EPOCH);
            }
            x => panic!("Unexpected protocol message: {x:?}"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn handle_certificate_wrong_version() {
        let mut csprng = StdRng::seed_from_u64(0);

        let store_key = messages::Key::default();
        let store_value = vec![1u8; 32];
        let epoch = test_util::INITIAL_EPOCH;
        let exp = ark_bw6_761::Fr::default();

        let authority = test_util::test_authority_state();

        // Send two certificates to advance the authority's state.
        for i in test_util::INITIAL_VERSION..test_util::INITIAL_VERSION + 2 {
            let certificate = {
                let version = i as u64;
                let tx =
                    WriteTransaction::new(store_key.clone(), store_value.clone(), version, epoch)
                        .with_write_proof(&exp, &mut csprng)
                        .unwrap();
                test_util::test_certificate_from_transaction(tx)
            };

            let result = authority.handle_certificate(certificate).await;
            assert!(result.is_ok());
        }

        // Ensure the authority rejects the certificate with low version.
        let wrong_version = test_util::INITIAL_VERSION;
        let tx = WriteTransaction::new(store_key, store_value, wrong_version, epoch)
            .with_write_proof(&exp, &mut csprng)
            .unwrap();
        let certificate = test_util::test_certificate_from_transaction(tx);

        match authority.handle_certificate(certificate).await {
            Err(AuthorityError::InvalidVersion { received, expected }) => {
                assert_eq!(received, wrong_version);
                assert_eq!(expected, test_util::INITIAL_VERSION + 2)
            }
            x => panic!("Unexpected protocol message: {x:?}"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn handle_multiple_certificates() {
        let mut csprng = StdRng::seed_from_u64(0);

        let store_key = messages::Key::default();
        let store_value = vec![1u8; 32];
        let epoch = test_util::INITIAL_EPOCH;
        let exp = ark_bw6_761::Fr::default();

        let authority = test_util::test_authority_state();

        for i in test_util::INITIAL_VERSION..test_util::INITIAL_VERSION + 10 {
            let certificate = {
                let version = i as u64;
                let tx =
                    WriteTransaction::new(store_key.clone(), store_value.clone(), version, epoch)
                        .with_write_proof(&exp, &mut csprng)
                        .unwrap();
                test_util::test_certificate_from_transaction(tx)
            };

            let result = authority.handle_certificate(certificate).await;
            assert!(result.is_ok());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn handle_multiple_write_operations() {
        let mut csprng = StdRng::seed_from_u64(0);

        let store_key = messages::Key::default();
        let store_value = vec![1u8; 32];
        let epoch = test_util::INITIAL_EPOCH;
        let exp = ark_bw6_761::Fr::default();

        let authority = test_util::test_authority_state();

        for i in test_util::INITIAL_VERSION..test_util::INITIAL_VERSION + 10 {
            let version = i as u64;

            // Submit the transaction to the authority.
            let tx = WriteTransaction::new(store_key.clone(), store_value.clone(), version, epoch)
                .with_write_proof(&exp, &mut csprng)
                .unwrap();
            let result = authority.handle_write_transaction(tx.clone()).await;
            assert!(result.is_ok());

            // Submit the corresponding certificate to the authority.
            let certificate = test_util::test_certificate_from_transaction(tx);
            let result = authority.handle_certificate(certificate).await;
            assert!(result.is_ok());
        }
    }
}
