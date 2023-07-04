use authority::{state::AuthorityState, storage::Storage};
use config::{Authority, Committee};
use fastcrypto::traits::KeyPair as _;
use messages::{Certificate, Epoch, KeyPair, Version, Vote, WriteTransaction};
use rand::{rngs::StdRng, SeedableRng};
use tempdir::TempDir;

pub const NUM_AUTHORITIES: usize = 4;
pub const INITIAL_VERSION: Version = 1;
pub const INITIAL_EPOCH: Epoch = 1;

pub fn test_keys() -> Vec<KeyPair> {
    let mut csprng = StdRng::seed_from_u64(0);
    (0..4).map(|_| KeyPair::generate(&mut csprng)).collect()
}

pub fn test_write_transaction() -> WriteTransaction {
    test_write_transaction_with_version_and_epoch(INITIAL_VERSION, INITIAL_EPOCH)
}

pub fn test_write_transaction_with_version_and_epoch(
    version: Version,
    epoch: Epoch,
) -> WriteTransaction {
    let key = messages::Key::default();
    let value = vec![1u8; 32];
    let exp = ark_bw6_761::Fr::default();
    let mut csprng = StdRng::seed_from_u64(0);
    WriteTransaction::new(key, value, version, epoch)
        .with_write_proof(&exp, &mut csprng)
        .unwrap()
}

pub fn test_vote() -> Vote {
    let keypair = test_keys().pop().unwrap();
    let transaction = test_write_transaction();
    Vote::new(transaction, keypair.public().clone()).sign(&keypair)
}

pub fn test_certificate() -> Certificate {
    let transaction = test_write_transaction();
    test_certificate_from_transaction(transaction)
}

pub fn test_certificate_from_transaction(transaction: WriteTransaction) -> Certificate {
    (
        transaction.clone(),
        test_keys()
            .iter()
            .map(|keypair| {
                let name = keypair.public().clone();
                Vote::new(transaction.clone(), name).sign(&keypair)
            })
            .collect::<Vec<_>>(),
    )
        .into()
}

pub fn test_committee() -> Committee {
    test_committee_with_base_port(0)
}

pub fn test_committee_with_base_port(base_port: u16) -> Committee {
    Committee {
        authorities: test_keys()
            .iter()
            .enumerate()
            .map(|(i, keypair)| {
                let port = base_port + i as u16;
                let authority = Authority {
                    voting_power: 1,
                    shards: [(0, format!("127.0.0.1:{port}").parse().unwrap())]
                        .iter()
                        .cloned()
                        .collect(),
                };
                (keypair.public().clone(), authority)
            })
            .collect(),
    }
}

pub fn test_storage() -> Storage {
    let tmp_dir = TempDir::new("test_db").unwrap();
    Storage::new(tmp_dir.path()).unwrap()
}

pub fn test_authority_state() -> AuthorityState {
    AuthorityState::new(
        test_keys().pop().unwrap(),
        test_committee(),
        INITIAL_EPOCH,
        test_storage(),
    )
}
