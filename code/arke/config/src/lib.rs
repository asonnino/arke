use std::{
    collections::{BTreeMap, HashMap},
    fs::{self, OpenOptions},
    io::{BufWriter, Write as _},
    net::SocketAddr,
};

use fastcrypto::{
    ed25519::{Ed25519KeyPair as KeyPair, Ed25519PublicKey as PublicKey},
    generate_keypair, generate_production_keypair,
    traits::KeyPair as _,
};
use rand::{rngs::StdRng, SeedableRng};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Failed to read config file '{file}': {message}")]
    ImportError { file: String, message: String },

    #[error("Failed to write config file '{file}': {message}")]
    ExportError { file: String, message: String },
}

/// Read from file a configuration.
pub trait Import: DeserializeOwned {
    fn import(path: &str) -> Result<Self, ConfigError> {
        let reader = || -> Result<Self, std::io::Error> {
            let data = fs::read(path)?;
            Ok(serde_json::from_slice(data.as_slice())?)
        };
        reader().map_err(|e| ConfigError::ImportError {
            file: path.to_string(),
            message: e.to_string(),
        })
    }
}

/// Write to file a configuration (in JSON format).
pub trait Export: Serialize {
    fn export(&self, path: &str) -> Result<(), ConfigError> {
        let writer = || -> Result<(), std::io::Error> {
            let file = OpenOptions::new().create(true).write(true).open(path)?;
            let mut writer = BufWriter::new(file);
            let data = serde_json::to_string_pretty(self).unwrap();
            writer.write_all(data.as_ref())?;
            writer.write_all(b"\n")?;
            Ok(())
        };
        writer().map_err(|e| ConfigError::ExportError {
            file: path.to_string(),
            message: e.to_string(),
        })
    }
}

/// Denomination of the voting power of each authority.
pub type VotingPower = u32;
/// The shard identifier.
pub type ShardId = u32;

/// The public information of a authority.
#[derive(Clone, Deserialize, Serialize)]
pub struct Authority {
    /// The voting power of this authority.
    pub voting_power: VotingPower,
    /// The network addresses of the authority.
    pub shards: HashMap<ShardId, SocketAddr>,
}

/// The (public) committee information.
#[derive(Clone, Deserialize, Serialize)]
pub struct Committee {
    pub authorities: BTreeMap<PublicKey, Authority>,
}

impl Import for Committee {}
impl Export for Committee {}

impl Committee {
    /// Return the number of authorities.
    pub fn size(&self) -> usize {
        self.authorities.len()
    }

    /// Return the number of shards per authority.
    pub fn shards(&self) -> usize {
        self.authorities
            .values()
            .next()
            .map_or_else(|| 0, |authority| authority.shards.len())
    }

    /// Return the voting power of a specific authority.
    pub fn voting_power(&self, name: &PublicKey) -> VotingPower {
        self.authorities
            .get(name)
            .map_or_else(|| 0, |x| x.voting_power)
    }

    /// Return the stake required to reach a quorum (2f+1).
    pub fn quorum_threshold(&self) -> VotingPower {
        // If N = 3f + 1 + k (0 <= k < 3)
        // then (2 N + 3) / 3 = 2f + 1 + (2k + 2)/3 = 2f + 1 + k = N - f
        let total_votes: VotingPower = self.authorities.values().map(|x| x.voting_power).sum();
        2 * total_votes / 3 + 1
    }

    /// Return the stake required to reach availability (f+1).
    pub fn validity_threshold(&self) -> VotingPower {
        // If N = 3f + 1 + k (0 <= k < 3)
        // then (N + 2) / 3 = f + 1 + k/3 = f + 1
        let total_votes: VotingPower = self.authorities.values().map(|x| x.voting_power).sum();
        (total_votes + 2) / 3
    }

    /// Return the network address of a particular shard of an authorities.
    pub fn authority_address(&self, name: &PublicKey, shard: &ShardId) -> Option<SocketAddr> {
        self.authorities
            .get(name)
            .map(|authority| authority.shards.get(shard).cloned())
            .flatten()
    }

    /// Return all network addresses of all shards of all authorities
    pub fn all_addresses(&self) -> Vec<SocketAddr> {
        self.authorities
            .values()
            .map(|authority| authority.shards.values())
            .flatten()
            .cloned()
            .collect()
    }

    /// Return all network addresses of a particular shard of all authorities
    pub fn shard_addresses(&self, shard: &ShardId) -> Vec<SocketAddr> {
        self.authorities
            .values()
            .filter_map(|authority| authority.shards.get(shard))
            .cloned()
            .collect()
    }
}

/// The private configuration of the identity provider and authorities.
#[derive(Serialize, Deserialize)]
pub struct PrivateConfig {
    /// The public key of this entity.
    pub name: PublicKey,
    /// The private key of this entity.
    pub secret: KeyPair,
}

impl Default for PrivateConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl PrivateConfig {
    /// Creates a new private configuration.
    pub fn new() -> Self {
        let keypair = generate_production_keypair::<KeyPair>();
        Self {
            name: keypair.public().clone(),
            secret: keypair,
        }
    }
}

impl Import for PrivateConfig {}
impl Export for PrivateConfig {}

pub fn private_config_filename(i: usize) -> String {
    format!("node-{i}.json")
}

pub fn committee_filename() -> String {
    "committee.json".into()
}

pub fn print_test_configs(committee_size: usize, shards: usize, mut addresses: Vec<SocketAddr>) {
    let mut csprng = StdRng::seed_from_u64(0);

    let mut authorities = BTreeMap::new();
    for i in 0..committee_size {
        let keypair: KeyPair = generate_keypair(&mut csprng);
        let name = keypair.public().clone();

        // Export the private configs.
        let private_config = PrivateConfig {
            name: name.clone(),
            secret: keypair,
        };
        let filename = private_config_filename(i);
        private_config
            .export(&filename)
            .expect("Failed to export keypair");

        // Add the authority to the committee.
        let shards = addresses
            .drain(0..shards)
            .into_iter()
            .enumerate()
            .map(|(id, addr)| (id as ShardId, addr))
            .collect();
        let authority = Authority {
            voting_power: 1,
            shards,
        };
        authorities.insert(name, authority);
    }

    let committee = Committee { authorities };
    let committee_file = committee_filename();
    committee
        .export(&committee_file)
        .expect("Failed to export committee");
}
