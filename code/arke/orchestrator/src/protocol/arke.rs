// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{
    fmt::{Debug, Display},
    path::PathBuf,
    str::FromStr,
};

use serde::{Deserialize, Serialize};

use crate::{
    benchmark::{BenchmarkParameters, BenchmarkType},
    client::Instance,
    settings::Settings,
};

use super::{ProtocolCommands, ProtocolMetrics};

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ArkeBenchmarkType {
    CollocatedShards { shards: usize, size: usize },
    StandaloneShards { shards: usize, size: usize },
}

impl Default for ArkeBenchmarkType {
    fn default() -> Self {
        Self::CollocatedShards {
            shards: 1,
            size: 32,
        }
    }
}

impl Debug for ArkeBenchmarkType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (location, shards, size) = match self {
            Self::CollocatedShards { shards, size } => ("c", shards, size),
            Self::StandaloneShards { shards, size } => ("s", shards, size),
        };
        write!(f, "{location}-{shards}-{size}")
    }
}

impl Display for ArkeBenchmarkType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CollocatedShards { shards, size } => {
                write!(f, "{shards} shards (collocated) -- {size}B txs")
            }
            Self::StandaloneShards { shards, size } => {
                write!(f, "{shards} shards (standalone) -- {size}B txs")
            }
        }
    }
}

impl FromStr for ArkeBenchmarkType {
    type Err = std::num::ParseIntError;

    // The format is the following x-c-y, where x is the number of shards and y is the tx's size.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<_> = s.split("-").collect();
        let shards = parts[0].parse::<usize>()?;
        let location = parts[1];
        let size = parts[2].parse::<usize>()?;

        if location.contains("c") {
            Ok(Self::CollocatedShards { shards, size })
        } else {
            Ok(Self::StandaloneShards { shards, size })
        }
    }
}

impl BenchmarkType for ArkeBenchmarkType {}

impl ArkeBenchmarkType {
    pub fn number_of_shards(&self) -> usize {
        match self {
            Self::CollocatedShards { shards, .. } => *shards,
            Self::StandaloneShards { shards, .. } => *shards,
        }
    }

    pub fn transaction_size(&self) -> usize {
        match self {
            Self::CollocatedShards { size, .. } => *size,
            Self::StandaloneShards { size, .. } => *size,
        }
    }
}

/// All configurations information to run a sui client or validator.
pub struct ArkeProtocol {
    /// The working directory on the remote hosts (containing the databases and configuration files).
    working_dir: PathBuf,
}

impl ProtocolCommands<ArkeBenchmarkType> for ArkeProtocol {
    fn protocol_dependencies(&self) -> Vec<&'static str> {
        vec!["sudo apt-get -y install clang cmake"]
    }

    fn db_directories(&self) -> Vec<PathBuf> {
        let db = [&self.working_dir, &PathBuf::from(Self::DB_NAME)]
            .iter()
            .collect();
        vec![db]
    }

    fn genesis_command<'a, I>(
        &self,
        instances: I,
        parameters: &BenchmarkParameters<ArkeBenchmarkType>,
    ) -> String
    where
        I: Iterator<Item = &'a Instance>,
    {
        let instances: Vec<_> = instances.cloned().collect();
        let committee = instances.len();
        let shards = parameters.benchmark_type.number_of_shards();
        let addresses = self.node_addresses(&instances, shards).join(" ");

        let genesis = [
            "cargo run --release --bin authority --",
            "print-test-configs",
            &format!("--committee {committee} --shards {shards} --addresses {addresses}"),
        ]
        .join(" ");

        ["source $HOME/.cargo/env", &genesis].join(" && ")
    }

    fn node_command<I>(
        &self,
        instances: I,
        parameters: &BenchmarkParameters<ArkeBenchmarkType>,
    ) -> Vec<(Instance, String)>
    where
        I: IntoIterator<Item = Instance>,
    {
        let shards = parameters.benchmark_type.number_of_shards();
        let committee = config::committee_filename();
        let storage = Self::DB_NAME;
        let epoch = 1;

        instances
            .into_iter()
            .enumerate()
            .map(|(i, instance)| {
                let keys = config::private_config_filename(i);

                let run = [
                    "cargo run --release --bin authority --",
                    "run",
                    &format!("--keys {keys} --shards {shards} --committee {committee} --storage {storage} --epoch {epoch}"),
                ]
                .join(" ");
                let command = ["source $HOME/.cargo/env", &run].join(" && ");

                (instance, command)
            })
            .collect()
    }

    fn client_command<I>(
        &self,
        clients_instances: I,
        nodes_instances: I,
        parameters: &BenchmarkParameters<ArkeBenchmarkType>,
    ) -> Vec<(Instance, String)>
    where
        I: IntoIterator<Item = Instance>,
    {
        let clients: Vec<_> = clients_instances.into_iter().collect();
        let nodes: Vec<_> = nodes_instances.into_iter().collect();

        let c = config::committee_filename();
        let r = parameters.load / clients.len();
        let s = parameters.benchmark_type.transaction_size();
        let f = parameters.faults.number_of_faults();
        let p = Self::CLIENT_METRICS_PORT;

        let shards = parameters.benchmark_type.number_of_shards();
        let targets = self.node_addresses(&nodes, shards);
        targets.into_iter().zip(clients.into_iter().cycle()).map(|(t, client)|{
            let run = [
                "cargo run --release --features benchmark --bin benchmark_client --",
                "-vv",
                &format!("--target-shard {t} --committee {c} --rate {r} --size {s} --faults {f} --metrics-port {p}")
            ]
            .join(" ");
            let command = ["source $HOME/.cargo/env", &run].join(" && ");

            (client, command)
        })
        .collect()
    }
}

impl ProtocolMetrics for ArkeProtocol {
    const NODE_METRICS_PORT: u16 = 9090;
    const CLIENT_METRICS_PORT: u16 = 8080;

    const BENCHMARK_DURATION: &'static str = "benchmark_duration";
    const TOTAL_TRANSACTIONS: &'static str = "finalized_latency_s_count";
    const LATENCY_BUCKETS: &'static str = "finalized_latency_s";
    const LATENCY_SUM: &'static str = "finalized_latency_s_sum";
    const LATENCY_SQUARED_SUM: &'static str = "finalized_latency_squared_s";
}

impl ArkeProtocol {
    const DB_NAME: &str = "arke_db";
    const AUTHORITY_BASE_PORT: u16 = 9000;

    /// Make a new instance of the Sui protocol commands generator.
    pub fn new(settings: &Settings) -> Self {
        Self {
            working_dir: settings.working_dir.clone(),
        }
    }

    fn node_addresses(&self, instances: &[Instance], shards: usize) -> Vec<String> {
        // TODO: Does not work for non-collocated authorities' shards. Get BenchmarkParameters as
        // input and compute the addresses according to the BenchmarkType.

        instances
            .iter()
            .map(|instance| {
                (0..shards)
                    .map(|i| {
                        format!(
                            "{}:{}",
                            instance.main_ip.to_string(),
                            Self::AUTHORITY_BASE_PORT + i as u16
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .flatten()
            .collect::<Vec<_>>()
    }
}
