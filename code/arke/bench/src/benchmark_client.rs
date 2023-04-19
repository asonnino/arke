use clap::Parser;
use config::{Committee, Import, ShardId};
use eyre::{ensure, eyre, Result, WrapErr};
use futures::stream::{futures_unordered::FuturesUnordered, StreamExt};
use messages::AuthorityToClientMessage;
use metrics::{start_prometheus_server, ClientMetrics};
use prometheus::default_registry;
use std::{collections::HashMap, net::SocketAddr};
use tokio::{
    net::TcpStream,
    time::{interval, sleep, Duration, Instant},
};
use tracing::metadata::LevelFilter;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

use crate::{
    network::BenchSender,
    utils::{AckAggregator, CertificateAggregator, WriteTransactionGenerator},
};

mod metrics;
mod network;
mod utils;

/// Default port to expose client metrics.
const DEFAULT_METRICS_PORT: u16 = 8080;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Turn debugging information on.
    #[clap(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
    /// The shard targeted by this client.
    #[clap(short, long, value_parser, value_name = "INT")]
    target_shard: ShardId,
    /// The file containing committee information.
    #[clap(short, long, value_parser, value_name = "FILE")]
    committee: String,
    /// The rate (tx/s) at which to send the write transactions.
    #[clap(short, long, value_parser, value_name = "INT")]
    rate: u64,
    /// The size of the value to store (in bytes).
    #[clap(short, long, value_parser, value_name = "INT")]
    size: usize,
    /// The number of (crash-)faults.
    #[clap(short, long, value_parser, value_name = "INT")]
    faults: usize,
    /// The port to expose metrics.
    #[clap(short, long, value_name = "INT")]
    metrics_port: Option<u16>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Args::parse();

    // Set the tracing subscriber.
    set_tracing_subscriber(cli.verbose);

    // Load the committee.
    let committee = Committee::import(&cli.committee).wrap_err("Failed to load committee")?;
    ensure!(
        cli.faults < committee.size(),
        eyre!("The number of faults should be less than the committee size")
    );

    // Make a benchmark client.
    let metrics_port = cli.metrics_port.unwrap_or(DEFAULT_METRICS_PORT);
    let client = BenchmarkClient::new(
        cli.target_shard,
        committee,
        cli.rate,
        cli.size,
        cli.faults,
        metrics_port,
    );
    client.print_parameters();

    // Wait for all nodes to be online and synchronized.
    client.wait().await;

    // Start the benchmark.
    client
        .benchmark()
        .await
        .context("Failed to submit transactions")?;

    Ok(())
}

fn set_tracing_subscriber(verbosity: u8) {
    let log_level = match verbosity {
        0 => LevelFilter::ERROR,
        1 => LevelFilter::WARN,
        2 => LevelFilter::INFO,
        3 => LevelFilter::DEBUG,
        _ => LevelFilter::TRACE,
    };

    let subscriber = FmtSubscriber::builder()
        // .compact()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(log_level.into())
                .from_env_lossy(),
        )
        // .pretty()
        .with_ansi(false)
        .finish();

    tracing::subscriber::set_global_default(subscriber).unwrap();
}

/// A client only useful to benchmark the authorities.
pub struct BenchmarkClient {
    /// Clients metrics exposing performance.
    metrics: ClientMetrics,
    /// The network address of the shards targeted by this client.
    targets: Vec<SocketAddr>,
    /// The committee information.
    committee: Committee,
    /// The number of requests per seconds that this client submits.
    rate: u64,
    /// The size of the values to write to the store (in bytes).
    size: usize,
    /// The number of crash-faults.
    faults: usize,
}

impl BenchmarkClient {
    /// Timing burst precision.
    const PRECISION: u64 = 10;
    /// Duration of each burst of transaction.
    const BURST_DURATION: Duration = Duration::from_millis(1_000 / Self::PRECISION);
    /// The number of connections per peer.
    const CONNECTIONS_PER_PEER: usize = 500;

    /// Create a new benchmark client.
    pub fn new(
        target_shard: ShardId,
        committee: Committee,
        rate: u64,
        size: usize,
        faults: usize,
        metrics_port: u16,
    ) -> Self {
        let registry = default_registry();
        let _handle = start_prometheus_server(
            format!("127.0.0.1:{}", metrics_port).parse().unwrap(),
            &registry,
        );
        let metrics = ClientMetrics::new(&registry);

        Self {
            metrics,
            targets: committee.shard_addresses(&target_shard),
            committee,
            rate,
            faults,
            size,
        }
    }

    pub fn print_parameters(&self) {
        tracing::info!("Transactions rate: {} tx/s", self.rate);
        tracing::info!("Values size: {} B", self.size);
        for target in &self.targets {
            tracing::info!("Target shard address: {target}");
        }
    }

    pub fn num_of_correct_authorities(&self) -> usize {
        self.committee.size() - self.faults
    }

    /// Wait for all authorities to be online.
    pub async fn wait(&self) {
        tracing::info!("Waiting for all authorities to be online...");
        let mut futures: FuturesUnordered<_> = self
            .targets
            .iter()
            .cloned()
            .map(|address| async move {
                while TcpStream::connect(address).await.is_err() {
                    sleep(Duration::from_millis(10)).await;
                }
                address
            })
            .collect();

        let mut online = 0;
        let expected_online = self.num_of_correct_authorities() * self.committee.shards();
        while let Some(address) = futures.next().await {
            tracing::info!("Connection with {address} established");
            online += 1;
            if online == expected_online {
                break;
            }
        }
    }

    /// Run a benchmark with the provided parameters.
    pub async fn benchmark(&self) -> Result<()> {
        let burst = self.rate / Self::PRECISION;

        // Connect to the witnesses.
        let connections_per_peer = Self::CONNECTIONS_PER_PEER / self.committee.size();
        let mut network = BenchSender::new(self.targets.clone(), connections_per_peer);

        // Initiate the generator of dumb messages.
        let correct_authorities = self.num_of_correct_authorities();
        let mut tx_generator = WriteTransactionGenerator::new(self.size);
        let mut cert_aggregator =
            CertificateAggregator::new(self.committee.clone(), correct_authorities);
        let mut acks_aggregator = AckAggregator::new(self.committee.clone(), correct_authorities);

        // Initialize a map keeping track of sending times.
        let mut sending_times = HashMap::with_capacity(self.rate as usize * 100);

        // Give a head start to the transaction generator to produce a few transactions.
        tracing::info!("Initializing generator");
        tx_generator.initialize().await;

        // Gather votes.
        let mut votes_handlers = FuturesUnordered::new();
        // Gather certificates' acknowledgments.
        let mut certificate_acknowledgements_handlers = FuturesUnordered::new();

        // Submit all transactions.
        let start = Instant::now();
        let interval = interval(Self::BURST_DURATION);
        tokio::pin!(interval);

        // NOTE: This log entry is used to compute performance.
        tracing::info!("Start sending transactions");
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let now = Instant::now();
                    let duration = now.duration_since(start);
                    self.metrics.benchmark_duration.inc_by(duration.as_secs());

                    for _ in 1..=burst {
                        let (id, bytes) = tx_generator.make_tx().await;

                        self.metrics.submitted.inc();
                        tracing::info!("Sending sample transaction {id}");

                        sending_times.insert(id, now);

                        network
                            .broadcast(bytes)
                            .await
                            .into_iter()
                            .for_each(|handle| votes_handlers.push(handle));
                    }

                    if now.elapsed() > Self::BURST_DURATION {
                        self.metrics.errors.with_label_values(&["rate too hight"]).inc();
                        tracing::warn!("Transaction rate too high for this client");
                    }
                },
                Some(bytes) = votes_handlers.next() => {
                    let result = match bincode::deserialize(&bytes?)? {
                        AuthorityToClientMessage::Vote(result) => result,
                        x => return Err(eyre!("Unexpected protocol message: {x:?}"))
                    };
                    let vote = result.context("Authority returned error")?;
                    tracing::debug!("Received {vote:?}");
                    if let Some((id, certificate)) = cert_aggregator.try_make_certificate(vote)
                    {
                        let sending_time = sending_times.get(&id).expect("Unknown transaction certified");
                        let latency = Instant::now().duration_since(sending_time.clone()).as_secs_f64();

                        let square_latency_ms = latency.powf(2.0);
                        self
                            .metrics
                            .certification_latency_s
                            .with_label_values(&["certified"])
                            .observe(latency);
                        self
                            .metrics
                            .certification_latency_squared_s
                            .with_label_values(&["certified"])
                            .inc_by(square_latency_ms);
                        tracing::info!("Assembled certificate {id}");

                        network
                            .broadcast(certificate)
                            .await
                            .into_iter()
                            .for_each(|handle| certificate_acknowledgements_handlers.push(handle));
                    }
                },
                Some(bytes) = certificate_acknowledgements_handlers.next() => {
                    let result = match bincode::deserialize(&bytes?)? {
                        AuthorityToClientMessage::Acknowledgement(result) => result,
                        x => return Err(eyre!("Unexpected protocol message: {x:?}"))
                    };
                    let id = result.context("Authority returned error")?;
                    tracing::debug!("Received ack for {id:?}");

                    if acks_aggregator.check_ack_quorum(id) {
                        let sending_time = sending_times.remove(&id).expect("Unknown transaction finalized");
                        let latency = Instant::now().duration_since(sending_time).as_secs_f64();

                        let square_latency_ms = latency.powf(2.0);
                        self
                            .metrics
                            .finality_latency_s
                            .with_label_values(&["finalized"])
                            .observe(latency);
                        self
                            .metrics
                            .finality_latency_squared_s
                            .with_label_values(&["finalized"])
                            .inc_by(square_latency_ms);
                        tracing::info!("Acknowledged certificate {id}");

                        cert_aggregator.clear();
                        acks_aggregator.clear();
                    }
                },
                else => break
            }
        }
        Ok(())
    }
}
