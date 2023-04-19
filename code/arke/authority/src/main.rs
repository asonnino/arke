use std::net::SocketAddr;

use authority::{spawn_authority, storage::Storage};
use clap::Parser;
use config::{Committee, Export, Import, PrivateConfig, ShardId};
use eyre::{Result, WrapErr};
use messages::Epoch;
use tracing::metadata::LevelFilter;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

/// Default metrics port.
const DEFAULT_METRICS_PORT: u16 = 9090;

#[derive(Parser)]
#[clap(name = "Arke authority")]
struct Args {
    /// Turn debugging information on.
    #[clap(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
    /// The command to execute.
    #[clap(subcommand)]
    command: Command,
}

#[derive(Parser)]
#[clap(rename_all = "kebab-case")]
enum Command {
    /// Generate a new keypair.
    Keys {
        /// The file where to print the new key pair.
        #[clap(short, long, value_parser, value_name = "FILE")]
        filename: String,
    },
    /// Print all configuration required to boot a test authority.
    PrintTestConfigs {
        /// The size of the committee.
        #[clap(short, long, value_parser, value_name = "INT")]
        committee: usize,
        /// The number of shards per authority.
        #[clap(short, long, value_parser, value_name = "INT")]
        shards: usize,
        /// List of ip addresses to form the committee. There must be `committee x shards` ip
        /// address in total. The addresses `list[i:i+shards]` are used for authority `i`.
        #[clap(
            long,
            value_name = "Addr",
            multiple_occurrences = false,
            multiple_values = true,
            value_delimiter = ','
        )]
        addresses: Vec<SocketAddr>,
    },
    /// Run a single authority.
    Run {
        /// The file containing the authority's key material.
        #[clap(short, long, value_parser, value_name = "FILE")]
        keys: String,
        /// The shard id to run.
        #[clap(short, long, value_parser, value_name = "INT")]
        shard: ShardId,
        /// The file containing committee information.
        #[clap(short, long, value_parser, value_name = "FILE")]
        committee: String,
        /// The path to the authority's storage.
        #[clap(short, long, value_parser, value_name = "FILE")]
        storage: String,
        /// The current epoch.
        #[clap(short, long, value_parser, value_name = "INT")]
        epoch: Epoch,
        /// The port to expose metrics.
        #[clap(short, long, value_name = "INT")]
        metrics_port: Option<u16>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Args::parse();

    // Set the tracing subscriber.
    set_tracing_subscriber(cli.verbose);

    match cli.command {
        Command::Keys { filename } => PrivateConfig::new()
            .export(&filename)
            .wrap_err("Failed to generate new key file")?,

        Command::PrintTestConfigs {
            committee,
            shards,
            addresses,
        } => config::print_test_configs(committee, shards, addresses),

        Command::Run {
            keys,
            shard,
            committee,
            storage,
            epoch,
            metrics_port,
        } => {
            // Load the authority's key material.
            let keypair = PrivateConfig::import(&keys).wrap_err("Failed to load key file")?;

            // Load the committee.
            let committee = Committee::import(&committee).wrap_err("Failed to load committee")?;

            // Open or create the persistent storage.
            let storage = Storage::new(storage).wrap_err("Failed to create storage")?;

            // Set the port where to expose metrics.
            let metrics_port = metrics_port.unwrap_or(DEFAULT_METRICS_PORT);

            // Spawn the authority.
            spawn_authority(
                keypair.secret,
                shard,
                committee,
                epoch,
                storage,
                metrics_port,
            )
            .await
            .wrap_err("Authority task terminated")?;
        }
    }

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
