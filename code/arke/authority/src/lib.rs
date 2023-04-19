use std::{collections::HashMap, error::Error, sync::Arc};

use ark_bls12_377::Bls12_377;
use ark_bw6_761::BW6_761;
use arke_core::{IssuerSecretKey, PublicParameters, RegistrarPublicKey};
use bytes::Bytes;
use config::{Committee, ShardId};
use fastcrypto::traits::KeyPair as _;
use futures::sink::SinkExt;
use messages::{
    AuthorityError, AuthorityToClientMessage, ClientToAuthorityMessage, Epoch, KeyPair,
    MessageError, PublicKey,
};
use network::receiver::{MessageHandler, Receiver as NetworkReceiver, Writer};
use prometheus::default_registry;
use state::AuthorityState;
use storage::Storage;
use tokio::task::JoinHandle;

use crate::{
    credentials::CredentialsIssuer,
    metrics::{start_prometheus_server, AuthorityMetrics},
};

pub mod credentials;
mod guard;
pub mod metrics;
pub mod state;
pub mod storage;

/// Spawn a new authority.
pub fn spawn_authority(
    keypair: KeyPair,
    shard_id: ShardId,
    committee: Committee,
    epoch: Epoch,
    storage: Storage,
    metrics_port: u16,
) -> JoinHandle<()> {
    let name = keypair.public().clone();

    // Spawn a prometheus server.
    let registry = default_registry();
    let _handle = start_prometheus_server(
        format!("0.0.0.0:{}", metrics_port).parse().unwrap(),
        &registry,
    );
    let metrics = AuthorityMetrics::new(&registry);

    // Make the authority's state.
    let state = Arc::new(
        AuthorityState::new(keypair, committee.clone(), epoch, storage).with_metrics(metrics),
    );

    // Spawn a network receiver.
    let mut address = committee
        .authority_address(&name, &shard_id)
        .expect("Our public key is not in the committee");
    address.set_ip("0.0.0.0".parse().unwrap());
    let handler = AuthorityHandler { state };
    let handler = NetworkReceiver::spawn(address, handler);

    tracing::info!(
        "Authority {} successfully booted on {}",
        name,
        committee
            .authority_address(&name, &shard_id)
            .expect("Our public key is not in the committee")
            .ip()
    );

    handler
}

/// Defines how the network receiver handles incoming messages.
#[derive(Clone)]
struct AuthorityHandler {
    /// The shared authority's state.
    state: Arc<AuthorityState>,
}

#[async_trait::async_trait]
impl MessageHandler for AuthorityHandler {
    async fn dispatch(&self, writer: &mut Writer, serialized: Bytes) -> Result<(), Box<dyn Error>> {
        // Process the client's message.
        let reply: AuthorityToClientMessage =
            match bincode::deserialize(&serialized).map_err(MessageError::from)? {
                ClientToAuthorityMessage::WriteTransaction(transaction) => self
                    .state
                    .handle_write_transaction(transaction)
                    .await
                    .into(),
                ClientToAuthorityMessage::Certificate(certificate) => {
                    self.state.handle_certificate(certificate).await.into()
                }
                ClientToAuthorityMessage::CredentialsRequest(_request) => {
                    AuthorityToClientMessage::CredentialsIssuance(Err(
                        AuthorityError::UnsupportedOperation("CredentialsRequest".into()),
                    ))
                }
            };

        // Reply to the client.
        let bytes = bincode::serialize(&reply).expect("Failed to serialize reply");
        writer.send(Bytes::from(bytes)).await?;
        Ok(())
    }
}

/// Spawn a new authority.
pub fn spawn_credentials_issuer(
    name: PublicKey,
    committee: Committee,
    public_parameters: PublicParameters<Bls12_377, BW6_761>,
    registrars: HashMap<Vec<u8>, RegistrarPublicKey<Bls12_377>>,
    credentials_key: IssuerSecretKey<Bls12_377>,
) -> JoinHandle<()> {
    // Make the authority's state.
    let state = Arc::new(CredentialsIssuer::new(
        public_parameters,
        registrars,
        credentials_key,
    ));

    // Spawn a network receiver.
    let mut address = committee
        .authority_address(&name, &0)
        .expect("Our public key is not in the committee");
    address.set_ip("0.0.0.0".parse().unwrap());
    let handler = CredentialsIssuerHandler { state };
    let handler = NetworkReceiver::spawn(address, handler);

    tracing::info!(
        "Credentials issuer {} successfully booted on {}",
        name,
        committee
            .authority_address(&name, &0)
            .expect("Our public key is not in the committee")
            .ip()
    );

    handler
}

/// Defines how the network receiver handles incoming messages.
#[derive(Clone)]
struct CredentialsIssuerHandler {
    /// The shared authority's state.
    state: Arc<CredentialsIssuer>,
}

#[async_trait::async_trait]
impl MessageHandler for CredentialsIssuerHandler {
    async fn dispatch(&self, writer: &mut Writer, serialized: Bytes) -> Result<(), Box<dyn Error>> {
        // Process the client's message.
        let reply: AuthorityToClientMessage =
            match bincode::deserialize(&serialized).map_err(MessageError::from)? {
                ClientToAuthorityMessage::WriteTransaction(_transaction) => {
                    AuthorityToClientMessage::CredentialsIssuance(Err(
                        AuthorityError::UnsupportedOperation("WriteTransaction".into()),
                    ))
                }
                ClientToAuthorityMessage::Certificate(_certificate) => {
                    AuthorityToClientMessage::CredentialsIssuance(Err(
                        AuthorityError::UnsupportedOperation("HandleCertificate".into()),
                    ))
                }
                ClientToAuthorityMessage::CredentialsRequest(request) => {
                    self.state.handle_credentials_request(request).into()
                }
            };

        // Reply to the client.
        let bytes = bincode::serialize(&reply).expect("Failed to serialize reply");
        writer.send(Bytes::from(bytes)).await?;
        Ok(())
    }
}
