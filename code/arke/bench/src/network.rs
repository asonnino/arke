use std::{collections::HashMap, net::SocketAddr};

use bytes::Bytes;
use network::reliable_sender::{CancelHandler, Connection, InnerMessage};
use tokio::sync::{
    mpsc::{channel, Sender},
    oneshot,
};

pub struct BenchSender {
    connections: HashMap<SocketAddr, Vec<Sender<InnerMessage>>>,
    connections_per_peer: usize,
    index: usize,
}

impl BenchSender {
    pub fn new(targets: Vec<SocketAddr>, connections_per_peer: usize) -> Self {
        Self {
            connections: targets
                .into_iter()
                .map(|address| {
                    let senders: Vec<_> = (0..connections_per_peer)
                        .map(|_| Self::spawn_connection(address.clone()))
                        .collect();
                    (address, senders)
                })
                .collect(),
            connections_per_peer,
            index: 0,
        }
    }

    /// Helper function to spawn a new connection.
    fn spawn_connection(address: SocketAddr) -> Sender<InnerMessage> {
        let (tx, rx) = channel(1_000);
        Connection::spawn(address, rx);
        tx
    }

    pub async fn broadcast(&mut self, data: Bytes) -> Vec<CancelHandler> {
        self.index = (self.index + 1) % self.connections_per_peer;
        let mut handles = Vec::with_capacity(self.connections.len());
        for connection in self.connections.values() {
            let (sender, receiver) = oneshot::channel();
            connection[self.index]
                .send(InnerMessage {
                    data: data.clone(),
                    cancel_handler: sender,
                })
                .await
                .expect("Failed to send internal message");
            handles.push(receiver);
        }
        handles
    }
}
