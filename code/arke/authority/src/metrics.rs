use axum::{http::StatusCode, routing::get, Extension, Router, Server};
use prometheus::{register_int_counter_with_registry, IntCounter, Registry, TextEncoder};
use std::net::SocketAddr;
use tokio::task::JoinHandle;

const METRICS_ROUTE: &str = "/metrics";

#[derive(Clone)]
pub struct AuthorityMetrics {
    pub transactions: IntCounter,
    pub certificates: IntCounter,
}

impl AuthorityMetrics {
    pub fn new(registry: &Registry) -> Self {
        Self {
            transactions: register_int_counter_with_registry!(
                "transactions",
                "The number of processed transactions",
                registry,
            )
            .unwrap(),
            certificates: register_int_counter_with_registry!(
                "certificates",
                "The number of processed certificates",
                registry,
            )
            .unwrap(),
        }
    }
}

pub fn start_prometheus_server(
    address: SocketAddr,
    registry: &Registry,
) -> JoinHandle<Result<(), hyper::Error>> {
    let app = Router::new()
        .route(METRICS_ROUTE, get(metrics))
        .layer(Extension(registry.clone()));

    tracing::info!("Prometheus server booted on {address}");
    tokio::spawn(async move { Server::bind(&address).serve(app.into_make_service()).await })
}

async fn metrics(registry: Extension<Registry>) -> (StatusCode, String) {
    let metrics_families = registry.gather();
    match TextEncoder.encode_to_string(&metrics_families) {
        Ok(metrics) => (StatusCode::OK, metrics),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Unable to encode metrics: {error}"),
        ),
    }
}
