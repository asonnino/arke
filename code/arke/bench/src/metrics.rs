use axum::{http::StatusCode, routing::get, Extension, Router, Server};
use prometheus::{
    register_counter_vec_with_registry, register_histogram_vec_with_registry,
    register_int_counter_with_registry, CounterVec, HistogramVec, IntCounter, Registry,
    TextEncoder,
};
use std::net::SocketAddr;
use tokio::task::JoinHandle;

const METRICS_ROUTE: &str = "/metrics";
const LATENCY_SEC_BUCKETS: &[f64] = &[
    0.1, 0.15, 0.20, 0.25, 0.5, 0.75, 1., 1.25, 1.5, 1.75, 2., 2.5, 5., 10.,
];

#[derive(Clone)]
pub struct ClientMetrics {
    pub benchmark_duration: IntCounter,
    pub submitted: IntCounter,
    pub finality_latency_s: HistogramVec,
    pub finality_latency_squared_s: CounterVec,
    pub certification_latency_s: HistogramVec,
    pub certification_latency_squared_s: CounterVec,
    pub errors: CounterVec,
}

impl ClientMetrics {
    pub fn new(registry: &Registry) -> Self {
        Self {
            benchmark_duration: register_int_counter_with_registry!(
                "benchmark_duration",
                "Duration of the benchmark",
                registry,
            )
            .unwrap(),
            submitted: register_int_counter_with_registry!(
                "submitted",
                "Number of submitted transactions",
                registry,
            )
            .unwrap(),
            finality_latency_s: register_histogram_vec_with_registry!(
                "finality_latency_s",
                "Total time in seconds to to achieve finality",
                &["status"],
                LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            finality_latency_squared_s: register_counter_vec_with_registry!(
                "finality_latency_squared_s",
                "Square of total time in seconds to achieve finality",
                &["status"],
                registry,
            )
            .unwrap(),
            certification_latency_s: register_histogram_vec_with_registry!(
                "certification_latency_s",
                "Total time in seconds to certify transactions",
                &["status"],
                LATENCY_SEC_BUCKETS.to_vec(),
                registry,
            )
            .unwrap(),
            certification_latency_squared_s: register_counter_vec_with_registry!(
                "certification_latency_squared_s",
                "Square of total time in seconds to certify transactions",
                &["status"],
                registry,
            )
            .unwrap(),
            errors: register_counter_vec_with_registry!(
                "errors",
                "Reports various errors",
                &["type"],
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
