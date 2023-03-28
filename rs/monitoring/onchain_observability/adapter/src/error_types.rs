use thiserror::Error;

#[derive(Debug, Hash, Eq, PartialEq, Error)]
pub enum MetricsCollectError {
    #[error("Metric parse failure: {0}")]
    MetricParseFailure(String),
    #[error("gPRC Request to replica failed with error {0}")]
    RpcRequestFailure(String),
}

#[derive(Debug, Hash, Eq, PartialEq, Error)]
pub enum CanisterPublishError {
    #[error("Serialization failed: {0}")]
    SerializationFailure(String),
    #[error("Canister client failed: {0}")]
    CanisterClientFailure(String),
}
