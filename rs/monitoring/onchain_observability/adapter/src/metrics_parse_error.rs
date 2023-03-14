#[derive(Debug, Hash, Eq, PartialEq)]
pub enum MetricsCollectError {
    MetricParseFailure(String),
    RpcRequestFailure(String),
}

impl std::fmt::Display for MetricsCollectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MetricParseFailure(msg) => {
                write!(f, "Metric parse failure: {:?}", msg)
            }
            Self::RpcRequestFailure(msg) => {
                write!(f, "gPRC Request to replica failed with error {:?}", msg)
            }
        }
    }
}

impl std::error::Error for MetricsCollectError {}
