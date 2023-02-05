#[derive(Debug, Hash, Eq, PartialEq)]
pub enum MetricsParseError {
    PeerLabelToIdConversionFailure(String),
    ConnectionStateParseFailure,
    MetricLabelNotFound,
    HttpResponseError(String),
}

impl std::fmt::Display for MetricsParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PeerLabelToIdConversionFailure(msg) => {
                write!(f, "Failed to convert peer label to peer id: {:?}", msg)
            }
            Self::ConnectionStateParseFailure => {
                write!(f, "Failed to parse connection state",)
            }
            Self::MetricLabelNotFound => {
                write!(f, "Metric label not found")
            }
            Self::HttpResponseError(msg) => {
                write!(f, "Http Response error {:?}", msg)
            }
        }
    }
}

impl std::error::Error for MetricsParseError {}
