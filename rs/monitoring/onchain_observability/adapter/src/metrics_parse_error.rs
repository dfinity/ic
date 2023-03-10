#[derive(Debug, Hash, Eq, PartialEq)]
pub enum MetricsParseError {
    MetricParseFailure(String),
    HttpResponseError(String),
}

impl std::fmt::Display for MetricsParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MetricParseFailure(msg) => {
                write!(f, "Metric parse failure: {:?}", msg)
            }
            Self::HttpResponseError(msg) => {
                write!(f, "Http Response error {:?}", msg)
            }
        }
    }
}

impl std::error::Error for MetricsParseError {}
