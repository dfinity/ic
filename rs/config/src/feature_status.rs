use serde::{Deserialize, Serialize};

/// Indicates whether a feature flag is enabled or disabled.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub enum FeatureStatus {
    Enabled,
    Disabled,
}
