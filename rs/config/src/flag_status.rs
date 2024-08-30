use serde::{Deserialize, Serialize};

/// Indicates whether a flag is enabled or disabled.
#[derive(Copy, Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub enum FlagStatus {
    Enabled,
    Disabled,
}
