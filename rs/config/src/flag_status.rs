use serde::{Deserialize, Serialize};

/// Indicates whether a flag is enabled or disabled.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub enum FlagStatus {
    Enabled,
    Disabled,
}
