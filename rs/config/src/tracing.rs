use serde::{Deserialize, Serialize};

#[derive(Clone, Eq, PartialEq, Debug, Default, Deserialize, Serialize)]
pub struct Config {
    pub jaeger_addr: Option<String>,
}
