//! Configuration data to connect to the registry

use gflags_derive::GFlags;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

#[derive(Error, Debug)]
pub(crate) enum ConfigError {
    #[error("--nns_urls did not parse as a comma-separated list of urls: {source}")]
    InvalidNnsUrls {
        #[from]
        source: url::ParseError,
    },
}

/// External mechanism for configuring registry client
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, GFlags)]
#[serde(default)]
#[gflags(prefix = "nns_")]
pub struct Config {
    /// Comma-separated URLs for the NNS subnet to fetch the registry from
    #[gflags(type = "&str", placeholder = "URLs")]
    pub urls: Vec<Url>,
}

pub(crate) fn from_flags(config: Config) -> Result<Config, ConfigError> {
    let mut config = config;

    if NNS_URLS.is_present() {
        config.urls = NNS_URLS
            .flag
            .split(',')
            .map(|s| Url::parse(s))
            .collect::<Result<Vec<Url>, _>>()?;
    }

    Ok(config)
}
