use anyhow::Result;
use canscan::{CanisterEndpoint, CanisterEndpoints};
use std::collections::BTreeSet;
use std::path::PathBuf;

#[derive(Debug, Default)]
pub struct Config {
    hidden: CanisterEndpoints,
}

impl Config {
    pub fn hidden(&self) -> &BTreeSet<CanisterEndpoint> {
        &self.hidden
    }
}

#[derive(Debug, Default)]
pub struct ConfigBuilder(Config);

impl ConfigBuilder {
    pub fn new() -> ConfigBuilder {
        Self::default()
    }

    pub fn hidden(mut self, endpoint: CanisterEndpoint) -> Self {
        self.0.hidden.insert(endpoint);
        self
    }

    pub fn build(self) -> Config {
        self.0
    }
}

#[derive(Debug, Default)]
pub struct ConfigParser {
    path: Option<PathBuf>,
    hidden: Vec<CanisterEndpoint>,
}

impl ConfigParser {
    pub fn new(path: Option<PathBuf>, hidden: Vec<CanisterEndpoint>) -> ConfigParser {
        Self { path, hidden }
    }

    pub fn parse(self) -> Result<Config> {
        let mut config = ConfigBuilder::new();

        for endpoint in self.hidden {
            config = config.hidden(endpoint);
        }

        if let Some(path) = self.path {
            todo!()
        }

        Ok(config.build())
    }
}
