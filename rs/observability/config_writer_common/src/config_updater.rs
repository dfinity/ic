use std::error::Error;

use crate::config_builder::Config;

pub trait ConfigUpdater {
    fn update(&self, config: &dyn Config) -> Result<(), Box<dyn Error>>;
}
