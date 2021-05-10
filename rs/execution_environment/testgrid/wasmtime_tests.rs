mod common;
use ic_config::{embedders::EmbedderType, execution_environment::Config};

pub fn config() -> Config {
    Config {
        embedder_type: EmbedderType::Wasmtime,
        ..Config::default()
    }
}
