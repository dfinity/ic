use crate::generate_sns_init_payload;
use clap::Parser;
use std::{path::PathBuf, str::FromStr};

pub(crate) mod friendly;

const DEFAULT_INIT_CONFIG_PATH: &str = "sns_init.yaml";

#[derive(Debug, Parser)]
pub struct InitConfigFileArgs {
    #[clap(long, value_parser = clap::value_parser!(std::path::PathBuf))]
    init_config_file_path: Option<PathBuf>,

    #[clap(subcommand)]
    sub_command: SubCommand,
}

#[derive(Debug, Parser)]
enum SubCommand {
    /// Validates that a init_config_file is well formed.
    Validate,
}

pub fn exec(init_config_file_args: InitConfigFileArgs) {
    let init_config_file_path = init_config_file_args
        .init_config_file_path
        .unwrap_or_else(|| PathBuf::from_str(DEFAULT_INIT_CONFIG_PATH).unwrap());
    match init_config_file_args.sub_command {
        SubCommand::Validate => validate(init_config_file_path),
    }
}

fn validate(init_config_file: PathBuf) {
    if let Err(err) = generate_sns_init_payload(&init_config_file) {
        eprintln!("{}", err);
        std::process::exit(1);
    }
}
