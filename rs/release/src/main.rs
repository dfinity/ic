use ic_release::error::ReleaseResult;
use ic_release::release::ReleaseContent;
use std::path::PathBuf;
use structopt::StructOpt;

fn main() -> ReleaseResult<()> {
    let cli_args = CliArgs::from_args();
    let release_content = cli_args.validate_release_content()?;
    println!("{}", release_content.get_release_identifier()?);
    release_content.pack(cli_args.target_file)?;
    Ok(())
}

#[derive(Debug, StructOpt)]
#[structopt(
    name = "release",
    about = "Arguments to the release builder of the Internet Computer."
)]
pub struct CliArgs {
    /// The path to the replica binary.
    #[structopt(long, parse(from_os_str))]
    replica_binary: PathBuf,

    /// The path to the orchestrator binary.
    #[structopt(long, parse(from_os_str))]
    orchestrator_binary: PathBuf,

    #[structopt(long, parse(from_os_str))]
    target_file: PathBuf,
}

impl CliArgs {
    fn validate_release_content(&self) -> ReleaseResult<ReleaseContent> {
        let release_content = ReleaseContent::from_paths(
            self.replica_binary.as_path(),
            self.orchestrator_binary.as_path(),
        );

        release_content.validate()?;
        Ok(release_content)
    }
}
