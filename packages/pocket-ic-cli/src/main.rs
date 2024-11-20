use candid::Principal;
use clap::{ArgAction, Parser, Subcommand};
use pocket_ic::{CanisterSettings, PocketIc};
use reqwest::Url;
use std::collections::BTreeSet;

const DEFAULT_MAX_REQUEST_TIME_MS: u64 = 300_000;

type InstanceId = usize;

/// PocketIC CLI: A CLI for PocketIC server
#[derive(Parser)]
#[clap(version = "5.0.0")]
struct Args {
    /// The URL of the PocketIC server.
    #[clap(long)]
    server_url: Url,
    /// Command to execute on the PocketIC server.
    #[clap(subcommand)]
    command: PocketIcCliCommand,
}

impl Args {
    pub fn exec(self) -> Result<(), String> {
        self.command.exec(self.server_url)
    }
}

/// CLI commands to execute on the PocketIC server.
#[derive(Debug, Clone, Subcommand)]
#[clap(version, about, long_about = None)]
pub enum PocketIcCliCommand {
    /// Command to execute on a canister.
    Canister(PocketIcCliCanisterSubcommand),
}

impl PocketIcCliCommand {
    pub fn exec(self, server_url: Url) -> Result<(), String> {
        match self {
            PocketIcCliCommand::Canister(subcommand) => subcommand.exec(server_url),
        }
    }
}

/// Command to execute on a canister.
#[derive(Debug, Clone, Parser)]
pub struct PocketIcCliCanisterSubcommand {
    /// The canister ID of the canister.
    canister_id: Principal,
    /// The instance ID of an instance on the PocketIC server to which the canister is deployed.
    #[clap(short, long)]
    instance_id: InstanceId,
    /// The principal on whose behalf the action is executed.
    #[clap(short, long)]
    sender: Option<Principal>,
    /// Action to execute on the canister.
    #[clap(subcommand)]
    action: PocketIcCliCanisterAction,
}

impl PocketIcCliCanisterSubcommand {
    pub fn exec(self, server_url: Url) -> Result<(), String> {
        let pic = PocketIc::new_from_existing_instance(
            server_url.clone(),
            self.instance_id,
            Some(DEFAULT_MAX_REQUEST_TIME_MS),
        );
        self.action.exec(&pic, self.canister_id, self.sender)
    }
}

/// Action to execute on a canister deployed to a PocketIC instance.
#[derive(Debug, Clone, Subcommand)]
#[clap(version, about, long_about = None)]
pub enum PocketIcCliCanisterAction {
    /// Update settings of the canister.
    UpdateSettings(UpdateSettingsOpts),
}

impl PocketIcCliCanisterAction {
    pub fn exec(
        self,
        pic: &PocketIc,
        canister_id: Principal,
        sender: Option<Principal>,
    ) -> Result<(), String> {
        match self {
            PocketIcCliCanisterAction::UpdateSettings(opts) => opts.exec(pic, canister_id, sender),
        }
    }
}

/// Update one or more of a canister's settings.
#[derive(Debug, Clone, Parser)]
pub struct UpdateSettingsOpts {
    /// Add a principal to the list of controllers of the canister.
    #[arg(long, action = ArgAction::Append)]
    add_controller: Option<Vec<Principal>>,
}

impl UpdateSettingsOpts {
    pub fn exec(
        self,
        pic: &PocketIc,
        canister_id: Principal,
        sender: Option<Principal>,
    ) -> Result<(), String> {
        let status = pic
            .canister_status(canister_id, sender)
            .map_err(|e| format!("Failed to get canister status: {:?}", e))?;
        let controllers = self.add_controller.map(|new_controllers| {
            let mut controllers: BTreeSet<_> = status.settings.controllers.into_iter().collect();
            for controller in new_controllers {
                controllers.insert(controller);
            }
            controllers.into_iter().collect::<Vec<_>>()
        });
        let settings = CanisterSettings {
            controllers,
            ..Default::default()
        };
        pic.update_canister_settings(canister_id, sender, settings)
            .map_err(|e| format!("Failed to update canister settings: {:?}.", e))
    }
}

fn main() {
    let args = Args::parse();
    if let Err(e) = args.exec() {
        eprintln!("Failed to execute command: {}", e);
        std::process::exit(1);
    } else {
        println!("Successfully executed.");
    }
}
