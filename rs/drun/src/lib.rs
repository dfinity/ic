//! Standalone interface for testing application canisters.

use crate::message::{msg_stream_from_file, Message};
use candid::{CandidType, Principal};
use hex::encode;
use pocket_ic::common::rest::{ExtendedSubnetConfigSet, RawEffectivePrincipal, SubnetSpec};
use pocket_ic::{
    call_candid_as, start_or_reuse_server_with_redirects, PocketIc, UserError, WasmResult,
};
use serde::Serialize;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::str::FromStr;

mod message;

pub const ENHANCED_ORTHOGONAL_PERSISTENCE_SECTION: &str = "enhanced-orthogonal-persistence";

const DEFAULT_CYCLES_PER_CANISTER: u128 = 100_000_000_000_000; // 100 T

/// Defines the different types of subnets that can exist on the IC.
#[derive(Debug, PartialEq)]
pub enum SubnetType {
    Application,
    System,
}

#[derive(CandidType, Serialize, Debug, PartialEq)]
pub enum WasmMemoryPersistence {
    Keep,
    Replace,
}

#[derive(CandidType, Serialize, Debug, PartialEq)]
pub struct SkipPreUpgrade {
    pub skip_pre_upgrade: Option<bool>,
    pub wasm_memory_persistence: Option<WasmMemoryPersistence>,
}

#[derive(CandidType, Serialize, Debug, PartialEq)]
pub enum CanisterInstallModeV2 {
    #[serde(rename = "install")]
    Install,
    #[serde(rename = "reinstall")]
    Reinstall,
    #[serde(rename = "upgrade")]
    Upgrade(Option<SkipPreUpgrade>),
}

#[derive(CandidType, Serialize, Debug, PartialEq)]
pub struct InstallCodeArgument {
    pub mode: CanisterInstallModeV2,
    pub canister_id: Principal,
    pub wasm_module: Vec<u8>,
    pub arg: Vec<u8>,
}

impl FromStr for SubnetType {
    type Err = String;

    fn from_str(input: &str) -> Result<SubnetType, Self::Err> {
        match input {
            "application" => Ok(SubnetType::Application),
            "system" => Ok(SubnetType::System),
            _ => Err("Unknown subnet type".to_string()),
        }
    }
}

pub struct DrunOptions {
    pub msg_filename: String,
    pub log_file: Option<PathBuf>,
    pub cycles_used_file: Option<PathBuf>,
    pub subnet_type: SubnetType,
}

pub fn run_drun(uo: DrunOptions) -> Result<(), String> {
    let DrunOptions {
        msg_filename,
        log_file,
        subnet_type,
        cycles_used_file,
    } = uo;

    let msg_stream = msg_stream_from_file(&msg_filename)?;

    let server_url = start_or_reuse_server_with_redirects(
        Some(
            log_file
                .map(|p| {
                    File::create(p)
                        .unwrap_or_else(|e| panic!("Could not create log file: {}", e))
                        .into()
                })
                .unwrap_or(std::process::Stdio::null()),
        ),
        Some(std::io::stdout().into()),
    );
    let mut config = ExtendedSubnetConfigSet::default();
    match subnet_type {
        SubnetType::Application => {
            config.application.push(SubnetSpec::default());
        }
        SubnetType::System => {
            config.system.push(SubnetSpec::default());
        }
    }
    let pocket_ic = PocketIc::from_config_and_server_url(config, server_url);

    let mut canister_ids = vec![];

    for parse_result in msg_stream {
        match parse_result? {
            Message::Install(msg) => {
                let arg = InstallCodeArgument {
                    mode: msg.mode,
                    canister_id: msg.canister_id,
                    wasm_module: msg.wasm_module,
                    arg: msg.arg,
                };
                let res: Result<(), _> = call_candid_as(
                    &pocket_ic,
                    Principal::management_canister(),
                    RawEffectivePrincipal::CanisterId(msg.canister_id.as_slice().to_vec()),
                    msg.sender,
                    "install_code",
                    (arg,),
                );
                match res {
                    Ok(()) => {
                        println!("Canister successfully installed.");
                    }
                    Err(e) => {
                        println!("Canister installation failed: {:?}", e);
                    }
                }
            }

            Message::Query(q) => {
                let res = pocket_ic.query_call(q.canister_id, q.sender, &q.method_name, q.arg);
                print_query_result(res);
            }

            Message::Ingress(msg) => {
                let res = pocket_ic.update_call(
                    msg.canister_id,
                    msg.sender,
                    &msg.method_name,
                    msg.arg.to_vec(),
                );
                print_ingress_result(res);
            }

            Message::Create => {
                let canister_id = pocket_ic.create_canister();
                pocket_ic.add_cycles(canister_id, DEFAULT_CYCLES_PER_CANISTER);
                canister_ids.push(canister_id);
                println!("Canister created: {}", canister_id);
            }
        }
    }

    if let Some(cycles_used_file_path) = cycles_used_file {
        let mut file = File::create(cycles_used_file_path)
            .unwrap_or_else(|e| panic!("Could not create cycles used file: {}", e));
        for canister_id in canister_ids {
            file.write_all(
                format!(
                    "{}:{}",
                    canister_id,
                    DEFAULT_CYCLES_PER_CANISTER - pocket_ic.cycle_balance(canister_id)
                )
                .as_bytes(),
            )
            .unwrap();
        }
    }

    Ok(())
}

fn print_query_result(res: Result<WasmResult, UserError>) {
    match res {
        Ok(payload) => {
            print!("Ok: ");
            print_wasm_result(payload);
        }
        Err(e) => println!("Err: {}", e),
    }
}

fn print_ingress_result(res: Result<WasmResult, UserError>) {
    print!("ingress ");
    match res {
        Ok(payload) => {
            print!("Ok: ");
            print_wasm_result(payload);
        }
        Err(error) => {
            println!("Err: {}", error);
        }
    };
}

fn print_wasm_result(wasm_result: WasmResult) {
    match wasm_result {
        WasmResult::Reply(v) => println!("Reply: 0x{}", encode(v)),
        WasmResult::Reject(e) => println!("Reject: {}", e),
    }
}
