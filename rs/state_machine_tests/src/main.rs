use clap::Parser;
use ic_config::execution_environment;
use ic_config::subnet_config::SubnetConfig;
use ic_crypto_iccsa::types::SignatureBytes;
use ic_crypto_iccsa::{public_key_bytes_from_der, verify};
use ic_crypto_utils_threshold_sig_der::{
    parse_threshold_sig_key_from_der, threshold_sig_public_key_to_der,
};
use ic_registry_subnet_type::SubnetType;
use ic_state_machine_tests::{StateMachineBuilder, StateMachineConfig};
use ic_test_state_machine_client::{CanisterCall, RawCanisterId, Request, Request::*};
use ic_types::{CanisterId, Cycles, PrincipalId};
use serde::Serialize;
use std::io::{Read, Write, stdin, stdout};

macro_rules! debug_print {
    ($opts:expr_2021, $msg:expr_2021 $(,$args:expr_2021)* $(,)*) => {
        if $opts.debug {
            eprintln!($msg $(,$args)*);
        }
    }
}

struct ParsedCanisterCall {
    sender: PrincipalId,
    canister_id: CanisterId,
    method: String,
    arg: Vec<u8>,
}

impl From<CanisterCall> for ParsedCanisterCall {
    fn from(call: CanisterCall) -> Self {
        ParsedCanisterCall {
            sender: PrincipalId::try_from(&call.sender).unwrap_or_else(|err| {
                panic!(
                    "failed to parse sender from bytes {}: {}",
                    hex::encode(&call.sender),
                    err
                )
            }),
            canister_id: CanisterId::try_from(&call.canister_id).unwrap_or_else(|err| {
                panic!(
                    "failed to parse canister id from bytes {}: {}",
                    hex::encode(&call.canister_id),
                    err
                )
            }),
            method: call.method,
            arg: call.arg,
        }
    }
}

/// Command-line options
#[derive(Parser)]
#[clap(version = "1.0")]
struct Opts {
    /// Prints additional debug information to stderr (to not interfere with data sent over stdin/stdout).
    #[clap(short, long)]
    debug: bool,
}

fn main() {
    let opts: Opts = Opts::parse();
    let hypervisor_config = execution_environment::Config {
        default_provisional_cycles_balance: Cycles::new(0),
        ..Default::default()
    };
    let config = StateMachineConfig::new(SubnetConfig::new(SubnetType::System), hypervisor_config);
    let env = StateMachineBuilder::new().with_config(Some(config)).build();
    loop {
        debug_print!(&opts, "enter request loop");
        let size =
            u64::from_le_bytes(TryFrom::try_from(read_bytes(8)).expect("failed to read data size"))
                as usize;
        debug_print!(&opts, "data size: {}", size);
        let payload = read_bytes(size);
        debug_print_data(&opts, "payload received", &payload);
        let data: Request = ciborium::from_reader(&payload[..]).unwrap();
        match data {
            RootKey => send_response(
                threshold_sig_public_key_to_der(env.root_key()).unwrap(),
                &opts,
            ),
            Time => send_response(env.time(), &opts),
            SetTime(time) => {
                env.set_time(time);
                send_response((), &opts);
            }
            AdvanceTime(amount) => {
                env.advance_time(amount);
                send_response((), &opts);
            }
            CanisterUpdateCall(call) => {
                let mut call = ParsedCanisterCall::from(call);
                if call.canister_id == CanisterId::ic_00() && call.method == "create_canister" {
                    call.method = "provisional_create_canister_with_cycles".to_string();
                }
                let result =
                    env.execute_ingress_as(call.sender, call.canister_id, call.method, call.arg);
                send_response(result, &opts);
            }
            CanisterQueryCall(call) => {
                let call = ParsedCanisterCall::from(call);
                let result = env.query_as(call.sender, call.canister_id, call.method, call.arg);
                send_response(result, &opts);
            }
            CanisterExists(canister_id) => {
                send_response(env.canister_exists(to_canister_id(canister_id)), &opts)
            }
            SetStableMemory(arg) => {
                let canister_id =
                    CanisterId::try_from(arg.canister_id).expect("invalid canister id");
                env.set_stable_memory(canister_id, arg.data.as_ref());
                send_response((), &opts);
            }
            ReadStableMemory(canister_id) => {
                send_response(env.stable_memory(to_canister_id(canister_id)), &opts);
            }
            CyclesBalance(canister_id) => {
                send_response(env.cycle_balance(to_canister_id(canister_id)), &opts)
            }
            AddCycles(arg) => send_response(
                env.add_cycles(
                    CanisterId::try_from(arg.canister_id).expect("invalid canister id"),
                    arg.amount,
                ),
                &opts,
            ),
            Tick => {
                env.tick();
                send_response((), &opts);
            }
            RunUntilCompletion(arg) => {
                env.run_until_completion(arg.max_ticks as usize);
                send_response((), &opts);
            }
            VerifyCanisterSig(arg) => {
                type VerificationResult = Result<(), String>;
                let pubkey = match public_key_bytes_from_der(&arg.pubkey) {
                    Ok(pubkey) => pubkey,
                    Err(err) => {
                        send_response(
                            VerificationResult::Err(format!(
                                "failed to parse DER encoded public key: {err:?}"
                            )),
                            &opts,
                        );
                        continue;
                    }
                };
                let root_pubkey = match parse_threshold_sig_key_from_der(&arg.root_pubkey) {
                    Ok(root_pubkey) => root_pubkey,
                    Err(err) => {
                        send_response(
                            VerificationResult::Err(format!(
                                "failed to parse DER encoded root public key: {err:?}"
                            )),
                            &opts,
                        );
                        continue;
                    }
                };
                match verify(&arg.msg, SignatureBytes(arg.sig), pubkey, &root_pubkey) {
                    Ok(()) => send_response(VerificationResult::Ok(()), &opts),
                    Err(err) => send_response(
                        VerificationResult::Err(format!(
                            "canister signature verification failed: {err:?}"
                        )),
                        &opts,
                    ),
                };
            }
        }
    }
}

fn debug_print_data(opts: &Opts, prefix: &str, data: &[u8]) {
    if opts.debug {
        let truncated = if data.len() > 512 {
            hex::encode(&data[..512]) + "..."
        } else {
            hex::encode(data)
        };
        debug_print!(opts, "{}: {}, length: {:?}", prefix, truncated, data.len());
    }
}

fn read_bytes(num_bytes: usize) -> Vec<u8> {
    let mut buf = vec![0u8; num_bytes];
    stdin()
        .read_exact(&mut buf)
        .expect("failed to read from stdin");
    buf
}

fn send_response<R: Serialize>(response: R, opts: &Opts) {
    let cbor = into_cbor(&response);
    let length_bytes = (cbor.len() as u64).to_le_bytes();
    stdout()
        .write_all(&length_bytes)
        .expect("failed to send response length");
    debug_print!(opts, "length sent: {:?}", cbor.len());

    stdout()
        .write_all(cbor.as_slice())
        .expect("failed to send response");
    stdout().flush().expect("failed to flush stdout");
    debug_print_data(opts, "payload sent", &cbor);
}

fn into_cbor<R: Serialize>(value: &R) -> Vec<u8> {
    let mut bytes = vec![];
    ciborium::ser::into_writer(&value, &mut bytes).expect("bug: failed to encode a block");
    bytes
}

fn to_canister_id(raw_id: RawCanisterId) -> CanisterId {
    CanisterId::try_from(raw_id.canister_id).expect("invalid canister id")
}
