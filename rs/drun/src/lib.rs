//! Standalone interface for testing application canisters.

use crate::message::{msg_stream_from_file, Message};
use hex::encode;
use ic_config::{subnet_config::SubnetConfigs, Config};
use ic_cycles_account_manager::CyclesAccountManager;
use ic_error_types::{ErrorCode, UserError};
use ic_execution_environment::ExecutionServices;
use ic_interfaces::{execution_environment::IngressHistoryReader, messaging::MessageRouting};
use ic_interfaces_state_manager::StateReader;
use ic_messaging::MessageRoutingImpl;
use ic_metrics::MetricsRegistry;
use ic_metrics_exporter::MetricsRuntimeImpl;
use ic_protobuf::registry::{
    provisional_whitelist::v1::ProvisionalWhitelist as PbProvisionalWhitelist,
    routing_table::v1::RoutingTable as PbRoutingTable,
};
use ic_protobuf::types::v1::PrincipalId as PrincipalIdIdProto;
use ic_protobuf::types::v1::SubnetId as SubnetIdProto;
use ic_registry_client::client::RegistryClientImpl;
use ic_registry_keys::{
    make_provisional_whitelist_record_key, make_routing_table_record_key, ROOT_SUBNET_ID_KEY,
};
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_registry_routing_table::{routing_table_insert_subnet, RoutingTable};
use ic_registry_subnet_type::SubnetType;
use ic_state_manager::StateManagerImpl;
use ic_test_utilities::consensus::fake::FakeVerifier;
use ic_test_utilities_registry::{
    add_subnet_record, insert_initial_dkg_transcript, SubnetRecordBuilder,
};
use ic_types::{
    batch::{Batch, BatchPayload, IngressPayload},
    ingress::{IngressState, IngressStatus, WasmResult},
    messages::{MessageId, SignedIngress},
    replica_config::ReplicaConfig,
    time::UNIX_EPOCH,
    CanisterId, NodeId, PrincipalId, Randomness, RegistryVersion, SubnetId,
};
use slog::{Drain, Logger};
use std::fs::OpenOptions;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::{thread::sleep, time::Duration};

mod message;

// drun will panic if it takes more than this many batches
// until a response for a message is received
const MAX_BATCHES_UNTIL_RESPONSE: u64 = 10000;
// how long to wait between batches
const WAIT_PER_BATCH: Duration = Duration::from_millis(5);

pub struct DrunOptions {
    pub msg_filename: String,
    pub cfg: Config,
    pub extra_batches: u64,
    pub log_file: Option<PathBuf>,
}

/// Deliver a single message to the Message Routing layer
fn deliver_message(
    msg: SignedIngress,
    message_routing: &dyn MessageRouting,
    ingress_hist_reader: &dyn IngressHistoryReader,
    extra_batches: u64,
) {
    let message_id = msg.id();

    let _ = execute_ingress_message(message_routing, msg, &message_id, ingress_hist_reader);
    // print result after waiting, to not interleave the result
    // with debug.print messages from subsequent calls. revise after DFN-1269.
    wait_extra_batches(message_routing, extra_batches);
    print_ingress_result(&message_id, ingress_hist_reader);
}

fn setup_logger(log_file: PathBuf) -> Logger {
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(log_file)
        .unwrap();

    let decorator = slog_term::PlainSyncDecorator::new(file);
    let format = slog_term::FullFormat::new(decorator).use_utc_timestamp();
    let format = format.use_original_order();
    let drain = Arc::new(Mutex::new(format.build().fuse()))
        .filter_level(slog::Level::Debug)
        .ignore_res();

    slog::Logger::root(drain, slog::o!())
}

fn get_registry(
    metrics_registry: &MetricsRegistry,
    subnet_id: SubnetId,
    root_subnet_id: SubnetId,
    subnet_type: SubnetType,
    node_ids: &[NodeId],
) -> Arc<RegistryClientImpl> {
    let registry_version = RegistryVersion::from(1);
    let data_provider = Arc::new(ProtoRegistryDataProvider::new());
    let root_subnet_id_proto = SubnetIdProto {
        principal_id: Some(PrincipalIdIdProto {
            raw: root_subnet_id.get_ref().to_vec(),
        }),
    };
    data_provider
        .add(
            ROOT_SUBNET_ID_KEY,
            registry_version,
            Some(root_subnet_id_proto),
        )
        .unwrap();
    let mut routing_table = RoutingTable::new();
    routing_table_insert_subnet(&mut routing_table, subnet_id).unwrap();
    let pb_routing_table = PbRoutingTable::from(routing_table);
    data_provider
        .add(
            &make_routing_table_record_key(),
            registry_version,
            Some(pb_routing_table),
        )
        .unwrap();
    let pb_whitelist = PbProvisionalWhitelist::from(ProvisionalWhitelist::All);
    data_provider
        .add(
            &make_provisional_whitelist_record_key(),
            registry_version,
            Some(pb_whitelist),
        )
        .unwrap();

    // Set subnetwork list(needed for filling network_topology.nns_subnet_id)
    let mut record = SubnetRecordBuilder::from(node_ids).build();
    record.subnet_type = i32::from(subnet_type);

    insert_initial_dkg_transcript(registry_version.get(), subnet_id, &record, &data_provider);
    add_subnet_record(&data_provider, registry_version.get(), subnet_id, record);

    let registry_client = Arc::new(RegistryClientImpl::new(
        data_provider,
        Some(metrics_registry),
    ));
    registry_client.fetch_and_start_polling().unwrap();
    registry_client
}

pub fn run_drun(uo: DrunOptions) -> Result<(), String> {
    let DrunOptions {
        msg_filename,
        cfg,
        extra_batches,
        log_file,
    } = uo;
    // Hardcoded magic values to create a ReplicaConfig that parses.
    let subnet_type = SubnetType::System;
    let subnet_config = SubnetConfigs::default().own_subnet_config(subnet_type);
    let subnet_id = SubnetId::from(PrincipalId::new_subnet_test_id(0));
    let root_subnet_id = SubnetId::from(PrincipalId::new_subnet_test_id(1));
    let replica_config = ReplicaConfig {
        node_id: NodeId::from(PrincipalId::new_node_test_id(27)),
        subnet_id,
    };

    let mut msg_stream = msg_stream_from_file(&msg_filename)?;
    let log = match log_file {
        Some(log_file) => setup_logger(log_file),
        None => slog::Logger::root(slog::Discard, slog::o!()),
    };

    let metrics_registry = MetricsRegistry::global();
    let registry = get_registry(
        &metrics_registry,
        subnet_id,
        root_subnet_id,
        subnet_type,
        &[replica_config.node_id],
    );

    let cycles_account_manager = Arc::new(CyclesAccountManager::new(
        subnet_config.scheduler_config.max_instructions_per_message,
        subnet_type,
        subnet_id,
        subnet_config.cycles_account_manager_config,
    ));

    let state_manager = Arc::new(StateManagerImpl::new(
        Arc::new(FakeVerifier::new()),
        replica_config.subnet_id,
        subnet_type,
        log.clone().into(),
        &metrics_registry,
        &cfg.state_manager,
        None,
        ic_types::malicious_flags::MaliciousFlags::default(),
    ));
    let (_, ingress_history_writer, ingress_hist_reader, query_handler, _, _, scheduler) =
        ExecutionServices::setup_execution(
            log.clone().into(),
            &metrics_registry,
            tokio::runtime::Handle::current(),
            replica_config.subnet_id,
            subnet_type,
            subnet_config.scheduler_config,
            cfg.hypervisor.clone(),
            Arc::clone(&cycles_account_manager),
            Arc::clone(&state_manager) as Arc<_>,
        )
        .into_parts();

    let _metrics_runtime = MetricsRuntimeImpl::new_insecure(
        tokio::runtime::Handle::current(),
        cfg.metrics,
        metrics_registry.clone(),
        &log,
    );

    let message_routing = MessageRoutingImpl::new(
        Arc::clone(&state_manager) as _,
        Arc::clone(&state_manager) as _,
        Arc::clone(&ingress_history_writer) as _,
        scheduler,
        cfg.hypervisor,
        cycles_account_manager,
        replica_config.subnet_id,
        &metrics_registry,
        log.clone().into(),
        Arc::clone(&registry) as _,
    );

    msg_stream.try_for_each(|parse_result| {
        parse_result.map(|msg| match msg {
            Message::Install(msg) => {
                deliver_message(
                    msg,
                    &message_routing,
                    ingress_hist_reader.as_ref(),
                    extra_batches,
                );
            }

            Message::Query(q) => {
                // NOTE: Data certificates aren't supported in drun yet.
                // To support them, we'd need to do something similar to
                // http_handler::get_latest_certified_state_and_data_certificate
                print_query_result(query_handler.query(
                    q,
                    state_manager.get_latest_state().take(),
                    Vec::new(),
                ));
            }

            Message::Ingress(msg) => {
                deliver_message(
                    msg,
                    &message_routing,
                    ingress_hist_reader.as_ref(),
                    extra_batches,
                );
            }
            Message::Create(msg) => {
                deliver_message(
                    msg,
                    &message_routing,
                    ingress_hist_reader.as_ref(),
                    extra_batches,
                );
            }
        })
    })
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

fn print_ingress_result(message_id: &MessageId, ingress_hist_reader: &dyn IngressHistoryReader) {
    let status = (ingress_hist_reader.get_latest_status())(message_id);
    print!("ingress ");
    match status {
        IngressStatus::Known {
            state: IngressState::Completed(result),
            ..
        } => {
            print!("Completed: ");
            print_wasm_result(result)
        }
        IngressStatus::Known {
            state: IngressState::Failed(error),
            ..
        } => println!("Err: {}", error),
        _ => panic!("Ingress message has not finished processing."),
    };
}

fn print_wasm_result(wasm_result: WasmResult) {
    match wasm_result {
        WasmResult::Reply(v) => println!("Reply: 0x{}", encode(v)),
        WasmResult::Reject(e) => println!("Reject: {}", e),
    }
}

fn build_batch(message_routing: &dyn MessageRouting, msgs: Vec<SignedIngress>) -> Batch {
    Batch {
        batch_number: message_routing.expected_batch_height(),
        requires_full_state_hash: !msgs.is_empty(),
        payload: BatchPayload {
            ingress: IngressPayload::from(msgs),
            ..BatchPayload::default()
        },
        randomness: Randomness::from([0; 32]),
        ecdsa_subnet_public_key: None,
        registry_version: RegistryVersion::from(1),
        time: UNIX_EPOCH,
        consensus_responses: vec![],
    }
}
/// Block till the given ingress message has finished executing and
/// then return the result.  To ensure that this function does not
/// block forever (in case of bugs), this function will panic if the
/// process is not finished in some amount of time.
fn execute_ingress_message(
    message_routing: &dyn MessageRouting,
    msg: SignedIngress,
    msg_id: &MessageId,
    ingress_history: &dyn IngressHistoryReader,
) -> Result<WasmResult, UserError> {
    let mut batch = build_batch(message_routing, vec![msg]);
    for _ in 0..MAX_BATCHES_UNTIL_RESPONSE {
        // In the first batch we try to send the ingress message itself. If it fails, we
        // repeat with the same batch.
        //
        // After the batch with a message is delivered, we keep submitting work to
        // message routing in the form of empty batches till the ingress message has
        // finished executing. This is necessary to get message routing to process
        // potential inter-canister messages that the ingress message may have
        // triggered.
        if message_routing.deliver_batch(batch.clone()).is_ok() {
            batch = build_batch(message_routing, vec![])
        }
        sleep(WAIT_PER_BATCH);

        let ingress_result = (ingress_history.get_latest_status())(msg_id);
        match ingress_result {
            IngressStatus::Known { state, .. } => match state {
                IngressState::Completed(result) => return Ok(result),
                IngressState::Failed(error) => return Err(error),
                IngressState::Done => {
                    return Err(UserError::new(
                        ErrorCode::SubnetOversubscribed,
                        "The call has completed but the reply/reject data has been pruned.",
                    ))
                }
                IngressState::Received | IngressState::Processing => (),
            },
            IngressStatus::Unknown => (),
        }
    }
    panic!(
        "Ingress message did not finish executing within {} batches, panicking",
        MAX_BATCHES_UNTIL_RESPONSE
    );
}

/// To have deterministic output, it is necessary in some cases to wait a number
/// of batches before executing the next message.
///
/// Example:
/// User --Ingress--> BA --Inter-canister-request--> Hotel 1
///                      --Inter-canister-request--> Hotel 2
///
/// The user sends an Ingress message to the booking agent (BA) and waits for
/// its completion. The booking agent may respond to the Ingress message after
/// receiving responses to a subset of requests it sent out. The user thinks the
/// request is done and starts executing the next message.
///
/// If processing of remaining messages produces an output, the order in which
/// output messages are produced by executing the query message in Hotel 2 and
/// the next message in Hotel 1 leads to non-determinism.
///
/// Waiting for some extra batches via this method helps avoid this problem.
///
/// This is a temporary measure until DFN-1269 is resolved. In that ticket, we
/// will actually try to wait until all messages have been executed.
fn wait_extra_batches(message_routing: &dyn MessageRouting, extra_batches: u64) {
    for _ in 0..extra_batches {
        loop {
            let batch = build_batch(message_routing, vec![]);
            let ok = message_routing.deliver_batch(batch).is_ok();
            sleep(WAIT_PER_BATCH);
            if ok {
                break;
            };
        }
    }
}
