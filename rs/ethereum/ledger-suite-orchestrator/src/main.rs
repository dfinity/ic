use ic_cdk::api::management_canister::main::{
    canister_status, CanisterIdRecord, CanisterStatusResponse,
};
use ic_cdk_macros::{init, post_upgrade, query, update};
use ic_ledger_suite_orchestrator::candid::Erc20Contract as CandidErc20Contract;
use ic_ledger_suite_orchestrator::candid::{ManagedCanisterIds, OrchestratorArg, OrchestratorInfo};
use ic_ledger_suite_orchestrator::lifecycle;
use ic_ledger_suite_orchestrator::scheduler::{
    encode_orchestrator_metrics, Erc20Token, IC_CANISTER_RUNTIME,
};
use ic_ledger_suite_orchestrator::state::read_state;
use ic_ledger_suite_orchestrator::storage::read_wasm_store;
use ic_ledger_suite_orchestrator::storage::TASKS;

mod dashboard;

#[query]
fn canister_ids(contract: CandidErc20Contract) -> Option<ManagedCanisterIds> {
    let contract = Erc20Token::try_from(contract)
        .unwrap_or_else(|e| ic_cdk::trap(&format!("Invalid ERC-20 contract: {:?}", e)));
    read_state(|s| s.managed_canisters(&contract).cloned()).map(ManagedCanisterIds::from)
}

#[query]
fn get_orchestrator_info() -> OrchestratorInfo {
    read_state(|s| OrchestratorInfo {
        managed_canisters: s
            .erc20_managed_canisters_iter()
            .map(|(token, canisters)| (token.clone(), canisters.clone()).into())
            .collect(),
        cycles_management: s.cycles_management().clone(),
        more_controller_ids: s.more_controller_ids().to_vec(),
        minter_id: s.minter_id().cloned(),
        ledger_suite_version: s.ledger_suite_version().cloned().map(|v| v.into()),
        managed_other_canisters: {
            let canisters: Vec<_> = s
                .other_managed_canisters_iter()
                .map(|canisters| canisters.clone().into())
                .collect();
            if canisters.is_empty() {
                None
            } else {
                Some(canisters)
            }
        },
    })
}

#[export_name = "canister_global_timer"]
fn timer() {
    ic_ledger_suite_orchestrator::scheduler::timer(IC_CANISTER_RUNTIME);
}

#[init]
fn init(arg: OrchestratorArg) {
    match arg {
        OrchestratorArg::InitArg(init_arg) => {
            lifecycle::init(init_arg);
        }
        OrchestratorArg::UpgradeArg(_) | OrchestratorArg::AddErc20Arg(_) => {
            ic_cdk::trap("cannot init canister state without init args");
        }
    }
}

#[post_upgrade]
fn post_upgrade(orchestrator_arg: Option<OrchestratorArg>) {
    match orchestrator_arg {
        Some(OrchestratorArg::InitArg(_)) => {
            ic_cdk::trap("cannot upgrade canister state with init args");
        }
        Some(OrchestratorArg::UpgradeArg(upgrade_arg)) => {
            lifecycle::post_upgrade(Some(upgrade_arg))
        }
        Some(OrchestratorArg::AddErc20Arg(erc20)) => {
            lifecycle::add_erc20(erc20);
        }
        None => lifecycle::post_upgrade(None),
    }
}

#[update]
async fn get_canister_status() -> CanisterStatusResponse {
    canister_status(CanisterIdRecord {
        canister_id: ic_cdk::id(),
    })
    .await
    .expect("failed to fetch canister status")
    .0
}

#[query(hidden = true)]
fn http_request(
    req: ic_canisters_http_types::HttpRequest,
) -> ic_canisters_http_types::HttpResponse {
    use askama::Template;
    use dashboard::DashboardTemplate;
    use ic_canisters_http_types::HttpResponseBuilder;

    if ic_cdk::api::data_certificate().is_none() {
        ic_cdk::trap("update call rejected");
    }

    match req.path() {
        "/dashboard" => {
            let dashboard = read_wasm_store(|wasm_store| {
                read_state(|s| DashboardTemplate::from_state(s, wasm_store))
            });
            HttpResponseBuilder::ok()
                .header("Content-Type", "text/html; charset=utf-8")
                .with_body_and_content_length(dashboard.render().unwrap())
                .build()
        }
        "/logs" => {
            use ic_ledger_suite_orchestrator::logs::{Log, Priority, Sort};
            use std::str::FromStr;

            let max_skip_timestamp = match req.raw_query_param("time") {
                Some(arg) => match u64::from_str(arg) {
                    Ok(value) => value,
                    Err(_) => {
                        return HttpResponseBuilder::bad_request()
                            .with_body_and_content_length("failed to parse the 'time' parameter")
                            .build();
                    }
                },
                None => 0,
            };

            let mut log: Log = Default::default();

            match req.raw_query_param("priority") {
                Some(priority_str) => match Priority::from_str(priority_str) {
                    Ok(priority) => match priority {
                        Priority::Info => log.push_logs(Priority::Info),
                        Priority::Debug => log.push_logs(Priority::Debug),
                    },
                    Err(_) => log.push_all(),
                },
                None => log.push_all(),
            }

            log.entries
                .retain(|entry| entry.timestamp >= max_skip_timestamp);

            fn ordering_from_query_params(sort: Option<&str>, max_skip_timestamp: u64) -> Sort {
                match sort {
                    Some(ord_str) => match Sort::from_str(ord_str) {
                        Ok(order) => order,
                        Err(_) => {
                            if max_skip_timestamp == 0 {
                                Sort::Ascending
                            } else {
                                Sort::Descending
                            }
                        }
                    },
                    None => {
                        if max_skip_timestamp == 0 {
                            Sort::Ascending
                        } else {
                            Sort::Descending
                        }
                    }
                }
            }

            log.sort_logs(ordering_from_query_params(
                req.raw_query_param("sort"),
                max_skip_timestamp,
            ));

            const MAX_BODY_SIZE: usize = 3_000_000;
            HttpResponseBuilder::ok()
                .header("Content-Type", "application/json; charset=utf-8")
                .with_body_and_content_length(log.serialize_logs(MAX_BODY_SIZE))
                .build()
        }
        "/metrics" => {
            use ic_metrics_encoder::MetricsEncoder;

            let mut writer = MetricsEncoder::new(vec![], ic_cdk::api::time() as i64 / 1_000_000);

            fn encode_metrics(w: &mut MetricsEncoder<Vec<u8>>) -> std::io::Result<()> {
                const WASM_PAGE_SIZE_IN_BYTES: f64 = 65536.0;

                w.encode_gauge(
                    "ledger_suite_orchestrator_stable_memory_bytes",
                    ic_cdk::api::stable::stable64_size() as f64 * WASM_PAGE_SIZE_IN_BYTES,
                    "Size of the stable memory allocated by this canister.",
                )?;

                w.encode_gauge(
                    "ledger_suite_orchestrator_heap_memory_bytes",
                    heap_memory_size_bytes() as f64,
                    "Size of the heap memory allocated by this canister.",
                )?;

                w.gauge_vec("cycle_balance", "Cycle balance of this canister.")?
                    .value(
                        &[("canister", "ledger-suite-orchestrator")],
                        ic_cdk::api::canister_balance128() as f64,
                    )?;

                read_state(|s| {
                    w.encode_counter(
                        "ledger_suite_orchestrator_managed_ledgers",
                        s.all_managed_canisters_iter()
                            .filter(|(_erc20, canisters)| canisters.ledger.is_some())
                            .count() as f64,
                        "Total count of ckERC20 ledgers managed by the orchestrator.",
                    )?;

                    w.encode_counter(
                        "ledger_suite_orchestrator_managed_indexes",
                        s.all_managed_canisters_iter()
                            .filter(|(_erc20, canisters)| canisters.index.is_some())
                            .count() as f64,
                        "Total count of ckERC20 indexes managed by the orchestrator.",
                    )?;

                    w.encode_counter(
                        "ledger_suite_orchestrator_managed_archives",
                        s.all_managed_canisters_iter()
                            .flat_map(|(_erc20, canisters)| &canisters.archives)
                            .count() as f64,
                        "Total count of ckERC20 archives managed by the orchestrator.",
                    )
                })?;

                let num_tasks = TASKS.with(|t| t.borrow().queue.len());
                w.encode_gauge(
                    "ledger_suite_orchestrator_tasks",
                    num_tasks as f64,
                    "Total number of pending tasks.",
                )?;

                encode_orchestrator_metrics(w)?;
                Ok(())
            }

            match encode_metrics(&mut writer) {
                Ok(()) => HttpResponseBuilder::ok()
                    .header("Content-Type", "text/plain; version=0.0.4")
                    .with_body_and_content_length(writer.into_inner())
                    .build(),
                Err(err) => {
                    HttpResponseBuilder::server_error(format!("Failed to encode metrics: {}", err))
                        .build()
                }
            }
        }
        _ => HttpResponseBuilder::not_found().build(),
    }
}

/// Returns the amount of heap memory in bytes that has been allocated.
#[cfg(target_arch = "wasm32")]
pub fn heap_memory_size_bytes() -> usize {
    const WASM_PAGE_SIZE_BYTES: usize = 65536;
    core::arch::wasm32::memory_size(0) * WASM_PAGE_SIZE_BYTES
}

#[cfg(not(any(target_arch = "wasm32")))]
pub fn heap_memory_size_bytes() -> usize {
    0
}

fn main() {}

#[test]
fn check_candid_interface_compatibility() {
    fn source_to_str(source: &candid_parser::utils::CandidSource) -> String {
        match source {
            candid_parser::utils::CandidSource::File(f) => {
                std::fs::read_to_string(f).unwrap_or_else(|_| "".to_string())
            }
            candid_parser::utils::CandidSource::Text(t) => t.to_string(),
        }
    }

    fn check_service_equal(
        new_name: &str,
        new: candid_parser::utils::CandidSource,
        old_name: &str,
        old: candid_parser::utils::CandidSource,
    ) {
        let new_str = source_to_str(&new);
        let old_str = source_to_str(&old);
        match candid_parser::utils::service_equal(new, old) {
            Ok(_) => {}
            Err(e) => {
                eprintln!(
                    "{} is not compatible with {}!\n\n\
            {}:\n\
            {}\n\n\
            {}:\n\
            {}\n",
                    new_name, old_name, new_name, new_str, old_name, old_str
                );
                panic!("{:?}", e);
            }
        }
    }

    candid::export_service!();

    let new_interface = __export_service();

    // check the public interface against the actual one
    let old_interface = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("ledger_suite_orchestrator.did");

    check_service_equal(
        "actual candid interface",
        candid_parser::utils::CandidSource::Text(&new_interface),
        "declared candid interface in ledger_suite_orchestrator.did file",
        candid_parser::utils::CandidSource::File(old_interface.as_path()),
    );
}
