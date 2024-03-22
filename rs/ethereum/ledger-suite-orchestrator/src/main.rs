use ic_cdk_macros::{init, post_upgrade, query};
use ic_ledger_suite_orchestrator::candid::Erc20Contract as CandidErc20Contract;
use ic_ledger_suite_orchestrator::candid::{ManagedCanisterIds, OrchestratorArg};
use ic_ledger_suite_orchestrator::lifecycle;
use ic_ledger_suite_orchestrator::scheduler::Erc20Token;
use ic_ledger_suite_orchestrator::state::read_state;

mod dashboard;

#[query]
async fn canister_ids(contract: CandidErc20Contract) -> Option<ManagedCanisterIds> {
    let contract = Erc20Token::try_from(contract)
        .unwrap_or_else(|e| ic_cdk::trap(&format!("Invalid ERC-20 contract: {:?}", e)));
    read_state(|s| s.managed_canisters(&contract).cloned()).map(ManagedCanisterIds::from)
}

#[export_name = "canister_global_timer"]
fn timer() {
    ic_ledger_suite_orchestrator::scheduler::timer();
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
            let dashboard = read_state(DashboardTemplate::from_state);
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
        _ => HttpResponseBuilder::not_found().build(),
    }
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
