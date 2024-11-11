use anyhow::{anyhow, bail};
use candid::{Encode, Nat, Principal};
use canister_test::{Canister, Runtime, Wasm};
use dfn_candid::candid_one;
use ic_base_types::CanisterId;
use ic_consensus_system_test_utils::rw_message::install_nns_with_customizations_and_check_progress;
use ic_ledger_suite_orchestrator::candid::{
    AddErc20Arg, Erc20Contract, InitArg, LedgerInitArg, ManagedCanisterIds, OrchestratorArg,
    UpgradeArg,
};
use ic_management_canister_types::CanisterInstallMode;
use ic_nervous_system_clients::canister_status::CanisterStatusResult;
use ic_nervous_system_common_test_keys::{TEST_NEURON_1_ID, TEST_NEURON_1_OWNER_KEYPAIR};
use ic_nervous_system_root::change_canister::ChangeCanisterRequest;
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, ROOT_CANISTER_ID};
use ic_nns_test_utils::governance::submit_external_update_proposal;
use ic_registry_subnet_type::SubnetType;
use ic_system_test_driver::{
    driver::{
        ic::{InternetComputer, Subnet},
        test_env::TestEnv,
        test_env_api::{
            get_dependency_path, HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer,
            NnsCustomizations,
        },
    },
    nns::vote_and_execute_proposal,
    util::{block_on, runtime_from_url},
};
use ic_wasm_types::CanisterModule;
use slog::info;
use std::{future::Future, path::Path, time::Duration};

pub fn setup_with_system_and_application_subnets(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::new(SubnetType::System).add_nodes(1))
        .add_subnet(Subnet::new(SubnetType::Application).add_nodes(1))
        .setup_and_start(&env)
        .expect("Failed to setup IC under test");
    install_nns_with_customizations_and_check_progress(
        env.topology_snapshot(),
        NnsCustomizations::default(),
    );

    env.topology_snapshot()
        .subnets()
        .for_each(|subnet| subnet.await_all_nodes_healthy().unwrap());
}

pub fn ic_xc_ledger_suite_orchestrator_test(env: TestEnv) {
    let logger = env.logger();
    let topology_snapshot = env.topology_snapshot();

    let system_subnet_runtime = {
        let nns_subnet = topology_snapshot.root_subnet();
        let nns_node = nns_subnet.nodes().next().unwrap();
        runtime_from_url(nns_node.get_public_url(), nns_node.effective_canister_id())
    };
    let root_canister = Canister::new(&system_subnet_runtime, ROOT_CANISTER_ID);
    let governance_canister = Canister::new(&system_subnet_runtime, GOVERNANCE_CANISTER_ID);

    let application_subnet_runtime = {
        let application_subnet = topology_snapshot
            .subnets()
            .find(|s| s.subnet_type() == SubnetType::Application)
            .expect("missing application subnet");
        let application_node = application_subnet.nodes().next().unwrap();
        runtime_from_url(
            application_node.get_public_url(),
            application_node.effective_canister_id(),
        )
    };

    let ledger_orchestrator_wasm = wasm_from_path(
        "rs/ethereum/ledger-suite-orchestrator/ledger_suite_orchestrator_canister.wasm.gz",
    );
    let ledger_orchestrator = block_on(async {
        use std::str::FromStr;
        let init_args = OrchestratorArg::InitArg(InitArg {
            more_controller_ids: vec![ROOT_CANISTER_ID.get().0],
            minter_id: Some(Principal::from_str("sv3dd-oaaaa-aaaar-qacoa-cai").unwrap()),
            cycles_management: None,
        });
        let canister = install_nns_controlled_canister(
            &logger,
            &application_subnet_runtime,
            &governance_canister,
            &root_canister,
            ledger_orchestrator_wasm.clone(),
            Encode!(&init_args).unwrap(),
        )
        .await;
        LedgerOrchestratorCanister { canister }
    });
    info!(
        &logger,
        "Installed ledger orchestrator canister at {}",
        ledger_orchestrator.as_ref().canister_id()
    );

    block_on(async {
        upgrade_ledger_suite_orchestrator_by_nns_proposal(
            &logger,
            &governance_canister,
            &root_canister,
            ledger_orchestrator_wasm.clone(),
            &ledger_orchestrator,
            OrchestratorArg::UpgradeArg(UpgradeArg {
                git_commit_hash: Some("6a8e5fca2c6b4e12966638c444e994e204b42989".to_string()),
                ledger_compressed_wasm_hash: None,
                index_compressed_wasm_hash: None,
                archive_compressed_wasm_hash: None,
                cycles_management: None,
                manage_ledger_suites: None,
            }),
        )
        .await
    });
    info!(
        &logger,
        "Registered embedded wasms in the ledger suite orchestrator {}",
        ledger_orchestrator.as_ref().canister_id()
    );

    let managed_canister_ids =
        block_on(async { ledger_orchestrator.call_canister_ids(usdc_contract()).await });
    assert_eq!(managed_canister_ids, None);

    let usdc_ledger_suite = block_on(async {
        add_erc_20_by_nns_proposal(
            &logger,
            &governance_canister,
            &root_canister,
            ledger_orchestrator_wasm,
            &ledger_orchestrator,
            AddErc20Arg {
                contract: usdc_contract(),
                ledger_init_arg: usdc_ledger_init_arg(),
            },
        )
        .await
    });

    block_on(async {
        let token_name: String = try_async("getting token_name", &logger, || {
            usdc_ledger_suite
                .ledger
                .query_("icrc1_name", candid_one, ())
        })
        .await;
        assert_eq!(token_name, "USD Coin".to_string());
    });
    info!(
        &logger,
        "USDC ledger {} is up and running",
        usdc_ledger_suite.ledger.canister_id(),
    );

    block_on(async {
        let index_status: ic_icrc1_index_ng::Status = try_async("getting status", &logger, || {
            usdc_ledger_suite.index.query_("status", candid_one, ())
        })
        .await;
        assert_eq!(
            index_status,
            ic_icrc1_index_ng::Status {
                num_blocks_synced: Nat::from(0_u8)
            }
        );
    });
    info!(
        &logger,
        "USDC index {} is up and running",
        usdc_ledger_suite.index.canister_id(),
    );

    assert!(usdc_ledger_suite.archives.is_empty());
}

async fn install_nns_controlled_canister<'a>(
    logger: &slog::Logger,
    application_subnet_runtime: &'a Runtime,
    governance_canister: &Canister<'_>,
    root_canister: &Canister<'_>,
    canister_wasm: CanisterModule,
    canister_init_payload: Vec<u8>,
) -> Canister<'a> {
    use ic_canister_client::Sender;
    use ic_nervous_system_clients::canister_status::CanisterStatusType;
    use ic_nns_common::types::{NeuronId, ProposalId};
    use ic_nns_governance_api::pb::v1::{NnsFunction, ProposalStatus};

    let canister = application_subnet_runtime
        .create_canister(Some(u128::MAX))
        .await
        .expect("failed to create canister");
    info!(
        logger,
        "Created empty canister at {}",
        canister.canister_id()
    );

    canister
        .set_controller(ROOT_CANISTER_ID.get())
        .await
        .expect("failed to modify canister controller");
    info!(
        logger,
        "Change controller of {} to root {}",
        canister.canister_id(),
        ROOT_CANISTER_ID
    );

    let new_module_hash = canister_wasm.module_hash().to_vec();
    let wasm = canister_wasm.as_slice().to_vec();
    let proposal_payload =
        ChangeCanisterRequest::new(true, CanisterInstallMode::Install, canister.canister_id())
            .with_wasm(wasm)
            .with_arg(canister_init_payload);

    let proposal_id: ProposalId = submit_external_update_proposal(
        governance_canister,
        Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
        NeuronId(TEST_NEURON_1_ID),
        NnsFunction::NnsCanisterUpgrade,
        proposal_payload,
        "Install Canister".to_string(),
        "<proposal created by install_nns_controlled_canister>".to_string(),
    )
    .await;

    let proposal_result = vote_and_execute_proposal(governance_canister, proposal_id).await;
    assert_eq!(proposal_result.status(), ProposalStatus::Executed);
    info!(
        logger,
        "Installed WASM to {} via NNS proposal",
        canister.canister_id()
    );

    status_of_nns_controlled_canister_satisfy(logger, root_canister, &canister, |status| {
        status.status == CanisterStatusType::Running
            && status.module_hash.as_deref() == Some(new_module_hash.as_ref())
    })
    .await;

    info!(logger, "Canister {} is ready!", canister.canister_id());

    canister
}

async fn upgrade_ledger_suite_orchestrator_by_nns_proposal<'a>(
    logger: &slog::Logger,
    governance_canister: &Canister<'_>,
    root_canister: &Canister<'_>,
    canister_wasm: CanisterModule,
    orchestrator: &LedgerOrchestratorCanister<'a>,
    upgrade_arg: OrchestratorArg,
) {
    use ic_canister_client::Sender;
    use ic_nervous_system_clients::canister_status::CanisterStatusType;
    use ic_nns_common::types::{NeuronId, ProposalId};
    use ic_nns_governance_api::pb::v1::{NnsFunction, ProposalStatus};

    let wasm = canister_wasm.as_slice().to_vec();
    let proposal_payload = ChangeCanisterRequest::new(
        true,
        CanisterInstallMode::Upgrade,
        orchestrator.as_ref().canister_id(),
    )
    .with_wasm(wasm)
    .with_arg(Encode!(&upgrade_arg).unwrap());

    let proposal_id: ProposalId = submit_external_update_proposal(
        governance_canister,
        Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
        NeuronId(TEST_NEURON_1_ID),
        NnsFunction::NnsCanisterUpgrade,
        proposal_payload,
        "Upgrade LSO".to_string(),
        "<proposal created by upgrade_lso_by_nns_proposal>".to_string(),
    )
    .await;

    let proposal_result = vote_and_execute_proposal(governance_canister, proposal_id).await;
    assert_eq!(proposal_result.status(), ProposalStatus::Executed);
    info!(
        logger,
        "Upgrade ledger suite orchestrator {:?} via NNS proposal", upgrade_arg
    );

    status_of_nns_controlled_canister_satisfy(
        logger,
        root_canister,
        orchestrator.as_ref(),
        |status| status.status == CanisterStatusType::Running,
    )
    .await;

    info!(
        logger,
        "Upgrade finished. Ledger orchestrator is back running"
    );
}

async fn add_erc_20_by_nns_proposal<'a>(
    logger: &slog::Logger,
    governance_canister: &Canister<'_>,
    root_canister: &Canister<'_>,
    canister_wasm: CanisterModule,
    orchestrator: &LedgerOrchestratorCanister<'a>,
    erc20_token: AddErc20Arg,
) -> ManagedCanisters<'a> {
    let erc20_contract = erc20_token.contract.clone();
    upgrade_ledger_suite_orchestrator_by_nns_proposal(
        logger,
        governance_canister,
        root_canister,
        canister_wasm,
        orchestrator,
        OrchestratorArg::AddErc20Arg(erc20_token),
    )
    .await;

    let created_canister_ids = ic_system_test_driver::retry_with_msg_async!(
        "checking if all canisters are created",
        logger,
        Duration::from_secs(100),
        Duration::from_secs(1),
        || async {
            let managed_canister_ids = orchestrator.call_canister_ids(erc20_contract.clone()).await;
            match managed_canister_ids {
                None => bail!("No managed canister IDs yet"),
                Some(x) if x.ledger.is_some() && x.index.is_some() => Ok(x),
                _ => bail!(
                    "Not all canisters were created yet: {:?}",
                    managed_canister_ids
                ),
            }
        }
    )
    .await
    .unwrap_or_else(|e| {
        panic!(
            "Canisters for contract {:?} were not created: {}",
            erc20_contract, e
        )
    });
    info!(
        &logger,
        "Created canister IDs: {} for contract {:?}", created_canister_ids, erc20_contract
    );

    ManagedCanisters::from(orchestrator.as_ref().runtime(), created_canister_ids)
}

fn wasm_from_path<P: AsRef<Path>>(path: P) -> CanisterModule {
    CanisterModule::new(Wasm::from_file(get_dependency_path(path)).bytes())
}

fn usdc_contract() -> Erc20Contract {
    Erc20Contract {
        chain_id: Nat::from(1_u8),
        address: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48".to_string(),
    }
}

fn usdc_ledger_init_arg() -> LedgerInitArg {
    const CKETH_TOKEN_LOGO: &str = "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTQ2IiBoZWlnaHQ9IjE0NiIgdmlld0JveD0iMCAwIDE0NiAxNDYiIGZpbGw9Im5vbmUiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+CjxyZWN0IHdpZHRoPSIxNDYiIGhlaWdodD0iMTQ2IiByeD0iNzMiIGZpbGw9IiMzQjAwQjkiLz4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik0xNi4zODM3IDc3LjIwNTJDMTguNDM0IDEwNS4yMDYgNDAuNzk0IDEyNy41NjYgNjguNzk0OSAxMjkuNjE2VjEzNS45NEMzNy4zMDg3IDEzMy44NjcgMTIuMTMzIDEwOC42OTEgMTAuMDYwNSA3Ny4yMDUySDE2LjM4MzdaIiBmaWxsPSJ1cmwoI3BhaW50MF9saW5lYXJfMTEwXzU4NikiLz4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik02OC43NjQ2IDE2LjM1MzRDNDAuNzYzOCAxOC40MDM2IDE4LjQwMzcgNDAuNzYzNyAxNi4zNTM1IDY4Ljc2NDZMMTAuMDMwMyA2OC43NjQ2QzEyLjEwMjcgMzcuMjc4NCAzNy4yNzg1IDEyLjEwMjYgNjguNzY0NiAxMC4wMzAyTDY4Ljc2NDYgMTYuMzUzNFoiIGZpbGw9IiMyOUFCRTIiLz4KPHBhdGggZmlsbC1ydWxlPSJldmVub2RkIiBjbGlwLXJ1bGU9ImV2ZW5vZGQiIGQ9Ik0xMjkuNjE2IDY4LjczNDNDMTI3LjU2NiA0MC43MzM0IDEwNS4yMDYgMTguMzczMyA3Ny4yMDUxIDE2LjMyMzFMNzcuMjA1MSA5Ljk5OTk4QzEwOC42OTEgMTIuMDcyNCAxMzMuODY3IDM3LjI0ODEgMTM1LjkzOSA2OC43MzQzTDEyOS42MTYgNjguNzM0M1oiIGZpbGw9InVybCgjcGFpbnQxX2xpbmVhcl8xMTBfNTg2KSIvPgo8cGF0aCBmaWxsLXJ1bGU9ImV2ZW5vZGQiIGNsaXAtcnVsZT0iZXZlbm9kZCIgZD0iTTc3LjIzNTQgMTI5LjU4NkMxMDUuMjM2IDEyNy41MzYgMTI3LjU5NiAxMDUuMTc2IDEyOS42NDcgNzcuMTc0OUwxMzUuOTcgNzcuMTc0OUMxMzMuODk3IDEwOC42NjEgMTA4LjcyMiAxMzMuODM3IDc3LjIzNTQgMTM1LjkwOUw3Ny4yMzU0IDEyOS41ODZaIiBmaWxsPSIjMjlBQkUyIi8+CjxwYXRoIGQ9Ik03My4xOTA0IDMxVjYxLjY4MThMOTkuMTIzIDczLjI2OTZMNzMuMTkwNCAzMVoiIGZpbGw9IndoaXRlIiBmaWxsLW9wYWNpdHk9IjAuNiIvPgo8cGF0aCBkPSJNNzMuMTkwNCAzMUw0Ny4yNTQ0IDczLjI2OTZMNzMuMTkwNCA2MS42ODE4VjMxWiIgZmlsbD0id2hpdGUiLz4KPHBhdGggZD0iTTczLjE5MDQgOTMuMTUyM1YxMTRMOTkuMTQwMyA3OC4wOTg0TDczLjE5MDQgOTMuMTUyM1oiIGZpbGw9IndoaXRlIiBmaWxsLW9wYWNpdHk9IjAuNiIvPgo8cGF0aCBkPSJNNzMuMTkwNCAxMTRWOTMuMTQ4OEw0Ny4yNTQ0IDc4LjA5ODRMNzMuMTkwNCAxMTRaIiBmaWxsPSJ3aGl0ZSIvPgo8cGF0aCBkPSJNNzMuMTkwNCA4OC4zMjY5TDk5LjEyMyA3My4yNjk2TDczLjE5MDQgNjEuNjg4N1Y4OC4zMjY5WiIgZmlsbD0id2hpdGUiIGZpbGwtb3BhY2l0eT0iMC4yIi8+CjxwYXRoIGQ9Ik00Ny4yNTQ0IDczLjI2OTZMNzMuMTkwNCA4OC4zMjY5VjYxLjY4ODdMNDcuMjU0NCA3My4yNjk2WiIgZmlsbD0id2hpdGUiIGZpbGwtb3BhY2l0eT0iMC42Ii8+CjxkZWZzPgo8bGluZWFyR3JhZGllbnQgaWQ9InBhaW50MF9saW5lYXJfMTEwXzU4NiIgeDE9IjUzLjQ3MzYiIHkxPSIxMjIuNzkiIHgyPSIxNC4wMzYyIiB5Mj0iODkuNTc4NiIgZ3JhZGllbnRVbml0cz0idXNlclNwYWNlT25Vc2UiPgo8c3RvcCBvZmZzZXQ9IjAuMjEiIHN0b3AtY29sb3I9IiNFRDFFNzkiLz4KPHN0b3Agb2Zmc2V0PSIxIiBzdG9wLWNvbG9yPSIjNTIyNzg1Ii8+CjwvbGluZWFyR3JhZGllbnQ+CjxsaW5lYXJHcmFkaWVudCBpZD0icGFpbnQxX2xpbmVhcl8xMTBfNTg2IiB4MT0iMTIwLjY1IiB5MT0iNTUuNjAyMSIgeDI9IjgxLjIxMyIgeTI9IjIyLjM5MTQiIGdyYWRpZW50VW5pdHM9InVzZXJTcGFjZU9uVXNlIj4KPHN0b3Agb2Zmc2V0PSIwLjIxIiBzdG9wLWNvbG9yPSIjRjE1QTI0Ii8+CjxzdG9wIG9mZnNldD0iMC42ODQxIiBzdG9wLWNvbG9yPSIjRkJCMDNCIi8+CjwvbGluZWFyR3JhZGllbnQ+CjwvZGVmcz4KPC9zdmc+Cg==";

    LedgerInitArg {
        transfer_fee: 2_000_000_000_000_u64.into(),
        decimals: 6,
        token_name: "USD Coin".to_string(),
        token_symbol: "USDC".to_string(),
        token_logo: CKETH_TOKEN_LOGO.to_string(),
    }
}

async fn status_of_nns_controlled_canister_satisfy<P: Fn(&CanisterStatusResult) -> bool>(
    logger: &slog::Logger,
    root_canister: &Canister<'_>,
    target_canister: &Canister<'_>,
    predicate: P,
) {
    use dfn_candid::candid;

    ic_system_test_driver::retry_with_msg_async!(
        format!(
            "calling canister_status of {} to check if {} satisfies the predicate",
            root_canister.canister_id(),
            target_canister.canister_id()
        ),
        logger,
        Duration::from_secs(60),
        Duration::from_secs(1),
        || async {
            let status: CanisterStatusResult = root_canister
                .update_("canister_status", candid, (target_canister.as_record(),))
                .await
                .map_err(|e| anyhow!(e))?;
            info!(
                logger,
                "Canister status of {}: {:?}",
                target_canister.canister_id(),
                status
            );
            if predicate(&status) {
                Ok(())
            } else {
                bail!(
                    "Status of {} did not satisfy predicate",
                    target_canister.canister_id()
                )
            }
        }
    )
    .await
    .unwrap_or_else(|e| {
        panic!(
            "Canister status of {} did not satisfy predicate: {}",
            target_canister.canister_id(),
            e
        )
    });
}

struct LedgerOrchestratorCanister<'a> {
    canister: Canister<'a>,
}

impl<'a> LedgerOrchestratorCanister<'a> {
    async fn call_canister_ids(&self, contract: Erc20Contract) -> Option<ManagedCanisterIds> {
        self.canister
            .query_("canister_ids", dfn_candid::candid, (contract,))
            .await
            .expect("Error while calling canister_ids endpoint")
    }
}

impl<'a> AsRef<Canister<'a>> for LedgerOrchestratorCanister<'a> {
    fn as_ref(&self) -> &Canister<'a> {
        &self.canister
    }
}

struct ManagedCanisters<'a> {
    ledger: Canister<'a>,
    index: Canister<'a>,
    archives: Vec<Canister<'a>>,
}

impl<'a> ManagedCanisters<'a> {
    pub fn from(runtime: &'a Runtime, canister_ids: ManagedCanisterIds) -> Self {
        let to_canister_id =
            |canister_id: Principal| CanisterId::unchecked_from_principal(canister_id.into());

        Self {
            ledger: Canister::new(runtime, to_canister_id(canister_ids.ledger.unwrap())),
            index: Canister::new(runtime, to_canister_id(canister_ids.index.unwrap())),
            archives: canister_ids
                .archives
                .into_iter()
                .map(|archive_id| Canister::new(runtime, to_canister_id(archive_id)))
                .collect(),
        }
    }
}

async fn try_async<S: AsRef<str>, F, Fut, R>(msg: S, logger: &slog::Logger, f: F) -> R
where
    Fut: Future<Output = Result<R, String>>,
    F: Fn() -> Fut,
{
    ic_system_test_driver::retry_with_msg_async!(
        msg.as_ref(),
        logger,
        Duration::from_secs(100),
        Duration::from_secs(1),
        || async { f().await.map_err(|e| anyhow!(e)) }
    )
    .await
    .expect("failed despite retries")
}
