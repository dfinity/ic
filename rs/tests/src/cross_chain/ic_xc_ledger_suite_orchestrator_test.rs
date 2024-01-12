use crate::driver::ic::{InternetComputer, Subnet};
use crate::driver::test_env::TestEnv;
use crate::driver::test_env_api::{
    retry_async, HasDependencies, HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer,
    NnsCanisterWasmStrategy, NnsCustomizations,
};
use crate::nns::vote_and_execute_proposal;
use crate::orchestrator::utils::rw_message::install_nns_with_customizations_and_check_progress;
use crate::util::{block_on, runtime_from_url};
use anyhow::{anyhow, bail};
use candid::{Encode, Nat, Principal};
use canister_test::{Canister, Runtime, Wasm};
use dfn_candid::candid_one;
use ic_base_types::CanisterId;
use ic_ic00_types::CanisterInstallMode;
use ic_ledger_suite_orchestrator::candid::{
    AddErc20Arg, Erc20Contract, InitArg, ManagedCanisterIds, OrchestratorArg,
};
use ic_nervous_system_clients::canister_status::CanisterStatusResult;
use ic_nervous_system_common_test_keys::TEST_NEURON_1_OWNER_KEYPAIR;
use ic_nervous_system_root::change_canister::ChangeCanisterRequest;
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, ROOT_CANISTER_ID};
use ic_nns_test_utils::governance::submit_external_update_proposal;
use ic_nns_test_utils::ids::TEST_NEURON_1_ID;
use ic_registry_subnet_type::SubnetType;
use slog::info;
use std::future::Future;
use std::path::Path;
use std::time::Duration;

pub fn setup_with_system_and_application_subnets(env: TestEnv) {
    InternetComputer::new()
        .add_subnet(Subnet::new(SubnetType::System).add_nodes(1))
        .add_subnet(Subnet::new(SubnetType::Application).add_nodes(1))
        .setup_and_start(&env)
        .expect("Failed to setup IC under test");
    install_nns_with_customizations_and_check_progress(
        env.topology_snapshot(),
        NnsCanisterWasmStrategy::TakeBuiltFromSources,
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
        &env,
        "rs/ethereum/ledger-suite-orchestrator/ledger_suite_orchestrator_canister.wasm",
    );
    let ledger_orchestrator = block_on(async {
        let init_args = orchestrator_init_arg(&env);
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
            usdc_contract(),
        )
        .await
    });

    block_on(async {
        let token_name: String = try_async(&logger, || {
            usdc_ledger_suite
                .ledger
                .query_("icrc1_name", candid_one, ())
        })
        .await;
        assert_eq!(token_name, "Test Token".to_string());
    });
    info!(
        &logger,
        "USDC ledger {} is up and running",
        usdc_ledger_suite.ledger.canister_id(),
    );

    block_on(async {
        let index_status: ic_icrc1_index_ng::Status = try_async(&logger, || {
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

fn orchestrator_init_arg(env: &TestEnv) -> OrchestratorArg {
    OrchestratorArg::InitArg(InitArg {
        ledger_wasm: wasm_from_path(
            env,
            "rs/rosetta-api/icrc1/ledger/ledger_canister_u256.wasm.gz",
        )
        .bytes(),
        index_wasm: wasm_from_path(
            env,
            "rs/rosetta-api/icrc1/index-ng/index_ng_canister_u256.wasm.gz",
        )
        .bytes(),
        archive_wasm: wasm_from_path(
            env,
            "rs/rosetta-api/icrc1/archive/archive_canister_u256.wasm.gz",
        )
        .bytes(),
    })
}

async fn install_nns_controlled_canister<'a>(
    logger: &slog::Logger,
    application_subnet_runtime: &'a Runtime,
    governance_canister: &Canister<'_>,
    root_canister: &Canister<'_>,
    canister_wasm: Wasm,
    canister_init_payload: Vec<u8>,
) -> Canister<'a> {
    use ic_canister_client::Sender;
    use ic_nervous_system_clients::canister_status::CanisterStatusType;
    use ic_nns_common::types::{NeuronId, ProposalId};
    use ic_nns_governance::pb::v1::{NnsFunction, ProposalStatus};

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

    let wasm = canister_wasm.bytes();
    let new_module_hash = &ic_crypto_sha2::Sha256::hash(&wasm);
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
            && status.module_hash.as_deref() == Some(new_module_hash)
    })
    .await;

    info!(logger, "Canister {} is ready!", canister.canister_id());

    canister
}

async fn add_erc_20_by_nns_proposal<'a>(
    logger: &slog::Logger,
    governance_canister: &Canister<'_>,
    root_canister: &Canister<'_>,
    canister_wasm: Wasm,
    orchestrator: &LedgerOrchestratorCanister<'a>,
    erc20_token: Erc20Contract,
) -> ManagedCanisters<'a> {
    use ic_canister_client::Sender;
    use ic_nervous_system_clients::canister_status::CanisterStatusType;
    use ic_nns_common::types::{NeuronId, ProposalId};
    use ic_nns_governance::pb::v1::{NnsFunction, ProposalStatus};

    let upgrade_arg = OrchestratorArg::AddErc20Arg(AddErc20Arg {
        contract: erc20_token.clone(),
    });
    let wasm = canister_wasm.bytes();
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
        "Add ERC-20".to_string(),
        "<proposal created by add_erc_20_by_nns_proposal>".to_string(),
    )
    .await;

    let proposal_result = vote_and_execute_proposal(governance_canister, proposal_id).await;
    assert_eq!(proposal_result.status(), ProposalStatus::Executed);
    info!(
        logger,
        "Added ERC-20 token {:?} via NNS proposal", upgrade_arg
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

    let created_canister_ids = retry_async(
        logger,
        Duration::from_secs(100),
        Duration::from_secs(1),
        || async {
            let managed_canister_ids = orchestrator.call_canister_ids(erc20_token.clone()).await;
            match managed_canister_ids {
                None => bail!("No managed canister IDs yet"),
                Some(x) => Ok(x),
            }
        },
    )
    .await
    .unwrap_or_else(|e| {
        panic!(
            "Canisters for contract {:?} were not created: {}",
            erc20_token, e
        )
    });
    info!(
        &logger,
        "Created canister IDs: {} for contract {:?}", created_canister_ids, erc20_token
    );

    ManagedCanisters::from(orchestrator.as_ref().runtime(), created_canister_ids)
}

fn wasm_from_path<P: AsRef<Path>>(env: &TestEnv, path: P) -> Wasm {
    Wasm::from_file(env.get_dependency_path(path))
}

fn usdc_contract() -> Erc20Contract {
    Erc20Contract {
        chain_id: Nat::from(1_u8),
        address: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48".to_string(),
    }
}

async fn status_of_nns_controlled_canister_satisfy<P: Fn(&CanisterStatusResult) -> bool>(
    logger: &slog::Logger,
    root_canister: &Canister<'_>,
    target_canister: &Canister<'_>,
    predicate: P,
) {
    use dfn_candid::candid;

    retry_async(
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
        },
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
            ledger: Canister::new(runtime, to_canister_id(canister_ids.ledger)),
            index: Canister::new(runtime, to_canister_id(canister_ids.index)),
            archives: canister_ids
                .archives
                .into_iter()
                .map(|archive_id| Canister::new(runtime, to_canister_id(archive_id)))
                .collect(),
        }
    }
}

async fn try_async<F, Fut, R>(logger: &slog::Logger, f: F) -> R
where
    Fut: Future<Output = Result<R, String>>,
    F: Fn() -> Fut,
{
    retry_async(
        logger,
        Duration::from_secs(100),
        Duration::from_secs(1),
        || async { f().await.map_err(|e| anyhow!(e)) },
    )
    .await
    .expect("failed despite retries")
}
