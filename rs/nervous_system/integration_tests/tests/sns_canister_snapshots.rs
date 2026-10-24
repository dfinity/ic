//! End-to-end tests of SNS canister snapshot proposals:
//!
//!   * UpgradeSnsControlledCanister with take_canister_snapshot set,
//!   * TakeCanisterSnapshot, and
//!   * LoadCanisterSnapshot.
//!
//! These run a real NNS and SNS (built from this branch; the SNS Governance canister is the
//! feature = "test" build, where snapshot proposals are enabled) in PocketIC.

use candid::{Decode, Encode, Principal};
use canister_test::Wasm;
use ic_base_types::{CanisterId, PrincipalId, SnapshotId};
use ic_nervous_system_agent::{
    helpers::await_with_timeout,
    pocketic_impl::PocketIcAgent,
    sns::{
        Sns,
        governance::{GovernanceCanister, ProposalSubmissionError, SubmittedProposal},
    },
};
use ic_nervous_system_integration_tests::{
    create_service_nervous_system_builder::CreateServiceNervousSystemBuilder,
    pocket_ic_helpers::{
        NnsInstaller, add_wasms_to_sns_wasm, install_canister_on_subnet, load_registry_mutations,
        nns, sns, sns::governance::find_neuron_with_majority_voting_power,
    },
};
use ic_nervous_system_root::take_canister_snapshot::{
    TakeCanisterSnapshotRequest, TakeCanisterSnapshotResponse,
};
use ic_nns_constants::ROOT_CANISTER_ID;
use ic_nns_test_utils::sns_wasm::build_mainnet_root_sns_wasm;
use ic_protobuf::types::v1::CanisterInstallMode as CanisterInstallModeProto;
use ic_sns_governance_api::pb::v1::{
    GovernanceError, ListProposals, ListProposalsResponse, LoadCanisterSnapshot, NeuronId,
    Proposal, ProposalData, ProposalId, SuccessfulProposalExecutionValue, TakeCanisterSnapshot,
    TakeCanisterSnapshotOk, UpgradeSnsControlledCanister, get_proposal_response, proposal::Action,
    upgrade_sns_controlled_canister::TakeSnapshotBeforeUpgrade,
};
use ic_sns_swap::pb::v1::Lifecycle;
use lazy_static::lazy_static;
use pocket_ic::{PocketIcBuilder, nonblocking::PocketIc};
use std::time::Duration;
use tempfile::TempDir;

/// The Management canister allows at most this many snapshots per canister.
const MAX_SNAPSHOTS_PER_CANISTER: usize = 10;

const MIN_UPGRADE_TIME_SECONDS: u64 = 0;
const MAX_UPGRADE_TIME_SECONDS: u64 = 5 * 60;

lazy_static! {
    /// A counter. `inc` increments it; `get` replies with its current value (as little-endian
    /// u32). The counter lives in (heap) memory, which an upgrade wipes (and a snapshot keeps).
    static ref V1_WASM: Vec<u8> = wat::parse_str(
        r#"
        (module
            (import "ic0" "msg_reply" (func $msg_reply))
            (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32 i32)))
            (memory 1)

            (func $inc
                (i32.store (i32.const 0) (i32.add (i32.load (i32.const 0)) (i32.const 1)))
                (call $msg_reply))

            (func $get
                (call $msg_reply_data_append (i32.const 0) (i32.const 4))
                (call $msg_reply))

            (export "canister_update inc" (func $inc))
            (export "canister_query get" (func $get))
        )
        "#,
    )
    .unwrap();

    /// Like V1_WASM, but `get` adds 1_000_000 to the counter, so that one can tell which code
    /// is running.
    static ref V2_WASM: Vec<u8> = wat::parse_str(
        r#"
        (module
            (import "ic0" "msg_reply" (func $msg_reply))
            (import "ic0" "msg_reply_data_append"
                (func $msg_reply_data_append (param i32 i32)))
            (memory 1)

            (func $inc
                (i32.store (i32.const 0) (i32.add (i32.load (i32.const 0)) (i32.const 1)))
                (call $msg_reply))

            (func $get
                (i32.store (i32.const 4) (i32.add (i32.load (i32.const 0)) (i32.const 1000000)))
                (call $msg_reply_data_append (i32.const 4) (i32.const 4))
                (call $msg_reply))

            (export "canister_update inc" (func $inc))
            (export "canister_query get" (func $get))
        )
        "#,
    )
    .unwrap();

    static ref V1_WASM_HASH: Vec<u8> = Wasm::from_bytes(V1_WASM.clone()).sha256_hash().to_vec();
    static ref V2_WASM_HASH: Vec<u8> = Wasm::from_bytes(V2_WASM.clone()).sha256_hash().to_vec();
}

struct World {
    pocket_ic: PocketIc,
    sns: Sns,
    /// Registered with the SNS; V1_WASM is installed.
    dapp_canister_ids: Vec<CanisterId>,
    neuron_id: NeuronId,
    proposer: PrincipalId,
    // Must outlive pocket_ic.
    _state_dir: TempDir,
}

impl World {
    /// Installs the NNS, publishes the SNS Wasms (built from this branch) to SNS-W, creates
    /// `dapp_count` dapp canisters running V1_WASM, and creates an SNS that controls them.
    async fn new(dapp_count: usize) -> Self {
        let state_dir = TempDir::new().unwrap();

        let pocket_ic = PocketIcBuilder::new()
            .with_state_dir(state_dir.path().to_path_buf())
            .with_nns_subnet()
            .with_sns_subnet()
            .with_ii_subnet()
            .with_application_subnet()
            .build_async()
            .await;

        // Install NNS.
        {
            let registry_proto_path = state_dir.path().join("registry.proto");
            let initial_mutations = load_registry_mutations(registry_proto_path);

            let mut nns_installer = NnsInstaller::default();
            nns_installer
                .with_current_nns_canister_versions()
                .with_cycles_minting_canister()
                .with_cycles_ledger()
                .with_custom_registry_mutations(vec![initial_mutations]);
            nns_installer.install(&pocket_ic).await;
        }

        // Publish SNS Wasms (from this branch) to SNS-W.
        let with_mainnet_sns_canisters = false;
        add_wasms_to_sns_wasm(&pocket_ic, with_mainnet_sns_canisters)
            .await
            .unwrap();

        // Create the dapp canisters.
        let app_subnet = pocket_ic.topology().await.get_app_subnets()[0];
        let mut dapp_canister_ids = vec![];
        for _ in 0..dapp_count {
            let canister_id = install_canister_on_subnet(
                &pocket_ic,
                app_subnet,
                vec![],
                Some(Wasm::from_bytes(V1_WASM.clone())),
                vec![ROOT_CANISTER_ID.into()],
            )
            .await;
            dapp_canister_ids.push(canister_id);
        }

        // Create the SNS.
        let sns = {
            let create_service_nervous_system = CreateServiceNervousSystemBuilder::default()
                .with_dapp_canisters(dapp_canister_ids.clone())
                .build();

            let swap_parameters = create_service_nervous_system
                .swap_parameters
                .clone()
                .unwrap();

            let sns_instance_label = "1";
            let (sns, _) = nns::governance::propose_to_deploy_sns_and_wait(
                &pocket_ic,
                create_service_nervous_system,
                sns_instance_label,
            )
            .await;

            sns::swap::await_swap_lifecycle(&pocket_ic, sns.swap.canister_id, Lifecycle::Open)
                .await
                .unwrap();
            sns::swap::smoke_test_participate_and_finalize(
                &pocket_ic,
                sns.swap.canister_id,
                swap_parameters,
            )
            .await;

            sns
        };

        // Proposals by this neuron are adopted right away.
        let (neuron_id, proposer) =
            find_neuron_with_majority_voting_power(&pocket_ic, sns.governance.canister_id)
                .await
                .expect("cannot find SNS neuron with dissolve delay over 6 months.");

        let world = Self {
            pocket_ic,
            sns,
            dapp_canister_ids,
            neuron_id,
            proposer,
            _state_dir: state_dir,
        };

        // Smoke test the world.
        for dapp_canister_id in world.dapp_canister_ids.clone() {
            assert_eq!(world.module_hash(dapp_canister_id).await, *V1_WASM_HASH);
            assert_eq!(world.get(dapp_canister_id).await, 0);
            assert_eq!(
                world.list_snapshots(dapp_canister_id).await,
                Vec::<Vec<u8>>::new()
            );
        }

        world
    }

    fn dapp(&self) -> CanisterId {
        self.dapp_canister_ids[0]
    }

    fn root_principal(&self) -> Principal {
        self.sns.root.canister_id.0
    }

    fn governance_principal(&self) -> Principal {
        self.sns.governance.canister_id.0
    }

    async fn inc(&self, canister_id: CanisterId) {
        // Make sure that the canister is running (see `get`).
        let _ = self.get(canister_id).await;
        self.pocket_ic
            .update_call(canister_id.into(), Principal::anonymous(), "inc", vec![])
            .await
            .unwrap();
    }

    /// Reads the counter. Because SNS Root does its work in the background (and stops the
    /// canister while it does), the canister might be stopped for a little while; this waits
    /// for it to be running again.
    async fn get(&self, canister_id: CanisterId) -> u32 {
        let mut last_err = None;
        for _ in 0..100 {
            match self
                .pocket_ic
                .query_call(canister_id.into(), Principal::anonymous(), "get", vec![])
                .await
            {
                Ok(reply) => return u32::from_le_bytes(reply.try_into().unwrap()),
                Err(err) => last_err = Some(err),
            }
            self.pocket_ic.tick().await;
        }
        panic!("Unable to read the counter of {canister_id}: {last_err:?}");
    }

    async fn module_hash(&self, canister_id: CanisterId) -> Vec<u8> {
        self.pocket_ic
            .canister_status(canister_id.into(), Some(self.root_principal()))
            .await
            .unwrap()
            .module_hash
            .unwrap()
    }

    /// Waits until the canister runs the code with the given hash. This is needed after
    /// upgrades, because SNS Root's change_canister replies before the upgrade is done.
    async fn await_module_hash(&self, canister_id: CanisterId, expected_module_hash: &[u8]) {
        await_with_timeout(
            &self.pocket_ic,
            MIN_UPGRADE_TIME_SECONDS..MAX_UPGRADE_TIME_SECONDS,
            |pocket_ic| async move {
                pocket_ic
                    .canister_status(canister_id.into(), Some(self.root_principal()))
                    .await
                    .unwrap()
                    .module_hash
            },
            &Some(expected_module_hash.to_vec()),
        )
        .await
        .unwrap();
    }

    /// The IDs of the snapshots of the canister, as seen by SNS Root (its controller).
    async fn list_snapshots(&self, canister_id: CanisterId) -> Vec<Vec<u8>> {
        self.pocket_ic
            .list_canister_snapshots(canister_id.into(), Some(self.root_principal()))
            .await
            .unwrap()
            .into_iter()
            .map(|snapshot| snapshot.id)
            .collect()
    }

    /// Takes a snapshot directly (i.e. not via a proposal), as SNS Root. Returns its ID.
    async fn take_snapshot_as_root(&self, canister_id: CanisterId) -> Vec<u8> {
        self.pocket_ic
            .take_canister_snapshot(canister_id.into(), Some(self.root_principal()), None)
            .await
            .unwrap()
            .id
    }

    /// Submits a proposal. Returns Err if it was rejected at submission (i.e. by validation).
    async fn submit(&self, action: Action) -> Result<ProposalId, GovernanceError> {
        let agent = PocketIcAgent::new(&self.pocket_ic, self.proposer);
        let proposal = Proposal {
            title: "A proposal about canister snapshots".to_string(),
            summary: "".to_string(),
            url: "".to_string(),
            action: Some(action),
        };
        let response = GovernanceCanister::new(self.sns.governance.canister_id)
            .submit_proposal(&agent, self.neuron_id.clone(), proposal)
            .await
            .unwrap();
        match SubmittedProposal::try_from(response) {
            Ok(SubmittedProposal { proposal_id }) => Ok(proposal_id),
            Err(ProposalSubmissionError::GovernanceError(err)) => Err(err),
            Err(err) => panic!("{err:?}"),
        }
    }

    /// Waits until the proposal has either been executed, or failed.
    async fn await_proposal_settled(&self, proposal_id: ProposalId) -> ProposalData {
        for _ in 0..100 {
            self.pocket_ic.advance_time(Duration::from_secs(1)).await;
            self.pocket_ic.tick().await;

            let response = sns::governance::get_proposal(
                &self.pocket_ic,
                self.sns.governance.canister_id,
                proposal_id,
                PrincipalId::new_anonymous(),
            )
            .await
            .unwrap();
            let Some(get_proposal_response::Result::Proposal(proposal_data)) = response.result
            else {
                panic!("{response:?}");
            };

            if proposal_data.executed_timestamp_seconds > 0
                || proposal_data.failed_timestamp_seconds > 0
            {
                return proposal_data;
            }
        }

        panic!("Proposal {proposal_id:?} did not settle.");
    }

    async fn submit_and_await(&self, action: Action) -> ProposalData {
        let proposal_id = self.submit(action).await.unwrap();
        self.await_proposal_settled(proposal_id).await
    }
}

fn upgrade_to_v2(
    canister_id: CanisterId,
    take_canister_snapshot: Option<TakeSnapshotBeforeUpgrade>,
) -> Action {
    Action::UpgradeSnsControlledCanister(UpgradeSnsControlledCanister {
        canister_id: Some(canister_id.get()),
        new_canister_wasm: V2_WASM.clone(),
        canister_upgrade_arg: None,
        mode: Some(CanisterInstallModeProto::Upgrade as i32),
        chunked_canister_wasm: None,
        canister_upgrade_options: None,
        take_canister_snapshot,
    })
}

fn load(canister_id: CanisterId, snapshot_id: Vec<u8>) -> Action {
    Action::LoadCanisterSnapshot(LoadCanisterSnapshot {
        canister_id: Some(canister_id.get()),
        snapshot_id: Some(snapshot_id),
    })
}

#[track_caller]
fn assert_executed(proposal_data: &ProposalData) {
    assert_eq!(proposal_data.failure_reason, None, "{proposal_data:#?}");
    assert!(
        proposal_data.executed_timestamp_seconds > 0,
        "{proposal_data:#?}"
    );
}

#[track_caller]
fn assert_failed_with(proposal_data: &ProposalData, substrings: &[&str]) {
    assert_eq!(
        proposal_data.executed_timestamp_seconds, 0,
        "{proposal_data:#?}"
    );
    assert!(
        proposal_data.failed_timestamp_seconds > 0,
        "{proposal_data:#?}"
    );
    let error_message = &proposal_data.failure_reason.as_ref().unwrap().error_message;
    for substring in substrings {
        assert!(
            error_message.contains(substring),
            "Expected {substring:?} in {error_message:?}"
        );
    }
}

#[track_caller]
fn assert_rejected_with(result: Result<ProposalId, GovernanceError>, substrings: &[&str]) {
    let err = match result {
        Ok(proposal_id) => panic!("Proposal {proposal_id:?} was not rejected at submission."),
        Err(err) => err,
    };
    for substring in substrings {
        assert!(
            err.error_message.contains(substring),
            "Expected {substring:?} in {:?}",
            err.error_message
        );
    }
}

/// Returns the ID of the snapshot recorded in the proposal's success_value.
#[track_caller]
fn recorded_snapshot_id(proposal_data: &ProposalData) -> Vec<u8> {
    match &proposal_data.success_value {
        Some(SuccessfulProposalExecutionValue::TakeCanisterSnapshot(TakeCanisterSnapshotOk {
            snapshot_id,
            taken_at_timestamp,
            total_size,
        })) => {
            assert!(*taken_at_timestamp > 0, "{proposal_data:#?}");
            assert!(*total_size > 0, "{proposal_data:#?}");
            snapshot_id.clone()
        }
        _ => panic!("No snapshot recorded in {proposal_data:#?}"),
    }
}

/// The main scenario: upgrade with a snapshot, then roll back by loading that snapshot. Then the
/// same for a Reinstall.
#[tokio::test]
async fn test_upgrade_with_snapshot_then_load_snapshot() {
    // Step 1: Prepare the world.
    let world = World::new(1).await;
    let dapp = world.dapp();
    for _ in 0..3 {
        world.inc(dapp).await;
    }
    assert_eq!(world.get(dapp).await, 3);

    // Step 2: Upgrade the dapp, with a snapshot.
    let proposal_data = world
        .submit_and_await(upgrade_to_v2(
            dapp,
            Some(TakeSnapshotBeforeUpgrade {
                replace_snapshot: None,
            }),
        ))
        .await;

    // Step 2.1: The upgrade happened. (V1 kept the counter in main memory, which the upgrade
    // wiped. So the counter is 0, and V2 adds 1_000_000.)
    assert_executed(&proposal_data);
    world.await_module_hash(dapp, &V2_WASM_HASH).await;
    assert_eq!(world.get(dapp).await, 1_000_000);

    // Step 2.2: The snapshot exists, and its ID was recorded in the proposal.
    let snapshot_id = recorded_snapshot_id(&proposal_data);
    assert_eq!(
        SnapshotId::try_from(&snapshot_id)
            .unwrap()
            .get_canister_id(),
        dapp
    );
    assert_eq!(world.list_snapshots(dapp).await, vec![snapshot_id.clone()]);

    // Step 2.3: The snapshot ID can also be seen in list_proposals.
    let list_proposals_response = world
        .pocket_ic
        .query_call(
            world.governance_principal(),
            Principal::anonymous(),
            "list_proposals",
            Encode!(&ListProposals::default()).unwrap(),
        )
        .await
        .unwrap();
    let list_proposals_response = Decode!(&list_proposals_response, ListProposalsResponse).unwrap();
    let listed = list_proposals_response
        .proposals
        .iter()
        .find(|listed| listed.id == proposal_data.id)
        .unwrap();
    assert_eq!(listed.success_value, proposal_data.success_value);

    // Step 3: Write some state after the snapshot (which a rollback is going to lose).
    world.inc(dapp).await;
    assert_eq!(world.get(dapp).await, 1_000_001);

    // Step 4: Roll back.
    let proposal_data = world
        .submit_and_await(load(dapp, snapshot_id.clone()))
        .await;

    // Step 5: Verify that both code and memory are back to what they were before the upgrade.
    assert_executed(&proposal_data);
    assert_eq!(proposal_data.success_value, None);
    world.await_module_hash(dapp, &V1_WASM_HASH).await;
    assert_eq!(world.get(dapp).await, 3);
    // The dapp is up and running again.
    world.inc(dapp).await;
    assert_eq!(world.get(dapp).await, 4);
    // Loading a snapshot does not consume it.
    assert_eq!(world.list_snapshots(dapp).await, vec![snapshot_id.clone()]);

    // Step 6: The same protects against an accidental Reinstall (which wipes all memory,
    // including stable memory).
    let proposal_data = world
        .submit_and_await(Action::UpgradeSnsControlledCanister(
            UpgradeSnsControlledCanister {
                canister_id: Some(dapp.get()),
                new_canister_wasm: V1_WASM.clone(),
                canister_upgrade_arg: None,
                mode: Some(CanisterInstallModeProto::Reinstall as i32),
                chunked_canister_wasm: None,
                canister_upgrade_options: None,
                take_canister_snapshot: Some(TakeSnapshotBeforeUpgrade {
                    replace_snapshot: None,
                }),
            },
        ))
        .await;
    assert_executed(&proposal_data);
    let reinstall_snapshot_id = recorded_snapshot_id(&proposal_data);
    assert_ne!(reinstall_snapshot_id, snapshot_id);
    await_with_timeout(
        &world.pocket_ic,
        MIN_UPGRADE_TIME_SECONDS..MAX_UPGRADE_TIME_SECONDS,
        |_pocket_ic| async { world.get(dapp).await },
        &0,
    )
    .await
    .unwrap();

    let proposal_data = world
        .submit_and_await(load(dapp, reinstall_snapshot_id.clone()))
        .await;
    assert_executed(&proposal_data);
    assert_eq!(world.get(dapp).await, 4);
    assert_eq!(
        world.list_snapshots(dapp).await.len(),
        2,
        "Expected both snapshots to still be there."
    );
}

/// At the limit, an upgrade with a snapshot fails (and does not upgrade), unless it replaces
/// an existing snapshot.
#[tokio::test]
async fn test_upgrade_with_snapshot_at_the_snapshot_limit() {
    // Step 1: Prepare the world: the dapp already has the maximum number of snapshots.
    let world = World::new(1).await;
    let dapp = world.dapp();
    world.inc(dapp).await;
    let mut existing_snapshots = vec![];
    for _ in 0..MAX_SNAPSHOTS_PER_CANISTER {
        existing_snapshots.push(world.take_snapshot_as_root(dapp).await);
    }
    existing_snapshots.sort();
    let list_sorted = |mut snapshots: Vec<Vec<u8>>| {
        snapshots.sort();
        snapshots
    };
    assert_eq!(
        list_sorted(world.list_snapshots(dapp).await),
        existing_snapshots
    );

    // Step 2: Without replace_snapshot, the proposal fails, and nothing is upgraded.
    let proposal_data = world
        .submit_and_await(upgrade_to_v2(
            dapp,
            Some(TakeSnapshotBeforeUpgrade {
                replace_snapshot: None,
            }),
        ))
        .await;
    assert_failed_with(
        &proposal_data,
        &[
            &format!("Canister {dapp} was not upgraded"),
            "taking a snapshot of it beforehand failed",
        ],
    );
    assert_eq!(proposal_data.success_value, None);
    // Give a (wrongly) started upgrade time to finish, if there were one.
    for _ in 0..10 {
        world.pocket_ic.tick().await;
    }
    assert_eq!(world.module_hash(dapp).await, *V1_WASM_HASH);
    assert_eq!(world.get(dapp).await, 1);
    assert_eq!(
        list_sorted(world.list_snapshots(dapp).await),
        existing_snapshots
    );

    // Step 3: With replace_snapshot, the upgrade goes ahead.
    let replaced_snapshot = existing_snapshots[0].clone();
    let proposal_data = world
        .submit_and_await(upgrade_to_v2(
            dapp,
            Some(TakeSnapshotBeforeUpgrade {
                replace_snapshot: Some(replaced_snapshot.clone()),
            }),
        ))
        .await;
    assert_executed(&proposal_data);
    world.await_module_hash(dapp, &V2_WASM_HASH).await;

    // Step 3.1: The new snapshot took the place of the replaced one.
    let new_snapshot = recorded_snapshot_id(&proposal_data);
    let snapshots = world.list_snapshots(dapp).await;
    assert_eq!(snapshots.len(), MAX_SNAPSHOTS_PER_CANISTER);
    assert!(snapshots.contains(&new_snapshot), "{snapshots:?}");
    assert!(!snapshots.contains(&replaced_snapshot), "{snapshots:?}");
}

/// TakeCanisterSnapshot works, and the validation rules (dapp canisters only; a snapshot must
/// belong to the target) hold end-to-end. SNS Root's snapshot methods are only for Governance.
#[tokio::test]
async fn test_take_canister_snapshot_and_validation() {
    // Step 1: Prepare the world, with two dapps.
    let world = World::new(2).await;
    let dapp_a = world.dapp_canister_ids[0];
    let dapp_b = world.dapp_canister_ids[1];
    world.inc(dapp_b).await;

    // Step 2: TakeCanisterSnapshot.
    let proposal_data = world
        .submit_and_await(Action::TakeCanisterSnapshot(TakeCanisterSnapshot {
            canister_id: Some(dapp_b.get()),
            replace_snapshot: None,
        }))
        .await;
    assert_executed(&proposal_data);
    let snapshot_of_b = recorded_snapshot_id(&proposal_data);
    assert_eq!(
        world.list_snapshots(dapp_b).await,
        vec![snapshot_of_b.clone()]
    );
    assert_eq!(world.list_snapshots(dapp_a).await, Vec::<Vec<u8>>::new());
    // Taking a snapshot leaves the canister running (and its state intact).
    assert_eq!(world.get(dapp_b).await, 1);
    world.inc(dapp_b).await;
    assert_eq!(world.get(dapp_b).await, 2);

    // Step 3: Loading B's snapshot into A is refused at submission.
    assert_rejected_with(
        world.submit(load(dapp_a, snapshot_of_b.clone())).await,
        &[&format!(
            "is a snapshot of canister {dapp_b}, not of the target canister {dapp_a}"
        )],
    );
    // Same for replacing B's snapshot with one of A.
    assert_rejected_with(
        world
            .submit(Action::TakeCanisterSnapshot(TakeCanisterSnapshot {
                canister_id: Some(dapp_a.get()),
                replace_snapshot: Some(snapshot_of_b.clone()),
            }))
            .await,
        &["not of the target canister"],
    );
    assert_rejected_with(
        world
            .submit(upgrade_to_v2(
                dapp_a,
                Some(TakeSnapshotBeforeUpgrade {
                    replace_snapshot: Some(snapshot_of_b.clone()),
                }),
            ))
            .await,
        &["not of the target canister"],
    );
    // A malformed snapshot ID is refused as well.
    assert_rejected_with(
        world.submit(load(dapp_a, vec![1, 2, 3])).await,
        &["is not a valid snapshot ID"],
    );

    // Step 4: SNS framework canisters cannot be targeted.
    let governance_canister_id =
        CanisterId::unchecked_from_principal(world.sns.governance.canister_id);
    let root_canister_id = CanisterId::unchecked_from_principal(world.sns.root.canister_id);
    let ledger_canister_id = CanisterId::unchecked_from_principal(world.sns.ledger.canister_id);
    for (canister_id, role) in [
        (governance_canister_id, "is the SNS Governance canister"),
        (root_canister_id, "is the SNS Root canister"),
        (ledger_canister_id, "is the SNS Ledger canister"),
    ] {
        assert_rejected_with(
            world
                .submit(Action::TakeCanisterSnapshot(TakeCanisterSnapshot {
                    canister_id: Some(canister_id.get()),
                    replace_snapshot: None,
                }))
                .await,
            &[role],
        );
        assert_rejected_with(
            world
                .submit(load(
                    canister_id,
                    SnapshotId::from((canister_id, 0)).to_vec(),
                ))
                .await,
            &[role],
        );
    }

    // Step 5: Nothing above changed the snapshots.
    assert_eq!(
        world.list_snapshots(dapp_b).await,
        vec![snapshot_of_b.clone()]
    );
    assert_eq!(world.list_snapshots(dapp_a).await, Vec::<Vec<u8>>::new());

    // Step 6: Only SNS Governance may call SNS Root's snapshot methods.
    let not_governance = PrincipalId::new_user_test_id(42).0;
    let request = TakeCanisterSnapshotRequest {
        canister_id: dapp_a.get(),
        replace_snapshot: None,
    };
    let err = world
        .pocket_ic
        .update_call(
            world.root_principal(),
            not_governance,
            "take_canister_snapshot",
            Encode!(&request).unwrap(),
        )
        .await
        .unwrap_err();
    assert!(err.reject_message.contains("assertion"), "{err:?}");
    let err = world
        .pocket_ic
        .update_call(
            world.root_principal(),
            not_governance,
            "load_canister_snapshot",
            Encode!(
                &ic_nervous_system_root::load_canister_snapshot::LoadCanisterSnapshotRequest {
                    canister_id: dapp_b.get(),
                    snapshot_id: snapshot_of_b.clone(),
                }
            )
            .unwrap(),
        )
        .await
        .unwrap_err();
    assert!(err.reject_message.contains("assertion"), "{err:?}");
    assert_eq!(world.list_snapshots(dapp_a).await, Vec::<Vec<u8>>::new());
    assert_eq!(world.get(dapp_b).await, 2);
}

/// If SNS Root is too old to take snapshots, an upgrade with a snapshot fails, and does not
/// upgrade. Upgrades without a snapshot keep working as before (with new and old Root alike).
#[tokio::test]
async fn test_upgrade_with_snapshot_fails_closed_with_old_root() {
    // Step 1: Prepare the world.
    let world = World::new(1).await;
    let dapp = world.dapp();

    // Step 1.1: An upgrade without take_canister_snapshot behaves as before: no snapshot.
    let proposal_data = world.submit_and_await(upgrade_to_v2(dapp, None)).await;
    assert_executed(&proposal_data);
    assert_eq!(proposal_data.success_value, None);
    world.await_module_hash(dapp, &V2_WASM_HASH).await;
    assert_eq!(world.list_snapshots(dapp).await, Vec::<Vec<u8>>::new());

    // Step 1.2: Downgrade SNS Root to the (mainnet) version, which has no snapshot methods.
    // SNS Governance is the controller of SNS Root, so it can do this directly.
    world
        .pocket_ic
        .upgrade_canister(
            world.root_principal(),
            build_mainnet_root_sns_wasm().wasm,
            Encode!().unwrap(),
            Some(world.governance_principal()),
        )
        .await
        .unwrap();
    let err = world
        .pocket_ic
        .update_call(
            world.root_principal(),
            world.governance_principal(),
            "take_canister_snapshot",
            Encode!(&TakeCanisterSnapshotRequest {
                canister_id: dapp.get(),
                replace_snapshot: None,
            })
            .unwrap(),
        )
        .await
        .map(|reply| Decode!(&reply, TakeCanisterSnapshotResponse));
    assert!(
        format!("{err:?}").contains("has no update method 'take_canister_snapshot'"),
        "The mainnet SNS Root already supports snapshots ({err:?}), so this test no longer \
         covers the case it is meant for."
    );

    // Step 2: Run the code under test: upgrade back to V1, with a snapshot.
    let proposal_data = world
        .submit_and_await(Action::UpgradeSnsControlledCanister(
            UpgradeSnsControlledCanister {
                canister_id: Some(dapp.get()),
                new_canister_wasm: V1_WASM.clone(),
                canister_upgrade_arg: None,
                mode: Some(CanisterInstallModeProto::Upgrade as i32),
                chunked_canister_wasm: None,
                canister_upgrade_options: None,
                take_canister_snapshot: Some(TakeSnapshotBeforeUpgrade {
                    replace_snapshot: None,
                }),
            },
        ))
        .await;

    // Step 3: Verify that it failed closed.
    assert_failed_with(
        &proposal_data,
        &[
            &format!("Canister {dapp} was not upgraded"),
            "Root.take_canister_snapshot failed",
        ],
    );
    assert_eq!(proposal_data.success_value, None);
    for _ in 0..10 {
        world.pocket_ic.tick().await;
    }
    assert_eq!(world.module_hash(dapp).await, *V2_WASM_HASH);
    assert_eq!(world.list_snapshots(dapp).await, Vec::<Vec<u8>>::new());

    // Step 4: Without a snapshot, upgrading with the old Root still works.
    let proposal_data = world
        .submit_and_await(Action::UpgradeSnsControlledCanister(
            UpgradeSnsControlledCanister {
                canister_id: Some(dapp.get()),
                new_canister_wasm: V1_WASM.clone(),
                canister_upgrade_arg: None,
                mode: Some(CanisterInstallModeProto::Upgrade as i32),
                chunked_canister_wasm: None,
                canister_upgrade_options: None,
                take_canister_snapshot: None,
            },
        ))
        .await;
    assert_executed(&proposal_data);
    world.await_module_hash(dapp, &V1_WASM_HASH).await;
}
