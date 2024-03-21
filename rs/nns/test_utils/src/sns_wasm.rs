use crate::{
    common::modify_wasm_bytes,
    state_test_helpers::{query, update, update_with_sender},
};
use candid::{Decode, Encode};
use canister_test::Project;
use dfn_candid::candid_one;
use ic_base_types::CanisterId;
use ic_nervous_system_common_test_keys::TEST_NEURON_1_OWNER_PRINCIPAL;
use ic_nns_common::{pb::v1::NeuronId, types::ProposalId};
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_governance::{
    init::TEST_NEURON_1_ID,
    pb::v1::{
        manage_neuron::{Command, NeuronIdOrSubaccount},
        manage_neuron_response::Command as CommandResponse,
        proposal, ExecuteNnsFunction, ManageNeuron, ManageNeuronResponse, NnsFunction, Proposal,
        ProposalInfo, ProposalStatus,
    },
};
use ic_sns_init::pb::v1::SnsInitPayload;
use ic_sns_wasm::pb::v1::{
    AddWasmRequest, AddWasmResponse, DeployNewSnsRequest, DeployNewSnsResponse,
    GetNextSnsVersionRequest, GetNextSnsVersionResponse, GetSnsSubnetIdsRequest,
    GetSnsSubnetIdsResponse, GetWasmRequest, GetWasmResponse, InsertUpgradePathEntriesRequest,
    ListDeployedSnsesRequest, ListDeployedSnsesResponse, SnsCanisterType, SnsUpgrade, SnsVersion,
    SnsWasm, UpdateSnsSubnetListRequest, UpdateSnsSubnetListResponse,
};
use ic_state_machine_tests::StateMachine;
use maplit::{btreemap, hashmap};
use std::{
    collections::{BTreeMap, HashMap},
    io::{Read, Write},
    time::{Duration, Instant},
};

/// Get a valid tiny WASM for use in tests of a particular SnsCanisterType
pub fn test_wasm(canister_type: SnsCanisterType, modify_with: Option<u8>) -> SnsWasm {
    let id_byte = modify_with.unwrap_or(1);
    create_modified_sns_wasm(
        &SnsWasm {
            wasm: vec![0, 0x61, 0x73, 0x6D, 1, 0, 0, 0],
            canister_type: canister_type.into(),
        },
        Some(&id_byte.to_string()),
    )
}

/// Make get_wasm request to a canister in the StateMachine
pub fn get_wasm(
    env: &StateMachine,
    sns_wasm_canister_id: CanisterId,
    hash: &[u8; 32],
) -> GetWasmResponse {
    let response_bytes = query(
        env,
        sns_wasm_canister_id,
        "get_wasm",
        Encode!(&GetWasmRequest {
            hash: hash.to_vec()
        })
        .unwrap(),
    )
    .unwrap();

    Decode!(&response_bytes, GetWasmResponse).unwrap()
}

/// Make add_wasm request to a canister in the StateMachine
pub fn add_wasm(
    env: &StateMachine,
    sns_wasm_canister_id: CanisterId,
    wasm: SnsWasm,
    hash: &[u8; 32],
) -> AddWasmResponse {
    let response = update(
        env,
        sns_wasm_canister_id,
        "add_wasm",
        Encode!(&AddWasmRequest {
            hash: hash.to_vec(),
            wasm: Some(wasm)
        })
        .unwrap(),
    )
    .unwrap();

    // Ensure we get the expected response
    Decode!(&response, AddWasmResponse).unwrap()
}

/// Make add_wasm request to a canister in the StateMachine
pub fn add_wasm_via_proposal(env: &StateMachine, wasm: SnsWasm) {
    let proposal_id = add_wasm_via_proposal_and_return_immediately(env, wasm);

    while get_proposal_info(env, proposal_id).unwrap().status == (ProposalStatus::Open as i32) {
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Insert custom upgrade path entries into SNs-W
pub fn insert_upgrade_path_entries_via_proposal(
    env: &StateMachine,
    upgrade_paths: Vec<SnsUpgrade>,
    sns_governance_canister_id: Option<CanisterId>,
) -> ProposalId {
    let sns_governance_canister_id = sns_governance_canister_id.map(|c| c.into());
    let payload = InsertUpgradePathEntriesRequest {
        upgrade_path: upgrade_paths,
        sns_governance_canister_id,
    };

    let proposal = Proposal {
        title: Some("title".into()),
        summary: "summary".into(),
        url: "".to_string(),
        action: Some(proposal::Action::ExecuteNnsFunction(ExecuteNnsFunction {
            nns_function: NnsFunction::InsertSnsWasmUpgradePathEntries as i32,
            payload: Encode!(&payload).expect("Error encoding proposal payload"),
        })),
    };

    make_proposal_with_test_neuron_1(env, proposal)
}

/// Make add_wasm request to a canister in the StateMachine
pub fn add_wasm_via_proposal_and_return_immediately(
    env: &StateMachine,
    wasm: SnsWasm,
) -> ProposalId {
    let hash = wasm.sha256_hash();
    let payload = AddWasmRequest {
        hash: hash.to_vec(),
        wasm: Some(wasm),
    };

    let proposal = Proposal {
        title: Some("title".into()),
        summary: "summary".into(),
        url: "".to_string(),
        action: Some(proposal::Action::ExecuteNnsFunction(ExecuteNnsFunction {
            nns_function: NnsFunction::AddSnsWasm as i32,
            payload: Encode!(&payload).expect("Error encoding proposal payload"),
        })),
    };

    make_proposal_with_test_neuron_1(env, proposal)
}

/// Make a proposal with test_neuron_1
fn make_proposal_with_test_neuron_1(env: &StateMachine, proposal: Proposal) -> ProposalId {
    let response: ManageNeuronResponse = update_with_sender(
        env,
        GOVERNANCE_CANISTER_ID,
        "manage_neuron",
        candid_one,
        ManageNeuron {
            id: None,
            command: Some(Command::MakeProposal(Box::new(proposal))),
            neuron_id_or_subaccount: Some(NeuronIdOrSubaccount::NeuronId(NeuronId {
                id: TEST_NEURON_1_ID,
            })),
        },
        *TEST_NEURON_1_OWNER_PRINCIPAL,
    )
    .unwrap();

    match response.command.unwrap() {
        CommandResponse::MakeProposal(resp) => ProposalId::from(resp.proposal_id.unwrap()),
        other => panic!("Unexpected response: {:?}", other),
    }
}

/// Make an update_sns_subnet_list request to a canister in the StateMachine
pub fn update_sns_subnet_list(
    env: &StateMachine,
    sns_wasm_canister_id: CanisterId,
    request: &UpdateSnsSubnetListRequest,
) -> UpdateSnsSubnetListResponse {
    let response = update(
        env,
        sns_wasm_canister_id,
        "update_sns_subnet_list",
        Encode!(request).unwrap(),
    )
    .unwrap();

    // Ensure we get the expected response
    Decode!(&response, UpdateSnsSubnetListResponse).unwrap()
}

/// Make an update_sns_subnet_list request via NNS proposal in the StateMachine
pub fn update_sns_subnet_list_via_proposal(
    env: &StateMachine,
    request: &UpdateSnsSubnetListRequest,
) {
    let proposal = Proposal {
        title: Some("title".into()),
        summary: "summary".into(),
        url: "".to_string(),
        action: Some(proposal::Action::ExecuteNnsFunction(ExecuteNnsFunction {
            nns_function: NnsFunction::UpdateSnsWasmSnsSubnetIds as i32,
            payload: Encode!(request).expect("Error encoding proposal payload"),
        })),
    };

    let pid = make_proposal_with_test_neuron_1(env, proposal);

    while get_proposal_info(env, pid).unwrap().status == (ProposalStatus::Open as i32) {
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Make a get_sns_subnet_ids request to a canister in the StateMachine
pub fn get_sns_subnet_ids(
    env: &StateMachine,
    sns_wasm_canister_id: CanisterId,
) -> GetSnsSubnetIdsResponse {
    let response_bytes = query(
        env,
        sns_wasm_canister_id,
        "get_sns_subnet_ids",
        Encode!(&GetSnsSubnetIdsRequest {}).unwrap(),
    )
    .unwrap();

    Decode!(&response_bytes, GetSnsSubnetIdsResponse).unwrap()
}

/// Call Governance's get_proposal_info method
fn get_proposal_info(env: &StateMachine, pid: ProposalId) -> Option<ProposalInfo> {
    let response = query(
        env,
        GOVERNANCE_CANISTER_ID,
        "get_proposal_info",
        Encode!(&pid).unwrap(),
    )
    .unwrap();

    Decode!(&response, Option<ProposalInfo>).unwrap()
}

/// Make deploy_new_sns request to a canister in the StateMachine
pub fn deploy_new_sns(
    env: &StateMachine,
    caller: CanisterId,
    sns_wasm_canister_id: CanisterId,
    sns_init_payload: SnsInitPayload,
) -> DeployNewSnsResponse {
    update_with_sender(
        env,
        sns_wasm_canister_id,
        "deploy_new_sns",
        candid_one,
        DeployNewSnsRequest {
            sns_init_payload: Some(sns_init_payload),
        },
        caller.get(),
    )
    .unwrap()
}

/// Make list_deployed_snses request to a canister in the StateMachine
pub fn list_deployed_snses(
    env: &StateMachine,
    sns_wasm_canister_id: CanisterId,
) -> ListDeployedSnsesResponse {
    let response = query(
        env,
        sns_wasm_canister_id,
        "list_deployed_snses",
        Encode!(&ListDeployedSnsesRequest {}).unwrap(),
    )
    .unwrap();

    Decode!(&response, ListDeployedSnsesResponse).unwrap()
}

/// Make get_next_sns_version request to a canister in the StateMachine
pub fn get_next_sns_version(
    env: &StateMachine,
    sns_wasm_canister_id: CanisterId,
    request: GetNextSnsVersionRequest,
) -> GetNextSnsVersionResponse {
    let response_bytes = query(
        env,
        sns_wasm_canister_id,
        "get_next_sns_version",
        Encode!(&request).unwrap(),
    )
    .unwrap();

    Decode!(&response_bytes, GetNextSnsVersionResponse).unwrap()
}

/// Adds non-functional wasms to the SNS-WASM canister (to avoid expensive init process in certain tests)
/// To add additional dummy wasms, set "group_number" to Some(1) or Some(2) to get additional distinct entries.
pub fn add_dummy_wasms_to_sns_wasms(
    machine: &StateMachine,
    group_number: Option<u8>,
) -> BTreeMap<SnsCanisterType, SnsWasm> {
    let delta = group_number.unwrap_or(0) * 6;
    let root_wasm = test_wasm(SnsCanisterType::Root, Some(delta));
    add_wasm_via_proposal(machine, root_wasm.clone());

    let gov_wasm = test_wasm(SnsCanisterType::Governance, Some(delta + 1));
    add_wasm_via_proposal(machine, gov_wasm.clone());

    let ledger_wasm = test_wasm(SnsCanisterType::Ledger, Some(delta + 2));
    add_wasm_via_proposal(machine, ledger_wasm.clone());

    let swap_wasm = test_wasm(SnsCanisterType::Swap, Some(delta + 3));
    add_wasm_via_proposal(machine, swap_wasm.clone());

    let archive_wasm = test_wasm(SnsCanisterType::Archive, Some(delta + 4));
    add_wasm_via_proposal(machine, archive_wasm.clone());

    let index_wasm = test_wasm(SnsCanisterType::Index, Some(delta + 5));
    add_wasm_via_proposal(machine, index_wasm.clone());

    btreemap! {
        SnsCanisterType::Root => root_wasm,
        SnsCanisterType::Governance =>  gov_wasm,
        SnsCanisterType::Ledger => ledger_wasm,
        SnsCanisterType::Swap =>  swap_wasm,
        SnsCanisterType::Archive =>  archive_wasm,
        SnsCanisterType::Index =>  index_wasm,
    }
}

/// Adds real SNS wasms to the SNS-WASM canister for more robust tests, and returns
/// a map of those wasms for use in further tests.
///
/// Here, "real" means built from current working tree.
///
/// Deprecated, because this does not do gzipping. Instead, use a combination of
/// add_freshly_built_sns_wasms + ensure_sns_wasm_gzipped.
pub fn add_real_wasms_to_sns_wasms(machine: &StateMachine) -> BTreeMap<SnsCanisterType, SnsWasm> {
    // Does nothing.
    fn filter_wasm(sns_wasm: SnsWasm) -> SnsWasm {
        sns_wasm
    }

    add_freshly_built_sns_wasms(machine, filter_wasm)
}

pub fn wait_for_proposal_status(
    machine: &StateMachine,
    proposal_id: ProposalId,
    is_status_achieved: impl Fn(i32) -> bool,
    timeout: Duration,
) {
    let now = Instant::now;
    let start = now();
    while now() - start < timeout {
        let status = get_proposal_info(machine, proposal_id).unwrap().status;
        if is_status_achieved(status) {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("Proposal {} never exited the Open state.", proposal_id);
}

/// Makes a bunch of proposals, and waits for them to be no longer be open.
///
/// One proposal for each type of SNS canister (i.e. root, governance, etc.).
///
/// Each proposal is to add a WASM to the sns-wasms canister (for that canister type). The WASM is
/// (pre-)built from the current working tree (this includes uncommitted changes).
pub fn add_freshly_built_sns_wasms(
    machine: &StateMachine,
    filter_wasm: impl Fn(SnsWasm) -> SnsWasm,
) -> BTreeMap<SnsCanisterType, SnsWasm> {
    let mut result = btreemap! {};
    for (sns_canister_type, (proposal_id, sns_wasm)) in
        add_freshly_built_sns_wasms_and_return_immediately(machine, filter_wasm)
    {
        fn is_not_open(status: i32) -> bool {
            status != ProposalStatus::Open as i32
        }
        let timeout = Duration::from_secs(120);
        wait_for_proposal_status(machine, proposal_id, is_not_open, timeout);

        result.insert(sns_canister_type, sns_wasm);
    }
    result
}

/// Like add_freshly_built_sns_wasms, but does not wait for the proposals to become not open.
fn add_freshly_built_sns_wasms_and_return_immediately(
    machine: &StateMachine,
    filter_wasm: impl Fn(SnsWasm) -> SnsWasm,
) -> HashMap<SnsCanisterType, (ProposalId, SnsWasm)> {
    let root_wasm = filter_wasm(build_root_sns_wasm());
    let root_proposal_id = add_wasm_via_proposal_and_return_immediately(machine, root_wasm.clone());

    let gov_wasm = filter_wasm(build_governance_sns_wasm());
    let gov_proposal_id = add_wasm_via_proposal_and_return_immediately(machine, gov_wasm.clone());

    let ledger_wasm = filter_wasm(build_ledger_sns_wasm());
    let ledger_proposal_id =
        add_wasm_via_proposal_and_return_immediately(machine, ledger_wasm.clone());

    let swap_wasm = filter_wasm(build_swap_sns_wasm());
    let swap_proposal_id = add_wasm_via_proposal_and_return_immediately(machine, swap_wasm.clone());

    let archive_wasm = filter_wasm(build_archive_sns_wasm());
    let archive_proposal_id =
        add_wasm_via_proposal_and_return_immediately(machine, archive_wasm.clone());

    let index_ng_wasm = filter_wasm(build_index_ng_sns_wasm());
    let index_proposal_id =
        add_wasm_via_proposal_and_return_immediately(machine, index_ng_wasm.clone());

    hashmap! {
        SnsCanisterType::Root => (root_proposal_id, root_wasm),
        SnsCanisterType::Governance => (gov_proposal_id, gov_wasm),
        SnsCanisterType::Ledger => (ledger_proposal_id, ledger_wasm),
        SnsCanisterType::Swap => (swap_proposal_id, swap_wasm),
        SnsCanisterType::Archive => (archive_proposal_id, archive_wasm),
        SnsCanisterType::Index => (index_proposal_id, index_ng_wasm),
    }
}

/// Builds the mainnet SnsWasm for the root canister.
pub fn build_mainnet_root_sns_wasm() -> SnsWasm {
    let root_wasm = Project::cargo_bin_maybe_from_env("mainnet-sns-root-canister", &[]);
    SnsWasm {
        wasm: root_wasm.bytes(),
        canister_type: SnsCanisterType::Root.into(),
    }
}

/// Builds the SnsWasm for the root canister.
pub fn build_root_sns_wasm() -> SnsWasm {
    let root_wasm = Project::cargo_bin_maybe_from_env("sns-root-canister", &[]);
    SnsWasm {
        wasm: root_wasm.bytes(),
        canister_type: SnsCanisterType::Root.into(),
    }
}

/// Builds the mainnet SnsWasm for the governance canister.
pub fn build_mainnet_governance_sns_wasm() -> SnsWasm {
    let governance_wasm = Project::cargo_bin_maybe_from_env("mainnet-sns-governance-canister", &[]);
    SnsWasm {
        wasm: governance_wasm.bytes(),
        canister_type: SnsCanisterType::Governance.into(),
    }
}

/// Builds the SnsWasm for the governance canister.
pub fn build_governance_sns_wasm() -> SnsWasm {
    let governance_wasm = Project::cargo_bin_maybe_from_env("sns-governance-canister", &[]);
    SnsWasm {
        wasm: governance_wasm.bytes(),
        canister_type: SnsCanisterType::Governance.into(),
    }
}

/// Builds the mainnet SnsWasm for the Swap Canister
pub fn build_mainnet_swap_sns_wasm() -> SnsWasm {
    let swap_wasm = Project::cargo_bin_maybe_from_env("mainnet-sns-swap-canister", &[]);
    SnsWasm {
        wasm: swap_wasm.bytes(),
        canister_type: SnsCanisterType::Swap.into(),
    }
}

/// Builds the SnsWasm for the Swap Canister
pub fn build_swap_sns_wasm() -> SnsWasm {
    let swap_wasm = Project::cargo_bin_maybe_from_env("sns-swap-canister", &[]);
    SnsWasm {
        wasm: swap_wasm.bytes(),
        canister_type: SnsCanisterType::Swap.into(),
    }
}

/// Builds the mainnet SnsWasm for the ledger canister.
pub fn build_mainnet_ledger_sns_wasm() -> SnsWasm {
    let ledger_wasm = Project::cargo_bin_maybe_from_env("mainnet-ic-icrc1-ledger", &[]);
    SnsWasm {
        wasm: ledger_wasm.bytes(),
        canister_type: SnsCanisterType::Ledger.into(),
    }
}

/// Builds the SnsWasm for the ledger canister.
pub fn build_ledger_sns_wasm() -> SnsWasm {
    let ledger_wasm = Project::cargo_bin_maybe_from_env("ic-icrc1-ledger", &[]);
    SnsWasm {
        wasm: ledger_wasm.bytes(),
        canister_type: SnsCanisterType::Ledger.into(),
    }
}

/// Builds the mainnet SnsWasm for the Ledger Archive Canister
pub fn build_mainnet_archive_sns_wasm() -> SnsWasm {
    let archive_wasm = Project::cargo_bin_maybe_from_env("mainnet-ic-icrc1-archive", &[]);
    SnsWasm {
        wasm: archive_wasm.bytes(),
        canister_type: SnsCanisterType::Archive.into(),
    }
}

/// Builds the SnsWasm for the Ledger Archive Canister
pub fn build_archive_sns_wasm() -> SnsWasm {
    let archive_wasm = Project::cargo_bin_maybe_from_env("ic-icrc1-archive", &[]);
    SnsWasm {
        wasm: archive_wasm.bytes(),
        canister_type: SnsCanisterType::Archive.into(),
    }
}

/// Builds the SnsWasm for the index-ng canister.
pub fn build_index_ng_sns_wasm() -> SnsWasm {
    let index_wasm = Project::cargo_bin_maybe_from_env("ic-icrc1-index-ng", &[]);
    SnsWasm {
        wasm: index_wasm.bytes(),
        canister_type: SnsCanisterType::Index.into(),
    }
}

/// Builds the mainnet SnsWasm for the index canister.
pub fn build_mainnet_index_ng_sns_wasm() -> SnsWasm {
    let index_wasm = Project::cargo_bin_maybe_from_env("mainnet-ic-icrc1-index-ng", &[]);
    SnsWasm {
        wasm: index_wasm.bytes(),
        canister_type: SnsCanisterType::Index.into(),
    }
}

/// Create an SnsWasm with custom metadata
pub fn create_modified_sns_wasm(original_wasm: &SnsWasm, modify_with: Option<&str>) -> SnsWasm {
    let original_hash = original_wasm.sha256_hash();
    let mut wasm_to_add = original_wasm.wasm.clone();

    let mut originally_gzipped = false;
    if is_gzipped_blob(&wasm_to_add) {
        originally_gzipped = true;
        let mut decoder = flate2::read::GzDecoder::new(&wasm_to_add[..]);
        let mut decoded = vec![];
        decoder.read_to_end(&mut decoded).unwrap();
        wasm_to_add = decoded;
    }

    let wasm_to_add = modify_wasm_bytes(&wasm_to_add, modify_with.unwrap_or("no op"));

    // We get our new WASM, which is functionally the same.
    let mut sns_wasm_to_add = SnsWasm {
        wasm: wasm_to_add,
        canister_type: original_wasm.canister_type,
    };

    if originally_gzipped {
        sns_wasm_to_add = ensure_sns_wasm_gzipped(sns_wasm_to_add);
    }

    // Make sure that the output differs from the input, since that is the whole point of this
    // function.
    let new_wasm_hash = sns_wasm_to_add.sha256_hash();
    assert_ne!(new_wasm_hash, original_hash);

    sns_wasm_to_add
}

fn is_gzipped_blob(blob: &[u8]) -> bool {
    (blob.len() > 4)
        // Has magic bytes.
        && (blob[0..2] == [0x1F, 0x8B])
}

pub fn ensure_sns_wasm_gzipped(mut sns_wasm: SnsWasm) -> SnsWasm {
    if is_gzipped_blob(&sns_wasm.wasm) {
        return sns_wasm;
    }

    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&sns_wasm.wasm).unwrap();
    sns_wasm.wasm = encoder.finish().unwrap();

    sns_wasm
}

/// Translates a WasmMap to a Version
pub fn wasm_map_to_sns_version(wasm_map: &BTreeMap<SnsCanisterType, SnsWasm>) -> SnsVersion {
    let version_hash_from_map = |canister_type: SnsCanisterType| {
        wasm_map.get(&canister_type).unwrap().sha256_hash().to_vec()
    };
    SnsVersion {
        root_wasm_hash: version_hash_from_map(SnsCanisterType::Root),
        governance_wasm_hash: version_hash_from_map(SnsCanisterType::Governance),
        ledger_wasm_hash: version_hash_from_map(SnsCanisterType::Ledger),
        swap_wasm_hash: version_hash_from_map(SnsCanisterType::Swap),
        archive_wasm_hash: version_hash_from_map(SnsCanisterType::Archive),
        index_wasm_hash: version_hash_from_map(SnsCanisterType::Index),
    }
}
