use super::*;
use crate::pb::v1::{Motion, NeuronPermissionType};
use async_trait::async_trait;
use candid::Nat;
use ic_nervous_system_clients::canister_status::{
    CanisterStatusResultFromManagementCanister, CanisterStatusResultV2, CanisterStatusType,
};
use ic_nervous_system_common::{
    E8, ONE_DAY_SECONDS, START_OF_2022_TIMESTAMP_SECONDS,
    ledger::compute_neuron_staking_subaccount_bytes,
};
use icrc_ledger_types::icrc3::blocks::GetBlocksRequest;
use icrc_ledger_types::icrc3::blocks::GetBlocksResult;

lazy_static! {
    pub(crate) static ref A_NEURON_PRINCIPAL_ID: PrincipalId = PrincipalId::new_user_test_id(956560);

    pub(crate) static ref A_NEURON_ID: NeuronId = NeuronId::from(
        compute_neuron_staking_subaccount_bytes(*A_NEURON_PRINCIPAL_ID, /* nonce = */ 0),
    );

    pub(crate) static ref A_NEURON: Neuron = Neuron {
        id: Some(A_NEURON_ID.clone()),
        permissions: vec![NeuronPermission {
            principal: Some(*A_NEURON_PRINCIPAL_ID),
            permission_type: NeuronPermissionType::all(),
        }],
        cached_neuron_stake_e8s: 100 * E8,
        aging_since_timestamp_seconds: START_OF_2022_TIMESTAMP_SECONDS,
        dissolve_state: Some(DissolveState::DissolveDelaySeconds(365 * ONE_DAY_SECONDS)),
        voting_power_percentage_multiplier: 100,
        ..Default::default()
    };

    pub(crate) static ref A_MOTION_PROPOSAL: Proposal = Proposal {
        title: "This Proposal is Wunderbar!".to_string(),
        summary: "This will solve all of your problems.".to_string(),
        url: "https://www.example.com/some/path".to_string(),
        action: Some(Action::Motion(Motion {
            motion_text: "See the summary.".to_string(),
        }))
    };

    pub(crate) static ref TEST_ROOT_CANISTER_ID: CanisterId = CanisterId::from(500);
    pub(crate) static ref TEST_GOVERNANCE_CANISTER_ID: CanisterId = CanisterId::from(501);
    pub(crate) static ref TEST_LEDGER_CANISTER_ID: CanisterId = CanisterId::from(502);
    pub(crate) static ref TEST_SWAP_CANISTER_ID: CanisterId = CanisterId::from(503);
    pub(crate) static ref TEST_ARCHIVES_CANISTER_IDS: Vec<CanisterId> =
        vec![CanisterId::from(504), CanisterId::from(505)];
    pub(crate) static ref TEST_INDEX_CANISTER_ID: CanisterId = CanisterId::from(506);
    pub(crate) static ref TEST_DAPP_CANISTER_IDS: Vec<CanisterId> = vec![CanisterId::from(600)];
}

pub(crate) fn basic_governance_proto() -> GovernanceProto {
    GovernanceProto {
        root_canister_id: Some(PrincipalId::new_user_test_id(53)),
        ledger_canister_id: Some(PrincipalId::new_user_test_id(228)),
        swap_canister_id: Some(PrincipalId::new_user_test_id(15)),

        parameters: Some(NervousSystemParameters::with_default_values()),
        mode: governance::Mode::Normal as i32,
        sns_metadata: Some(SnsMetadata {
            logo: Some("data:image/png;base64,aGVsbG8gZnJvbSBkZmluaXR5IQ==".to_string()),
            name: Some("ServiceNervousSystem-Test".to_string()),
            description: Some("A project to spin up a ServiceNervousSystem".to_string()),
            url: Some("https://internetcomputer.org".to_string()),
        }),

        // Ensure that cached metrics are not attempted to be refreshed in tests.
        metrics: Some(GovernanceCachedMetrics {
            timestamp_seconds: u64::MAX,
            ..Default::default()
        }),
        ..Default::default()
    }
}

pub(crate) fn canister_status_from_management_canister_for_test(
    module_hash: Vec<u8>,
    status: CanisterStatusType,
) -> CanisterStatusResultFromManagementCanister {
    let module_hash = Some(module_hash);

    CanisterStatusResultFromManagementCanister {
        status,
        module_hash,
        ..Default::default()
    }
}

pub(crate) fn canister_status_for_test(
    module_hash: Vec<u8>,
    status: CanisterStatusType,
) -> CanisterStatusResultV2 {
    CanisterStatusResultV2::from(canister_status_from_management_canister_for_test(
        module_hash,
        status,
    ))
}

pub(crate) struct DoNothingLedger {}

#[async_trait]
impl ICRC1Ledger for DoNothingLedger {
    async fn transfer_funds(
        &self,
        _amount_e8s: u64,
        _fee_e8s: u64,
        _from_subaccount: Option<Subaccount>,
        _to: Account,
        _memo: u64,
    ) -> Result<u64, NervousSystemError> {
        unimplemented!();
    }

    async fn total_supply(&self) -> Result<Tokens, NervousSystemError> {
        unimplemented!()
    }

    async fn account_balance(&self, _account: Account) -> Result<Tokens, NervousSystemError> {
        unimplemented!()
    }

    fn canister_id(&self) -> CanisterId {
        CanisterId::from(42)
    }

    async fn icrc2_approve(
        &self,
        _spender: Account,
        _amount: u64,
        _expires_at: Option<u64>,
        _fee: u64,
        _from_subaccount: Option<Subaccount>,
        _expected_allowance: Option<u64>,
    ) -> Result<Nat, NervousSystemError> {
        Err(NervousSystemError {
            error_message: "Not Implemented".to_string(),
        })
    }

    async fn icrc3_get_blocks(
        &self,
        _args: Vec<GetBlocksRequest>,
    ) -> Result<GetBlocksResult, NervousSystemError> {
        unimplemented!()
    }
}
