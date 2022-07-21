pub mod pb;

use crate::pb::v1::{
    set_dapp_controllers_response, CanisterCallError, ListSnsCanistersResponse,
    RegisterDappCanisterRequest, RegisterDappCanisterResponse, SetDappControllersRequest,
    SetDappControllersResponse, SnsRootCanister,
};
use async_trait::async_trait;
use candid::{CandidType, Deserialize};
use dfn_core::api::call;
use dfn_core::CanisterId;
use ic_base_types::{NumBytes, PrincipalId};
use ic_nervous_system_root::LOG_PREFIX;
use ic_sns_swap::pb::v1::GetCanisterStatusRequest;
use num_traits::cast::ToPrimitive;
use std::{cell::RefCell, thread::LocalKey};

/// Begin Local Copy of Various Candid Type definitions from ic00_types
///
/// This is the standard practice; this allows the Candid interface to evolve
/// without requiring downstream code changes. A more detailed explanation here:
/// https://gitlab.com/dfinity-lab/public/ic/-/merge_requests/5995#note_1020182140

/// Struct used for encoding/decoding `(record {canister_id})`.
#[derive(CandidType, Deserialize, Debug)]
pub struct CanisterIdRecord {
    canister_id: PrincipalId,
}

impl CanisterIdRecord {
    pub fn get_canister_id(&self) -> CanisterId {
        // Safe as this was converted from CanisterId when Self was constructed.
        CanisterId::new(self.canister_id).unwrap()
    }
}

impl From<CanisterId> for CanisterIdRecord {
    fn from(canister_id: CanisterId) -> Self {
        Self {
            canister_id: canister_id.into(),
        }
    }
}

#[derive(CandidType, Debug, Deserialize, Eq, PartialEq)]
pub struct CanisterStatusResultV2 {
    status: CanisterStatusType,
    module_hash: Option<Vec<u8>>,
    controller: candid::Principal,
    settings: DefiniteCanisterSettingsArgs,
    memory_size: candid::Nat,
    cycles: candid::Nat,
    // this is for compat with Spec 0.12/0.13
    balance: Vec<(Vec<u8>, candid::Nat)>,
    freezing_threshold: candid::Nat,
    idle_cycles_burned_per_day: candid::Nat,
}

impl CanisterStatusResultV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        status: CanisterStatusType,
        module_hash: Option<Vec<u8>>,
        controller: PrincipalId,
        controllers: Vec<PrincipalId>,
        memory_size: NumBytes,
        cycles: u128,
        compute_allocation: u64,
        memory_allocation: Option<u64>,
        freezing_threshold: u64,
        idle_cycles_burned_per_day: u128,
    ) -> Self {
        Self {
            status,
            module_hash,
            controller: candid::Principal::from_text(controller.to_string()).unwrap(),
            memory_size: candid::Nat::from(memory_size.get()),
            cycles: candid::Nat::from(cycles),
            // the following is spec 0.12/0.13 compat;
            // "\x00" denotes cycles
            balance: vec![(vec![0], candid::Nat::from(cycles))],
            settings: DefiniteCanisterSettingsArgs::new(
                controller,
                controllers,
                compute_allocation,
                memory_allocation,
                freezing_threshold,
            ),
            freezing_threshold: candid::Nat::from(freezing_threshold),
            idle_cycles_burned_per_day: candid::Nat::from(idle_cycles_burned_per_day),
        }
    }

    pub fn status(&self) -> CanisterStatusType {
        self.status.clone()
    }

    pub fn module_hash(&self) -> Option<Vec<u8>> {
        self.module_hash.clone()
    }

    pub fn controller(&self) -> PrincipalId {
        PrincipalId::try_from(self.controller.as_slice()).unwrap()
    }

    pub fn controllers(&self) -> Vec<PrincipalId> {
        self.settings.controllers()
    }

    pub fn memory_size(&self) -> NumBytes {
        NumBytes::from(self.memory_size.0.to_u64().unwrap())
    }

    pub fn cycles(&self) -> u128 {
        self.cycles.0.to_u128().unwrap()
    }

    pub fn freezing_threshold(&self) -> u64 {
        self.freezing_threshold.0.to_u64().unwrap()
    }

    pub fn idle_cycles_burned_per_day(&self) -> u128 {
        self.idle_cycles_burned_per_day.0.to_u128().unwrap()
    }
}

/// Indicates whether the canister is running, stopping, or stopped.
///
/// Unlike `CanisterStatus`, it contains no additional metadata.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Deserialize, CandidType)]
pub enum CanisterStatusType {
    #[serde(rename = "running")]
    Running,
    #[serde(rename = "stopping")]
    Stopping,
    #[serde(rename = "stopped")]
    Stopped,
}

/// Struct used for encoding/decoding
/// `(record {
///     controller : principal;
///     compute_allocation: nat;
///     memory_allocation: opt nat;
/// })`
#[derive(CandidType, Deserialize, Debug, Eq, PartialEq)]
pub struct DefiniteCanisterSettingsArgs {
    controller: PrincipalId,
    controllers: Vec<PrincipalId>,
    compute_allocation: candid::Nat,
    memory_allocation: candid::Nat,
    freezing_threshold: candid::Nat,
}

impl DefiniteCanisterSettingsArgs {
    pub fn new(
        controller: PrincipalId,
        controllers: Vec<PrincipalId>,
        compute_allocation: u64,
        memory_allocation: Option<u64>,
        freezing_threshold: u64,
    ) -> Self {
        let memory_allocation = match memory_allocation {
            None => candid::Nat::from(0),
            Some(memory) => candid::Nat::from(memory),
        };
        Self {
            controller,
            controllers,
            compute_allocation: candid::Nat::from(compute_allocation),
            memory_allocation,
            freezing_threshold: candid::Nat::from(freezing_threshold),
        }
    }

    pub fn controllers(&self) -> Vec<PrincipalId> {
        self.controllers.clone()
    }
}

#[derive(Debug, CandidType, Deserialize)]
pub struct EmptyBlob;

#[derive(PartialEq, Eq, Debug, CandidType, Deserialize)]
pub struct UpdateSettingsArgs {
    pub canister_id: PrincipalId,
    pub settings: CanisterSettingsArgs,
}

#[derive(PartialEq, Eq, Default, Clone, CandidType, Deserialize, Debug)]
pub struct CanisterSettingsArgs {
    pub controller: Option<PrincipalId>,
    pub controllers: Option<Vec<PrincipalId>>,
    pub compute_allocation: Option<candid::Nat>,
    pub memory_allocation: Option<candid::Nat>,
    pub freezing_threshold: Option<candid::Nat>,
}

/// End ic00_type copies

impl From<(Option<i32>, String)> for CanisterCallError {
    fn from((code, description): (Option<i32>, String)) -> Self {
        Self { code, description }
    }
}

/// The managment (virtual) canister, also known as IC_00.
/// Reference: https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-management-canister
#[async_trait]
pub trait ManagementCanisterClient {
    async fn canister_status(
        &mut self,
        canister_id_record: &CanisterIdRecord,
    ) -> Result<CanisterStatusResultV2, CanisterCallError>;

    /// Our use case for this is to set controllers of dapp canisters, but this
    /// can be used in other ways as well.
    async fn update_settings(
        &mut self,
        settings: &UpdateSettingsArgs,
    ) -> Result<EmptyBlob, CanisterCallError>;
}

fn swap_remove_if<T>(v: &mut Vec<T>, predicate: impl Fn(&T) -> bool) {
    let mut i = 0;
    while i < v.len() {
        if predicate(&v[i]) {
            v.swap_remove(i);
            // Do not increment i, because there is now a new element at i, and
            // it hasn't been examined yet.
        } else {
            i += 1;
        }
    }
}

// Defined in Rust instead of PB, because we want CanisterStatusResultV2
// (defined in ic00_types) to be in the response, but CSRV2 doesn't have a
// corresponding PB definition.
#[derive(PartialEq, Eq, Debug, candid::CandidType, candid::Deserialize)]
pub struct GetSnsCanistersSummaryRequest {
    // This struct intentionally left blank (for now).
}

#[derive(PartialEq, Eq, Debug, candid::CandidType, candid::Deserialize)]
pub struct GetSnsCanistersSummaryResponse {
    pub root: Option<CanisterSummary>,
    pub governance: Option<CanisterSummary>,
    pub ledger: Option<CanisterSummary>,
    pub swap: Option<CanisterSummary>,
    pub dapps: Vec<CanisterSummary>,
    pub archives: Vec<CanisterSummary>,
}

impl GetSnsCanistersSummaryResponse {
    pub fn root_canister_summary(&self) -> &CanisterSummary {
        self.root.as_ref().unwrap()
    }

    pub fn governance_canister_summary(&self) -> &CanisterSummary {
        self.governance.as_ref().unwrap()
    }

    pub fn ledger_canister_summary(&self) -> &CanisterSummary {
        self.ledger.as_ref().unwrap()
    }

    pub fn swap_canister_summary(&self) -> &CanisterSummary {
        self.swap.as_ref().unwrap()
    }

    pub fn dapp_canister_summaries(&self) -> &Vec<CanisterSummary> {
        &self.dapps
    }

    pub fn archives_canister_summaries(&self) -> &Vec<CanisterSummary> {
        &self.archives
    }
}

#[derive(PartialEq, Eq, Debug, candid::CandidType, candid::Deserialize)]
pub struct CanisterSummary {
    pub canister_id: Option<PrincipalId>,
    pub status: Option<CanisterStatusResultV2>,
}

impl CanisterSummary {
    pub fn canister_id(&self) -> PrincipalId {
        self.canister_id.unwrap()
    }
    pub fn status(&self) -> &CanisterStatusResultV2 {
        self.status.as_ref().unwrap()
    }
}

impl SnsRootCanister {
    fn governance_canister_id(&self) -> PrincipalId {
        self.governance_canister_id
            .expect("Invalid root canister state: missing governance_canister_id.")
    }

    fn ledger_canister_id(&self) -> PrincipalId {
        self.ledger_canister_id
            .expect("Invalid root canister state: missing ledger_canister_id.")
    }

    fn swap_canister_id(&self) -> PrincipalId {
        self.swap_canister_id
            .expect("Invalid root canister state: missing swap_canister_id.")
    }

    /// Return the canister status of all SNS canisters that this root canister
    /// is part of, as well as of all registered dapp canisters (See
    /// SnsRootCanister::register_dapp_canister).
    pub async fn get_sns_canisters_summary(
        self_ref: &'static LocalKey<RefCell<Self>>,
        management_canister_client: &mut impl ManagementCanisterClient,
        own_canister_id: CanisterId,
    ) -> GetSnsCanistersSummaryResponse {
        // Get ID of other canisters.
        let (governance_canister_id, ledger_canister_id, swap_canister_id, dapp_canister_ids) =
            self_ref.with(|self_ref| {
                let self_ref = self_ref.borrow();
                (
                    self_ref.governance_canister_id(),
                    self_ref.ledger_canister_id(),
                    self_ref.swap_canister_id(),
                    self_ref.dapp_canister_ids.clone(),
                )
            });

        // Get our status.
        let root_status = get_root_status(governance_canister_id).await;
        let root_canister_summary = Some(CanisterSummary {
            canister_id: Some(own_canister_id.into()),
            status: Some(root_status),
        });

        // Get governance status.
        let governance_status = management_canister_client
            .canister_status(&CanisterIdRecord::from(
                CanisterId::try_from(governance_canister_id).expect(
                    "Could not convert from the recorded principal ID of the SNS \
                     governance to a canister ID.",
                ),
            ))
            .await
            .expect("Unable to get the status of the SNS governance canister.");
        let governance_canister_summary = Some(CanisterSummary {
            canister_id: Some(governance_canister_id),
            status: Some(governance_status),
        });

        // Get status of ledger.
        let ledger_status = management_canister_client
            .canister_status(&CanisterIdRecord::from(
                CanisterId::try_from(ledger_canister_id).expect(
                    "Could not convert from the recorded principal ID of the SNS \
                     ledger to a canister ID.",
                ),
            ))
            .await
            .expect("Unable to get the status of the SNS ledger canister.");
        let ledger_canister_summary = Some(CanisterSummary {
            canister_id: Some(ledger_canister_id),
            status: Some(ledger_status),
        });

        // Get status of swap.
        let swap_status = get_swap_status(swap_canister_id).await;
        let swap_canister_summary = Some(CanisterSummary {
            canister_id: Some(swap_canister_id),
            status: swap_status,
        });

        // Get status of dapp canister(s).
        let mut dapp_canister_summaries = vec![];
        for dapp_canister_id in dapp_canister_ids {
            let dapp_status = management_canister_client
                .canister_status(&CanisterIdRecord::from(
                    CanisterId::try_from(dapp_canister_id).unwrap_or_else(|e| {
                        panic!(
                            "Could not convert from the recorded principal ID of (one of) the \
                         Dapp's canisters ({dapp_canister_id}) to a canister ID: {e:#?}"
                        )
                    }),
                ))
                .await
                // TODO(NNS1-1525): What if a dapp canister goes away? This could be
                // intentional. In that case, we'll need to implement
                // deregister_dapp_canister.
                .unwrap_or_else(|e| {
                    panic!(
                        "Unable to get the status of one of the Dapp's canisters \
                     ({dapp_canister_id}): {e:#?}"
                    )
                });
            dapp_canister_summaries.push(CanisterSummary {
                canister_id: Some(dapp_canister_id),
                status: Some(dapp_status),
            });
        }

        GetSnsCanistersSummaryResponse {
            root: root_canister_summary,
            governance: governance_canister_summary,
            ledger: ledger_canister_summary,
            swap: swap_canister_summary,
            dapps: dapp_canister_summaries,
            archives: vec![],
        }
    }

    /// Return the `PrincipalId`s of all SNS canisters that this root canister
    /// is part of, as well as of all registered dapp canisters (See
    /// SnsRootCanister::register_dapp_canister).
    pub fn list_sns_canisters(&self, root_canister_id: CanisterId) -> ListSnsCanistersResponse {
        ListSnsCanistersResponse {
            root: Some(root_canister_id.get()),
            governance: self.governance_canister_id,
            ledger: self.ledger_canister_id,
            swap: self.swap_canister_id,
            dapps: self.dapp_canister_ids.clone(),
            // TODO NNS1-1488 Add archive canister ids to root
            archives: vec![],
        }
    }

    /// Tells this canister (SNS root) about a dapp canister that it controls.
    ///
    /// The canister must not be one of the distinguished SNS canisters
    /// (i.e. root, governance, ledger). Furthermore, the canister must be
    /// exclusively be controlled by this canister (i.e. SNS root). Otherwise,
    /// the request will be rejected.
    ///
    /// Registered dapp canisters are used by at least two methods:
    ///   1. get_sns_canisters_summary
    ///   2. set_dapp_controllers (currently in review).
    pub async fn register_dapp_canister(
        self_ref: &'static LocalKey<RefCell<Self>>,
        management_canister_client: &mut impl ManagementCanisterClient,
        own_canister_id: CanisterId,
        request: RegisterDappCanisterRequest,
    ) -> RegisterDappCanisterResponse {
        // Validate/unpack request.
        let query_canister_id = request
            .canister_id
            .expect("Invalid RegisterDappCanisterRequest: canister_id field must be populated.");
        // Reject if canister_id is one of the distinguished canisters in the SNS.
        // TODO: Include ledger archive in this list: https://dfinity.atlassian.net/browse/NNS1-1488
        let sns_canister_ids = self_ref.with(|s| {
            let s = s.borrow();
            [
                s.governance_canister_id.unwrap(),
                s.ledger_canister_id.unwrap(),
                own_canister_id.into(),
            ]
        });
        if sns_canister_ids.contains(&query_canister_id) {
            panic!(
                "Invalid RegisterDappCanisterRequest: \
                 The requested canister is an SNS canister."
            );
        }
        let query_canister_id = CanisterId::new(query_canister_id)
            .expect("Invalid RegisterDappCanisterRequest: contained an invalid canister ID.");

        // Make sure we are a controller by querying the management canister.
        //
        // TODO: Add support for notifying that we have lost control of a
        // canister. Currently, only adding is supported, because that's the
        // only thing we need right now.
        let canister_status = management_canister_client
            .canister_status(&query_canister_id.into())
            .await
            .unwrap_or_else(|err| {
                panic!(
                    "Unable to get the status of the canister referenced in the request: {err:#?}"
                )
            });
        // Reject if we do not have exclusive control.
        assert_eq!(
            canister_status.controllers(),
            vec![own_canister_id.into()],
            "The canister referenced by the request ({query_canister_id}) is not \
             exclusively controlled by this SNS root canister.",
        );

        // Add query_canister_id to self.dapp_canister_ids (if it isn't already there).
        self_ref.with(|s| {
            let query_canister_id = PrincipalId::from(query_canister_id);
            let mut s = s.borrow_mut();
            if s.dapp_canister_ids.contains(&query_canister_id) {
                return;
            }
            s.dapp_canister_ids.push(query_canister_id);
        });

        // Report success.
        RegisterDappCanisterResponse {}
    }

    /// Sets the controllers of registered dapp canisters.
    ///
    /// Dapp canisters can be registered via the register_dapp_canister method.
    ///
    /// Caller must be the swap canister. Otherwise, the request will be
    /// rejected.
    ///
    /// Registered dapp canisters must not have disappeared prior to this being
    /// called. Otherwise, request will be rejected. Some precautions are taken
    /// to avoid a partially completed operation, but this cannot be guaranteed.
    pub async fn set_dapp_controllers<'a>(
        self_ref: &'static LocalKey<RefCell<Self>>,
        management_canister_client: &'a mut impl ManagementCanisterClient,
        own_canister_id: CanisterId,
        caller: PrincipalId,
        request: &'a SetDappControllersRequest,
    ) -> SetDappControllersResponse {
        let is_authorized =
            self_ref.with(|self_ref| caller == self_ref.borrow().swap_canister_id());
        assert!(is_authorized, "Caller ({caller}) is not authorized.");

        // Grab a snapshot of canisters to operate on.
        let dapp_canister_ids =
            self_ref.with(|self_ref| self_ref.borrow().dapp_canister_ids.clone());

        // A pre-flight check: Assert that we still control all canisters
        // referenced in dapp_canister_ids. This way, we minimize that chance of
        // failing half way through controllership changes, since changing the
        // controllers of many canisters cannot be done atomically.
        for dapp_canister_id in &dapp_canister_ids {
            let dapp_canister_id = CanisterId::try_from(*dapp_canister_id).unwrap_or_else(|err| {
                panic!(
                    "Unable to convert principal ID ({dapp_canister_id}) of a dapp into a \
                     canister ID: {err:#?}"
                )
            });
            let is_controllee = management_canister_client
                .canister_status(&dapp_canister_id.into())
                .await
                .is_ok();
            assert!(
                is_controllee,
                "Operation aborted due to an error; no changes have been made: \
                 Unable to determine whether this canister (SNS root) is the controller \
                 of a registered dapp canister ({dapp_canister_id}). This may be due to \
                 the canister having been deleted, which may be due to it running out \
                 of cycles."
            );
        }

        let still_controlled_by_this_canister = request
            .controller_principal_ids
            .contains(&own_canister_id.into());

        // Set controller(s) of dapp canisters.
        //
        // From now on, we should avoid panicing, because we'll be making
        // changes to external state, and we want to stay abreast of those
        // changes by not rolling back due to panic.
        let mut failed_updates = vec![];
        for dapp_canister_id in &dapp_canister_ids {
            // Prepare to call management canister.
            let request = UpdateSettingsArgs {
                canister_id: *dapp_canister_id,
                settings: CanisterSettingsArgs {
                    controllers: Some(request.controller_principal_ids.clone()),
                    // Leave everything else alone.
                    controller: None,
                    compute_allocation: None,
                    memory_allocation: None,
                    freezing_threshold: None,
                },
            };

            // Perform the call.
            let update_result: Result<EmptyBlob, _> =
                management_canister_client.update_settings(&request).await;

            // Handle the result.
            match update_result {
                Ok(_) => (),
                Err(err) => {
                    println!("{LOG_PREFIX}ERROR: Unable to set controller of {dapp_canister_id}: {err:#?}");
                    let err = err.into();
                    failed_updates.push(set_dapp_controllers_response::FailedUpdate {
                        dapp_canister_id: Some(*dapp_canister_id),
                        err,
                    });
                    continue;
                }
            }

            // If necessary, remove dapp_canister_id from self_ref.
            if !still_controlled_by_this_canister {
                self_ref.with(|self_ref| {
                    swap_remove_if(&mut self_ref.borrow_mut().dapp_canister_ids, |element| {
                        element == dapp_canister_id
                    })
                });
            }
        }

        // Report what happened.
        SetDappControllersResponse { failed_updates }
    }
}

/// Get the canister status of the Root canister controlled by the given Governance canister.
/// Root cannot get its own status because only the controller of a canister is able to
/// query the canister's status, and Root is solely controlled by Governance.
async fn get_root_status(governance_id: PrincipalId) -> CanisterStatusResultV2 {
    call(
        CanisterId::new(governance_id).unwrap(),
        "get_root_canister_status",
        dfn_candid::candid,
        (),
    )
    .await
    .unwrap()
}

async fn get_swap_status(swap_id: PrincipalId) -> Option<CanisterStatusResultV2> {
    let response: Result<CanisterStatusResultV2, (Option<i32>, String)> = call(
        CanisterId::new(swap_id).unwrap(),
        "get_canister_status",
        dfn_candid::candid,
        (GetCanisterStatusRequest {},),
    )
    .await;

    match response {
        Ok(canister_status) => Some(canister_status),
        Err(err) => {
            println!(
                "Couldn't get the CanisterStatus of the SNS Swap Canister({}). This may be \
                due to the Swap concluding and the canister stopping. Err: {:?}",
                swap_id, err
            );

            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pb::v1::ListSnsCanistersResponse;
    use ic_base_types::NumBytes;
    use std::collections::VecDeque;

    #[derive(Debug)]
    enum ManagementCanisterClientCall {
        CanisterStatus {
            expected_canister_id: PrincipalId,
            result: Result<CanisterStatusResultV2, CanisterCallError>,
        },
        UpdateSettings {
            update_settings_args: UpdateSettingsArgs,
            result: Result<EmptyBlob, CanisterCallError>,
        },
    }

    #[derive(Debug)]
    struct MockManagementCanisterClient {
        calls: VecDeque<ManagementCanisterClientCall>,
    }

    #[async_trait]
    impl ManagementCanisterClient for MockManagementCanisterClient {
        async fn canister_status(
            &mut self,
            observed_canister_id_record: &CanisterIdRecord,
        ) -> Result<CanisterStatusResultV2, CanisterCallError> {
            let (expected_canister_id, result) = match self.calls.pop_front().unwrap() {
                ManagementCanisterClientCall::CanisterStatus {
                    expected_canister_id,
                    result,
                } => (expected_canister_id, result),

                call => panic!(
                    "An unexpected canister_status call was made. \
                     Should have been {call:#?} instead: {observed_canister_id_record:#?}"
                ),
            };
            let observed_canister_id = observed_canister_id_record.get_canister_id();

            assert_eq!(
                PrincipalId::from(observed_canister_id),
                expected_canister_id
            );

            result
        }

        async fn update_settings(
            &mut self,
            observed_update_settings_args: &UpdateSettingsArgs,
        ) -> Result<EmptyBlob, CanisterCallError> {
            let (expected_update_settings_args, result) = match self.calls.pop_front().unwrap() {
                ManagementCanisterClientCall::UpdateSettings {
                    update_settings_args,
                    result,
                } => (update_settings_args, result),

                call => panic!(
                    "An unexpected update_settings call was made. \
                     Should have been {call:#?} instead: {observed_update_settings_args:#?}"
                ),
            };

            assert_eq!(
                *observed_update_settings_args,
                expected_update_settings_args,
            );

            result
        }
    }

    impl Drop for MockManagementCanisterClient {
        fn drop(&mut self) {
            assert!(self.calls.is_empty(), "{self:#?}");
        }
    }

    #[tokio::test]
    async fn register_dapp_canister_happy() {
        // Step 1: Prepare the world.
        thread_local! {
            static SNS_ROOT_CANISTER: RefCell<SnsRootCanister> = RefCell::new(SnsRootCanister {
                governance_canister_id: Some(PrincipalId::new_user_test_id(1)),
                ledger_canister_id: Some(PrincipalId::new_user_test_id(2)),
                swap_canister_id: Some(PrincipalId::new_user_test_id(99)),
                dapp_canister_ids: vec![],
            });
        }
        let original_sns_root_canister = SNS_ROOT_CANISTER.with(|r| r.borrow().clone());
        let sns_root_canister_id = PrincipalId::new_user_test_id(3);
        let dapp_canister_id = PrincipalId::new_user_test_id(4);

        let mut management_canister_client = MockManagementCanisterClient {
            calls: vec![ManagementCanisterClientCall::CanisterStatus {
                expected_canister_id: dapp_canister_id,
                result: Ok(CanisterStatusResultV2::new(
                    CanisterStatusType::Running,
                    None,                       // module_hash
                    sns_root_canister_id,       // controller
                    vec![sns_root_canister_id], // controllers
                    NumBytes::new(42),          // memory_size
                    43,                         // cycles
                    44,                         // compute_allocation
                    None,                       // memory_allocation
                    45,                         // freezing_threshold
                    46,                         // idle_cycles_burned_per_day
                )),
            }]
            .into(),
        };

        // Step 2: Call the code under test.
        let result = SnsRootCanister::register_dapp_canister(
            &SNS_ROOT_CANISTER,
            &mut management_canister_client,
            sns_root_canister_id.try_into().unwrap(),
            RegisterDappCanisterRequest {
                canister_id: Some(dapp_canister_id),
            },
        )
        .await;

        // Step 3: Inspect results.
        assert_eq!(result, RegisterDappCanisterResponse {}, "{result:#?}");
        assert_eq!(
            management_canister_client.calls.len(),
            0,
            "{management_canister_client:#?}"
        );
        SNS_ROOT_CANISTER.with(|r| {
            assert_eq!(
                *r.borrow(),
                SnsRootCanister {
                    // Most importantly, root became aware that it controls the
                    // dapp, since that is the whole point of calling notify_*,
                    // the code under test.
                    dapp_canister_ids: vec![dapp_canister_id],
                    ..original_sns_root_canister
                }
            );
        });
    }

    #[should_panic]
    #[tokio::test]
    async fn register_dapp_canister_sad() {
        // Step 1: Prepare the world.
        thread_local! {
            static SNS_ROOT_CANISTER: RefCell<SnsRootCanister> = RefCell::new(SnsRootCanister {
                governance_canister_id: Some(PrincipalId::new_user_test_id(1)),
                ledger_canister_id: Some(PrincipalId::new_user_test_id(2)),
                swap_canister_id: Some(PrincipalId::new_user_test_id(99)),
                dapp_canister_ids: vec![],
            });
        }
        let sns_root_canister_id = PrincipalId::new_user_test_id(3);
        let dapp_canister_id = PrincipalId::new_user_test_id(4);

        let mut management_canister_client = MockManagementCanisterClient {
            calls: vec![ManagementCanisterClientCall::CanisterStatus {
                expected_canister_id: dapp_canister_id,
                result: Err(CanisterCallError {
                    code: None,
                    description: "You don't control that canister.".to_string(),
                }),
            }]
            .into(),
        };

        // Step 2: Call the code under test.
        let result = SnsRootCanister::register_dapp_canister(
            &SNS_ROOT_CANISTER,
            &mut management_canister_client,
            sns_root_canister_id.try_into().unwrap(),
            RegisterDappCanisterRequest {
                canister_id: Some(dapp_canister_id),
            },
        )
        .await;

        // Step 3: Inspect results.
        eprintln!(
            "Should have panicked: {result:#?}, {:#?}",
            SNS_ROOT_CANISTER.with(|c| c.clone())
        );
    }

    #[tokio::test]
    async fn register_dapp_canister_redundant() {
        // Step 1: Prepare the world.
        thread_local! {
            static DAPP_CANISTER_ID: PrincipalId = PrincipalId::new_user_test_id(4);
            static SNS_ROOT_CANISTER: RefCell<SnsRootCanister> = RefCell::new(SnsRootCanister {
                governance_canister_id: Some(PrincipalId::new_user_test_id(1)),
                ledger_canister_id: Some(PrincipalId::new_user_test_id(2)),
                swap_canister_id: Some(PrincipalId::new_user_test_id(99)),
                dapp_canister_ids: vec![DAPP_CANISTER_ID.with(|i| *i)],
            });
        }
        let original_sns_root_canister = SNS_ROOT_CANISTER.with(|r| r.borrow().clone());
        let sns_root_canister_id = PrincipalId::new_user_test_id(3);

        let mut management_canister_client = MockManagementCanisterClient {
            calls: vec![ManagementCanisterClientCall::CanisterStatus {
                expected_canister_id: DAPP_CANISTER_ID.with(|i| *i),
                result: Ok(CanisterStatusResultV2::new(
                    CanisterStatusType::Running,
                    None,                       // module_hash
                    sns_root_canister_id,       // controller
                    vec![sns_root_canister_id], // controllers
                    NumBytes::new(42),          // memory_size
                    43,                         // cycles
                    44,                         // compute_allocation
                    None,                       // memory_allocation
                    45,                         // freezing_threshold
                    46,                         // idle_cycles_burned_per_day
                )),
            }]
            .into(),
        };

        // Step 2: Call the code under test.
        let result = SnsRootCanister::register_dapp_canister(
            &SNS_ROOT_CANISTER,
            &mut management_canister_client,
            sns_root_canister_id.try_into().unwrap(),
            RegisterDappCanisterRequest {
                canister_id: Some(DAPP_CANISTER_ID.with(|i| *i)),
            },
        )
        .await;

        // Step 3: Inspect results.
        assert_eq!(result, RegisterDappCanisterResponse {}, "{result:#?}");
        assert_eq!(
            management_canister_client.calls.len(),
            0,
            "{management_canister_client:#?}"
        );
        // Assert no change (because we already knew about the dapp).
        SNS_ROOT_CANISTER.with(|r| {
            assert_eq!(*r.borrow(), original_sns_root_canister);
        });
    }

    #[should_panic(expected = "exclusive")]
    #[tokio::test]
    async fn register_dapp_canister_not_exclusively_controlled() {
        // Step 1: Prepare the world.
        thread_local! {
            static DAPP_CANISTER_ID: PrincipalId = PrincipalId::new_user_test_id(4);
            static SNS_ROOT_CANISTER: RefCell<SnsRootCanister> = RefCell::new(SnsRootCanister {
                governance_canister_id: Some(PrincipalId::new_user_test_id(1)),
                ledger_canister_id: Some(PrincipalId::new_user_test_id(2)),
                swap_canister_id: Some(PrincipalId::new_user_test_id(99)),
                dapp_canister_ids: vec![DAPP_CANISTER_ID.with(|i| *i)],
            });
        }
        let sns_root_canister_id = PrincipalId::new_user_test_id(3);

        let mut management_canister_client = MockManagementCanisterClient {
            calls: vec![ManagementCanisterClientCall::CanisterStatus {
                expected_canister_id: DAPP_CANISTER_ID.with(|i| *i),
                result: Ok(CanisterStatusResultV2::new(
                    CanisterStatusType::Running,
                    None,                 // module_hash
                    sns_root_canister_id, // controller
                    // Controllers. This is the foil of this test:
                    vec![sns_root_canister_id, PrincipalId::new_user_test_id(9999)],
                    NumBytes::new(42), // memory_size
                    43,                // cycles
                    44,                // compute_allocation
                    None,              // memory_allocation
                    45,                // freezing_threshold
                    46,                // idle_cycles_burned_per_day
                )),
            }]
            .into(),
        };

        // Step 2: Call the code under test.
        let result = SnsRootCanister::register_dapp_canister(
            &SNS_ROOT_CANISTER,
            &mut management_canister_client,
            sns_root_canister_id.try_into().unwrap(),
            RegisterDappCanisterRequest {
                canister_id: Some(DAPP_CANISTER_ID.with(|i| *i)),
            },
        )
        .await;

        // Step 3: Inspect results.
        // This is already mostly taken care of by #[should_panic].
        println!("Panic was not triggered! result: {result:#?}");
    }

    #[test]
    fn test_swap_remove_if() {
        let mut v = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        swap_remove_if(&mut v, |e| e % 2 == 0);
        assert_eq!(v, vec![1, 9, 3, 7, 5],);
    }

    #[tokio::test]
    async fn test_set_dapp_controllers() {
        // Step 1: Prepare the world.
        thread_local! {
            static STATE: RefCell<SnsRootCanister> = RefCell::new(SnsRootCanister {
                governance_canister_id: Some(PrincipalId::new_user_test_id(1)),
                ledger_canister_id: Some(PrincipalId::new_user_test_id(2)),
                swap_canister_id: Some(PrincipalId::new_user_test_id(99)),
                dapp_canister_ids: vec![PrincipalId::new_user_test_id(3)],
            });
        }
        let sns_root_canister_id = CanisterId::try_from(PrincipalId::new_user_test_id(4)).unwrap();
        let new_controller_principal_id = PrincipalId::new_user_test_id(5);

        // Step 1.1: Prepare helpers.
        let mut management_canister_client = MockManagementCanisterClient {
            calls: vec![
                ManagementCanisterClientCall::CanisterStatus {
                    expected_canister_id: PrincipalId::new_user_test_id(3),
                    result: Ok(CanisterStatusResultV2::new(
                        CanisterStatusType::Running,
                        None,                              // module_hash
                        sns_root_canister_id.into(),       // controller
                        vec![sns_root_canister_id.into()], // controllers
                        NumBytes::new(42),                 // memory_size
                        43,                                // cycles
                        44,                                // compute_allocation
                        None,                              // memory_allocation
                        45,                                // freezing_threshold
                        46,                                // idle_cycles_burned_per_day
                    )),
                },
                ManagementCanisterClientCall::UpdateSettings {
                    update_settings_args: UpdateSettingsArgs {
                        canister_id: PrincipalId::new_user_test_id(3),
                        settings: CanisterSettingsArgs {
                            controllers: Some(vec![new_controller_principal_id]),
                            controller: None,
                            compute_allocation: None,
                            memory_allocation: None,
                            freezing_threshold: None,
                        },
                    },
                    result: Ok(EmptyBlob {}),
                },
            ]
            .into(),
        };

        // Step 2: Run code under test.
        let response = SnsRootCanister::set_dapp_controllers(
            &STATE,
            &mut management_canister_client,
            sns_root_canister_id,
            STATE.with(|state| state.borrow().swap_canister_id.unwrap()),
            &SetDappControllersRequest {
                controller_principal_ids: vec![new_controller_principal_id],
            },
        )
        .await;

        // Step 3: Inspect results.
        assert_eq!(
            response,
            SetDappControllersResponse {
                failed_updates: vec![]
            }
        );
        assert!(
            management_canister_client.calls.is_empty(),
            "{management_canister_client:#?}",
        );
        let state = &STATE.with(|state| state.borrow().clone());
        assert!(state.dapp_canister_ids.is_empty(), "{state:#?}",);
    }

    #[should_panic(expected = "authorize")]
    #[tokio::test]
    async fn test_set_dapp_controllers_rejects_non_swap_caller() {
        // Step 1: Prepare the world.
        thread_local! {
            static STATE: RefCell<SnsRootCanister> = RefCell::new(SnsRootCanister {
                governance_canister_id: Some(PrincipalId::new_user_test_id(1)),
                ledger_canister_id: Some(PrincipalId::new_user_test_id(2)),
                swap_canister_id: Some(PrincipalId::new_user_test_id(99)),
                dapp_canister_ids: vec![PrincipalId::new_user_test_id(3)],
            });
        }
        let sns_root_canister_id = CanisterId::try_from(PrincipalId::new_user_test_id(4)).unwrap();
        let new_controller_principal_id = PrincipalId::new_user_test_id(5);
        let not_swap = PrincipalId::new_user_test_id(9001);
        assert!(not_swap != STATE.with(|state| state.borrow().swap_canister_id.unwrap()));

        // Step 1.1: Prepare helpers.
        let mut management_canister_client = MockManagementCanisterClient {
            calls: vec![].into(),
        };

        // Step 2: Run code under test.
        SnsRootCanister::set_dapp_controllers(
            &STATE,
            &mut management_canister_client,
            sns_root_canister_id,
            not_swap,
            &SetDappControllersRequest {
                controller_principal_ids: vec![new_controller_principal_id],
            },
        )
        .await;
    }

    #[tokio::test]
    async fn test_set_dapp_controllers_state_not_changed_if_sns_root_still_controls() {
        // Step 1: Prepare the world.
        thread_local! {
            static STATE: RefCell<SnsRootCanister> = RefCell::new(SnsRootCanister {
                governance_canister_id: Some(PrincipalId::new_user_test_id(1)),
                ledger_canister_id: Some(PrincipalId::new_user_test_id(2)),
                swap_canister_id: Some(PrincipalId::new_user_test_id(99)),
                dapp_canister_ids: vec![PrincipalId::new_user_test_id(3)],
            });
        }
        let sns_root_canister_id = CanisterId::try_from(PrincipalId::new_user_test_id(4)).unwrap();
        let new_controller_principal_id = PrincipalId::new_user_test_id(5);
        let not_swap = PrincipalId::new_user_test_id(9001);
        assert!(not_swap != STATE.with(|state| state.borrow().swap_canister_id.unwrap()));

        // Step 1.1: Prepare helpers.
        let mut management_canister_client = MockManagementCanisterClient {
            calls: vec![
                ManagementCanisterClientCall::CanisterStatus {
                    expected_canister_id: PrincipalId::new_user_test_id(3),
                    result: Ok(CanisterStatusResultV2::new(
                        CanisterStatusType::Running,
                        None,                              // module_hash
                        sns_root_canister_id.into(),       // controller
                        vec![sns_root_canister_id.into()], // controllers
                        NumBytes::new(42),                 // memory_size
                        43,                                // cycles
                        44,                                // compute_allocation
                        None,                              // memory_allocation
                        45,                                // freezing_threshold
                        46,                                // idle_cycles_burned_per_day
                    )),
                },
                ManagementCanisterClientCall::UpdateSettings {
                    update_settings_args: UpdateSettingsArgs {
                        canister_id: PrincipalId::new_user_test_id(3),
                        settings: CanisterSettingsArgs {
                            controllers: Some(vec![
                                new_controller_principal_id,
                                sns_root_canister_id.into(),
                            ]),
                            controller: None,
                            compute_allocation: None,
                            memory_allocation: None,
                            freezing_threshold: None,
                        },
                    },
                    result: Ok(EmptyBlob {}),
                },
            ]
            .into(),
        };

        // Step 2: Run code under test.
        let original_state = STATE.with(|state| state.borrow().clone());
        let response = SnsRootCanister::set_dapp_controllers(
            &STATE,
            &mut management_canister_client,
            sns_root_canister_id,
            STATE.with(|state| state.borrow().swap_canister_id.unwrap()),
            &SetDappControllersRequest {
                controller_principal_ids: vec![
                    new_controller_principal_id,
                    sns_root_canister_id.into(),
                ],
            },
        )
        .await;

        // Step 3: Inspect results.
        assert_eq!(
            response,
            SetDappControllersResponse {
                failed_updates: vec![]
            }
        );
        assert!(
            management_canister_client.calls.is_empty(),
            "{management_canister_client:#?}",
        );

        // State should be unchanged, because sns root is STILL a controller of dapp_canisters.
        let state = STATE.with(|state| state.borrow().clone());
        assert_eq!(state, original_state, "{state:#?}");
    }

    #[test]
    fn test_list_sns_canisters() {
        let state = SnsRootCanister {
            governance_canister_id: Some(PrincipalId::new_user_test_id(1)),
            ledger_canister_id: Some(PrincipalId::new_user_test_id(2)),
            swap_canister_id: Some(PrincipalId::new_user_test_id(3)),
            dapp_canister_ids: vec![PrincipalId::new_user_test_id(4)],
        };
        let sns_root_canister_id = CanisterId::try_from(PrincipalId::new_user_test_id(5)).unwrap();

        let response = state.list_sns_canisters(sns_root_canister_id);

        assert_eq!(
            response,
            ListSnsCanistersResponse {
                root: Some(sns_root_canister_id.get()),
                governance: state.governance_canister_id,
                ledger: state.ledger_canister_id,
                swap: state.swap_canister_id,
                dapps: state.dapp_canister_ids,
                archives: vec![],
            }
        )
    }
}
