use crate::{
    logs::{ERROR, INFO},
    pb::v1::{
        CanisterCallError, CleanUpFailedRegisterExtensionRequest,
        CleanUpFailedRegisterExtensionResponse, Extensions, ListSnsCanistersResponse,
        ManageDappCanisterSettingsRequest, ManageDappCanisterSettingsResponse,
        RegisterDappCanistersRequest, RegisterDappCanistersResponse, SetDappControllersRequest,
        SetDappControllersResponse, SnsRootCanister, set_dapp_controllers_response,
    },
    types::{Environment, RejectCode},
};
use async_trait::async_trait;
use candid::{Decode, Encode, Nat};
use futures::{future::join_all, join};
use ic_base_types::{CanisterId, PrincipalId};
use ic_canister_log::log;
use ic_nervous_system_clients::{
    canister_id_record::CanisterIdRecord,
    canister_status::CanisterStatusResultV2,
    management_canister_client::ManagementCanisterClient,
    update_settings::{CanisterSettings, LogVisibility, UpdateSettings},
};
use ic_nervous_system_runtime::{CdkRuntime, Runtime};
use ic_sns_swap::pb::v1::GetCanisterStatusRequest;
use std::{
    cell::RefCell,
    collections::{BTreeSet, HashSet},
    fmt::Write,
    thread::LocalKey,
};
use types::SnsCanisterType;

pub use icrc_ledger_types::icrc3::archive::ArchiveInfo;
pub mod logs;
pub mod pb;
pub mod types;

// The number of dapp amd extension canisters that can be registered with the SNS Root
const DAPP_AND_EXTENSION_CANISTER_REGISTRATION_LIMIT: usize = 100;

impl From<(i32, String)> for CanisterCallError {
    fn from((code, description): (i32, String)) -> Self {
        Self {
            code: Some(code),
            description,
        }
    }
}

// TODO NNS1-1593: Use a common icrc1 trait
/// A trait for querying the icrc1 ledger from SNS Root.
#[async_trait]
pub trait LedgerCanisterClient {
    async fn archives(&self) -> Result<Vec<ArchiveInfo>, CanisterCallError>;
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
// (defined in management_canister_types) to be in the response, but CSRV2 doesn't have a
// corresponding PB definition.
#[derive(Eq, PartialEq, Debug, Default, candid::CandidType, candid::Deserialize)]
pub struct GetSnsCanistersSummaryRequest {
    /// If set to true, root will update the list of canisters it owns before building the
    /// GetSnsCanistersSummaryResponse. This currently amounts to asking ledger about its archive
    /// canisters.
    /// Only the SNS governance canister can set this field to true currently.
    pub update_canister_list: Option<bool>,
}

#[derive(Clone, Eq, PartialEq, Debug, Default, candid::CandidType, candid::Deserialize)]
pub struct GetSnsCanistersSummaryResponse {
    pub root: Option<CanisterSummary>,
    pub governance: Option<CanisterSummary>,
    pub ledger: Option<CanisterSummary>,
    pub swap: Option<CanisterSummary>,
    pub dapps: Vec<CanisterSummary>,
    pub archives: Vec<CanisterSummary>,
    pub index: Option<CanisterSummary>,
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

    pub fn index_canister_summary(&self) -> &CanisterSummary {
        self.index.as_ref().unwrap()
    }
}

impl IntoIterator for GetSnsCanistersSummaryResponse {
    type Item = (Option<CanisterSummary>, SnsCanisterType);

    // Using Box<dyn Iterator<...>> because the type is very long otherwise.
    // But this could be changed to a more specific type.
    type IntoIter = Box<dyn Iterator<Item = Self::Item>>;

    fn into_iter(self) -> Self::IntoIter {
        let canisters = [
            (self.root, SnsCanisterType::Root),
            (self.governance, SnsCanisterType::Governance),
            (self.ledger, SnsCanisterType::Ledger),
            (self.swap, SnsCanisterType::Swap),
            (self.index, SnsCanisterType::Index),
        ];

        Box::new(
            canisters
                .into_iter()
                .chain(
                    self.dapps
                        .into_iter()
                        .map(|d| (Some(d), SnsCanisterType::Dapp)),
                )
                .chain(
                    self.archives
                        .into_iter()
                        .map(|a| (Some(a), SnsCanisterType::Archive)),
                ),
        )
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Default, candid::CandidType, candid::Deserialize)]
pub struct CanisterSummary {
    pub canister_id: Option<PrincipalId>,
    pub status: Option<CanisterStatusResultV2>,
}

impl CanisterSummary {
    pub fn new_with_no_status(principal_id: PrincipalId) -> CanisterSummary {
        CanisterSummary {
            canister_id: Some(principal_id),
            status: None,
        }
    }

    pub fn canister_id(&self) -> PrincipalId {
        self.canister_id.unwrap()
    }

    pub fn status(&self) -> &CanisterStatusResultV2 {
        self.status.as_ref().unwrap()
    }
}

#[derive(Eq, PartialEq, Debug)]
struct ValidatedManageDappCanisterSettingsRequest {
    canister_ids: Vec<PrincipalId>,
    settings: CanisterSettings,
}

impl ValidatedManageDappCanisterSettingsRequest {
    fn try_from(
        request: ManageDappCanisterSettingsRequest,
        dapp_canister_id_set: HashSet<PrincipalId>,
    ) -> Result<Self, String> {
        let settings = CanisterSettings {
            controllers: None,
            compute_allocation: request.compute_allocation.map(Nat::from),
            memory_allocation: request.memory_allocation.map(Nat::from),
            freezing_threshold: request.freezing_threshold.map(Nat::from),
            reserved_cycles_limit: request.reserved_cycles_limit.map(Nat::from),
            log_visibility: LogVisibility::try_from(request.log_visibility()).ok(),
            wasm_memory_limit: request.wasm_memory_limit.map(Nat::from),
            wasm_memory_threshold: request.wasm_memory_threshold.map(Nat::from),
        };
        let invalid_dapp_canister_ids = request
            .canister_ids
            .iter()
            .filter(|canister_id| !dapp_canister_id_set.contains(canister_id))
            .cloned()
            .collect::<Vec<_>>();
        if !invalid_dapp_canister_ids.is_empty() {
            return Err(format!(
                "The following canister IDs are not registered dapp canisters: {invalid_dapp_canister_ids:?}"
            ));
        }

        Ok(ValidatedManageDappCanisterSettingsRequest {
            canister_ids: request.canister_ids,
            settings,
        })
    }
}

async fn call_management_canister_for_update_dapp_canister_settings(
    request: ValidatedManageDappCanisterSettingsRequest,
    management_canister_client: impl ManagementCanisterClient,
) {
    let ValidatedManageDappCanisterSettingsRequest {
        canister_ids,
        settings,
    } = request;
    for canister_id in canister_ids {
        if let Err(error) = management_canister_client
            .update_settings(UpdateSettings {
                canister_id,
                settings: settings.clone(),
                sender_canister_version: management_canister_client.canister_version(),
            })
            .await
        {
            log!(
                ERROR,
                "Failed to manage settings for canister {canister_id}: {error:?}"
            );
        } else {
            log!(
                INFO,
                "Successfully changed settings for canister {canister_id}"
            );
        }
    }
}

impl SnsRootCanister {
    pub fn governance_canister_id(&self) -> PrincipalId {
        self.governance_canister_id
            .expect("Invalid root canister state: missing governance_canister_id.")
    }

    pub fn ledger_canister_id(&self) -> PrincipalId {
        self.ledger_canister_id
            .expect("Invalid root canister state: missing ledger_canister_id.")
    }

    pub fn swap_canister_id(&self) -> PrincipalId {
        self.swap_canister_id
            .expect("Invalid root canister state: missing swap_canister_id.")
    }

    pub fn index_canister_id(&self) -> PrincipalId {
        self.index_canister_id
            .expect("Invalid root canister state: missing index_canister_id.")
    }

    /// Return the canister status of all SNS canisters that this root canister
    /// is part of, as well as of all registered dapp canisters (See
    /// SnsRootCanister::register_dapp_canister).
    pub async fn get_sns_canisters_summary(
        self_ref: &'static LocalKey<RefCell<Self>>,
        management_canister_client: &impl ManagementCanisterClient,
        ledger_canister_client: &impl LedgerCanisterClient,
        env: &impl Environment,
        update_canister_list: bool,
        root_canister_id: PrincipalId,
    ) -> GetSnsCanistersSummaryResponse {
        // Optionally update the canister list
        if update_canister_list {
            Self::poll_for_new_archive_canisters(self_ref, ledger_canister_client).await;
        }

        // Get ID of other canisters.
        let (
            governance_canister_id,
            ledger_canister_id,
            swap_canister_id,
            dapp_canister_ids,
            archive_canister_ids,
            index_canister_id,
        ) = self_ref.with(|self_ref| {
            let self_ref = self_ref.borrow();
            (
                self_ref.governance_canister_id(),
                self_ref.ledger_canister_id(),
                self_ref.swap_canister_id(),
                self_ref.dapp_canister_ids.clone(),
                self_ref.archive_canister_ids.clone(),
                self_ref.index_canister_id(),
            )
        });

        let (
            root_canister_summary,
            governance_canister_summary,
            ledger_canister_summary,
            index_canister_summary,
            swap_canister_summary,
            dapp_canister_summaries,
            archive_canister_summaries,
        ) = join!(
            // Safe because canisters can get their own status summary
            get_owned_canister_summary(management_canister_client, root_canister_id),
            get_owned_canister_summary(management_canister_client, governance_canister_id),
            get_owned_canister_summary(management_canister_client, ledger_canister_id),
            get_owned_canister_summary(management_canister_client, index_canister_id),
            get_swap_status(env, swap_canister_id),
            join_all(dapp_canister_ids.into_iter().map(|dapp_canister_id| {
                get_owned_canister_summary(management_canister_client, dapp_canister_id)
            })),
            join_all(archive_canister_ids.into_iter().map(|archive_canister_id| {
                get_owned_canister_summary(management_canister_client, archive_canister_id)
            }))
        );

        GetSnsCanistersSummaryResponse {
            root: Some(root_canister_summary),
            governance: Some(governance_canister_summary),
            ledger: Some(ledger_canister_summary),
            swap: Some(swap_canister_summary),
            dapps: dapp_canister_summaries.into_iter().collect(),
            archives: archive_canister_summaries.into_iter().collect(),
            index: Some(index_canister_summary),
        }
    }

    /// Return the `PrincipalId`s of all SNS canisters that this root canister
    /// is part of, as well as of all registered dapp canisters (See
    /// SnsRootCanister::register_dapp_canister).
    pub fn list_sns_canisters(&self, root_canister_id: PrincipalId) -> ListSnsCanistersResponse {
        ListSnsCanistersResponse {
            root: Some(root_canister_id),
            governance: self.governance_canister_id,
            ledger: self.ledger_canister_id,
            swap: self.swap_canister_id,
            dapps: self.dapp_canister_ids.clone(),
            archives: self.archive_canister_ids.clone(),
            index: self.index_canister_id,
            extensions: self.extensions.clone(),
        }
    }

    /// Tells this canister (SNS root) about a list of dapp canisters that it controls.
    ///
    /// The canisters must not be one of the distinguished SNS canisters
    /// (i.e. root, governance, ledger). Furthermore, the canisters must be
    /// controlled by this canister (i.e. SNS root). Otherwise, the request will
    /// be rejected.
    ///
    /// If there are any controllers on the canister besides root, they will be
    /// removed.
    ///
    /// Registered dapp canisters are used by at least two methods:
    ///   1. get_sns_canisters_summary
    ///   2. set_dapp_controllers (currently in review).
    pub async fn register_dapp_canisters(
        self_ref: &'static LocalKey<RefCell<Self>>,
        management_canister_client: &impl ManagementCanisterClient,
        root_canister_id: PrincipalId,
        request: RegisterDappCanistersRequest,
    ) -> RegisterDappCanistersResponse {
        let result = Self::try_register_dapp_canisters(
            self_ref,
            management_canister_client,
            root_canister_id,
            request,
        )
        .await;
        match result {
            Ok(response) => response,
            Err(errors) => {
                let message =
                    errors
                        .into_iter()
                        .fold(String::new(), |mut out, (principal, reason)| {
                            let _ = write!(out, "\n{principal}: {reason}");
                            out
                        });
                panic!("Registering dapp canisters failed. {message}");
            }
        }
    }

    /// Returns `(framework_canisters, dapps, extensions)`.
    fn sns_canister_ids(
        self_ref: &'static LocalKey<RefCell<Self>>,
        root_canister_id: PrincipalId,
    ) -> (Vec<PrincipalId>, Vec<PrincipalId>, Vec<PrincipalId>) {
        let ListSnsCanistersResponse {
            root,
            governance,
            ledger,
            swap,
            dapps,
            archives,
            index,
            extensions,
        } = self_ref.with_borrow(|state| state.list_sns_canisters(root_canister_id));

        let framework_canisters = vec![
            root.unwrap(),
            governance.unwrap(),
            ledger.unwrap(),
            index.unwrap(),
            swap.unwrap(),
        ]
        .into_iter()
        .chain(archives)
        .collect();

        let extensions = extensions
            .map_or_else(Vec::new, |ext| ext.extension_canister_ids)
            .into_iter()
            .collect();

        (framework_canisters, dapps, extensions)
    }

    // Helper function for `register_dapp_canisters`. Instead of panicking when
    // some of the input canisters can't be registered, this function
    // returns a list of errors.
    // This function still panics if the input list is empty.
    // This function is separate from `register_dapp_canisters` for use in tests
    // (functions that return Result are easier to test than those that panic.)
    async fn try_register_dapp_canisters(
        self_ref: &'static LocalKey<RefCell<Self>>,
        management_canister_client: &impl ManagementCanisterClient,
        root_canister_id: PrincipalId,
        request: RegisterDappCanistersRequest,
    ) -> Result<RegisterDappCanistersResponse, Vec<(PrincipalId, String)>> {
        let testflight = self_ref.with(|self_ref| self_ref.borrow().testflight);

        // Validate/unpack request.
        if request.canister_ids.is_empty() {
            panic!("Invalid RegisterDappCanistersRequest: canister_ids field must not be empty.");
        }
        // Deduplicate the canisters in the request
        let canisters_to_register = request
            .canister_ids
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();

        let mut errors = Vec::new();

        for canister_to_register in canisters_to_register {
            let result = Self::register_dapp_canister(
                self_ref,
                management_canister_client,
                root_canister_id,
                canister_to_register,
                testflight,
            )
            .await;

            if let Err(reason) = result {
                errors.push((canister_to_register, reason));
            }
        }

        if !errors.is_empty() {
            Err(errors)
        } else {
            Ok(RegisterDappCanistersResponse {})
        }
    }

    pub async fn register_extension(
        self_ref: &'static LocalKey<RefCell<Self>>,
        management_canister_client: &impl ManagementCanisterClient,
        root_canister_id: PrincipalId,
        canister_id: PrincipalId,
    ) -> Result<(), CanisterCallError> {
        let reject = |description: &str| {
            Err(CanisterCallError {
                code: Some(RejectCode::CanisterReject as i32),
                description: description.to_string(),
            })
        };

        let (sns_canister_ids, dapps, extensions) =
            Self::sns_canister_ids(self_ref, root_canister_id);

        let canisters_registered_count = dapps.len().saturating_add(extensions.len());

        if canisters_registered_count >= DAPP_AND_EXTENSION_CANISTER_REGISTRATION_LIMIT {
            return reject(&format!(
                "Canister registration limit of {DAPP_AND_EXTENSION_CANISTER_REGISTRATION_LIMIT} was reached. No more canisters can be \
                 registered until a current dapp canister or extension is deregistered."
            ));
        }

        // Reject if canister_id is one of the distinguished canisters in the SNS.
        if sns_canister_ids.contains(&canister_id) {
            return reject("Canister is a distinguished SNS canister can so cannot be registered");
        }

        // Do nothing if canister_to_register is already registered.
        if extensions.contains(&canister_id) {
            log!(
                INFO,
                "Attempting to register {} as an extension, but it is already registered.",
                canister_id
            );
            return Ok(());
        }

        if dapps.contains(&canister_id) {
            return reject(&format!(
                "{canister_id} is a registered dapp canister and cannot be registered as an extension."
            ));
        }

        let governance_canister_id = self_ref.with_borrow(|state| state.governance_canister_id());

        // Unlike regular dapp canisters, extensions should be controlled by both the root canister
        // and the SNS governance canisters. The former is responsible for upgrading the extension,
        // while the latter is responsible for calling its update functions (which are typically
        // covered by SNS proposals).
        let expected_controllers = BTreeSet::from([root_canister_id, governance_canister_id]);

        // Remove all controllers except for Root and Governance. This successds only if the
        // Root is already a controller.
        management_canister_client
            .update_settings(UpdateSettings {
                canister_id,
                settings: CanisterSettings {
                    controllers: Some(expected_controllers.iter().copied().collect()),
                    ..Default::default()
                },
                sender_canister_version: management_canister_client.canister_version(),
            })
            .await
            .map_err(|(code, message)| {
                let description = format!("Controller change failed: {message}");
                CanisterCallError {
                    code: Some(code),
                    description,
                }
            })?;

        // Verify that the extension is now controlled only by Root and Governance.
        {
            let canister_id = CanisterId::unchecked_from_principal(canister_id);

            let canister_status = management_canister_client
                .canister_status(canister_id.into())
                .await
                .map_err(|(code, message)| {
                    let description = format!("Canister status unavailable: {message}");
                    CanisterCallError {
                        code: Some(code),
                        description,
                    }
                })?;

            let controllers = canister_status
                .controllers()
                .iter()
                .copied()
                .collect::<BTreeSet<_>>();

            if controllers != expected_controllers {
                let controllers = controllers
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");

                return reject(&format!(
                    "Extension canister must be controlled by Root ({root_canister_id}) and Governance ({governance_canister_id}) \
                     of this SNS. However, despite the update_settings call seemingly \
                     succeeding, extension canister ({canister_id}) is still controlled by {controllers}.",
                ));
            }
        }

        self_ref.with_borrow_mut(|state| {
            if let Some(extensions) = state.extensions.as_mut() {
                extensions.extension_canister_ids.push(canister_id);
            } else {
                let extension_canister_ids = vec![canister_id];
                state.extensions.replace(Extensions {
                    extension_canister_ids,
                });
            }
        });

        Ok(())
    }

    pub async fn clean_up_failed_register_extension(
        self_ref: &'static LocalKey<RefCell<Self>>,
        management_canister_client: &impl ManagementCanisterClient,
        request: CleanUpFailedRegisterExtensionRequest,
    ) -> CleanUpFailedRegisterExtensionResponse {
        let main = async || -> Result<(), CanisterCallError> {
            // Unpack request.
            let CleanUpFailedRegisterExtensionRequest {
                canister_id: extension_canister_id,
            } = request;
            let Some(extension_canister_id) = extension_canister_id else {
                return Err(CanisterCallError {
                    code: Some(RejectCode::CanisterReject as i32),
                    description: "Request lacks canister_id.".to_string(),
                });
            };

            // Remove extension_canister_id from self.extensions.
            //
            // (This might result in no actual changes. In that case, we still
            // power through with the rest of this method; we do not return
            // early if there are no changes.)
            self_ref.with_borrow_mut(|state| {
                let Some(extensions) = state.extensions.as_mut() else {
                    return;
                };

                extensions
                    .extension_canister_ids
                    .retain(|prior_extension_canister_id| {
                        prior_extension_canister_id != &extension_canister_id
                    });
            });

            // Prepare to call stop_canister and delete_canister (by wrapping
            // extension_canister_id in a couple extra layers).
            let extension_canister_id =
                CanisterIdRecord::from(CanisterId::unchecked_from_principal(extension_canister_id));

            // Prepare to delete the canister by stopping it first.
            management_canister_client
                .stop_canister(extension_canister_id)
                .await?;

            // Delete the canister.
            management_canister_client
                .delete_canister(extension_canister_id)
                .await?;

            Ok(())
        };

        CleanUpFailedRegisterExtensionResponse::from(main().await)
    }

    /// Register a single canister.
    async fn register_dapp_canister(
        self_ref: &'static LocalKey<RefCell<SnsRootCanister>>,
        management_canister_client: &impl ManagementCanisterClient,
        root_canister_id: PrincipalId,
        canister_to_register: PrincipalId,
        testflight: bool,
    ) -> Result<(), String> {
        let (sns_canister_ids, dapps, extensions) =
            Self::sns_canister_ids(self_ref, root_canister_id);

        let canisters_registered_count = dapps.len().saturating_add(extensions.len());

        if canisters_registered_count >= DAPP_AND_EXTENSION_CANISTER_REGISTRATION_LIMIT {
            Err(format!(
                "Canister registration limit of {DAPP_AND_EXTENSION_CANISTER_REGISTRATION_LIMIT} was reached. No more canisters can be \
                 registered until a current dapp canister or extension is deregistered."
            ))?;
        }

        // Reject if canister_to_register is one of the distinguished canisters in the SNS.
        if sns_canister_ids.contains(&canister_to_register) {
            Err("Canister is a distinguished SNS canister can so cannot be registered")?;
        }

        if extensions.contains(&canister_to_register) {
            Err(format!(
                "{canister_to_register} is a registered extension canister and cannot be registered as a dapp canister."
            ))?;
        }

        // Do nothing if canister_to_register is already registered.
        if dapps.contains(&canister_to_register) {
            log!(
                INFO,
                "Attempting to register {canister_to_register} as a dapp canister, but it is already registered."
            );
            return Ok(());
        }
        let canister_to_register = CanisterId::unchecked_from_principal(canister_to_register);

        // Make sure we are a controller by querying the management canister.
        let canister_status = management_canister_client
            .canister_status(canister_to_register.into())
            .await
            .map_err(|err| format!("Canister status unavailable: {err:?}"))?;

        // Reject if we do not have control.
        if !canister_status.controllers().contains(&root_canister_id) {
            Err("Canister is not controlled by this SNS root canister")?;
        }

        // If testflight is not active, we want to make sure root is the
        // only controller.
        let root_is_only_controller = canister_status.controllers() == vec![root_canister_id];
        if !testflight && !root_is_only_controller {
            // Remove all controllers except for root.
            management_canister_client
                .update_settings(UpdateSettings {
                    canister_id: canister_to_register.into(),
                    settings: CanisterSettings {
                        controllers: Some(vec![root_canister_id]),
                        ..Default::default()
                    },
                    sender_canister_version: management_canister_client.canister_version(),
                })
                .await
                .map_err(|err| format!("Controller change failed: {err:?}"))?;

            // Verify that we are the only controller.
            // This is a sanity check, and should never fail.
            let canister_status = management_canister_client
                .canister_status(canister_to_register.into())
                .await
                .map_err(|err| format!("Canister status unavailable: {err:?}"))?;
            if canister_status.controllers() != vec![root_canister_id] {
                Err("Controller change failed")?;
            }
        }
        // Add canister_to_register to self.dapp_canister_ids.
        self_ref.with_borrow_mut(|state| {
            let canister_to_register = PrincipalId::from(canister_to_register);
            state.dapp_canister_ids.push(canister_to_register);
        });
        Ok(())
    }

    /// Sets the controllers of registered dapp canisters.
    ///
    /// Dapp canisters can be registered via the register_dapp_canisters method.
    ///
    /// Caller must be the swap canister or the governance canister.
    /// Otherwise, the request will be rejected.
    ///
    /// Registered dapp canisters must not have disappeared prior to this being
    /// called. Otherwise, request will be rejected. Some precautions are taken
    /// to avoid a partially completed operation, but this cannot be guaranteed.
    ///
    /// If `request.canister_ids` is `None`, all registered dapps will be set!
    /// This functionality may be removed in the future: see NNS1-1989.
    /// Only the swap canister can use this functionality.
    pub async fn set_dapp_controllers<'a>(
        self_ref: &'static LocalKey<RefCell<Self>>,
        management_canister_client: &'a impl ManagementCanisterClient,
        own_canister_id: PrincipalId,
        caller: PrincipalId,
        request: &'a SetDappControllersRequest,
    ) -> SetDappControllersResponse {
        let is_authorized = self_ref.with(|self_ref| {
            caller == self_ref.borrow().swap_canister_id()
                || caller == self_ref.borrow().governance_canister_id()
        });
        // TODO(NNS1-1993): Remove this assertion and return an error type instead.
        assert!(is_authorized, "Caller ({caller}) is not authorized.");

        // Grab a snapshot of canisters to operate on.
        let dapp_canister_ids = match &request.canister_ids {
            Some(canister_ids) => canister_ids.canister_ids.clone(),
            // If no canister list is specified, we take all the canisters controlled by root.
            None => {
                let is_authorized_to_set_all_controllers =
                    self_ref.with(|self_ref| caller == self_ref.borrow().swap_canister_id());
                if is_authorized_to_set_all_controllers {
                    self_ref.with(|self_ref| self_ref.borrow().dapp_canister_ids.clone())
                } else {
                    // TODO(NNS1-1993): Remove this panic and return an error type instead.
                    panic!("Only the swap canister is authorized to set all dapp controllers")
                }
            }
        };

        // A pre-flight check: Assert that we still control all canisters
        // referenced in dapp_canister_ids. This way, we minimize that chance of
        // failing half way through controller changes, since changing the
        // controllers of many canisters cannot be done atomically.
        for dapp_canister_id in &dapp_canister_ids {
            let dapp_canister_id = CanisterId::try_from(*dapp_canister_id).unwrap_or_else(|err| {
                panic!(
                    "Unable to convert principal ID ({dapp_canister_id}) of a dapp into a \
                     canister ID: {err:#?}"
                )
            });
            let canister_status = match management_canister_client
                .canister_status(dapp_canister_id.into())
                .await
            {
                Err(_) => {
                    // TODO(NNS1-1993): Remove this panic and return an error type instead.
                    panic!(
                        "Could not get the status of canister: {dapp_canister_id}.  Root may not be a controller."
                    )
                }
                Ok(status) => status,
            };
            let is_controllee = canister_status.controllers().contains(&own_canister_id);

            // TODO(NNS1-1993): Remove this assertion and return an error type instead.
            assert!(
                is_controllee,
                "Operation aborted due to an error; no changes have been made: \
                 Unable to determine whether this canister (SNS root) is the controller \
                 of a registered dapp canister ({dapp_canister_id}). This may be due to \
                 the canister having been deleted, which may be due to it running out \
                 of cycles."
            );
        }

        let still_controlled_by_this_canister =
            request.controller_principal_ids.contains(&own_canister_id);

        // Set controller(s) of dapp canisters.
        //
        // From now on, we should avoid panicking, because we'll be making
        // changes to external state, and we want to stay abreast of those
        // changes by not rolling back due to panic.
        let mut failed_updates = vec![];
        for dapp_canister_id in &dapp_canister_ids {
            // Prepare to call management canister.
            let request = UpdateSettings {
                canister_id: *dapp_canister_id,
                settings: CanisterSettings {
                    controllers: Some(request.controller_principal_ids.clone()),
                    ..Default::default()
                },
                sender_canister_version: management_canister_client.canister_version(),
            };

            // Perform the call.
            let update_result: Result<(), _> =
                management_canister_client.update_settings(request).await;

            // Handle the result.
            match update_result {
                Ok(_) => (),
                Err(err) => {
                    log!(
                        ERROR,
                        "Unable to set controller of {dapp_canister_id}: {err:#?}"
                    );
                    let err = Some(CanisterCallError {
                        code: Some(err.0),
                        description: err.1,
                    });
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

    /// Updates a limited subset of canister settings, for dapp canisters only.
    /// * Does NOT update controllers. Managing controllers should be done through the registration API.
    /// * Does NOT update SNS canisters because those cannot be dapp canisters.
    pub fn manage_dapp_canister_settings(
        &self,
        request: ManageDappCanisterSettingsRequest,
        manage_canister_client: impl ManagementCanisterClient + 'static,
    ) -> ManageDappCanisterSettingsResponse {
        let request = match ValidatedManageDappCanisterSettingsRequest::try_from(
            request,
            self.dapp_canister_ids.iter().cloned().collect(),
        ) {
            Ok(validated_request) => validated_request,
            Err(failure_reason) => {
                return ManageDappCanisterSettingsResponse {
                    failure_reason: Some(failure_reason),
                };
            }
        };

        CdkRuntime::spawn_future(call_management_canister_for_update_dapp_canister_settings(
            request,
            manage_canister_client,
        ));
        ManageDappCanisterSettingsResponse {
            failure_reason: None,
        }
    }

    /// Polls for new archives canisters from the ledger canister.
    pub async fn poll_for_new_archive_canisters(
        self_ref: &'static LocalKey<RefCell<Self>>,
        ledger_client: &impl LedgerCanisterClient,
    ) {
        log!(INFO, "Polling for new archive canisters");

        let archives_result = ledger_client.archives().await;

        let archive_infos: Vec<ArchiveInfo> = match archives_result {
            Ok(archives) => archives,
            Err(canister_call_error) => {
                // TODO NNS1-1595 - Export metrics if this call fails
                // Log the error and do nothing (return).
                log!(
                    ERROR,
                    "Unable to get the Ledger Archives: {:?}",
                    canister_call_error
                );
                return;
            }
        };

        let archive_principals_ids: Vec<PrincipalId> = archive_infos
            .iter()
            .map(|archive| PrincipalId(archive.canister_id))
            .collect();

        self_ref.with(|state| {
            let defects = Self::compare_archives_responses(
                &state.borrow().archive_canister_ids,
                &archive_principals_ids,
            );

            if !defects.is_empty() {
                // TODO NNS1-1595 - Export metrics if defects are detected
                // Log the error and do nothing (return)
                log!(
                    ERROR,
                    "Defects detected between polls of archive canisters: {}",
                    defects
                );
                return;
            }

            state.borrow_mut().archive_canister_ids = archive_principals_ids;
        });
    }

    /// Compare two responses from the Ledger Canister's archives() API. Detect if any
    /// archive CanisterIds previously tracked are no longer in the more recent response.
    fn compare_archives_responses(
        old_archive_canisters: &[PrincipalId],
        new_archive_canisters: &[PrincipalId],
    ) -> String {
        let mut defects = Vec::new();

        let new_archive_set: BTreeSet<PrincipalId> =
            new_archive_canisters.iter().cloned().collect();
        old_archive_canisters.iter().for_each(|principal_id| {
            if !new_archive_set.contains(principal_id) {
                defects.push(format!("Previous archive_canister_ids PrincipalId {principal_id} is missing from response of new poll"))
            }
        });

        defects.join("\n")
    }
}

async fn get_swap_status(env: &impl Environment, swap_id: PrincipalId) -> CanisterSummary {
    let canister_id = CanisterId::unchecked_from_principal(swap_id);
    let status = match env
        .call_canister(
            canister_id,
            "get_canister_status",
            Encode!(&GetCanisterStatusRequest {}).unwrap(),
        )
        .await
        .map_err(|(code, msg)| format!("Could not get swap status from swap: {code}: {msg}"))
        .and_then(|bytes| {
            Decode!(&bytes, CanisterStatusResultV2)
                .map_err(|e| format!("Could not decode response: {e:?}"))
        }) {
        Ok(summary) => Some(summary),
        Err(err) => {
            log!(
                ERROR,
                "Unable to get the status of swap canister_id {}. Reason: {:?}",
                swap_id,
                err
            );

            None
        }
    };

    CanisterSummary {
        canister_id: Some(swap_id),
        status,
    }
}

async fn get_owned_canister_summary(
    management_canister_client: &impl ManagementCanisterClient,
    canister_id: PrincipalId,
) -> CanisterSummary {
    let canister_id_record = match CanisterIdRecord::try_from(canister_id) {
        Ok(canister_id_record) => canister_id_record,
        Err(err_msg) => {
            // Log an error and return a CanisterSummary with no status.
            log!(
                ERROR,
                "Could not convert canister_id {} into a CanisterIdRecord. Reason: {}",
                canister_id,
                err_msg
            );
            return CanisterSummary::new_with_no_status(canister_id);
        }
    };

    let status = match management_canister_client
        .canister_status(canister_id_record)
        .await
        .map(CanisterStatusResultV2::from)
    {
        Ok(canister_status_result_v2) => Some(canister_status_result_v2),
        Err(err) => {
            // Log an error and return a CanisterSummary with no status
            log!(
                ERROR,
                "Unable to get the status of canister_id {}. Reason: {:?}",
                canister_id,
                err
            );
            None
        }
    };

    CanisterSummary {
        canister_id: Some(canister_id),
        status,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pb::v1::{ListSnsCanistersResponse, set_dapp_controllers_request::CanisterIds};
    use ic_nervous_system_clients::{
        canister_status::CanisterStatusResultFromManagementCanister,
        management_canister_client::{
            MockManagementCanisterClient, MockManagementCanisterClientCall,
            MockManagementCanisterClientReply,
        },
    };
    use maplit::hashset;
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };

    const NOW: u64 = 123_456_789;

    #[derive(Clone, Debug)]
    enum LedgerCanisterClientCall {
        Archives {
            result: Result<Vec<ArchiveInfo>, CanisterCallError>,
        },
    }

    #[derive(Clone, Debug)]
    struct MockLedgerCanisterClient {
        calls: Arc<futures::lock::Mutex<VecDeque<LedgerCanisterClientCall>>>,
    }

    impl MockLedgerCanisterClient {
        fn new<T>(calls: T) -> Self
        where
            VecDeque<LedgerCanisterClientCall>: From<T>,
        {
            Self {
                calls: Arc::new(futures::lock::Mutex::new(calls.into())),
            }
        }
    }

    #[async_trait]
    impl LedgerCanisterClient for MockLedgerCanisterClient {
        async fn archives(&self) -> Result<Vec<ArchiveInfo>, CanisterCallError> {
            let mut calls = self.calls.lock().await;
            match calls.pop_front().unwrap() {
                LedgerCanisterClientCall::Archives { result } => result,
            }
        }
    }

    #[derive(Clone, Debug)]
    enum EnvironmentCall {
        CallCanister {
            expected_canister: CanisterId,
            expected_method: String,
            expected_bytes: Option<Vec<u8>>,
            result: Result<Vec<u8>, (i32, String)>,
        },
    }

    struct TestEnvironment {
        calls: Arc<Mutex<VecDeque<EnvironmentCall>>>,
    }

    #[async_trait]
    impl Environment for TestEnvironment {
        fn now(&self) -> u64 {
            NOW
        }

        async fn call_canister(
            &self,
            canister_id: CanisterId,
            method_name: &str,
            arg: Vec<u8>,
        ) -> Result<Vec<u8>, (i32, String)> {
            let mut calls = self.calls.lock().unwrap();
            match calls.pop_front().unwrap() {
                EnvironmentCall::CallCanister {
                    expected_canister,
                    expected_method,
                    expected_bytes,
                    result,
                } => {
                    if expected_canister != canister_id || !expected_method.eq(method_name) {
                        panic!(
                            "An unexpected call_canister call was made. \
                            Should have been {expected_canister:#?}, {expected_method}. \
                            instead: {canister_id:#?} {method_name} (bytes omitted)\n \
                            {} calls remaining on stack",
                            calls.len(),
                        );
                    }
                    if let Some(bytes) = expected_bytes {
                        assert_eq!(
                            bytes, arg,
                            "Expected bytes were not the same when calling \
                        {expected_canister} {expected_method}"
                        );
                    }

                    result
                }
            }
        }
    }

    fn build_test_sns_root_canister(testflight: bool) -> SnsRootCanister {
        SnsRootCanister {
            governance_canister_id: Some(PrincipalId::new_user_test_id(1)),
            ledger_canister_id: Some(PrincipalId::new_user_test_id(2)),
            swap_canister_id: Some(PrincipalId::new_user_test_id(3)),
            dapp_canister_ids: vec![],
            extensions: Some(vec![].into()),
            archive_canister_ids: vec![],
            index_canister_id: Some(PrincipalId::new_user_test_id(4)),
            testflight,
            timers: None,
        }
    }

    // Helper function to assert state changes after polling for archive canisters
    fn assert_archive_poll_state_change(
        root_state: &'static LocalKey<RefCell<SnsRootCanister>>,
        expected_canister_ids: &[CanisterId],
    ) {
        let expected_principal_ids: Vec<PrincipalId> = expected_canister_ids
            .iter()
            .map(|canister_id| canister_id.get())
            .collect();

        root_state.with(|state| {
            assert_eq!(*state.borrow().archive_canister_ids, expected_principal_ids);
        });
    }

    #[tokio::test]
    async fn register_dapp_canisters_testflight() {
        // Step 1: Prepare the world.
        thread_local! {
            static SNS_ROOT_CANISTER: RefCell<SnsRootCanister> = RefCell::new(build_test_sns_root_canister(true));
        }
        let original_sns_root_canister = SNS_ROOT_CANISTER.with(|r| r.borrow().clone());
        let sns_root_canister_id = PrincipalId::new_user_test_id(4);
        let dapp_canister_id_1 = PrincipalId::new_user_test_id(5);
        let dapp_canister_id_2 = PrincipalId::new_user_test_id(6);
        let user_id = PrincipalId::new_user_test_id(7);

        let management_canister_client = MockManagementCanisterClient::new(vec![
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    sns_root_canister_id,
                    user_id,
                ]),
            )),
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    sns_root_canister_id,
                    user_id,
                ]),
            )),
        ]);

        // Step 2: Call the code under test.
        let result = SnsRootCanister::register_dapp_canisters(
            &SNS_ROOT_CANISTER,
            &management_canister_client,
            sns_root_canister_id,
            RegisterDappCanistersRequest {
                canister_ids: vec![dapp_canister_id_1, dapp_canister_id_2],
            },
        )
        .await;

        // Step 3: Inspect results.
        assert_eq!(result, RegisterDappCanistersResponse {}, "{result:#?}");
        SNS_ROOT_CANISTER.with(|r| {
            assert_eq!(
                *r.borrow(),
                SnsRootCanister {
                    // Most importantly, root became aware that it controls the
                    // dapp, since that is the whole point of calling notify_*,
                    // the code under test.
                    dapp_canister_ids: vec![dapp_canister_id_1, dapp_canister_id_2],
                    ..original_sns_root_canister
                }
            );
        });

        let actual_management_canister_calls = management_canister_client.get_calls_snapshot();
        let expected_management_canister_calls = vec![
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: CanisterId::try_from(dapp_canister_id_1).unwrap(),
            }),
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: CanisterId::try_from(dapp_canister_id_2).unwrap(),
            }),
        ];
        assert_eq!(
            actual_management_canister_calls,
            expected_management_canister_calls
        );
    }

    #[tokio::test]
    async fn register_dapp_canisters_happy() {
        // Step 1: Prepare the world.
        thread_local! {
            static SNS_ROOT_CANISTER: RefCell<SnsRootCanister> = RefCell::new(build_test_sns_root_canister(false));
        }
        let original_sns_root_canister = SNS_ROOT_CANISTER.with(|r| r.borrow().clone());
        let sns_root_canister_id = PrincipalId::new_user_test_id(4);
        let dapp_canister_id_1 = PrincipalId::new_user_test_id(5);
        let dapp_canister_id_2 = PrincipalId::new_user_test_id(6);

        let management_canister_client = MockManagementCanisterClient::new(vec![
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    sns_root_canister_id,
                ]),
            )),
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    sns_root_canister_id,
                ]),
            )),
        ]);

        // Step 2: Call the code under test.
        let result = SnsRootCanister::register_dapp_canisters(
            &SNS_ROOT_CANISTER,
            &management_canister_client,
            sns_root_canister_id,
            RegisterDappCanistersRequest {
                canister_ids: vec![dapp_canister_id_1, dapp_canister_id_2],
            },
        )
        .await;

        // Step 3: Inspect results.
        assert_eq!(result, RegisterDappCanistersResponse {}, "{result:#?}");
        SNS_ROOT_CANISTER.with(|r| {
            assert_eq!(
                *r.borrow(),
                SnsRootCanister {
                    // Most importantly, root became aware that it controls the
                    // dapp
                    dapp_canister_ids: vec![dapp_canister_id_1, dapp_canister_id_2],
                    ..original_sns_root_canister
                }
            );
        });

        let actual_management_canister_calls = management_canister_client.get_calls_snapshot();
        let expected_management_canister_calls = vec![
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: CanisterId::try_from(dapp_canister_id_1).unwrap(),
            }),
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: CanisterId::try_from(dapp_canister_id_2).unwrap(),
            }),
        ];
        assert_eq!(
            actual_management_canister_calls,
            expected_management_canister_calls
        );
    }

    #[tokio::test]
    async fn register_dapp_canisters_duplicate() {
        // Step 1: Prepare the world.
        thread_local! {
            static SNS_ROOT_CANISTER: RefCell<SnsRootCanister> = RefCell::new(build_test_sns_root_canister(false));
        }
        let original_sns_root_canister = SNS_ROOT_CANISTER.with(|r| r.borrow().clone());
        let sns_root_canister_id = PrincipalId::new_user_test_id(4);
        let dapp_canister_id_1 = PrincipalId::new_user_test_id(5);

        let management_canister_client = MockManagementCanisterClient::new(vec![
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    sns_root_canister_id,
                ]),
            )),
        ]);

        // Step 2: Call the code under test.
        let result = SnsRootCanister::register_dapp_canisters(
            &SNS_ROOT_CANISTER,
            &management_canister_client,
            sns_root_canister_id,
            RegisterDappCanistersRequest {
                canister_ids: vec![dapp_canister_id_1, dapp_canister_id_1],
            },
        )
        .await;

        // Step 3: Inspect results.
        assert_eq!(result, RegisterDappCanistersResponse {}, "{result:#?}");
        SNS_ROOT_CANISTER.with(|r| {
            assert_eq!(
                *r.borrow(),
                SnsRootCanister {
                    // Most importantly, root became aware that it controls the
                    // dapp
                    dapp_canister_ids: vec![dapp_canister_id_1],
                    ..original_sns_root_canister
                }
            );
        });

        let actual_management_canister_calls = management_canister_client.get_calls_snapshot();
        let expected_management_canister_calls =
            vec![MockManagementCanisterClientCall::CanisterStatus(
                CanisterIdRecord {
                    canister_id: CanisterId::try_from(dapp_canister_id_1).unwrap(),
                },
            )];
        assert_eq!(
            actual_management_canister_calls,
            expected_management_canister_calls
        );
    }

    #[tokio::test]
    async fn register_dapp_canisters_idempotent() {
        // Step 1: Prepare the world.
        thread_local! {
            static SNS_ROOT_CANISTER: RefCell<SnsRootCanister> = RefCell::new(build_test_sns_root_canister(false));
        }
        let original_sns_root_canister = SNS_ROOT_CANISTER.with(|r| r.borrow().clone());
        let sns_root_canister_id = PrincipalId::new_user_test_id(4);
        let dapp_canister_id_1 = PrincipalId::new_user_test_id(5);

        let management_canister_client = MockManagementCanisterClient::new(vec![
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    sns_root_canister_id,
                ]),
            )),
        ]);

        // Step 2: Attempt to add the same canister twice.
        for _ in 0..2 {
            SnsRootCanister::register_dapp_canisters(
                &SNS_ROOT_CANISTER,
                &management_canister_client,
                sns_root_canister_id,
                RegisterDappCanistersRequest {
                    canister_ids: vec![dapp_canister_id_1],
                },
            )
            .await;
        }

        SNS_ROOT_CANISTER.with(|r| {
            assert_eq!(
                *r.borrow(),
                SnsRootCanister {
                    // Most importantly, root became aware that it controls the
                    // dapp
                    dapp_canister_ids: vec![dapp_canister_id_1],
                    ..original_sns_root_canister
                }
            );
        });

        let actual_management_canister_calls = management_canister_client.get_calls_snapshot();
        let expected_management_canister_calls =
            vec![MockManagementCanisterClientCall::CanisterStatus(
                CanisterIdRecord {
                    canister_id: CanisterId::try_from(dapp_canister_id_1).unwrap(),
                },
            )];
        assert_eq!(
            actual_management_canister_calls,
            expected_management_canister_calls
        );
    }

    #[test]
    fn register_dapp_canisters_in_forbidden_list() {
        // Step 1: Prepare the world.
        thread_local! {
            static SNS_ROOT_CANISTER: RefCell<SnsRootCanister> = RefCell::new(build_test_sns_root_canister(false));
        }
        let (governance_canister_id, ledger_canister_id, swap_canister_id, index_canister_id) =
            SNS_ROOT_CANISTER.with(|c| {
                let canister = c.borrow();
                (
                    canister.governance_canister_id.unwrap(),
                    canister.ledger_canister_id.unwrap(),
                    canister.swap_canister_id.unwrap(),
                    canister.index_canister_id.unwrap(),
                )
            });
        let sns_root_canister_id = PrincipalId::new_user_test_id(5);
        let archive_canister_id = PrincipalId::new_user_test_id(6);
        // Add an archive canister to list
        SNS_ROOT_CANISTER.with(|canister| {
            canister
                .borrow_mut()
                .archive_canister_ids
                .push(archive_canister_id)
        });

        // Step 2: Call the code under test.
        for canister_id in [
            governance_canister_id,
            ledger_canister_id,
            swap_canister_id,
            index_canister_id,
            sns_root_canister_id,
            archive_canister_id,
        ] {
            let result = std::panic::catch_unwind(|| {
                tokio::runtime::Runtime::new().unwrap().block_on(async {
                    let management_canister_client = MockManagementCanisterClient::new(vec![]);

                    SnsRootCanister::register_dapp_canisters(
                        &SNS_ROOT_CANISTER,
                        &management_canister_client,
                        sns_root_canister_id,
                        RegisterDappCanistersRequest {
                            canister_ids: vec![canister_id],
                        },
                    )
                    .await
                })
            });

            // Assert that it is an error
            assert!(result.is_err());
        }
    }

    #[should_panic = "is not controlled by this SNS root canister"]
    #[tokio::test]
    async fn register_dapp_canisters_sad_root_not_controller() {
        // Step 1: Prepare the world.
        thread_local! {
            static SNS_ROOT_CANISTER: RefCell<SnsRootCanister> = RefCell::new(build_test_sns_root_canister(false));
        }
        let user_id = PrincipalId::new_user_test_id(50);
        let sns_root_canister_id = PrincipalId::new_user_test_id(4);
        let dapp_canister_id_1 = PrincipalId::new_user_test_id(5);

        // Don't make root the controller
        let management_canister_client = MockManagementCanisterClient::new(vec![
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![user_id]),
            )),
        ]);

        // Step 2: Call the code under test.
        // We panic here
        SnsRootCanister::register_dapp_canisters(
            &SNS_ROOT_CANISTER,
            &management_canister_client,
            sns_root_canister_id,
            RegisterDappCanistersRequest {
                canister_ids: vec![dapp_canister_id_1],
            },
        )
        .await;
    }

    #[should_panic = "You don't control that canister."]
    #[tokio::test]
    async fn register_dapp_canisters_sad_root_canister_status_error() {
        // Step 1: Prepare the world.
        thread_local! {
            static SNS_ROOT_CANISTER: RefCell<SnsRootCanister> = RefCell::new(build_test_sns_root_canister(false));
        }
        let sns_root_canister_id = PrincipalId::new_user_test_id(4);
        let dapp_canister_id = PrincipalId::new_user_test_id(5);

        let management_canister_client = MockManagementCanisterClient::new(vec![
            MockManagementCanisterClientReply::CanisterStatus(Err((
                0,
                "You don't control that canister.".to_string(),
            ))),
        ]);

        // Step 2: Call the code under test.
        let result = SnsRootCanister::register_dapp_canisters(
            &SNS_ROOT_CANISTER,
            &management_canister_client,
            sns_root_canister_id,
            RegisterDappCanistersRequest {
                canister_ids: vec![dapp_canister_id],
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
    async fn register_dapp_canisters_sad_root_not_controller_for_some() {
        // Step 1: Prepare the world.
        thread_local! {
            static SNS_ROOT_CANISTER: RefCell<SnsRootCanister> = RefCell::new(build_test_sns_root_canister(false));
        }
        let user_id = PrincipalId::new_user_test_id(50);
        let sns_root_canister_id = PrincipalId::new_user_test_id(4);
        let dapp_canister_id_1 = PrincipalId::new_user_test_id(5);
        let dapp_canister_id_2 = PrincipalId::new_user_test_id(6);
        let dapp_canister_id_3 = PrincipalId::new_user_test_id(7);
        let dapp_canister_id_4 = PrincipalId::new_user_test_id(8);

        // Don't make root the controller
        let management_canister_client = MockManagementCanisterClient::new(vec![
            // Root is the only controller from the start, no need to do an update_settings call
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    sns_root_canister_id,
                ]),
            )),
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![user_id]),
            )),
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    sns_root_canister_id,
                    user_id,
                ]),
            )),
            MockManagementCanisterClientReply::UpdateSettings(Ok(())),
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    sns_root_canister_id,
                ]),
            )),
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![user_id]),
            )),
        ]);

        // Step 2: Call the code under test.
        // We panic here
        let result = SnsRootCanister::try_register_dapp_canisters(
            &SNS_ROOT_CANISTER,
            &management_canister_client,
            sns_root_canister_id,
            RegisterDappCanistersRequest {
                canister_ids: vec![
                    dapp_canister_id_1,
                    dapp_canister_id_2,
                    dapp_canister_id_3,
                    dapp_canister_id_4,
                ],
            },
        )
        .await
        .unwrap_err();

        // Step 3: Inspect results.
        let message = "Canister is not controlled by this SNS root canister".to_string();
        assert_eq!(result.len(), 2);
        assert!(
            result.contains(&(dapp_canister_id_2, message.clone())),
            "{result:#?}"
        );
        assert!(
            result.contains(&(dapp_canister_id_4, message)),
            "{result:#?}"
        );

        SNS_ROOT_CANISTER
            .with(|c| assert!(c.borrow().dapp_canister_ids.contains(&dapp_canister_id_1)));
        SNS_ROOT_CANISTER
            .with(|c| assert!(c.borrow().dapp_canister_ids.contains(&dapp_canister_id_3)));

        let actual_management_canister_calls = management_canister_client.get_calls_snapshot();
        let expected_management_canister_calls = vec![
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: CanisterId::try_from(dapp_canister_id_1).unwrap(),
            }),
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: CanisterId::try_from(dapp_canister_id_2).unwrap(),
            }),
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: CanisterId::try_from(dapp_canister_id_3).unwrap(),
            }),
            MockManagementCanisterClientCall::UpdateSettings(UpdateSettings {
                canister_id: dapp_canister_id_3,
                settings: CanisterSettings {
                    controllers: Some(vec![sns_root_canister_id]),
                    ..Default::default()
                },
                sender_canister_version: None,
            }),
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: CanisterId::try_from(dapp_canister_id_3).unwrap(),
            }),
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: CanisterId::try_from(dapp_canister_id_4).unwrap(),
            }),
        ];
        assert_eq!(
            actual_management_canister_calls,
            expected_management_canister_calls
        );
    }

    #[should_panic = "is not controlled by this SNS root canister"]
    #[tokio::test]
    async fn register_dapp_canisters_sad_no_controllers() {
        // Step 1: Prepare the world.
        thread_local! {
            static SNS_ROOT_CANISTER: RefCell<SnsRootCanister> = RefCell::new(build_test_sns_root_canister(false));
        }
        let sns_root_canister_id = PrincipalId::new_user_test_id(4);
        let dapp_canister_id_1 = PrincipalId::new_user_test_id(5);

        let management_canister_client = MockManagementCanisterClient::new(vec![
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![]),
            )),
        ]);

        // Step 2: Call the code under test.
        // We panic here
        SnsRootCanister::register_dapp_canisters(
            &SNS_ROOT_CANISTER,
            &management_canister_client,
            sns_root_canister_id,
            RegisterDappCanistersRequest {
                canister_ids: vec![dapp_canister_id_1],
            },
        )
        .await;
    }

    #[tokio::test]
    async fn register_dapp_canisters_happy_multiple() {
        // Step 1: Prepare the world.
        thread_local! {
            static SNS_ROOT_CANISTER: RefCell<SnsRootCanister> = RefCell::new(build_test_sns_root_canister(false));
        }
        let original_sns_root_canister = SNS_ROOT_CANISTER.with(|r| r.borrow().clone());

        let user_id = PrincipalId::new_user_test_id(50);
        let sns_root_canister_id = PrincipalId::new_user_test_id(4);
        let dapp_canister_id_1 = PrincipalId::new_user_test_id(5);
        let dapp_canister_id_2 = PrincipalId::new_user_test_id(6);
        let dapp_canister_id_3 = PrincipalId::new_user_test_id(7);

        // Don't make root the controller
        let management_canister_client = MockManagementCanisterClient::new(vec![
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    sns_root_canister_id,
                    user_id,
                ]),
            )),
            MockManagementCanisterClientReply::UpdateSettings(Ok(())),
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    sns_root_canister_id,
                ]),
            )),
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    sns_root_canister_id,
                    user_id,
                ]),
            )),
            MockManagementCanisterClientReply::UpdateSettings(Ok(())),
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    sns_root_canister_id,
                ]),
            )),
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    sns_root_canister_id,
                    user_id,
                ]),
            )),
            MockManagementCanisterClientReply::UpdateSettings(Ok(())),
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    sns_root_canister_id,
                ]),
            )),
        ]);

        // Step 2: Call the code under test.
        let result = SnsRootCanister::register_dapp_canisters(
            &SNS_ROOT_CANISTER,
            &management_canister_client,
            sns_root_canister_id,
            RegisterDappCanistersRequest {
                canister_ids: vec![dapp_canister_id_1, dapp_canister_id_2, dapp_canister_id_3],
            },
        )
        .await;

        // Step 3: Inspect results.
        assert_eq!(result, RegisterDappCanistersResponse {}, "{result:#?}");
        SNS_ROOT_CANISTER.with(|r| {
            assert_eq!(
                *r.borrow(),
                SnsRootCanister {
                    // Most importantly, root became aware that it controls the
                    // dapp
                    dapp_canister_ids: vec![
                        dapp_canister_id_1,
                        dapp_canister_id_2,
                        dapp_canister_id_3
                    ],
                    ..original_sns_root_canister
                }
            );
        });

        let actual_management_canister_calls = management_canister_client.get_calls_snapshot();
        let expected_management_canister_calls = vec![
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: CanisterId::try_from(dapp_canister_id_1).unwrap(),
            }),
            MockManagementCanisterClientCall::UpdateSettings(UpdateSettings {
                canister_id: dapp_canister_id_1,
                settings: CanisterSettings {
                    controllers: Some(vec![sns_root_canister_id]),
                    ..Default::default()
                },
                sender_canister_version: None,
            }),
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: CanisterId::try_from(dapp_canister_id_1).unwrap(),
            }),
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: CanisterId::try_from(dapp_canister_id_2).unwrap(),
            }),
            MockManagementCanisterClientCall::UpdateSettings(UpdateSettings {
                canister_id: dapp_canister_id_2,
                settings: CanisterSettings {
                    controllers: Some(vec![sns_root_canister_id]),
                    ..Default::default()
                },
                sender_canister_version: None,
            }),
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: CanisterId::try_from(dapp_canister_id_2).unwrap(),
            }),
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: CanisterId::try_from(dapp_canister_id_3).unwrap(),
            }),
            MockManagementCanisterClientCall::UpdateSettings(UpdateSettings {
                canister_id: dapp_canister_id_3,
                settings: CanisterSettings {
                    controllers: Some(vec![sns_root_canister_id]),
                    ..Default::default()
                },
                sender_canister_version: None,
            }),
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: CanisterId::try_from(dapp_canister_id_3).unwrap(),
            }),
        ];
        assert_eq!(
            actual_management_canister_calls,
            expected_management_canister_calls
        );
    }

    #[tokio::test]
    async fn register_dapp_canisters_redundant() {
        // Step 1: Prepare the world.
        thread_local! {
            static DAPP_CANISTER_ID: PrincipalId = const { PrincipalId::new_user_test_id(4) };
            static SNS_ROOT_CANISTER: RefCell<SnsRootCanister> = RefCell::new(SnsRootCanister {
                governance_canister_id: Some(PrincipalId::new_user_test_id(1)),
                ledger_canister_id: Some(PrincipalId::new_user_test_id(2)),
                swap_canister_id: Some(PrincipalId::new_user_test_id(99)),
                dapp_canister_ids: vec![DAPP_CANISTER_ID.with(|i| *i)],
                archive_canister_ids: vec![],
                index_canister_id: Some(PrincipalId::new_user_test_id(3)),
                ..Default::default()
            });
        }
        let original_sns_root_canister = SNS_ROOT_CANISTER.with(|r| r.borrow().clone());
        let sns_root_canister_id = PrincipalId::new_user_test_id(3);

        let management_canister_client = MockManagementCanisterClient::new(vec![]);

        // Step 2: Call the code under test.
        let result = SnsRootCanister::register_dapp_canisters(
            &SNS_ROOT_CANISTER,
            &management_canister_client,
            sns_root_canister_id,
            RegisterDappCanistersRequest {
                canister_ids: vec![DAPP_CANISTER_ID.with(|i| *i)],
            },
        )
        .await;

        // Step 3: Inspect results.
        assert_eq!(result, RegisterDappCanistersResponse {}, "{result:#?}");
        // Assert no change (because we already knew about the dapp).
        SNS_ROOT_CANISTER.with(|r| {
            assert_eq!(*r.borrow(), original_sns_root_canister);
        });
    }

    #[tokio::test]
    // cpumi-3qaaa-aaaaa-aadeq-cai is CanisterId::from(201), which shows this does not fail at an earlier limit
    #[should_panic(
        expected = "cpumi-3qaaa-aaaaa-aadeq-cai: Canister registration limit of 100 was reached. No more canisters can be registered until a current dapp canister or extension is deregistered."
    )]
    async fn register_dapp_canisters_fails_at_limit_number() {
        // Step 1: Prepare the world.
        thread_local! {
            static SNS_ROOT_CANISTER: RefCell<SnsRootCanister> = RefCell::new(SnsRootCanister {
                governance_canister_id: Some(PrincipalId::new_user_test_id(1)),
                ledger_canister_id: Some(PrincipalId::new_user_test_id(2)),
                swap_canister_id: Some(PrincipalId::new_user_test_id(99)),
                dapp_canister_ids: vec![],
                archive_canister_ids: vec![],
                index_canister_id: Some(PrincipalId::new_user_test_id(3)),
                ..Default::default()
            });
        }
        let sns_root_canister_id = PrincipalId::new_user_test_id(3);

        let canister_ids: Vec<PrincipalId> =
            (100..200).map(|id| CanisterId::from(id).get()).collect();

        let mut management_canister_client = MockManagementCanisterClient::new(vec![]);

        canister_ids.iter().for_each(|_| {
            management_canister_client.push_reply(
                MockManagementCanisterClientReply::CanisterStatus(Ok(
                    CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                        sns_root_canister_id,
                        PrincipalId::new_user_test_id(9999),
                    ]),
                )),
            );
            management_canister_client
                .push_reply(MockManagementCanisterClientReply::UpdateSettings(Ok(())));
            management_canister_client.push_reply(
                MockManagementCanisterClientReply::CanisterStatus(Ok(
                    CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                        sns_root_canister_id,
                    ]),
                )),
            );
        });

        // Step 2: Max out the registered dapps, and confirm they were registered.
        SnsRootCanister::register_dapp_canisters(
            &SNS_ROOT_CANISTER,
            &management_canister_client,
            sns_root_canister_id,
            RegisterDappCanistersRequest {
                canister_ids: canister_ids.clone(),
            },
        )
        .await;

        SNS_ROOT_CANISTER.with(|r| {
            assert_eq!(
                *r.borrow().dapp_canister_ids,
                // Check that root became aware that it controls the dapp canister.
                canister_ids
            );
        });

        // Step 3: Attempt to register another dapp, which should trigger panic
        SnsRootCanister::register_dapp_canisters(
            &SNS_ROOT_CANISTER,
            &management_canister_client,
            sns_root_canister_id,
            RegisterDappCanistersRequest {
                canister_ids: vec![CanisterId::from(201).get()],
            },
        )
        .await;
    }

    #[test]
    fn test_swap_remove_if() {
        let mut v = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        swap_remove_if(&mut v, |e| e % 2 == 0);
        assert_eq!(v, vec![1, 9, 3, 7, 5],);
    }

    #[tokio::test]
    async fn test_set_dapp_controllers_set_all() {
        // Step 1: Prepare the world.
        thread_local! {
            static STATE: RefCell<SnsRootCanister> = RefCell::new(SnsRootCanister {
                governance_canister_id: Some(PrincipalId::new_user_test_id(1)),
                ledger_canister_id: Some(PrincipalId::new_user_test_id(2)),
                swap_canister_id: Some(PrincipalId::new_user_test_id(99)),
                dapp_canister_ids: vec![PrincipalId::new_user_test_id(3)],
                archive_canister_ids: vec![],
                index_canister_id: Some(PrincipalId::new_user_test_id(4)),
                ..Default::default()
            });
        }
        let sns_root_canister_id = PrincipalId::new_user_test_id(4);
        let new_controller_principal_id = PrincipalId::new_user_test_id(5);

        // Step 1.1: Prepare helpers.
        let management_canister_client = MockManagementCanisterClient::new(vec![
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    sns_root_canister_id,
                ]),
            )),
            MockManagementCanisterClientReply::UpdateSettings(Ok(())),
        ]);

        // Step 2: Run code under test.
        let response = SnsRootCanister::set_dapp_controllers(
            &STATE,
            &management_canister_client,
            sns_root_canister_id,
            STATE.with(|state| state.borrow().swap_canister_id.unwrap()),
            &SetDappControllersRequest {
                // Change controller to all dapps controlled by the root canister.
                canister_ids: None,
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
        let state = &STATE.with(|state| state.borrow().clone());
        assert!(state.dapp_canister_ids.is_empty(), "{state:#?}",);

        let actual_management_canister_calls = management_canister_client.get_calls_snapshot();
        let expected_management_canister_calls = vec![
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: CanisterId::try_from(PrincipalId::new_user_test_id(3)).unwrap(),
            }),
            MockManagementCanisterClientCall::UpdateSettings(UpdateSettings {
                canister_id: PrincipalId::new_user_test_id(3),
                settings: CanisterSettings {
                    controllers: Some(vec![new_controller_principal_id]),
                    ..Default::default()
                },
                sender_canister_version: None,
            }),
        ];
        assert_eq!(
            actual_management_canister_calls,
            expected_management_canister_calls
        );
    }

    #[tokio::test]
    #[should_panic]
    async fn test_set_dapp_controllers_set_all_not_usable_by_governance() {
        // Step 1: Prepare the world.
        thread_local! {
            static STATE: RefCell<SnsRootCanister> = RefCell::new(SnsRootCanister {
                governance_canister_id: Some(PrincipalId::new_user_test_id(1)),
                ledger_canister_id: Some(PrincipalId::new_user_test_id(2)),
                swap_canister_id: Some(PrincipalId::new_user_test_id(99)),
                dapp_canister_ids: vec![PrincipalId::new_user_test_id(3)],
                archive_canister_ids: vec![],
                index_canister_id: Some(PrincipalId::new_user_test_id(4)),
                ..Default::default()
            });
        }
        let sns_root_canister_id = PrincipalId::new_user_test_id(4);
        let new_controller_principal_id = PrincipalId::new_user_test_id(5);

        // Step 1.1: Prepare helpers.
        let management_canister_client = MockManagementCanisterClient::new(vec![]);

        // Step 2: Run code under test.
        // We except to panic here, because we're passing the governance canister
        // as the caller while attempting to deregister all canisters. That functionality
        // can only be used by the swap canister – see NNS1-1989.
        let _response = SnsRootCanister::set_dapp_controllers(
            &STATE,
            &management_canister_client,
            sns_root_canister_id,
            STATE.with(|state| state.borrow().governance_canister_id.unwrap()),
            &SetDappControllersRequest {
                // Change controller to all dapps controlled by the root canister.
                canister_ids: None,
                controller_principal_ids: vec![new_controller_principal_id],
            },
        )
        .await;
    }

    #[tokio::test]
    #[should_panic]
    async fn test_set_dapp_controllers_set_some_usable_by_governance() {
        // Step 1: Prepare the world.
        thread_local! {
            static STATE: RefCell<SnsRootCanister> = RefCell::new(SnsRootCanister {
                governance_canister_id: Some(PrincipalId::new_user_test_id(1)),
                ledger_canister_id: Some(PrincipalId::new_user_test_id(2)),
                swap_canister_id: Some(PrincipalId::new_user_test_id(99)),
                dapp_canister_ids: vec![PrincipalId::new_user_test_id(3)],
                archive_canister_ids: vec![],
                index_canister_id: Some(PrincipalId::new_user_test_id(4)),
                ..Default::default()
            });
        }
        let sns_root_canister_id = PrincipalId::new_user_test_id(4);
        let new_controller_principal_id = PrincipalId::new_user_test_id(5);

        // Step 1.1: Prepare helpers.
        let management_canister_client = MockManagementCanisterClient::new(vec![
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    sns_root_canister_id,
                ]),
            )),
            MockManagementCanisterClientReply::UpdateSettings(Ok(())),
        ]);

        // Step 2: Run code under test.
        // We except to panic here, because we're passing the governance canister
        // as the caller while attempting to deregister all canisters. That functionality
        // can only be used by the swap canister – see NNS1-1989.
        let _response = SnsRootCanister::set_dapp_controllers(
            &STATE,
            &management_canister_client,
            sns_root_canister_id,
            STATE.with(|state| state.borrow().governance_canister_id.unwrap()),
            &SetDappControllersRequest {
                // Change controller to all dapps controlled by the root canister.
                canister_ids: Some(CanisterIds {
                    canister_ids: vec![CanisterId::from_u64(10000).get()],
                }),
                controller_principal_ids: vec![new_controller_principal_id],
            },
        )
        .await;

        let actual_management_canister_calls = management_canister_client.get_calls_snapshot();
        let expected_management_canister_calls = vec![
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: CanisterId::try_from(PrincipalId::new_user_test_id(3)).unwrap(),
            }),
            MockManagementCanisterClientCall::UpdateSettings(UpdateSettings {
                canister_id: PrincipalId::new_user_test_id(3),
                settings: CanisterSettings {
                    controllers: Some(vec![new_controller_principal_id]),
                    ..Default::default()
                },
                sender_canister_version: None,
            }),
        ];
        assert_eq!(
            actual_management_canister_calls,
            expected_management_canister_calls
        );
    }

    #[tokio::test]
    async fn test_set_dapp_controllers_some_canisters() {
        // Step 1: Prepare the world.
        thread_local! {
            static STATE: RefCell<SnsRootCanister> = RefCell::new(SnsRootCanister {
                governance_canister_id: Some(PrincipalId::new_user_test_id(1)),
                ledger_canister_id: Some(PrincipalId::new_user_test_id(2)),
                swap_canister_id: Some(PrincipalId::new_user_test_id(99)),
                dapp_canister_ids: vec![PrincipalId::new_user_test_id(3), PrincipalId::new_user_test_id(4), PrincipalId::new_user_test_id(5), PrincipalId::new_user_test_id(6)],
                archive_canister_ids: vec![],
                ..Default::default()
            });
        }
        let sns_root_canister_id = PrincipalId::new_user_test_id(4);
        let new_controller_principal_id = PrincipalId::new_user_test_id(5);

        // Step 1.1: Prepare helpers.
        let management_canister_client = MockManagementCanisterClient::new(vec![
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    sns_root_canister_id,
                ]),
            )),
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    sns_root_canister_id,
                ]),
            )),
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    sns_root_canister_id,
                ]),
            )),
            MockManagementCanisterClientReply::UpdateSettings(Ok(())),
            MockManagementCanisterClientReply::UpdateSettings(Ok(())),
            MockManagementCanisterClientReply::UpdateSettings(Ok(())),
        ]);

        // Step 2: Run code under test.
        let response = SnsRootCanister::set_dapp_controllers(
            &STATE,
            &management_canister_client,
            sns_root_canister_id,
            STATE.with(|state| state.borrow().swap_canister_id.unwrap()),
            &SetDappControllersRequest {
                // Change controller to all dapps controlled by the root canister.
                canister_ids: Some(CanisterIds {
                    canister_ids: vec![
                        PrincipalId::new_user_test_id(4),
                        PrincipalId::new_user_test_id(5),
                        PrincipalId::new_user_test_id(6),
                    ],
                }),
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
        let state = &STATE.with(|state| state.borrow().clone());
        assert_eq!(
            state.dapp_canister_ids,
            vec![PrincipalId::new_user_test_id(3)],
            "{state:#?}",
        );

        let actual_management_canister_calls = management_canister_client.get_calls_snapshot();
        let expected_management_canister_calls = vec![
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: CanisterId::try_from(PrincipalId::new_user_test_id(4)).unwrap(),
            }),
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: CanisterId::try_from(PrincipalId::new_user_test_id(5)).unwrap(),
            }),
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: CanisterId::try_from(PrincipalId::new_user_test_id(6)).unwrap(),
            }),
            MockManagementCanisterClientCall::UpdateSettings(UpdateSettings {
                canister_id: PrincipalId::new_user_test_id(4),
                settings: CanisterSettings {
                    controllers: Some(vec![new_controller_principal_id]),
                    ..Default::default()
                },
                sender_canister_version: None,
            }),
            MockManagementCanisterClientCall::UpdateSettings(UpdateSettings {
                canister_id: PrincipalId::new_user_test_id(5),
                settings: CanisterSettings {
                    controllers: Some(vec![new_controller_principal_id]),
                    ..Default::default()
                },
                sender_canister_version: None,
            }),
            MockManagementCanisterClientCall::UpdateSettings(UpdateSettings {
                canister_id: PrincipalId::new_user_test_id(6),
                settings: CanisterSettings {
                    controllers: Some(vec![new_controller_principal_id]),
                    ..Default::default()
                },
                sender_canister_version: None,
            }),
        ];
        assert_eq!(
            actual_management_canister_calls,
            expected_management_canister_calls
        );
    }

    // Only governance and swap canisters can call set dapp controllers.
    #[should_panic(expected = "authorize")]
    #[tokio::test]
    async fn test_set_dapp_controllers_rejects_non_authorized_caller() {
        // Step 1: Prepare the world.
        thread_local! {
            static STATE: RefCell<SnsRootCanister> = RefCell::new(SnsRootCanister {
                governance_canister_id: Some(PrincipalId::new_user_test_id(1)),
                ledger_canister_id: Some(PrincipalId::new_user_test_id(2)),
                swap_canister_id: Some(PrincipalId::new_user_test_id(99)),
                dapp_canister_ids: vec![PrincipalId::new_user_test_id(3)],
                archive_canister_ids: vec![],
                index_canister_id: Some(PrincipalId::new_user_test_id(4)),
                ..Default::default()
            });
        }
        let sns_root_canister_id = PrincipalId::new_user_test_id(4);
        let new_controller_principal_id = PrincipalId::new_user_test_id(5);
        let not_authorized = PrincipalId::new_user_test_id(9001);
        assert_ne!(
            not_authorized,
            STATE.with(|state| state.borrow().swap_canister_id.unwrap())
        );
        assert_ne!(
            not_authorized,
            STATE.with(|state| state.borrow().governance_canister_id.unwrap())
        );

        // Step 1.1: Prepare helpers.
        let management_canister_client = MockManagementCanisterClient::new(vec![]);

        // Step 2: Run code under test.
        SnsRootCanister::set_dapp_controllers(
            &STATE,
            &management_canister_client,
            sns_root_canister_id,
            not_authorized,
            &SetDappControllersRequest {
                // Change controller to all dapps controlled by the root canister.
                canister_ids: None,
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
                archive_canister_ids: vec![],
                index_canister_id: Some(PrincipalId::new_user_test_id(4)),
                ..Default::default()
            });
        }
        let sns_root_canister_id = PrincipalId::new_user_test_id(4);
        let new_controller_principal_id = PrincipalId::new_user_test_id(5);
        let not_swap = PrincipalId::new_user_test_id(9001);
        assert_ne!(
            not_swap,
            STATE.with(|state| state.borrow().swap_canister_id.unwrap())
        );

        // Step 1.1: Prepare helpers.
        let management_canister_client = MockManagementCanisterClient::new(vec![
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    sns_root_canister_id,
                ]),
            )),
            MockManagementCanisterClientReply::UpdateSettings(Ok(())),
        ]);

        // Step 2: Run code under test.
        let original_state = STATE.with(|state| state.borrow().clone());
        let response = SnsRootCanister::set_dapp_controllers(
            &STATE,
            &management_canister_client,
            sns_root_canister_id,
            STATE.with(|state| state.borrow().swap_canister_id.unwrap()),
            &SetDappControllersRequest {
                // Change controller to all dapps controlled by the root canister.
                canister_ids: None,
                controller_principal_ids: vec![new_controller_principal_id, sns_root_canister_id],
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

        // State should be unchanged, because sns root is STILL a controller of dapp_canisters.
        let state = STATE.with(|state| state.borrow().clone());
        assert_eq!(state, original_state, "{state:#?}");

        let actual_management_canister_calls = management_canister_client.get_calls_snapshot();
        let expected_management_canister_calls = vec![
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: CanisterId::try_from(PrincipalId::new_user_test_id(3)).unwrap(),
            }),
            MockManagementCanisterClientCall::UpdateSettings(UpdateSettings {
                canister_id: PrincipalId::new_user_test_id(3),
                settings: CanisterSettings {
                    controllers: Some(vec![new_controller_principal_id, sns_root_canister_id]),
                    ..Default::default()
                },
                sender_canister_version: None,
            }),
        ];
        assert_eq!(
            actual_management_canister_calls,
            expected_management_canister_calls
        );
    }

    #[test]
    fn test_validate_manage_dapp_canister_settings_valid() {
        let request = ManageDappCanisterSettingsRequest {
            canister_ids: vec![
                PrincipalId::new_user_test_id(1),
                PrincipalId::new_user_test_id(2),
            ],
            compute_allocation: Some(50),
            memory_allocation: Some(1 << 30),
            freezing_threshold: Some(100_000),
            reserved_cycles_limit: Some(1_000_000_000_000),
            log_visibility: Some(crate::pb::v1::LogVisibility::Controllers as i32),
            wasm_memory_limit: Some(1_000_000_000),
            wasm_memory_threshold: Some(1_000_000),
        };
        let validated_request = ValidatedManageDappCanisterSettingsRequest::try_from(
            request,
            hashset! {
                PrincipalId::new_user_test_id(1),
                PrincipalId::new_user_test_id(2),
                PrincipalId::new_user_test_id(3),
            },
        )
        .unwrap();
        assert_eq!(
            validated_request,
            ValidatedManageDappCanisterSettingsRequest {
                canister_ids: vec![
                    PrincipalId::new_user_test_id(1),
                    PrincipalId::new_user_test_id(2),
                ],
                settings: CanisterSettings {
                    controllers: None,
                    compute_allocation: Some(Nat::from(50u64)),
                    memory_allocation: Some(Nat::from(1u64 << 30)),
                    freezing_threshold: Some(Nat::from(100_000u64)),
                    reserved_cycles_limit: Some(Nat::from(1_000_000_000_000u64)),
                    log_visibility: Some(LogVisibility::Controllers),
                    wasm_memory_limit: Some(Nat::from(1_000_000_000u64)),
                    wasm_memory_threshold: Some(Nat::from(1_000_000u64)),
                },
            }
        );
    }

    #[test]
    fn test_validate_manage_dapp_canister_settings_invalid() {
        let request = ManageDappCanisterSettingsRequest {
            canister_ids: vec![
                PrincipalId::new_user_test_id(1),
                PrincipalId::new_user_test_id(2),
                PrincipalId::new_user_test_id(4),
            ],
            compute_allocation: Some(50),
            memory_allocation: Some(1 << 30),
            freezing_threshold: Some(100_000),
            reserved_cycles_limit: Some(1_000_000_000_000),
            log_visibility: Some(crate::pb::v1::LogVisibility::Controllers as i32),
            wasm_memory_limit: Some(1_000_000_000),
            wasm_memory_threshold: Some(1_000_000),
        };
        let failure_reason = ValidatedManageDappCanisterSettingsRequest::try_from(
            request,
            hashset! {
                PrincipalId::new_user_test_id(1),
                PrincipalId::new_user_test_id(2),
                PrincipalId::new_user_test_id(3),
            },
        )
        .unwrap_err();
        assert!(failure_reason.contains(&PrincipalId::new_user_test_id(4).to_string()));
    }

    #[test]
    fn test_list_sns_canisters() {
        let state = SnsRootCanister {
            governance_canister_id: Some(PrincipalId::new_user_test_id(1)),
            ledger_canister_id: Some(PrincipalId::new_user_test_id(2)),
            swap_canister_id: Some(PrincipalId::new_user_test_id(3)),
            dapp_canister_ids: vec![PrincipalId::new_user_test_id(4)],
            archive_canister_ids: vec![PrincipalId::new_user_test_id(5)],
            index_canister_id: Some(PrincipalId::new_user_test_id(6)),
            extensions: Some(vec![PrincipalId::new_user_test_id(7)].into()),
            ..Default::default()
        };
        let sns_root_canister_id = PrincipalId::new_user_test_id(5);

        let response = state.list_sns_canisters(sns_root_canister_id);

        assert_eq!(
            response,
            ListSnsCanistersResponse {
                root: Some(sns_root_canister_id),
                governance: state.governance_canister_id,
                ledger: state.ledger_canister_id,
                swap: state.swap_canister_id,
                dapps: state.dapp_canister_ids,
                archives: state.archive_canister_ids,
                index: state.index_canister_id,
                extensions: state.extensions,
            }
        )
    }

    #[tokio::test]
    async fn poll_for_archives_single_archive() {
        // Step 1: Prepare the world.
        thread_local! {
            static SNS_ROOT_CANISTER: RefCell<SnsRootCanister> = RefCell::new(build_test_sns_root_canister(false));
        }

        let expected_archive_canister_id = CanisterId::from_u64(99);

        let ledger_canister_client =
            MockLedgerCanisterClient::new(vec![LedgerCanisterClientCall::Archives {
                result: Ok(vec![ArchiveInfo {
                    canister_id: expected_archive_canister_id.into(),
                    block_range_start: Default::default(),
                    block_range_end: Default::default(),
                }]),
            }]);

        // Step 2: Call the code under test.
        SnsRootCanister::poll_for_new_archive_canisters(
            &SNS_ROOT_CANISTER,
            &ledger_canister_client,
        )
        .await;

        // Step 3: Inspect results.
        assert_archive_poll_state_change(&SNS_ROOT_CANISTER, &[expected_archive_canister_id]);
    }

    #[tokio::test]
    async fn poll_for_archives_multiple_archives() {
        // Step 1: Prepare the world.
        thread_local! {
            static SNS_ROOT_CANISTER: RefCell<SnsRootCanister> = RefCell::new(build_test_sns_root_canister(false));
        }

        let expected_archive_canister_ids =
            vec![CanisterId::from_u64(99), CanisterId::from_u64(100)];

        let ledger_canister_client =
            MockLedgerCanisterClient::new(vec![LedgerCanisterClientCall::Archives {
                result: Ok(vec![
                    ArchiveInfo {
                        canister_id: expected_archive_canister_ids[0].into(),
                        block_range_start: Default::default(),
                        block_range_end: Default::default(),
                    },
                    ArchiveInfo {
                        canister_id: expected_archive_canister_ids[1].into(),
                        block_range_start: Default::default(),
                        block_range_end: Default::default(),
                    },
                ]),
            }]);

        // Step 2: Call the code under test.
        SnsRootCanister::poll_for_new_archive_canisters(
            &SNS_ROOT_CANISTER,
            &ledger_canister_client,
        )
        .await;

        // Step 3: Inspect results.
        assert_archive_poll_state_change(
            &SNS_ROOT_CANISTER,
            expected_archive_canister_ids.as_slice(),
        );
    }

    #[tokio::test]
    async fn poll_for_archives_multiple_polls() {
        // Step 1: Prepare the world.
        thread_local! {
            static SNS_ROOT_CANISTER: RefCell<SnsRootCanister> = RefCell::new(build_test_sns_root_canister(false));
        }

        let expected_archive_canister_ids =
            vec![CanisterId::from_u64(99), CanisterId::from_u64(100)];

        let ledger_canister_client = MockLedgerCanisterClient::new(vec![
            LedgerCanisterClientCall::Archives {
                result: Ok(vec![ArchiveInfo {
                    canister_id: expected_archive_canister_ids[0].into(),
                    block_range_start: Default::default(),
                    block_range_end: Default::default(),
                }]),
            },
            LedgerCanisterClientCall::Archives {
                result: Ok(vec![
                    ArchiveInfo {
                        canister_id: expected_archive_canister_ids[0].into(),
                        block_range_start: Default::default(),
                        block_range_end: Default::default(),
                    },
                    ArchiveInfo {
                        canister_id: expected_archive_canister_ids[1].into(),
                        block_range_start: Default::default(),
                        block_range_end: Default::default(),
                    },
                ]),
            },
        ]);

        // Step 2: Call the code under test.
        SnsRootCanister::poll_for_new_archive_canisters(
            &SNS_ROOT_CANISTER,
            &ledger_canister_client,
        )
        .await;

        // Step 3: Inspect results.
        assert_archive_poll_state_change(&SNS_ROOT_CANISTER, &expected_archive_canister_ids[0..1]);

        SnsRootCanister::poll_for_new_archive_canisters(
            &SNS_ROOT_CANISTER,
            &ledger_canister_client,
        )
        .await;

        assert_archive_poll_state_change(&SNS_ROOT_CANISTER, &expected_archive_canister_ids);
    }

    #[tokio::test]
    async fn poll_for_archives_multiple_polls_with_call_errors() {
        // Step 1: Prepare the world.
        thread_local! {
            static SNS_ROOT_CANISTER: RefCell<SnsRootCanister> = RefCell::new(build_test_sns_root_canister(false));
        }

        let expected_archive_canister_ids = [
            CanisterId::from_u64(99),
            CanisterId::from_u64(100),
            CanisterId::from_u64(101),
            CanisterId::from_u64(102),
        ];

        let ledger_canister_client = MockLedgerCanisterClient::new(vec![
            LedgerCanisterClientCall::Archives {
                result: Ok(vec![
                    ArchiveInfo {
                        canister_id: expected_archive_canister_ids[0].into(),
                        block_range_start: Default::default(),
                        block_range_end: Default::default(),
                    },
                    ArchiveInfo {
                        canister_id: expected_archive_canister_ids[1].into(),
                        block_range_start: Default::default(),
                        block_range_end: Default::default(),
                    },
                ]),
            },
            LedgerCanisterClientCall::Archives {
                result: Ok(vec![
                    ArchiveInfo {
                        canister_id: expected_archive_canister_ids[0].into(),
                        block_range_start: Default::default(),
                        block_range_end: Default::default(),
                    },
                    ArchiveInfo {
                        canister_id: expected_archive_canister_ids[2].into(),
                        block_range_start: Default::default(),
                        block_range_end: Default::default(),
                    },
                    ArchiveInfo {
                        canister_id: expected_archive_canister_ids[3].into(),
                        block_range_start: Default::default(),
                        block_range_end: Default::default(),
                    },
                ]),
            },
        ]);

        // Step 2: Call the code under test.
        SnsRootCanister::poll_for_new_archive_canisters(
            &SNS_ROOT_CANISTER,
            &ledger_canister_client,
        )
        .await;

        // Step 3: Inspect results.
        assert_archive_poll_state_change(&SNS_ROOT_CANISTER, &expected_archive_canister_ids[0..2]);

        // This should produce an error since the newly polled archives are not a superset of
        // the previous archive canisters.
        SnsRootCanister::poll_for_new_archive_canisters(
            &SNS_ROOT_CANISTER,
            &ledger_canister_client,
        )
        .await;

        // Since the error happens in canister_heartbeat, this should result in a 'do nothing'
        // operation.
        assert_archive_poll_state_change(&SNS_ROOT_CANISTER, &expected_archive_canister_ids[0..2]);
    }

    #[tokio::test]
    async fn poll_for_archives_multiple_polls_missing_canisters() {
        // Step 1: Prepare the world.
        thread_local! {
            static SNS_ROOT_CANISTER: RefCell<SnsRootCanister> = RefCell::new(build_test_sns_root_canister(false));
        }

        let expected_archive_canister_ids = [CanisterId::from_u64(99), CanisterId::from_u64(100)];

        let ledger_canister_client = MockLedgerCanisterClient::new(vec![
            LedgerCanisterClientCall::Archives {
                result: Ok(vec![ArchiveInfo {
                    canister_id: expected_archive_canister_ids[0].into(),
                    block_range_start: Default::default(),
                    block_range_end: Default::default(),
                }]),
            },
            LedgerCanisterClientCall::Archives {
                result: Err(CanisterCallError {
                    code: Some(1),
                    description: "This is an error".to_string(),
                }),
            },
            LedgerCanisterClientCall::Archives {
                result: Ok(vec![
                    ArchiveInfo {
                        canister_id: expected_archive_canister_ids[0].into(),
                        block_range_start: Default::default(),
                        block_range_end: Default::default(),
                    },
                    ArchiveInfo {
                        canister_id: expected_archive_canister_ids[1].into(),
                        block_range_start: Default::default(),
                        block_range_end: Default::default(),
                    },
                ]),
            },
            LedgerCanisterClientCall::Archives {
                result: Err(CanisterCallError {
                    code: Some(1),
                    description: "This is also an error".to_string(),
                }),
            },
        ]);

        // Step 2: Call the code under test.

        // The first call should result in new archives being returned
        SnsRootCanister::poll_for_new_archive_canisters(
            &SNS_ROOT_CANISTER,
            &ledger_canister_client,
        )
        .await;

        // Step 3: Inspect results.
        assert_archive_poll_state_change(&SNS_ROOT_CANISTER, &expected_archive_canister_ids[0..1]);

        // The second call is set to return an error, so no new archive canisters.
        SnsRootCanister::poll_for_new_archive_canisters(
            &SNS_ROOT_CANISTER,
            &ledger_canister_client,
        )
        .await;

        assert_archive_poll_state_change(&SNS_ROOT_CANISTER, &expected_archive_canister_ids[0..1]);

        // The third call is set to succeed and should result in tracking new archive canisters.
        SnsRootCanister::poll_for_new_archive_canisters(
            &SNS_ROOT_CANISTER,
            &ledger_canister_client,
        )
        .await;

        assert_archive_poll_state_change(&SNS_ROOT_CANISTER, &expected_archive_canister_ids[0..2]);

        // The fourth call is set to return an error, and should result in no new archive canisters.
        SnsRootCanister::poll_for_new_archive_canisters(
            &SNS_ROOT_CANISTER,
            &ledger_canister_client,
        )
        .await;

        assert_archive_poll_state_change(&SNS_ROOT_CANISTER, &expected_archive_canister_ids[0..2]);
    }

    #[tokio::test]
    async fn list_of_canisters_updates_when_update_canister_list_is_true() {
        // Step 1: Prepare the world.
        thread_local! {
            static SNS_ROOT_CANISTER: RefCell<SnsRootCanister> = RefCell::new(build_test_sns_root_canister(false));
        }

        let root_canister_id = CanisterId::from_u64(1000);
        let expected_archive_canister_ids =
            vec![CanisterId::from_u64(99), CanisterId::from_u64(100)];

        let (governance_canister_id, ledger_canister_id, swap_canister_id, index_canister_id) =
            SNS_ROOT_CANISTER.with(|sns_root| {
                let sns_root = sns_root.borrow();
                (
                    sns_root.governance_canister_id(),
                    sns_root.ledger_canister_id(),
                    sns_root.swap_canister_id(),
                    sns_root.index_canister_id(),
                )
            });

        let management_canister_client = MockManagementCanisterClient::new(vec![
            // First set of calls
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    governance_canister_id,
                ]),
            )),
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    root_canister_id.get(),
                ]),
            )),
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    root_canister_id.get(),
                ]),
            )),
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    root_canister_id.get(),
                ]),
            )),
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    root_canister_id.get(),
                ]),
            )),
            // Second set of calls
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    governance_canister_id,
                ]),
            )),
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    root_canister_id.get(),
                ]),
            )),
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    root_canister_id.get(),
                ]),
            )),
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    root_canister_id.get(),
                ]),
            )),
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    root_canister_id.get(),
                ]),
            )),
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    root_canister_id.get(),
                ]),
            )),
        ]);

        let ledger_canister_client = MockLedgerCanisterClient::new(vec![
            LedgerCanisterClientCall::Archives {
                result: Ok(vec![ArchiveInfo {
                    canister_id: expected_archive_canister_ids[0].into(),
                    block_range_start: Default::default(),
                    block_range_end: Default::default(),
                }]),
            },
            LedgerCanisterClientCall::Archives {
                result: Ok(vec![
                    ArchiveInfo {
                        canister_id: expected_archive_canister_ids[0].into(),
                        block_range_start: Default::default(),
                        block_range_end: Default::default(),
                    },
                    ArchiveInfo {
                        canister_id: expected_archive_canister_ids[1].into(),
                        block_range_start: Default::default(),
                        block_range_end: Default::default(),
                    },
                ]),
            },
        ]);

        let env =
            TestEnvironment {
                calls: Arc::new(Mutex::new(
                    vec![
                        EnvironmentCall::CallCanister {
                            expected_canister: CanisterId::try_from(swap_canister_id).unwrap(),
                            expected_method: "get_canister_status".to_string(),
                            expected_bytes: None,
                            result: Ok(Encode!(&CanisterStatusResultV2::dummy_with_controllers(
                                vec![governance_canister_id]
                            ))
                            .unwrap()),
                        },
                        EnvironmentCall::CallCanister {
                            expected_canister: CanisterId::try_from(swap_canister_id).unwrap(),
                            expected_method: "get_canister_status".to_string(),
                            expected_bytes: None,
                            result: Ok(Encode!(&CanisterStatusResultV2::dummy_with_controllers(
                                vec![governance_canister_id]
                            ))
                            .unwrap()),
                        },
                    ]
                    .into(),
                )),
            };

        // Step 2: Call the code under test.
        SnsRootCanister::poll_for_new_archive_canisters(
            &SNS_ROOT_CANISTER,
            &ledger_canister_client,
        )
        .await;

        // We should now have a single Archive canister registered.
        assert_archive_poll_state_change(&SNS_ROOT_CANISTER, &expected_archive_canister_ids[0..1]);

        let first_result = SnsRootCanister::get_sns_canisters_summary(
            &SNS_ROOT_CANISTER,
            &management_canister_client,
            &ledger_canister_client,
            &env,
            false,
            root_canister_id.into(),
        )
        .await;

        // No change should happen after our first call as it doesn't force an update.
        assert_archive_poll_state_change(&SNS_ROOT_CANISTER, &expected_archive_canister_ids[0..1]);

        let second_result = SnsRootCanister::get_sns_canisters_summary(
            &SNS_ROOT_CANISTER,
            &management_canister_client,
            &ledger_canister_client,
            &env,
            true,
            root_canister_id.into(),
        )
        .await;

        assert_eq!(
            first_result
                .archives
                .into_iter()
                .map(|status| CanisterId::try_from(status.canister_id.unwrap()).unwrap())
                .collect::<Vec<_>>(),
            expected_archive_canister_ids[0..1].to_vec()
        );

        assert_archive_poll_state_change(&SNS_ROOT_CANISTER, &expected_archive_canister_ids);
        assert_eq!(
            second_result
                .archives
                .into_iter()
                .map(|status| CanisterId::try_from(status.canister_id.unwrap()).unwrap())
                .collect::<Vec<_>>(),
            expected_archive_canister_ids.to_vec()
        );

        let actual_management_canister_calls = management_canister_client.get_calls_snapshot();
        let expected_management_canister_calls = vec![
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: root_canister_id,
            }),
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: CanisterId::try_from(governance_canister_id).unwrap(),
            }),
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: CanisterId::try_from(ledger_canister_id).unwrap(),
            }),
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: CanisterId::try_from(index_canister_id).unwrap(),
            }),
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: expected_archive_canister_ids[0],
            }),
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: root_canister_id,
            }),
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: CanisterId::try_from(governance_canister_id).unwrap(),
            }),
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: CanisterId::try_from(ledger_canister_id).unwrap(),
            }),
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: CanisterId::try_from(index_canister_id).unwrap(),
            }),
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: expected_archive_canister_ids[0],
            }),
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: expected_archive_canister_ids[1],
            }),
        ];
        assert_eq!(
            actual_management_canister_calls,
            expected_management_canister_calls
        );
    }

    #[tokio::test]
    async fn test_get_sns_canisters_summary_reports_settings() {
        // Step 1: Prepare the world.
        thread_local! {
            static SNS_ROOT_CANISTER: RefCell<SnsRootCanister> = const { RefCell::new(SnsRootCanister {
                governance_canister_id: Some(PrincipalId::new_user_test_id(1)),
                ledger_canister_id: Some(PrincipalId::new_user_test_id(2)),
                swap_canister_id: Some(PrincipalId::new_user_test_id(3)),
                dapp_canister_ids: vec![],
                extensions: Some(Extensions { extension_canister_ids: vec![] }),
                archive_canister_ids: vec![],
                index_canister_id: Some(PrincipalId::new_user_test_id(4)),
                testflight: false,
                timers: None,
            }) };
        }

        let root_canister_id = CanisterId::from_u64(4);

        let (governance_canister_id, _, swap_canister_id, _) = SNS_ROOT_CANISTER.with(|sns_root| {
            let sns_root = sns_root.borrow();
            (
                sns_root.governance_canister_id(),
                sns_root.ledger_canister_id(),
                sns_root.swap_canister_id(),
                sns_root.index_canister_id(),
            )
        });

        let management_canister_client = MockManagementCanisterClient::new(vec![
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    governance_canister_id,
                ]),
            )),
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    governance_canister_id,
                ]),
            )),
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    governance_canister_id,
                ]),
            )),
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    governance_canister_id,
                ]),
            )),
        ]);

        let ledger_canister_client = MockLedgerCanisterClient::new(vec![]);

        let env = TestEnvironment {
            calls: Arc::new(Mutex::new(
                vec![EnvironmentCall::CallCanister {
                    expected_canister: CanisterId::try_from(swap_canister_id).unwrap(),
                    expected_method: "get_canister_status".to_string(),
                    expected_bytes: None,
                    result: Ok(
                        Encode!(&CanisterStatusResultV2::dummy_with_controllers(vec![
                            governance_canister_id
                        ]))
                        .unwrap(),
                    ),
                }]
                .into(),
            )),
        };

        let result = SnsRootCanister::get_sns_canisters_summary(
            &SNS_ROOT_CANISTER,
            &management_canister_client,
            &ledger_canister_client,
            &env,
            false,
            root_canister_id.into(),
        )
        .await;

        let expected_settings =
            CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                governance_canister_id,
            ])
            .settings;

        for (result, canister_name) in [
            (result.governance, "governance"),
            (result.ledger, "ledger"),
            (result.index, "index"),
        ] {
            // compute_allocation
            assert_eq!(
                result
                    .clone()
                    .unwrap()
                    .status
                    .unwrap()
                    .settings
                    .compute_allocation,
                expected_settings.clone().compute_allocation,
                "{canister_name}'s compute_allocation did not match"
            );
            // controllers
            assert_eq!(
                result.clone().unwrap().status.unwrap().settings.controllers,
                expected_settings.clone().controllers,
                "{canister_name}'s controllers did not match"
            );
            // freezing_threshold
            assert_eq!(
                result
                    .clone()
                    .unwrap()
                    .status
                    .unwrap()
                    .settings
                    .freezing_threshold,
                expected_settings.clone().freezing_threshold,
                "{canister_name}'s freezing_threshold did not match"
            );
            // memory_allocation
            assert_eq!(
                result
                    .clone()
                    .unwrap()
                    .status
                    .unwrap()
                    .settings
                    .memory_allocation,
                expected_settings.clone().memory_allocation,
                "{canister_name}'s memory_allocation did not match"
            );
            // wasm_memory_limit
            assert_eq!(
                result
                    .clone()
                    .unwrap()
                    .status
                    .unwrap()
                    .settings
                    .wasm_memory_limit,
                Some(expected_settings.clone().wasm_memory_limit),
                "{canister_name}'s wasm_memory_limit did not match"
            );
        }
    }

    #[tokio::test]
    async fn test_get_sns_canisters_summary_handles_dapp_status_failures() {
        // Step 1: Prepare the world.
        thread_local! {
            static EXPECTED_DAPP_CANISTERS_PRINCIPAL_IDS: Vec<PrincipalId> =  vec![
                CanisterId::from_u64(99).get(),
                CanisterId::from_u64(100).get(),
            ];
            static SNS_ROOT_CANISTER: RefCell<SnsRootCanister> = RefCell::new(SnsRootCanister {
                governance_canister_id: Some(PrincipalId::new_user_test_id(1)),
                ledger_canister_id: Some(PrincipalId::new_user_test_id(2)),
                swap_canister_id: Some(PrincipalId::new_user_test_id(3)),
                dapp_canister_ids: EXPECTED_DAPP_CANISTERS_PRINCIPAL_IDS.with(|i| i.clone()),
                extensions: Some(Extensions { extension_canister_ids: vec![] }),
                archive_canister_ids: vec![],
                index_canister_id: Some(PrincipalId::new_user_test_id(4)),
                testflight: false,
                timers: None,
            });
        }

        let root_canister_id = CanisterId::from_u64(4);

        let (governance_canister_id, ledger_canister_id, swap_canister_id, index_canister_id) =
            SNS_ROOT_CANISTER.with(|sns_root| {
                let sns_root = sns_root.borrow();
                (
                    sns_root.governance_canister_id(),
                    sns_root.ledger_canister_id(),
                    sns_root.swap_canister_id(),
                    sns_root.index_canister_id(),
                )
            });
        let expected_dapp_canisters_principal_ids =
            EXPECTED_DAPP_CANISTERS_PRINCIPAL_IDS.with(|i| i.clone());

        let management_canister_client = MockManagementCanisterClient::new(vec![
            // First set of calls
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    governance_canister_id,
                ]),
            )),
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    root_canister_id.get(),
                ]),
            )),
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    root_canister_id.get(),
                ]),
            )),
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    root_canister_id.get(),
                ]),
            )),
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    root_canister_id.get(),
                ]),
            )),
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    root_canister_id.get(),
                ]),
            )),
            // Second set of calls
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    governance_canister_id,
                ]),
            )),
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    root_canister_id.get(),
                ]),
            )),
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    root_canister_id.get(),
                ]),
            )),
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    root_canister_id.get(),
                ]),
            )),
            MockManagementCanisterClientReply::CanisterStatus(Err((
                1,
                "Error calling status on dapp".to_string(),
            ))),
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    root_canister_id.get(),
                ]),
            )),
        ]);

        let ledger_canister_client = MockLedgerCanisterClient::new(vec![]);

        let env =
            TestEnvironment {
                calls: Arc::new(Mutex::new(
                    vec![
                        // First set of calls
                        EnvironmentCall::CallCanister {
                            expected_canister: CanisterId::try_from(swap_canister_id).unwrap(),
                            expected_method: "get_canister_status".to_string(),
                            expected_bytes: None,
                            result: Ok(Encode!(&CanisterStatusResultV2::dummy_with_controllers(
                                vec![governance_canister_id]
                            ))
                            .unwrap()),
                        },
                        // Second set of calls
                        EnvironmentCall::CallCanister {
                            expected_canister: CanisterId::try_from(swap_canister_id).unwrap(),
                            expected_method: "get_canister_status".to_string(),
                            expected_bytes: None,
                            result: Ok(Encode!(&CanisterStatusResultV2::dummy_with_controllers(
                                vec![governance_canister_id]
                            ))
                            .unwrap()),
                        },
                    ]
                    .into(),
                )),
            };

        // Call the code under test which consumes the first set of calls
        let result_1 = SnsRootCanister::get_sns_canisters_summary(
            &SNS_ROOT_CANISTER,
            &management_canister_client,
            &ledger_canister_client,
            &env,
            false,
            root_canister_id.into(),
        )
        .await;

        // Assert the dapp canister_id[0] and has some status
        assert_eq!(
            result_1.dapps[0].canister_id,
            Some(expected_dapp_canisters_principal_ids[0])
        );
        assert!(result_1.dapps[0].status.is_some());

        // Assert the dapp canister_id[1] and has some status
        assert_eq!(
            result_1.dapps[1].canister_id,
            Some(expected_dapp_canisters_principal_ids[1])
        );
        assert!(result_1.dapps[1].status.is_some());

        // Call the code under test which consumes the second set of calls
        let result_2 = SnsRootCanister::get_sns_canisters_summary(
            &SNS_ROOT_CANISTER,
            &management_canister_client,
            &ledger_canister_client,
            &env,
            false,
            root_canister_id.into(),
        )
        .await;

        // Assert the dapp canister_id[0] and has NO status
        assert_eq!(
            result_2.dapps[0].canister_id,
            Some(expected_dapp_canisters_principal_ids[0])
        );
        assert!(result_2.dapps[0].status.is_none());

        // Assert the dapp canister_id[1] and has some status
        assert_eq!(
            result_2.dapps[1].canister_id,
            Some(expected_dapp_canisters_principal_ids[1])
        );
        assert!(result_2.dapps[1].status.is_some());

        let actual_management_canister_calls = management_canister_client.get_calls_snapshot();
        let expected_management_canister_calls = vec![
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: root_canister_id,
            }),
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: CanisterId::try_from(governance_canister_id).unwrap(),
            }),
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: CanisterId::try_from(ledger_canister_id).unwrap(),
            }),
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: CanisterId::try_from(index_canister_id).unwrap(),
            }),
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: CanisterId::try_from(expected_dapp_canisters_principal_ids[0])
                    .unwrap(),
            }),
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: CanisterId::try_from(expected_dapp_canisters_principal_ids[1])
                    .unwrap(),
            }),
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: root_canister_id,
            }),
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: CanisterId::try_from(governance_canister_id).unwrap(),
            }),
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: CanisterId::try_from(ledger_canister_id).unwrap(),
            }),
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: CanisterId::try_from(index_canister_id).unwrap(),
            }),
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: CanisterId::try_from(expected_dapp_canisters_principal_ids[0])
                    .unwrap(),
            }),
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: CanisterId::try_from(expected_dapp_canisters_principal_ids[1])
                    .unwrap(),
            }),
        ];
        assert_eq!(
            actual_management_canister_calls,
            expected_management_canister_calls
        );
    }

    #[tokio::test]
    async fn test_get_sns_canisters_summary_handles_archives_status_failures() {
        // Step 1: Prepare the world.
        thread_local! {
            static EXPECTED_ARCHIVE_CANISTERS_PRINCIPAL_IDS: Vec<PrincipalId> =  vec![
                CanisterId::from_u64(99).get(),
                CanisterId::from_u64(100).get(),
            ];
            static SNS_ROOT_CANISTER: RefCell<SnsRootCanister> = RefCell::new(SnsRootCanister {
                governance_canister_id: Some(PrincipalId::new_user_test_id(1)),
                ledger_canister_id: Some(PrincipalId::new_user_test_id(2)),
                swap_canister_id: Some(PrincipalId::new_user_test_id(3)),
                dapp_canister_ids: vec![],
                extensions: Some(Extensions { extension_canister_ids: vec![] }),
                archive_canister_ids: EXPECTED_ARCHIVE_CANISTERS_PRINCIPAL_IDS.with(|i| i.clone()),
                index_canister_id: Some(PrincipalId::new_user_test_id(4)),
                testflight: false,
                timers: None,
            });
        }

        let root_canister_id = CanisterId::from_u64(4);

        let (governance_canister_id, ledger_canister_id, swap_canister_id, index_canister_id) =
            SNS_ROOT_CANISTER.with(|sns_root| {
                let sns_root = sns_root.borrow();
                (
                    sns_root.governance_canister_id(),
                    sns_root.ledger_canister_id(),
                    sns_root.swap_canister_id(),
                    sns_root.index_canister_id(),
                )
            });
        let expected_archive_canisters_principal_ids =
            EXPECTED_ARCHIVE_CANISTERS_PRINCIPAL_IDS.with(|i| i.clone());

        let management_canister_client = MockManagementCanisterClient::new(vec![
            // First set of calls
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    governance_canister_id,
                ]),
            )),
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    root_canister_id.get(),
                ]),
            )),
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    root_canister_id.get(),
                ]),
            )),
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    root_canister_id.get(),
                ]),
            )),
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    root_canister_id.get(),
                ]),
            )),
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    root_canister_id.get(),
                ]),
            )),
            // Second set of calls
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    governance_canister_id,
                ]),
            )),
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    root_canister_id.get(),
                ]),
            )),
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    root_canister_id.get(),
                ]),
            )),
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    root_canister_id.get(),
                ]),
            )),
            MockManagementCanisterClientReply::CanisterStatus(Err((
                1,
                "Error calling status on dapp".to_string(),
            ))),
            MockManagementCanisterClientReply::CanisterStatus(Ok(
                CanisterStatusResultFromManagementCanister::dummy_with_controllers(vec![
                    root_canister_id.get(),
                ]),
            )),
        ]);

        let ledger_canister_client = MockLedgerCanisterClient::new(vec![]);

        let env =
            TestEnvironment {
                calls: Arc::new(Mutex::new(
                    vec![
                        // First set of calls
                        EnvironmentCall::CallCanister {
                            expected_canister: CanisterId::try_from(swap_canister_id).unwrap(),
                            expected_method: "get_canister_status".to_string(),
                            expected_bytes: None,
                            result: Ok(Encode!(&CanisterStatusResultV2::dummy_with_controllers(
                                vec![governance_canister_id]
                            ))
                            .unwrap()),
                        },
                        // Second set of calls
                        EnvironmentCall::CallCanister {
                            expected_canister: CanisterId::try_from(swap_canister_id).unwrap(),
                            expected_method: "get_canister_status".to_string(),
                            expected_bytes: None,
                            result: Ok(Encode!(&CanisterStatusResultV2::dummy_with_controllers(
                                vec![governance_canister_id]
                            ))
                            .unwrap()),
                        },
                    ]
                    .into(),
                )),
            };

        // Call the code under test which consumes the first set of calls
        let result_1 = SnsRootCanister::get_sns_canisters_summary(
            &SNS_ROOT_CANISTER,
            &management_canister_client,
            &ledger_canister_client,
            &env,
            false,
            root_canister_id.into(),
        )
        .await;

        // Assert the archive canister_id[0] and has some status
        assert_eq!(
            result_1.archives[0].canister_id,
            Some(expected_archive_canisters_principal_ids[0])
        );
        assert!(result_1.archives[0].status.is_some());

        // Assert the archive canister_id[1] and has some status
        assert_eq!(
            result_1.archives[1].canister_id,
            Some(expected_archive_canisters_principal_ids[1])
        );
        assert!(result_1.archives[1].status.is_some());

        // Call the code under test which consumes the second set of calls
        let result_2 = SnsRootCanister::get_sns_canisters_summary(
            &SNS_ROOT_CANISTER,
            &management_canister_client,
            &ledger_canister_client,
            &env,
            false,
            root_canister_id.into(),
        )
        .await;

        // Assert the archive canister_id[0] and has NO status
        assert_eq!(
            result_2.archives[0].canister_id,
            Some(expected_archive_canisters_principal_ids[0])
        );
        assert!(result_2.archives[0].status.is_none());

        // Assert the archive canister_id[1] and has some status
        assert_eq!(
            result_2.archives[1].canister_id,
            Some(expected_archive_canisters_principal_ids[1])
        );
        assert!(result_2.archives[1].status.is_some());

        let actual_management_canister_calls = management_canister_client.get_calls_snapshot();
        let expected_management_canister_calls = vec![
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: root_canister_id,
            }),
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: CanisterId::try_from(governance_canister_id).unwrap(),
            }),
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: CanisterId::try_from(ledger_canister_id).unwrap(),
            }),
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: CanisterId::try_from(index_canister_id).unwrap(),
            }),
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: CanisterId::try_from(expected_archive_canisters_principal_ids[0])
                    .unwrap(),
            }),
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: CanisterId::try_from(expected_archive_canisters_principal_ids[1])
                    .unwrap(),
            }),
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: root_canister_id,
            }),
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: CanisterId::try_from(governance_canister_id).unwrap(),
            }),
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: CanisterId::try_from(ledger_canister_id).unwrap(),
            }),
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: CanisterId::try_from(index_canister_id).unwrap(),
            }),
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: CanisterId::try_from(expected_archive_canisters_principal_ids[0])
                    .unwrap(),
            }),
            MockManagementCanisterClientCall::CanisterStatus(CanisterIdRecord {
                canister_id: CanisterId::try_from(expected_archive_canisters_principal_ids[1])
                    .unwrap(),
            }),
        ];
        assert_eq!(
            actual_management_canister_calls,
            expected_management_canister_calls
        );
    }
}
