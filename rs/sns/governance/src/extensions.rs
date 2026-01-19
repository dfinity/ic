use crate::{
    governance::{Governance, TREASURY_SUBACCOUNT_NONCE},
    logs::{ERROR, INFO},
    pb::{
        sns_root_types::{
            CanisterCallError, CleanUpFailedRegisterExtensionRequest,
            CleanUpFailedRegisterExtensionResponse, ListSnsCanistersRequest,
            ListSnsCanistersResponse, RegisterExtensionRequest, RegisterExtensionResponse,
            clean_up_failed_register_extension_response, register_extension_response,
        },
        v1 as pb,
        v1::{
            ChunkedCanisterWasm, ExecuteExtensionOperation, ExtensionInit, ExtensionOperationArg,
            ExtensionUpgradeArg, GovernanceError, Precise, PreciseMap, RegisterExtension, Topic,
            governance_error::ErrorType, precise,
        },
    },
    storage::{cache_registered_extension, get_registered_extension_from_cache},
    types::{Environment, Wasm},
};
use candid::{CandidType, Decode, Deserialize, Encode, Nat};
use candid_utils::printing;
use futures::future::BoxFuture;
use ic_base_types::{CanisterId, PrincipalId, SubnetId};
use ic_canister_log::log;
use ic_ledger_core::Tokens;
use ic_management_canister_types_private::{
    CanisterInfoRequest, CanisterInfoResponse, CanisterInstallMode,
};
use ic_nervous_system_common::{
    NANO_SECONDS_PER_SECOND, ONE_HOUR_SECONDS, ledger::compute_distribution_subaccount_bytes,
};
use ic_nns_constants::{CYCLES_MINTING_CANISTER_ID, REGISTRY_CANISTER_ID};
use icrc_ledger_types::icrc1::account::Account;
use lazy_static::lazy_static;
use maplit::btreemap;
use serde::Serialize;
use sns_treasury_manager::{
    Allowance, Asset, DepositRequest, TreasuryManagerArg, TreasuryManagerInit,
    TreasuryManagerUpgrade, WithdrawRequest,
};
use std::{
    cell::RefCell,
    collections::BTreeMap,
    fmt::{Display, Formatter},
};

thread_local! {
    static ALLOWED_EXTENSIONS: RefCell<BTreeMap<[u8; 32], ExtensionSpec>> = RefCell::new(btreemap! {
    hex::decode("1c07ceba560e7bcffa43d1b5ae97db81151854f068b707c1728e213948212a6c")
    .unwrap()
    .try_into()
    .unwrap() => ExtensionSpec {
            name: "sns-kongswap-adaptor".to_string(),
            version: ExtensionVersion(1),
            topic: Topic::TreasuryAssetManagement,
            extension_type: ExtensionType::TreasuryManager,
    }});
}

#[cfg(any(test, feature = "test"))]
lazy_static! {
    static ref TEST_HASH_TO_EXTENSION_SPEC: BTreeMap<[u8; 32], ExtensionSpec> = {
        // KongSwap v1 hash from integration test
        let v1_hash: [u8; 32] = [
            103, 45, 67, 136, 153, 129, 99, 42, 252, 137, 234, 215, 249, 199, 209, 167,
            144, 31, 212, 229, 137, 163, 153, 11, 118, 34, 52, 243, 17, 86, 97, 209,
        ];

        // KongSwap v2 hash from integration test
        let v2_hash: [u8; 32] = [
            128, 15, 128, 73, 49, 167, 207, 220, 204, 215, 20, 218, 174, 6, 171, 203,
            196, 247, 243, 160, 84, 98, 133, 2, 3, 47, 184, 165, 191, 94, 123, 231,
        ];

        // This is the SHA-256 has of SMALLEST_VALID_WASM_BYTES in
        // ic_nervous_system_common_test_utils::wasm_helpers. Depending on that
        // crate creates problems (namely, that it makes the resulting WASM
        // assume that bindgen is available, which only happens in browsers, not
        // the ICP). To work around that, we copy the value of
        // SMALLEST_VALID_WASM_HASH here.
        let smallest_valid_wasm_hash: [u8; 32] = [
            147, 164, 75, 187, 150, 199, 81, 33, 142, 76, 0, 212, 121, 228, 193, 67,
            88, 18, 42, 56, 154, 204, 161, 98, 5, 177, 228, 208, 220, 95, 148, 118,
        ];

        let mut additional = btreemap! {
            v1_hash => ExtensionSpec {
                name: "My Test Extension".to_string(),
                version: ExtensionVersion(1),
                topic: Topic::TreasuryAssetManagement,
                extension_type: ExtensionType::TreasuryManager,
            },

            v2_hash => ExtensionSpec {
                name: "My Test Extension".to_string(),
                version: ExtensionVersion(2),
                topic: Topic::TreasuryAssetManagement,
                extension_type: ExtensionType::TreasuryManager,
            },

            smallest_valid_wasm_hash => ExtensionSpec {
                name: "Does Nothing Except Explode in Tests".to_string(),
                version: ExtensionVersion(123),
                topic: Topic::TreasuryAssetManagement,
                extension_type: ExtensionType::TreasuryManager,
            },
        };

        ALLOWED_EXTENSIONS.with(|base| {
            let mut result = base.borrow().clone();
            result.append(&mut additional);
            result
        })
    };
}

#[cfg(feature = "test")]
pub fn add_allowed_extension_spec(hash: [u8; 32], spec: ExtensionSpec) {
    ALLOWED_EXTENSIONS.with_borrow_mut(|allowed| allowed.insert(hash, spec));
}

#[derive(Clone)]
pub struct TreasuryManagerDepositContext {
    pub sns_root_canister_id: CanisterId,
    pub sns_governance_canister_id: CanisterId,
    pub sns_ledger_canister_id: CanisterId,
    pub sns_token_symbol: String,
    pub sns_ledger_transaction_fee_e8s: u64,
    pub icp_ledger_canister_id: CanisterId,
}

#[derive(Clone, Debug, Eq, PartialEq, candid::CandidType, candid::Deserialize)]
pub enum ExtensionType {
    TreasuryManager,
}

impl Display for ExtensionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TreasuryManager => write!(f, "TreasuryManager"),
        }
    }
}

#[derive(Clone, Debug)]
pub enum ValidatedExtensionInit {
    TreasuryManager(ValidatedDepositOperationArg),
    // Future: other extension type init arguments would go here
}

/// Enum that captures all possible validated operation arguments
#[derive(Clone, Debug)]
pub enum ValidatedOperationArg {
    // Treasury Manager operations
    TreasuryManagerDeposit(ValidatedDepositOperationArg),
    TreasuryManagerWithdraw(ValidatedWithdrawOperationArg),
    // Future: other extension type operations would go here
    // VotingCreatePoll(ValidatedCreatePollArg),
    // etc.
}

impl ValidatedOperationArg {
    /// Returns the original Precise value that was validated
    pub fn get_original_value(&self) -> &Precise {
        match self {
            Self::TreasuryManagerDeposit(arg) => &arg.original,
            Self::TreasuryManagerWithdraw(arg) => &arg.original,
        }
    }

    /// Renders the operation arguments as markdown suitable for proposal display
    pub fn render_for_proposal(&self) -> String {
        match self {
            Self::TreasuryManagerDeposit(args) => args.render_for_proposal(),
            Self::TreasuryManagerWithdraw(args) => args.render_for_proposal(),
        }
    }
}

impl Display for ValidatedOperationArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.render_for_proposal())
    }
}

/// Trait for payloads that can be rendered as markdown for proposal display
pub trait RenderablePayload {
    /// Renders the payload as markdown suitable for proposal display
    fn render_for_proposal(&self) -> String;
}

impl RenderablePayload for Precise {
    fn render_for_proposal(&self) -> String {
        let render = if let Ok(candid_str) = printing::pretty(self) {
            candid_str
        } else {
            // Fallback in case Candid serialization crashes.
            format!("{self:#?}")
        };

        format!("#### Raw Payload\n\n{render}")
    }
}

#[derive(Clone, Debug, Eq, PartialEq, candid::CandidType, candid::Deserialize)]
pub enum OperationType {
    TreasuryManagerDeposit,
    TreasuryManagerWithdraw,
}

impl Display for OperationType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            OperationType::TreasuryManagerDeposit => write!(f, "deposit"),
            OperationType::TreasuryManagerWithdraw => write!(f, "withdraw"),
        }
    }
}

/// Specification for an extension operation
#[derive(Clone, Debug, Eq, PartialEq, candid::CandidType, candid::Deserialize)]
pub struct ExtensionOperationSpec {
    pub operation_type: OperationType,
    pub description: String,
    pub extension_type: ExtensionType,
    pub topic: Topic,
}

impl ExtensionOperationSpec {
    pub fn name(&self) -> String {
        format!("{}", &self.operation_type)
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    async fn validate_operation_arg(
        &self,
        governance: &Governance,
        arg: ExtensionOperationArg,
    ) -> Result<ValidatedOperationArg, String> {
        match &self.operation_type {
            OperationType::TreasuryManagerDeposit => {
                validate_deposit_operation(governance, arg).await
            }
            OperationType::TreasuryManagerWithdraw => {
                validate_withdraw_operation(governance, arg).await
            }
        }
    }
}

/// Validates treasury manager init arguments
fn validate_treasury_manager_init(
    governance: &Governance,
    init: ExtensionInit,
) -> BoxFuture<'_, Result<ValidatedExtensionInit, String>> {
    Box::pin(async move {
        let ExtensionInit { value } = init;
        validate_deposit_operation_impl(governance, value)
            .await
            .map(ValidatedExtensionInit::TreasuryManager)
    })
}

/// Validates treasury manager upgrade arguments
async fn validate_treasury_manager_upgrade(
    upgrade_arg: Option<ExtensionUpgradeArg>,
) -> Result<ValidatedExtensionUpgradeArg, String> {
    // For now, treasury manager doesn't have any specific upgrade arguments
    // Any upgrade arg provided should be None or an empty value
    if let Some(ExtensionUpgradeArg { value: Some(_) }) = upgrade_arg {
        return Err("Treasury manager extensions do not support upgrade arguments yet".to_string());
    }

    Ok(ValidatedExtensionUpgradeArg::TreasuryManager)
}

async fn validate_deposit_operation_impl(
    governance: &Governance,
    value: Option<Precise>,
) -> Result<ValidatedDepositOperationArg, String> {
    let structurally_valid = ValidatedDepositOperationArg::try_from(value)?;

    let sns_subaccount = governance.sns_treasury_subaccount();
    let icp_subaccount = governance.icp_treasury_subaccount();

    // Fail if either is asking for more than 50% of current balance.  The balance could have changed
    // since the proposal was created, and we don't assume that the proposal should work
    let sns_balance = governance
        .ledger
        .account_balance(Account {
            owner: governance.env.canister_id().get().0,
            subaccount: sns_subaccount,
        })
        .await
        .map_err(|e| format!("Failed to get SNS treasury balance: {e:?}"))?;
    let icp_balance = governance
        .nns_ledger
        .account_balance(Account {
            owner: governance.env.canister_id().get().0,
            subaccount: icp_subaccount,
        })
        .await
        .map_err(|e| format!("Failed to get ICP treasury balance: {e:?}"))?;

    let icp_requested = Tokens::from_e8s(structurally_valid.treasury_allocation_icp_e8s);
    let sns_requested = Tokens::from_e8s(structurally_valid.treasury_allocation_sns_e8s);

    // Unwrap is safe, only fails if divisor is zero, which we don't do.
    if sns_requested > sns_balance.checked_div(2).unwrap() {
        return Err(format!(
            "SNS treasury deposit request of {sns_requested} exceeds 50% of current SNS Token balance of {sns_balance}"
        ));
    }

    if icp_requested > icp_balance.checked_div(2).unwrap() {
        return Err(format!(
            "ICP treasury deposit request of {icp_requested} exceeds 50% of current ICP balance of {icp_balance}"
        ));
    }

    Ok(structurally_valid)
}

// This map contains the ExtensionOperationSpecs for operations supported by governance.
lazy_static! {
    pub static ref EXTENSION_OPERATION_SPECS: BTreeMap<String, ExtensionOperationSpec> = {
        let specs = vec![
            ExtensionOperationSpec {
                operation_type: OperationType::TreasuryManagerDeposit,
                description: "Deposit funds into the treasury manager.".to_string(),
                extension_type: ExtensionType::TreasuryManager,
                topic: Topic::TreasuryAssetManagement,
            },
            ExtensionOperationSpec {
                operation_type: OperationType::TreasuryManagerWithdraw,
                description: "Withdraw funds from the treasury manager.".to_string(),
                extension_type: ExtensionType::TreasuryManager,
                topic: Topic::TreasuryAssetManagement,
            },
        ];

        let mut map = BTreeMap::new();
        for spec in specs {
            let key = spec.name();
            assert!(
                !map.contains_key(&key),
                "Duplicate operation name detected: '{key}'. Each operation must have a unique name."
            );
            map.insert(key, spec);
        }
        map
    };
}

pub fn get_extension_operation_spec_from_cache(
    execute_extension_operation: &ExecuteExtensionOperation,
) -> Result<ExtensionOperationSpec, String> {
    // Extract and validate basic fields
    let ExecuteExtensionOperation {
        extension_canister_id,
        operation_name,
        operation_arg: _,
    } = execute_extension_operation;

    let Some(extension_canister_id) = extension_canister_id else {
        return Err("extension_canister_id is required.".to_string());
    };

    let extension_canister_id = CanisterId::try_from_principal_id(*extension_canister_id)
        .map_err(|err| format!("Cannot interpret extension_canister_id as canister ID: {err}"))?;

    let Some(operation_name) = operation_name else {
        return Err("operation_name is required.".to_string());
    };

    get_registered_extension_from_cache(extension_canister_id)
        .and_then(|spec| spec.get_operation(operation_name))
        .ok_or(format!(
            "No operation found called '{operation_name}' for extension with \
                canister id: {extension_canister_id}"
        ))
}

/// Validates deposit operation arguments
fn validate_deposit_operation(
    governance: &Governance,
    arg: ExtensionOperationArg,
) -> BoxFuture<'_, Result<ValidatedOperationArg, String>> {
    Box::pin(async move {
        let ExtensionOperationArg { value } = arg;
        validate_deposit_operation_impl(governance, value)
            .await
            .map(ValidatedOperationArg::TreasuryManagerDeposit)
    })
}

/// Validates withdraw operation arguments (currently requires empty arguments)
fn validate_withdraw_operation(
    _governance: &Governance,
    arg: ExtensionOperationArg,
) -> BoxFuture<'_, Result<ValidatedOperationArg, String>> {
    Box::pin(async move {
        let ExtensionOperationArg { value } = arg;

        ValidatedWithdrawOperationArg::try_from(value)
            .map(ValidatedOperationArg::TreasuryManagerWithdraw)
    })
}

impl ExtensionType {
    pub fn standard_operations(&self) -> Vec<ExtensionOperationSpec> {
        match self {
            ExtensionType::TreasuryManager => vec![
                EXTENSION_OPERATION_SPECS.get("deposit").cloned().unwrap(),
                EXTENSION_OPERATION_SPECS.get("withdraw").cloned().unwrap(),
            ],
            // Future extension types would define their standard operations here
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct ExtensionVersion(pub u64);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionSpec {
    pub name: String,
    pub version: ExtensionVersion,
    pub topic: Topic,
    pub extension_type: ExtensionType,
}

impl ExtensionSpec {
    pub async fn validate_init_arg(
        &self,
        gov: &Governance,
        init: ExtensionInit,
    ) -> Result<ValidatedExtensionInit, String> {
        match &self.extension_type {
            ExtensionType::TreasuryManager => validate_treasury_manager_init(gov, init).await, // Future extension types would be handled here
        }
    }

    pub async fn validate_upgrade_arg(
        &self,
        _gov: &Governance,
        upgrade_arg: Option<ExtensionUpgradeArg>,
    ) -> Result<ValidatedExtensionUpgradeArg, String> {
        match &self.extension_type {
            ExtensionType::TreasuryManager => validate_treasury_manager_upgrade(upgrade_arg).await,
            // Future extension types would be handled here
        }
    }

    /// Get all operations for this extension
    pub fn all_operations(&self) -> BTreeMap<String, ExtensionOperationSpec> {
        let mut operations = BTreeMap::new();

        // Add standard operations from the extension type
        for op in self.extension_type.standard_operations() {
            operations.insert(op.name(), op);
        }

        operations
    }

    /// Get a specific operation by name
    /// Standard operations take precedence to ensure deterministic behavior
    pub fn get_operation(&self, name: &str) -> Option<ExtensionOperationSpec> {
        self.extension_type
            .standard_operations()
            .into_iter()
            .find(|op| op.name() == name)
    }

    pub fn supports_extension_type(&self, extension_type: ExtensionType) -> bool {
        self.extension_type == extension_type
    }
}

impl Display for ExtensionSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let operations_str = self
            .all_operations()
            .keys()
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");

        write!(
            f,
            "SNS Extension {{ name: {}, topic: {}, type: {:?}, operations: {} }}",
            self.name, self.topic, self.extension_type, operations_str
        )
    }
}

#[derive(Debug)]
pub struct ValidatedRegisterExtension {
    pub wasm: Wasm,
    pub extension_canister_id: CanisterId,
    pub spec: ExtensionSpec,
    pub init: ValidatedExtensionInit,
}

impl ValidatedRegisterExtension {
    pub async fn execute(self, governance: &Governance) -> Result<(), GovernanceError> {
        let main = async || {
            let context = governance.treasury_manager_deposit_context().await?;

            let ValidatedRegisterExtension {
                spec,
                init,
                extension_canister_id,
                wasm,
            } = self;

            governance
                .register_extension_with_root(extension_canister_id)
                .await?;

            // Before granting any SNS capabilities to the extension, we must ensure that old code
            // could not have snuck in between proposal (re-)validation and the SNS assuming control.
            governance
                .ensure_no_code_is_installed(extension_canister_id)
                .await?;

            // This needs to happen before the canister code is installed.
            let init_blob = match init {
                ValidatedExtensionInit::TreasuryManager(ValidatedDepositOperationArg {
                    treasury_allocation_sns_e8s,
                    treasury_allocation_icp_e8s,
                    original,
                }) => {
                    let init_blob =
                        construct_treasury_manager_init_payload(context.clone(), original)
                            .map_err(|err| {
                                GovernanceError::new_with_message(
                                    ErrorType::InvalidProposal,
                                    format!(
                                        "Error constructing TreasuryManagerInit payload: {err}"
                                    ),
                                )
                            })?;

                    governance
                        .approve_treasury_manager(
                            extension_canister_id,
                            treasury_allocation_sns_e8s,
                            treasury_allocation_icp_e8s,
                        )
                        .await?;

                    init_blob
                }
            };

            governance
                .upgrade_non_root_canister(
                    extension_canister_id,
                    wasm,
                    init_blob,
                    CanisterInstallMode::Install,
                )
                .await?;

            let extension_name = spec.name.clone();
            cache_registered_extension(extension_canister_id, spec);

            // Inject fault, i.e. when there is a test that tries to force us to
            // explode, return Err.
            if cfg!(any(test, feature = "test")) && extension_name.contains("Explode in Test") {
                return Err(GovernanceError::new_with_message(
                    ErrorType::External,
                    "Something has gone terribly terribly wrong. Actually, this is just \
                     an injected fault. This would only appear in tests."
                        .to_string(),
                ));
            }

            Ok(())
        };

        let main_result = main().await;

        // Try to clean up if main_result is Err. Cleaning up consists of
        // calling the Root canister's clean_up_failed_register_extension method.
        if main_result.is_err() {
            governance
                .clean_up_failed_register_extension(self.extension_canister_id)
                .await;
        }

        main_result
    }
}

#[derive(Debug)]
pub struct ValidatedExecuteExtensionOperation {
    pub extension_canister_id: CanisterId,
    pub operation_name: String,
    pub arg: ValidatedOperationArg,
}

impl ValidatedExecuteExtensionOperation {
    pub async fn execute(self, governance: &Governance) -> Result<(), GovernanceError> {
        let Self {
            operation_name: _,
            extension_canister_id,
            arg,
        } = self;

        match arg {
            ValidatedOperationArg::TreasuryManagerDeposit(arg) => {
                execute_treasury_manager_deposit(governance, extension_canister_id, arg).await
            }
            ValidatedOperationArg::TreasuryManagerWithdraw(arg) => {
                execute_treasury_manager_withdraw(governance, extension_canister_id, arg).await
            }
        }
    }
}

impl Governance {
    /// Returns the ICRC-1 subaccount for the SNS treasury
    fn sns_treasury_subaccount(&self) -> Option<[u8; 32]> {
        // See ic_sns_init::distributions::FractionalDeveloperVotingPower.insert_treasury_accounts
        Some(compute_distribution_subaccount_bytes(
            self.env.canister_id().get(),
            TREASURY_SUBACCOUNT_NONCE,
        ))
    }

    /// Returns the ICRC-1 subaccounts for the ICP treasury.
    fn icp_treasury_subaccount(&self) -> Option<[u8; 32]> {
        None
    }
    async fn treasury_manager_deposit_context(
        &self,
    ) -> Result<TreasuryManagerDepositContext, GovernanceError> {
        let sns_ledger_canister_id = self.ledger.canister_id();

        let sns_token_symbol = get_sns_token_symbol(&*self.env, sns_ledger_canister_id).await?;

        Ok(TreasuryManagerDepositContext {
            sns_token_symbol,
            sns_ledger_canister_id,
            sns_root_canister_id: self.proto.root_canister_id_or_panic(),
            sns_governance_canister_id: self.env.canister_id(),
            sns_ledger_transaction_fee_e8s: self.transaction_fee_e8s_or_panic(),
            icp_ledger_canister_id: self.nns_ledger.canister_id(),
        })
    }
    async fn register_extension_with_root(
        &self,
        extension_canister_id: CanisterId,
    ) -> Result<(), GovernanceError> {
        let payload = Encode!(&RegisterExtensionRequest {
            canister_id: Some(extension_canister_id.get()),
        })
        .map_err(|err| {
            GovernanceError::new_with_message(
                ErrorType::InvalidPrincipal,
                format!("Could not encode RegisterExtensionRequest: {err:?}"),
            )
        })?;

        let reply = self
            .env
            .call_canister(
                self.proto.root_canister_id_or_panic(),
                "register_extension",
                payload,
            )
            .await
            .map_err(|err| {
                GovernanceError::new_with_message(
                    ErrorType::External,
                    format!("Canister method call failed: {err:?}"),
                )
            })?;

        let RegisterExtensionResponse { result } = Decode!(&reply, RegisterExtensionResponse)
            .map_err(|err| {
                GovernanceError::new_with_message(
                    ErrorType::External,
                    format!("Could not decode RegisterExtensionResponse: {err:?}"),
                )
            })?;

        if let Some(register_extension_response::Result::Err(CanisterCallError {
            code,
            description,
        })) = result
        {
            let code = if let Some(code) = code {
                code.to_string()
            } else {
                "<no code>".to_string()
            };
            return Err(GovernanceError::new_with_message(
                ErrorType::External,
                format!("Root.register_extension failed with code {code}: {description}"),
            ));
        }

        log!(
            INFO,
            "Root.register_extension succeeded for canister {}",
            extension_canister_id.get()
        );

        Ok(())
    }

    // Currently, this just consists of calling Root's
    // clean_up_failed_register_extension method, but maybe, in the future, this
    // would do more (locally, in this SNS Governance canister).
    async fn clean_up_failed_register_extension(&self, extension_canister_id: CanisterId) {
        let main = async || -> Result<(), String> {
            let request = Encode!(&CleanUpFailedRegisterExtensionRequest {
                canister_id: Some(extension_canister_id.get()),
            })
            .map_err(|err| {
                format!("Could not encode Root.clean_up_failed_register_extension request: {err:?}")
            })?;

            // Call clean_up_failed_register_extension method of the SNS Root canister.
            let reply = self
                .env
                .call_canister(
                    self.proto.root_canister_id_or_panic(),
                    "clean_up_failed_register_extension",
                    request,
                )
                .await
                .map_err(|err| {
                    format!("Failed to call Root.clean_up_failed_register_extension: {err:?}")
                })?;

            // Make sure reply does not indicate any problems.
            let CleanUpFailedRegisterExtensionResponse { result } =
                Decode!(&reply, CleanUpFailedRegisterExtensionResponse).map_err(|err| {
                    format!(
                        "Failed to decode Root.clean_up_failed_register_extension response: {err:?}"
                    )
                })?;
            if let Some(clean_up_failed_register_extension_response::Result::Err(
                CanisterCallError { code, description },
            )) = result
            {
                let code = if let Some(code) = code {
                    code.to_string()
                } else {
                    "<no code>".to_string()
                };

                return Err(format!(
                    "Root.clean_up_failed_register_extension failed with code {code}: {description}"
                ));
            }

            Ok(())
        };

        if let Err(err) = main().await {
            log!(ERROR, "{err}");
            return;
        }

        log!(
            INFO,
            "Root.clean_up_failed_register_extension succeeded for canister {}",
            extension_canister_id.get()
        );
    }

    async fn approve_treasury_manager(
        &self,
        treasury_manager_canister_id: CanisterId,
        sns_amount_e8s: u64,
        icp_amount_e8s: u64,
    ) -> Result<(), GovernanceError> {
        let to = Account {
            owner: treasury_manager_canister_id.get().0,
            subaccount: None,
        };

        let expiry_time_sec = self.env.now().saturating_add(ONE_HOUR_SECONDS);
        let expiry_time_nsec = expiry_time_sec.saturating_mul(NANO_SECONDS_PER_SECOND);

        // If expected_allowance is None, the ledger *blindly* overwrites any existing
        // allowance (even if non-zero). Therefore, there is no risk of double spending.

        self.ledger
            .icrc2_approve(
                to,
                sns_amount_e8s,
                Some(expiry_time_nsec),
                self.transaction_fee_e8s_or_panic(),
                self.sns_treasury_subaccount(),
                None,
            )
            .await
            .map(|_| ())
            .map_err(|e| {
                GovernanceError::new_with_message(
                    ErrorType::External,
                    format!("Error making SNS Token treasury transfer: {e}"),
                )
            })?;

        self.nns_ledger
            .icrc2_approve(
                to,
                icp_amount_e8s,
                Some(expiry_time_nsec),
                icp_ledger::DEFAULT_TRANSFER_FEE.get_e8s(),
                self.icp_treasury_subaccount(),
                None,
            )
            .await
            .map(|_| ())
            .map_err(|e| {
                GovernanceError::new_with_message(
                    ErrorType::External,
                    format!("Error making ICP Token treasury transfer: {e}"),
                )
            })?;

        Ok(())
    }

    async fn ensure_no_code_is_installed(
        &self,
        extension_canister_id: CanisterId,
    ) -> Result<(), GovernanceError> {
        // Ideally, we would ensure that the extension canister is not running any code by calling
        // uninstall_code. However, this would also wipe out the Wasm chunk store, so a subsequent
        // call to install_code would fail.
        //
        // See https://internetcomputer.org/docs/references/ic-interface-spec#ic-uninstall_code
        //
        // Instead, we just check that the canister doesn't have any Wasm module installed up until
        // this point.
        if let Some(module_hash) = canister_module_hash(&*self.env, extension_canister_id).await? {
            return Err(GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                format!(
                    "Extension canister {} already has code installed (module hash {}). \
                     Treating this as an attack.",
                    extension_canister_id,
                    hex::encode(module_hash),
                ),
            ));
        };

        Ok(())
    }
}

pub mod treasury_manager {
    use candid::Nat;
    use sns_treasury_manager::{Account, Allowance, Asset};

    use crate::pb::v1::{Precise, PreciseMap, precise};

    pub fn construct_deposit_allowances(
        arg: Precise,
        sns_token: Asset,
        icp_token: Asset,
        treasury_sns_account: Account,
        treasury_icp_account: Account,
    ) -> Result<Vec<Allowance>, String> {
        const PREFIX: &str = "Cannot parse ExtensionInit as TreasuryManagerInit: ";

        let Precise {
            value: Some(precise::Value::Map(PreciseMap { mut map })),
        } = arg
        else {
            return Err(format!("{PREFIX}Top-level type must be PreciseMap."));
        };

        if map.len() != 2 {
            return Err(format!(
                "{PREFIX}Top-level type must be PreciseMap with exactly 2 entries."
            ));
        }

        let mut token_amount_e8s = |field_name: &str| {
            map.remove(field_name)
                .and_then(|Precise { value }| {
                    if let Some(precise::Value::Nat(amount_e8s)) = value {
                        Some(amount_e8s)
                    } else {
                        None
                    }
                })
                .ok_or_else(|| format!("{PREFIX}{field_name} must contain a precise value."))
        };

        let sns_token_amount_e8s = token_amount_e8s("treasury_allocation_sns_e8s")?;
        let icp_token_amount_e8s = token_amount_e8s("treasury_allocation_icp_e8s")?;

        let allowances = vec![
            Allowance {
                amount_decimals: Nat::from(sns_token_amount_e8s),
                asset: sns_token,
                owner_account: treasury_sns_account,
            },
            Allowance {
                amount_decimals: Nat::from(icp_token_amount_e8s),
                asset: icp_token,
                owner_account: treasury_icp_account,
            },
        ];
        Ok(allowances)
    }
}

/// Validates an extension WASM against the global ALLOWED_EXTENSIONS.
pub fn validate_extension_wasm(wasm_module_hash: &[u8]) -> Result<ExtensionSpec, String> {
    // Validate the hash length
    if wasm_module_hash.len() != 32 {
        return Err(format!(
            "Invalid wasm module hash length: expected 32 bytes, got {}",
            wasm_module_hash.len()
        ));
    }

    validate_extension_wasm_with_allowed(
        wasm_module_hash,
        #[cfg(any(test, feature = "test"))]
        &TEST_HASH_TO_EXTENSION_SPEC,
        #[cfg(not(any(test, feature = "test")))]
        &ALLOWED_EXTENSIONS.with_borrow(|map| map.clone()),
    )
}

/// Validates an extension WASM against a provided set of allowed extensions.
fn validate_extension_wasm_with_allowed(
    wasm_module_hash: &[u8],
    allowed_extensions: &BTreeMap<[u8; 32], ExtensionSpec>,
) -> Result<ExtensionSpec, String> {
    // Should never fail, b/c we validate the length before calling this.
    let hash_array: [u8; 32] = wasm_module_hash.try_into().map_err(|_| {
        format!(
            "Invalid wasm module hash length: expected 32 bytes, got {}",
            wasm_module_hash.len()
        )
    })?;

    if let Some(spec) = allowed_extensions.get(&hash_array) {
        return Ok(spec.clone());
    }

    Err(format!(
        "Wasm module with hash {:?} is not allowed as an extension.",
        hex::encode(wasm_module_hash)
    ))
}

async fn list_extensions(
    env: &dyn Environment,
    root_canister_id: CanisterId,
) -> Result<Vec<PrincipalId>, GovernanceError> {
    let list_extensions_arg = Encode!(&ListSnsCanistersRequest {}).unwrap();

    let ListSnsCanistersResponse { extensions, .. } = env
        .call_canister(root_canister_id, "list_sns_canisters", list_extensions_arg)
        .await
        .map_err(|err| {
            GovernanceError::new_with_message(
                ErrorType::External,
                format!("Canister method call Root.list_sns_canisters failed: {err:?}"),
            )
        })
        .and_then(|blob| {
            Decode!(&blob, ListSnsCanistersResponse).map_err(|err| {
                GovernanceError::new_with_message(
                    ErrorType::External,
                    format!("Error decoding Root.list_sns_canisters response: {err:?}"),
                )
            })
        })?;

    let extensions = extensions
        .map(|extensions| extensions.extension_canister_ids)
        .unwrap_or_default();

    Ok(extensions)
}

async fn canister_module_hash_impl(
    env: &dyn Environment,
    canister_id: CanisterId,
) -> Result<Option<Vec<u8>>, String> {
    let canister_info_arg = Encode!(&CanisterInfoRequest::new(canister_id, Some(1),))
        .map_err(|err| format!("Error encoding canister_info request.\n{err}"))?;

    let response = env
        .call_canister(CanisterId::ic_00(), "canister_info", canister_info_arg)
        .await
        .map_err(|err: (Option<i32>, String)| {
            format!("Canister method call IC00.canister_info failed: {err:?}")
        })
        .and_then(|blob| {
            Decode!(&blob, CanisterInfoResponse)
                .map_err(|err| format!("Error decoding IC00.canister_info response:\n{err}"))
        })?;

    Ok(response.module_hash())
}

async fn canister_module_hash(
    env: &dyn Environment,
    canister_id: CanisterId,
) -> Result<Option<Vec<u8>>, GovernanceError> {
    canister_module_hash_impl(env, canister_id)
        .await
        .map_err(|err| GovernanceError::new_with_message(ErrorType::External, err))
}

/// Returns the ICRC-1 subaccounts for the SNS treasury and ICP treasury.
fn treasury_subaccounts(
    context: TreasuryManagerDepositContext,
) -> (Option<[u8; 32]>, Option<[u8; 32]>) {
    // See ic_sns_init::distributions::FractionalDeveloperVotingPower.insert_treasury_accounts
    let sns_governance_principal_id = context.sns_governance_canister_id.get();
    let treasury_sns_subaccount = Some(compute_distribution_subaccount_bytes(
        sns_governance_principal_id,
        TREASURY_SUBACCOUNT_NONCE,
    ));
    let treasury_icp_subaccount = None;
    (treasury_sns_subaccount, treasury_icp_subaccount)
}

fn construct_treasury_manager_deposit_allowances(
    context: TreasuryManagerDepositContext,
    value: Precise,
) -> Result<Vec<Allowance>, String> {
    // See ic_sns_init::distributions::FractionalDeveloperVotingPower.insert_treasury_accounts
    let (treasury_sns_subaccount, treasury_icp_subaccount) = treasury_subaccounts(context.clone());

    let allowances = treasury_manager::construct_deposit_allowances(
        value,
        Asset::Token {
            symbol: context.sns_token_symbol,
            ledger_canister_id: context.sns_ledger_canister_id.get().0,
            ledger_fee_decimals: Nat::from(context.sns_ledger_transaction_fee_e8s),
        },
        Asset::Token {
            symbol: "ICP".to_string(),
            ledger_canister_id: context.icp_ledger_canister_id.get().0,
            ledger_fee_decimals: Nat::from(icp_ledger::DEFAULT_TRANSFER_FEE.get_e8s()),
        },
        sns_treasury_manager::Account {
            owner: context.sns_governance_canister_id.get().0,
            subaccount: treasury_sns_subaccount,
        },
        sns_treasury_manager::Account {
            owner: context.sns_governance_canister_id.get().0,
            subaccount: treasury_icp_subaccount,
        },
    )
    .map_err(|err| format!("Error extracting initial allowances: {err}"))?;

    Ok(allowances)
}

/// Returns `arg_blob` in the Ok result.
fn construct_treasury_manager_init_payload(
    context: TreasuryManagerDepositContext,
    value: Precise,
) -> Result<Vec<u8>, String> {
    let allowances = construct_treasury_manager_deposit_allowances(context, value)?;

    let arg = TreasuryManagerArg::Init(TreasuryManagerInit { allowances });
    candid::encode_one(&arg).map_err(|err| format!("Error encoding TreasuryManagerArg: {err}"))
}

fn construct_treasury_manager_upgrade_payload() -> Result<Vec<u8>, String> {
    let arg = TreasuryManagerArg::Upgrade(TreasuryManagerUpgrade {});

    candid::encode_one(&arg).map_err(|err| format!("Error encoding TreasuryManagerArg: {err}"))
}

/// Returns `arg_blob` in the Ok result.
fn construct_treasury_manager_deposit_payload(
    context: TreasuryManagerDepositContext,
    value: Precise,
) -> Result<Vec<u8>, String> {
    let allowances = construct_treasury_manager_deposit_allowances(context, value)?;

    let arg = DepositRequest { allowances };
    let arg =
        candid::encode_one(&arg).map_err(|err| format!("Error encoding DepositRequest: {err}"))?;

    Ok(arg)
}

/// Returns `arg_blob` in the Ok result.
fn construct_treasury_manager_withdraw_payload(_value: Precise) -> Result<Vec<u8>, String> {
    let arg = WithdrawRequest {
        withdraw_accounts: None,
    };
    let arg =
        candid::encode_one(&arg).map_err(|err| format!("Error encoding WithdrawRequest: {err}"))?;

    Ok(arg)
}

pub async fn validate_register_extension(
    governance: &Governance,
    register_extension: RegisterExtension,
) -> Result<ValidatedRegisterExtension, String> {
    let RegisterExtension {
        chunked_canister_wasm,
        extension_init,
    } = register_extension;

    // Phase I. Validate all local properties.
    let Some(ChunkedCanisterWasm {
        wasm_module_hash,
        store_canister_id,
        chunk_hashes_list,
    }) = chunked_canister_wasm
    else {
        return Err("chunked_canister_wasm is required".to_string());
    };

    let Some(store_canister_id) = store_canister_id else {
        return Err("chunked_canister_wasm.store_canister_id is required".to_string());
    };

    let store_canister_id = CanisterId::try_from_principal_id(store_canister_id)
        .map_err(|err| format!("Invalid store_canister_id: {err}"))?;

    // Use the store canister to install the extension itself.
    let extension_canister_id = store_canister_id;

    let spec = validate_extension_wasm(&wasm_module_hash)
        .map_err(|err| format!("Invalid extension wasm: {err}"))?;

    let wasm = Wasm::Chunked {
        wasm_module_hash,
        store_canister_id,
        chunk_hashes_list,
    };

    let Some(init) = extension_init else {
        return Err("RegisterExtension.extension_init is required".to_string());
    };

    let init = spec
        .validate_init_arg(governance, init)
        .await
        .map_err(|err| format!("Invalid init argument: {err}"))?;

    if spec.supports_extension_type(ExtensionType::TreasuryManager) {
        // We validate that the canister is running on a fiduciary subnet.
        let subnet_type =
            get_subnet_type_canister_is_running_on(&*governance.env, extension_canister_id).await;

        if subnet_type != Some("fiduciary".to_string()) {
            return Err(
                "TreasuryManager extensions must be installed on a fiduciary subnet.".to_string(),
            );
        }
    }

    // Check that the extension canister does not have any code installed yet.
    //
    // This will need to be checked again after the SNS assumes control over the extension.
    if let Some(module_hash) =
        canister_module_hash_impl(&*governance.env, extension_canister_id).await?
    {
        return Err(format!(
            "Extension canister {} already has code installed (module hash {}).",
            extension_canister_id,
            hex::encode(module_hash),
        ));
    };

    Ok(ValidatedRegisterExtension {
        wasm,
        extension_canister_id,
        spec,
        init,
    })
}

#[derive(Clone, Debug, PartialEq)]
pub enum ValidatedExtensionUpgradeArg {
    TreasuryManager, // Currently has no upgrade args, but can be supported later
                     // Future: other extension type upgrade arguments would go here
}

#[derive(Debug, PartialEq)]
pub struct ValidatedUpgradeExtension {
    pub extension_canister_id: CanisterId,
    pub wasm: Wasm,
    pub spec: ExtensionSpec,
    pub current_version: ExtensionVersion,
    pub new_version: ExtensionVersion,
    pub upgrade_arg: ValidatedExtensionUpgradeArg,
}

impl ValidatedUpgradeExtension {
    pub async fn execute(self, governance: &Governance) -> Result<(), GovernanceError> {
        let ValidatedUpgradeExtension {
            extension_canister_id,
            wasm,
            upgrade_arg,
            spec,
            ..
        } = self;

        let arg_bytes = match &upgrade_arg {
            ValidatedExtensionUpgradeArg::TreasuryManager => {
                construct_treasury_manager_upgrade_payload().map_err(|err| {
                    // This should not be possible, and it's not clear that it falls in another category of error.
                    GovernanceError::new_with_message(ErrorType::Unspecified, err)
                })?
            }
        };

        governance
            .upgrade_non_root_canister(
                extension_canister_id,
                wasm,
                arg_bytes,
                CanisterInstallMode::Upgrade,
            )
            .await?;

        // Update the extension cache with the new spec
        cache_registered_extension(extension_canister_id, spec);

        Ok(())
    }
}

pub async fn validate_upgrade_extension(
    governance: &Governance,
    upgrade_extension: pb::UpgradeExtension,
) -> Result<ValidatedUpgradeExtension, String> {
    let pb::UpgradeExtension {
        extension_canister_id,
        canister_upgrade_arg,
        wasm,
    } = &upgrade_extension;

    // Validate extension canister ID
    let Some(extension_canister_id) = extension_canister_id else {
        return Err("extension_canister_id is required".to_string());
    };

    let extension_canister_id = CanisterId::try_from_principal_id(*extension_canister_id)
        .map_err(|err| format!("Invalid extension_canister_id: {err}"))?;

    // Validate that the extension is registered
    let current_extension = get_registered_extension_from_cache(extension_canister_id)
        .ok_or_else(|| format!("Extension canister {extension_canister_id} is not registered"))?;

    // Extract and validate WASM (either direct bytes or chunked)
    let Some(pb_wasm) = wasm else {
        return Err("wasm field is required".to_string());
    };

    let wasm =
        Wasm::try_from(pb_wasm).map_err(|err| format!("Invalid WASM specification: {err}"))?;

    // Get the WASM hash for validation against ALLOWED_EXTENSIONS
    let wasm_module_hash = wasm.sha256sum();

    // Validate the new WASM against ALLOWED_EXTENSIONS
    let new_spec = validate_extension_wasm(&wasm_module_hash)
        .map_err(|err| format!("Invalid extension wasm: {err}"))?;

    // Validate the typed upgrade argument using the extension spec first
    let upgrade_arg = new_spec
        .validate_upgrade_arg(governance, canister_upgrade_arg.clone())
        .await
        .map_err(|err| format!("Invalid upgrade argument: {err}"))?;

    // Note: upgrade_arg is validated and will be serialized during execution
    // No need to generate bytes here since WASM validation was removed

    // Check that the new extension has the same name as the current one
    if new_spec.name != current_extension.name {
        return Err(format!(
            "Extension name mismatch: current extension is '{}', new extension is '{}'",
            current_extension.name, new_spec.name
        ));
    }

    // Check that the new version is higher than the current version
    if new_spec.version <= current_extension.version {
        return Err(format!(
            "New extension version {} must be higher than current version {}",
            new_spec.version.0, current_extension.version.0
        ));
    }

    // Check that extension types match
    if new_spec.extension_type != current_extension.extension_type {
        return Err(format!(
            "Extension type mismatch: current is {:?}, new is {:?}",
            current_extension.extension_type, new_spec.extension_type
        ));
    }

    // Clone the new version before moving new_spec
    let new_version = new_spec.version.clone();

    Ok(ValidatedUpgradeExtension {
        extension_canister_id,
        wasm,
        spec: new_spec,
        current_version: current_extension.version,
        new_version,
        upgrade_arg,
    })
}

// Copied from Registry canister, to avoid import for just one type.
#[derive(candid::CandidType, candid::Deserialize, Clone, PartialEq)]
pub struct GetSubnetForCanisterRequest {
    pub principal: ::core::option::Option<::ic_base_types::PrincipalId>,
}

#[derive(candid::CandidType, candid::Deserialize, Clone, PartialEq)]
pub struct SubnetForCanister {
    pub subnet_id: ::core::option::Option<::ic_base_types::PrincipalId>,
}

async fn get_subnet_for_canister(
    env: &dyn Environment,
    canister_id: CanisterId,
) -> Result<SubnetId, String> {
    let request = GetSubnetForCanisterRequest {
        principal: Some(canister_id.get()),
    };

    let payload = Encode!(&request)
        .map_err(|e| format!("Failed to encode GetSubnetForCanisterRequest: {e}"))?;

    let response_blob = env
        .call_canister(REGISTRY_CANISTER_ID, "get_subnet_for_canister", payload)
        .await
        .map_err(|(code, err)| {
            format!("Registry.get_subnet_for_canister failed with code {code:?}: {err}")
        })?;

    let response = Decode!(&response_blob, Result<SubnetForCanister, String>)
        .map_err(|e| format!("Failed to decode get_subnet_for_canister response: {e}"))?
        .map_err(|e| format!("Registry.get_subnet_for_canister returned error: {e}"))?;

    let subnet_id = response
        .subnet_id
        .ok_or("Registry response missing subnet_id".to_string())?;

    Ok(SubnetId::from(subnet_id))
}

// Type from CMC (copied to avoid unnecessary import)
#[derive(Clone, Eq, PartialEq, Debug, Default, CandidType, Deserialize, Serialize)]
pub struct SubnetTypesToSubnetsResponse {
    pub data: Vec<(String, Vec<SubnetId>)>,
}

async fn get_subnet_types_to_subnets(
    env: &dyn Environment,
) -> Result<SubnetTypesToSubnetsResponse, String> {
    let payload = Encode!(&()).map_err(|e| format!("Failed to encode empty request: {e}"))?;

    let response_blob = env
        .call_canister(
            CYCLES_MINTING_CANISTER_ID,
            "get_subnet_types_to_subnets",
            payload,
        )
        .await
        .map_err(|(code, err)| {
            format!("CMC.get_subnet_types_to_subnets failed with code {code:?}: {err}")
        })?;

    let response = Decode!(&response_blob, SubnetTypesToSubnetsResponse)
        .map_err(|e| format!("Failed to decode get_subnet_types_to_subnets response: {e}"))?;

    Ok(response)
}

async fn get_subnet_type_canister_is_running_on(
    env: &dyn Environment,
    canister_id: CanisterId,
) -> Option<String> {
    // Get the subnet ID for the current canister
    let subnet_id = match get_subnet_for_canister(env, canister_id).await {
        Ok(id) => id,
        Err(_) => return None,
    };

    // Get the mapping of subnet types to subnets
    let subnet_types_response = match get_subnet_types_to_subnets(env).await {
        Ok(response) => response,
        Err(_) => return None,
    };

    // Look through the mapping to find which subnet type contains our subnet ID
    for (subnet_type, subnet_ids) in subnet_types_response.data {
        if subnet_ids.contains(&subnet_id) {
            return Some(subnet_type);
        }
    }

    None
}

async fn get_extension_spec_and_update_cache(
    env: &dyn Environment,
    root_canister_id: CanisterId,
    extension_canister_id: CanisterId,
) -> Result<ExtensionSpec, GovernanceError> {
    let registered_extensions = list_extensions(env, root_canister_id).await?;

    if !registered_extensions.contains(&extension_canister_id.get()) {
        return Err(GovernanceError::new_with_message(
            ErrorType::NotFound,
            format!("Extension canister {extension_canister_id} is not registered with the SNS."),
        ));
    }

    let Some(wasm_module_hash) = canister_module_hash(env, extension_canister_id).await? else {
        return Err(GovernanceError::new_with_message(
            ErrorType::InvalidProposal,
            format!(
                "Extension canister {extension_canister_id} does not have a Wasm module installed."
            ),
        ));
    };

    let result = validate_extension_wasm(&wasm_module_hash).map_err(|err| {
        GovernanceError::new_with_message(
            ErrorType::InvalidProposal,
            format!(
                "Extension canister {extension_canister_id} does not have an extension spec \
                    despite being registered with Root: {err}",
            ),
        )
    });

    if result.is_ok() {
        cache_registered_extension(extension_canister_id, result.as_ref().cloned().unwrap());
    }

    result
}

/// Validates that this is a supported extension operation and runs any validation for that
/// operation.
pub(crate) async fn validate_execute_extension_operation(
    governance: &crate::governance::Governance,
    operation: ExecuteExtensionOperation,
) -> Result<ValidatedExecuteExtensionOperation, GovernanceError> {
    // Extract and validate basic fields
    let ExecuteExtensionOperation {
        extension_canister_id,
        operation_name,
        operation_arg,
    } = operation;

    let Some(extension_canister_id) = extension_canister_id else {
        return Err(GovernanceError::new_with_message(
            ErrorType::InvalidProposal,
            "extension_canister_id is required.",
        ));
    };

    let extension_canister_id =
        CanisterId::try_from_principal_id(extension_canister_id).map_err(|err| {
            GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                format!("Cannot interpret extension_canister_id as canister ID: {err}"),
            )
        })?;

    let Some(operation_name) = operation_name else {
        return Err(GovernanceError::new_with_message(
            ErrorType::InvalidProposal,
            "operation_name is required.",
        ));
    };

    let Some(operation_arg) = operation_arg else {
        return Err(GovernanceError::new_with_message(
            ErrorType::InvalidProposal,
            "operation_arg is required.",
        ));
    };

    let extension_spec = get_extension_spec_and_update_cache(
        &*governance.env,
        governance.proto.root_canister_id_or_panic(),
        extension_canister_id,
    )
    .await?;

    // Currently only support extensions that implement TreasuryManager
    if !extension_spec.supports_extension_type(ExtensionType::TreasuryManager) {
        return Err(GovernanceError::new_with_message(
            ErrorType::InvalidProposal,
            "Only extensions implementing TreasuryManager are currently supported.",
        ));
    }

    let Some(operation_spec) = extension_spec.get_operation(&operation_name) else {
        return Err(GovernanceError::new_with_message(
            ErrorType::InvalidProposal,
            format!(
                "Extension canister {extension_canister_id} does not have an operation named {operation_name}"
            ),
        ));
    };

    let validated_arg = operation_spec
        .validate_operation_arg(governance, operation_arg)
        .await
        .map_err(|err| {
            GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                format!(
                    "Extension canister {extension_canister_id} operation {operation_name} validation failed: {err}"
                ),
            )
        })?;

    Ok(ValidatedExecuteExtensionOperation {
        extension_canister_id,
        operation_name,
        arg: validated_arg,
    })
}

/// Execute a treasury manager deposit operation
async fn execute_treasury_manager_deposit(
    governance: &Governance,
    extension_canister_id: CanisterId,
    arg: ValidatedDepositOperationArg,
) -> Result<(), GovernanceError> {
    let ValidatedDepositOperationArg {
        treasury_allocation_sns_e8s,
        treasury_allocation_icp_e8s,
        original,
    } = arg;

    let context = governance.treasury_manager_deposit_context().await?;
    let arg_blob =
        construct_treasury_manager_deposit_payload(context, original).map_err(|err| {
            GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                format!("Failed to construct treasury manager deposit payload: {err}"),
            )
        })?;

    // 1. Transfer funds from treasury to treasury manager
    governance
        .approve_treasury_manager(
            extension_canister_id,
            treasury_allocation_sns_e8s,
            treasury_allocation_icp_e8s,
        )
        .await?;

    // 2. Call deposit on treasury manager
    let balances = governance
        .env
        .call_canister(extension_canister_id, "deposit", arg_blob)
        .await
        .map_err(|(code, err)| {
            GovernanceError::new_with_message(
                ErrorType::External,
                format!(
                    "Canister method call {extension_canister_id}.deposit failed with code {code:?}: {err}"
                ),
            )
        })
        .and_then(|blob| {
            Decode!(&blob, sns_treasury_manager::TreasuryManagerResult).map_err(|err| {
                GovernanceError::new_with_message(
                    ErrorType::External,
                    format!("Error decoding TreasuryManager.deposit response: {err:?}"),
                )
            })
        })?
        .map_err(|err| {
            GovernanceError::new_with_message(
                ErrorType::External,
                format!("TreasuryManager.deposit failed: {err:?}"),
            )
        })?;

    log!(
        INFO,
        "TreasuryManager.deposit succeeded with response: {:?}",
        balances
    );

    Ok(())
}

/// Execute a treasury manager withdraw operation
async fn execute_treasury_manager_withdraw(
    governance: &Governance,
    extension_canister_id: CanisterId,
    arg: ValidatedWithdrawOperationArg,
) -> Result<(), GovernanceError> {
    let arg_blob = construct_treasury_manager_withdraw_payload(arg.original).map_err(|err| {
        GovernanceError::new_with_message(
            ErrorType::PreconditionFailed,
            format!("Failed to construct treasury manager withdraw payload: {err}"),
        )
    })?;

    let balances = governance
        .env
        .call_canister(extension_canister_id, "withdraw", arg_blob)
        .await
        .map_err(|(code, err)| {
            GovernanceError::new_with_message(
                ErrorType::External,
                format!(
                    "Canister method call {extension_canister_id}.withdraw failed with code {code:?}: {err}"
                ),
            )
        })
        .and_then(|blob| {
            Decode!(&blob, sns_treasury_manager::TreasuryManagerResult).map_err(|err| {
                GovernanceError::new_with_message(
                    ErrorType::External,
                    format!(
                        "Error decoding TreasuryManager.withdraw response: {err:?}"
                    ),
                )
            })
        })?
        .map_err(|err| {
            GovernanceError::new_with_message(
                ErrorType::External,
                format!("TreasuryManager.withdraw failed: {err:?}"),
            )
        })?;

    log!(
        INFO,
        "TreasuryManager.withdraw succeeded with response: {:?}",
        balances
    );

    Ok(())
}

/// Validated deposit operation arguments
#[derive(Debug, Clone)]
pub struct ValidatedDepositOperationArg {
    /// Amount of SNS tokens to allocate from treasury
    pub treasury_allocation_sns_e8s: u64,
    /// Amount of ICP tokens to allocate from treasury
    pub treasury_allocation_icp_e8s: u64,
    /// Original Precise value with all fields
    pub original: Precise,
}

impl TryFrom<Option<Precise>> for ValidatedDepositOperationArg {
    type Error = String;

    fn try_from(value: Option<Precise>) -> Result<Self, Self::Error> {
        let Some(original) = value else {
            return Err("Deposit operation arguments must be provided".to_string());
        };

        let map = match &original.value {
            Some(precise::Value::Map(PreciseMap { map })) => map,
            _ => return Err("Deposit operation arguments must be a PreciseMap".to_string()),
        };

        let treasury_allocation_sns_e8s = map
            .get("treasury_allocation_sns_e8s")
            .and_then(|p| match &p.value {
                Some(precise::Value::Nat(n)) => Some(*n),
                _ => None,
            })
            .ok_or_else(|| "treasury_allocation_sns_e8s must be a Nat value".to_string())?;

        let treasury_allocation_icp_e8s = map
            .get("treasury_allocation_icp_e8s")
            .and_then(|p| match &p.value {
                Some(precise::Value::Nat(n)) => Some(*n),
                _ => None,
            })
            .ok_or_else(|| "treasury_allocation_icp_e8s must be a Nat value".to_string())?;

        Ok(Self {
            treasury_allocation_sns_e8s,
            treasury_allocation_icp_e8s,
            original,
        })
    }
}

impl RenderablePayload for ValidatedDepositOperationArg {
    fn render_for_proposal(&self) -> String {
        let raw_payload = self.original.render_for_proposal();
        format!(
            r#"### Treasury Deposit

**SNS Tokens:** {} e8s
**ICP Tokens:** {} e8s

{raw_payload}"#,
            self.treasury_allocation_sns_e8s, self.treasury_allocation_icp_e8s
        )
    }
}

/// Validated withdraw operation arguments
#[derive(Debug, Clone)]
pub struct ValidatedWithdrawOperationArg {
    /// Original operation arguments
    original: Precise,
}

impl TryFrom<Option<Precise>> for ValidatedWithdrawOperationArg {
    type Error = String;

    fn try_from(value: Option<Precise>) -> Result<Self, Self::Error> {
        let original = value.unwrap_or_default();

        // For now, only allow empty arguments
        // This ensures withdraw operations don't accept parameters yet
        if original.value.is_some() {
            return Err("Withdraw operation does not accept arguments at this time".to_string());
        }

        Ok(Self { original })
    }
}

impl RenderablePayload for ValidatedWithdrawOperationArg {
    fn render_for_proposal(&self) -> String {
        // Since we're not parsing the fields yet, just show the raw operation
        let raw_payload = self.original.render_for_proposal();

        format!(
            r#"### Treasury Withdrawal

{raw_payload}"#,
        )
    }
}

pub async fn get_sns_token_symbol(
    env: &dyn Environment,
    ledger_canister_id: CanisterId,
) -> Result<String, GovernanceError> {
    let arg = Encode!(&()).unwrap();
    let symbol = env
        .call_canister(ledger_canister_id, "icrc1_symbol", arg)
        .await
        .map_err(|(code, err)| {
            GovernanceError::new_with_message(
                ErrorType::External,
                format!(
                    "Canister method call {ledger_canister_id}.deposit failed with code {code:?}: {err}"
                ),
            )
        })
        .map(|blob| {
            Decode!(&blob, String).map_err(|err| {
                GovernanceError::new_with_message(
                    ErrorType::External,
                    format!(
                        "Error decoding {ledger_canister_id}.icrc1_symbol response: {err}"
                    ),
                )
            })
        })??;

    Ok(symbol)
}

// ============================================================================
// Extension-related conversions
// ============================================================================

impl From<ExtensionType> for pb::ExtensionType {
    fn from(item: ExtensionType) -> Self {
        match item {
            ExtensionType::TreasuryManager => pb::ExtensionType::TreasuryManager,
        }
    }
}

impl TryFrom<pb::ExtensionType> for ExtensionType {
    type Error = String;

    fn try_from(item: pb::ExtensionType) -> Result<Self, Self::Error> {
        match item {
            pb::ExtensionType::Unspecified => Err("Unspecified ExtensionType".to_string()),
            pb::ExtensionType::TreasuryManager => Ok(ExtensionType::TreasuryManager),
        }
    }
}

impl From<ExtensionSpec> for pb::ExtensionSpec {
    fn from(item: ExtensionSpec) -> Self {
        Self {
            name: Some(item.name),
            version: Some(item.version.0),
            topic: Some(item.topic as i32),
            extension_type: Some(pb::ExtensionType::from(item.extension_type) as i32),
        }
    }
}

impl TryFrom<pb::ExtensionSpec> for ExtensionSpec {
    type Error = String;

    fn try_from(item: pb::ExtensionSpec) -> Result<Self, Self::Error> {
        Ok(Self {
            name: item.name.ok_or("Missing name")?,
            version: ExtensionVersion(item.version.ok_or("Missing version")?),
            topic: item
                .topic
                .and_then(|t| pb::Topic::try_from(t).ok())
                .ok_or("No valid topic")?,
            extension_type: pb::ExtensionType::try_from(
                item.extension_type.ok_or("Missing extension_type")?,
            )
            .map_err(|_| "Invalid extension_type")?
            .try_into()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        governance::{Governance, ValidGovernanceProto},
        pb::{
            sns_root_types::{ListSnsCanistersRequest, ListSnsCanistersResponse},
            v1::{
                Governance as GovernanceProto, NervousSystemParameters, governance,
                governance::SnsMetadata,
            },
        },
        types::test_helpers::NativeEnvironment,
    };
    use ic_ledger_core::Tokens;
    use ic_management_canister_types_private::{CanisterInfoRequest, CanisterInfoResponse};
    use ic_nervous_system_canisters::{cmc::MockCMC, ledger::MockICRC1Ledger};
    use maplit::btreemap;

    /// Common function to create a basic GovernanceProto for tests
    fn create_test_governance_proto() -> GovernanceProto {
        GovernanceProto {
            root_canister_id: Some(CanisterId::from_u64(1000).get()),
            ledger_canister_id: Some(CanisterId::from_u64(4000).get()),
            swap_canister_id: Some(CanisterId::from_u64(5000).get()),
            parameters: Some(NervousSystemParameters::with_default_values()),
            sns_metadata: Some(SnsMetadata {
                logo: None,
                url: Some("https://example.com".to_string()),
                name: Some("Test SNS".to_string()),
                description: Some("Test SNS for extensions".to_string()),
            }),
            mode: governance::Mode::Normal.into(),
            ..Default::default()
        }
    }

    /// Creates a Governance instance with default ledger mocks for basic testing
    fn setup_gov_for_tests(extension_registered: bool) -> Governance {
        let mut env = NativeEnvironment::new(Some(CanisterId::from_u64(123)));
        let governance_proto = create_test_governance_proto();
        let extension_canister_id = CanisterId::from_u64(2000);

        // Mock list_sns_canisters call
        let extension_canister_ids = if extension_registered {
            vec![extension_canister_id.get()]
        } else {
            vec![] // Empty for unregistered extension tests
        };

        let sns_root_canister_id = CanisterId::from_u64(1000);
        let sns_governance_canister_id = CanisterId::from_u64(3000);
        let sns_ledger_canister_id = CanisterId::from_u64(4000);

        env.set_call_canister_response(
            sns_root_canister_id,
            "list_sns_canisters",
            Encode!(&ListSnsCanistersRequest {}).unwrap(),
            Ok(Encode!(&ListSnsCanistersResponse {
                root: Some(sns_root_canister_id.get()),
                governance: Some(sns_governance_canister_id.get()),
                ledger: Some(sns_ledger_canister_id.get()),
                swap: Some(CanisterId::from_u64(5000).get()),
                index: Some(CanisterId::from_u64(6000).get()),
                archives: vec![],
                dapps: vec![],
                extensions: Some(crate::pb::sns_root_types::Extensions {
                    extension_canister_ids,
                }),
            })
            .unwrap()),
        );

        // Mock canister_info call for extension canister (only needed if extension is registered)

        // Get the test hash from our test allowed extensions
        if extension_registered {
            let test_hash: Vec<u8> = vec![
                103, 45, 67, 136, 153, 129, 99, 42, 252, 137, 234, 215, 249, 199, 209, 167, 144,
                31, 212, 229, 137, 163, 153, 11, 118, 34, 52, 243, 17, 86, 97, 209,
            ];
            env.set_call_canister_response(
                CanisterId::ic_00(),
                "canister_info",
                Encode!(&CanisterInfoRequest::new(extension_canister_id, Some(1))).unwrap(),
                Ok(Encode!(&CanisterInfoResponse::new(
                    0,               // total_num_changes
                    vec![],          // recent_changes
                    Some(test_hash), // module_hash matching our test allowed extensions
                    vec![],          // controllers
                ))
                .unwrap()),
            );
        }

        // Create default ledgers with basic expectations for any ledger calls
        let mut icp_ledger = MockICRC1Ledger::default();
        icp_ledger.expect_account_balance().returning(|_| {
            Ok(Tokens::from_e8s(200_000_000_000)) // Mock ICP balance
        });

        let mut sns_ledger = MockICRC1Ledger::default();
        sns_ledger.expect_account_balance().returning(|_| {
            Ok(Tokens::from_e8s(100_000_000_000)) // Mock SNS balance
        });

        Governance::new(
            ValidGovernanceProto::try_from(governance_proto)
                .expect("Failed validating governance proto"),
            Box::new(env),
            Box::new(sns_ledger),
            Box::new(icp_ledger),
            Box::new(MockCMC::default()),
        )
    }

    // Tests for validate_execute_extension_operation with proper environment mocking

    #[tokio::test]
    async fn test_validate_execute_extension_operation_deposit_success() {
        let governance = setup_gov_for_tests(true);

        let execute_operation = ExecuteExtensionOperation {
            extension_canister_id: Some(CanisterId::from_u64(2000).get()),
            operation_name: Some("deposit".to_string()),
            operation_arg: Some(ExtensionOperationArg {
                value: Some(Precise {
                    value: Some(precise::Value::Map(PreciseMap {
                        map: btreemap! {
                            "treasury_allocation_sns_e8s".to_string() => Precise {
                                value: Some(precise::Value::Nat(1000000))
                            },
                            "treasury_allocation_icp_e8s".to_string() => Precise {
                                value: Some(precise::Value::Nat(2000000))
                            },
                        },
                    })),
                }),
            }),
        };

        // Test with valid operation name - should succeed
        let result = validate_execute_extension_operation(&governance, execute_operation).await;

        result.unwrap();
    }

    #[tokio::test]
    async fn test_validate_execute_extension_operation_withdraw_success() {
        let governance = setup_gov_for_tests(true);

        let execute_operation = ExecuteExtensionOperation {
            extension_canister_id: Some(CanisterId::from_u64(2000).get()),
            operation_name: Some("withdraw".to_string()),
            operation_arg: Some(ExtensionOperationArg { value: None }),
        };
        // Test with withdraw operation - should succeed (since test mode supports withdraw)
        let result = validate_execute_extension_operation(&governance, execute_operation).await;

        result.unwrap();
    }

    #[tokio::test]
    async fn test_validate_execute_extension_operation_unregistered_extension() {
        let governance = setup_gov_for_tests(false); // false = extension not registered

        let execute_operation = ExecuteExtensionOperation {
            extension_canister_id: Some(CanisterId::from_u64(2000).get()),
            operation_name: Some("deposit".to_string()),
            operation_arg: Some(ExtensionOperationArg {
                value: Some(Precise {
                    value: Some(precise::Value::Map(PreciseMap {
                        map: btreemap! {
                            "treasury_allocation_sns_e8s".to_string() => Precise {
                                value: Some(precise::Value::Nat(1000000))
                            },
                            "treasury_allocation_icp_e8s".to_string() => Precise {
                                value: Some(precise::Value::Nat(2000000))
                            },
                        },
                    })),
                }),
            }),
        };

        let result = validate_execute_extension_operation(&governance, execute_operation).await;

        let error = result.unwrap_err();
        assert_eq!(error.error_type, ErrorType::NotFound as i32);
        assert!(error.error_message.contains("Extension canister"));
        assert!(
            error
                .error_message
                .contains("is not registered with the SNS")
        );
    }

    #[tokio::test]
    async fn test_validate_execute_extension_operation_invalid_operation_name() {
        let governance = setup_gov_for_tests(true);

        let execute_operation = ExecuteExtensionOperation {
            extension_canister_id: Some(CanisterId::from_u64(2000).get()),
            operation_name: Some("invalid_operation".to_string()),
            operation_arg: Some(ExtensionOperationArg { value: None }),
        };

        // Test with invalid operation name - should fail
        let result = validate_execute_extension_operation(&governance, execute_operation).await;

        let error = result.unwrap_err();
        assert_eq!(error.error_type, ErrorType::InvalidProposal as i32);
        assert!(
            error
                .error_message
                .contains("does not have an operation named invalid_operation")
        );
    }

    /// Helper function to create a valid RegisterExtension payload for tests
    fn valid_register_extension_payload(store_canister_id: CanisterId) -> RegisterExtension {
        RegisterExtension {
            chunked_canister_wasm: Some(ChunkedCanisterWasm {
                wasm_module_hash: vec![
                    103, 45, 67, 136, 153, 129, 99, 42, 252, 137, 234, 215, 249, 199, 209, 167,
                    144, 31, 212, 229, 137, 163, 153, 11, 118, 34, 52, 243, 17, 86, 97, 209,
                ], // Use whitelisted hash from other tests
                store_canister_id: Some(store_canister_id.get()),
                chunk_hashes_list: vec![], // Can be empty for tests
            }),
            extension_init: Some(ExtensionInit {
                value: Some(Precise {
                    value: Some(precise::Value::Map(PreciseMap {
                        map: btreemap! {
                            "treasury_allocation_sns_e8s".to_string() => Precise {
                                value: Some(precise::Value::Nat(1000000))
                            },
                            "treasury_allocation_icp_e8s".to_string() => Precise {
                                value: Some(precise::Value::Nat(2000000))
                            },
                        },
                    })),
                }),
            }),
        }
    }

    #[tokio::test]
    async fn test_validate_register_extension_fiduciary_subnet_success() {
        // Set up mock environment for successful fiduciary subnet validation
        let mut env = NativeEnvironment::new(Some(CanisterId::from_u64(1000)));
        let store_canister_id = CanisterId::from_u64(3000); // This becomes extension_canister_id

        // Mock get_subnet_for_canister response (registry call)
        let subnet_id = SubnetId::from(PrincipalId::new_user_test_id(100));
        env.set_call_canister_response(
            REGISTRY_CANISTER_ID,
            "get_subnet_for_canister",
            Encode!(&GetSubnetForCanisterRequest {
                principal: Some(store_canister_id.get()),
            })
            .unwrap(),
            Ok(Encode!(&Ok::<SubnetForCanister, String>(SubnetForCanister {
                subnet_id: Some(subnet_id.get()),
            }))
            .unwrap()),
        );

        // Mock get_subnet_types_to_subnets response (CMC call)
        env.set_call_canister_response(
            CYCLES_MINTING_CANISTER_ID,
            "get_subnet_types_to_subnets",
            Encode!(&()).unwrap(),
            Ok(Encode!(&SubnetTypesToSubnetsResponse {
                data: vec![
                    (
                        "european".to_string(),
                        vec![SubnetId::from(PrincipalId::new_user_test_id(101))]
                    ),
                    ("fiduciary".to_string(), vec![subnet_id]), // Our subnet is fiduciary
                ],
            })
            .unwrap()),
        );

        // Mock canister_info response (management canister call)
        env.set_call_canister_response(
            CanisterId::ic_00(),
            "canister_info",
            Encode!(&CanisterInfoRequest::new(store_canister_id, Some(1))).unwrap(),
            Ok(Encode!(&CanisterInfoResponse::new(
                0,      // total_num_changes
                vec![], // recent_changes
                None,   // module_hash should be empty
                vec![], // controllers
            ))
            .unwrap()),
        );

        // Start with properly configured ledger balances
        let mut governance = setup_governance_with_treasury_balances(100_000_000, 200_000_000);

        // Replace the environment with our custom mock for subnet validation
        governance.env = Box::new(env);

        // Create a valid RegisterExtension request for TreasuryManager
        let register_extension = valid_register_extension_payload(store_canister_id);

        // Should succeed because extension canister is on fiduciary subnet
        let result = validate_register_extension(&governance, register_extension).await;
        assert!(
            result.is_ok(),
            "Expected success but got error: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_validate_register_extension_non_fiduciary_subnet_failure() {
        // Set up mock environment for non-fiduciary subnet (should fail)
        let mut env = NativeEnvironment::new(Some(CanisterId::from_u64(1000)));
        let store_canister_id = CanisterId::from_u64(3000); // This becomes extension_canister_id

        // Mock get_subnet_for_canister response (registry call)
        let subnet_id = SubnetId::from(PrincipalId::new_user_test_id(100));
        env.set_call_canister_response(
            REGISTRY_CANISTER_ID,
            "get_subnet_for_canister",
            Encode!(&GetSubnetForCanisterRequest {
                principal: Some(store_canister_id.get()),
            })
            .unwrap(),
            Ok(Encode!(&Ok::<SubnetForCanister, String>(SubnetForCanister {
                subnet_id: Some(subnet_id.get()),
            }))
            .unwrap()),
        );

        // Mock get_subnet_types_to_subnets response (CMC call) - subnet is NOT fiduciary
        env.set_call_canister_response(
            CYCLES_MINTING_CANISTER_ID,
            "get_subnet_types_to_subnets",
            Encode!(&()).unwrap(),
            Ok(Encode!(&SubnetTypesToSubnetsResponse {
                data: vec![
                    ("european".to_string(), vec![subnet_id]), // Our subnet is application, not fiduciary
                    (
                        "fiduciary".to_string(),
                        vec![SubnetId::from(PrincipalId::new_user_test_id(101))]
                    ),
                ],
            })
            .unwrap()),
        );

        // Start with properly configured ledger balances
        let mut governance = setup_governance_with_treasury_balances(100_000_000, 200_000_000);

        // Replace the environment with our custom mock for subnet validation
        governance.env = Box::new(env);

        // Create a valid RegisterExtension request for TreasuryManager
        let register_extension = valid_register_extension_payload(store_canister_id);

        // Should fail because extension canister is NOT on fiduciary subnet
        let result = validate_register_extension(&governance, register_extension).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("TreasuryManager extensions must be installed on a fiduciary subnet")
        );
    }

    #[tokio::test]
    async fn test_validate_register_extension_subnet_lookup_failure() {
        // Set up mock environment where subnet lookup fails
        let mut env = NativeEnvironment::new(Some(CanisterId::from_u64(1000)));
        let store_canister_id = CanisterId::from_u64(3000); // This becomes extension_canister_id

        // Mock get_subnet_for_canister response (registry call) - return error
        env.set_call_canister_response(
            REGISTRY_CANISTER_ID,
            "get_subnet_for_canister",
            Encode!(&GetSubnetForCanisterRequest {
                principal: Some(store_canister_id.get()),
            })
            .unwrap(),
            Err((Some(999), "Registry lookup failed".to_string())),
        );

        // Start with properly configured ledger balances
        let mut governance = setup_governance_with_treasury_balances(100_000_000, 200_000_000);

        // Replace the environment with our custom mock for subnet validation
        governance.env = Box::new(env);

        // Create a valid RegisterExtension request for TreasuryManager
        let register_extension = valid_register_extension_payload(store_canister_id);

        // Should fail because subnet lookup failed
        let result = validate_register_extension(&governance, register_extension).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("TreasuryManager extensions must be installed on a fiduciary subnet")
        );
    }

    #[tokio::test]
    async fn test_validate_deposit_operation() {
        // Use setup that configures mock ledgers to return balances and root responses
        let governance = setup_governance_with_treasury_balances(100_000_000, 200_000_000);

        // Test valid deposit operation
        let valid_arg = ExtensionOperationArg {
            value: Some(Precise {
                value: Some(precise::Value::Map(PreciseMap {
                    map: btreemap! {
                        "treasury_allocation_sns_e8s".to_string() => Precise {
                            value: Some(precise::Value::Nat(1000000)),
                        },
                        "treasury_allocation_icp_e8s".to_string() => Precise {
                            value: Some(precise::Value::Nat(2000000)),
                        },
                    },
                })),
            }),
        };

        let result = validate_deposit_operation(&governance, valid_arg.clone())
            .await
            .unwrap();

        match result {
            ValidatedOperationArg::TreasuryManagerDeposit(deposit) => {
                assert_eq!(deposit.treasury_allocation_sns_e8s, 1000000);
                assert_eq!(deposit.treasury_allocation_icp_e8s, 2000000);
            }
            _ => panic!("Expected TreasuryManagerDeposit variant"),
        }

        let missing_sns_arg = ExtensionOperationArg {
            value: Some(Precise {
                value: Some(precise::Value::Map(PreciseMap {
                    map: btreemap! {
                        "treasury_allocation_icp_e8s".to_string() => Precise {
                            value: Some(precise::Value::Nat(2000000)),
                        },
                    },
                })),
            }),
        };

        let result = validate_deposit_operation(&governance, missing_sns_arg)
            .await
            .unwrap_err();
        assert!(result.contains("treasury_allocation_sns_e8s must be a Nat value"));

        // Test missing ICP amount
        let missing_icp_arg = ExtensionOperationArg {
            value: Some(Precise {
                value: Some(precise::Value::Map(PreciseMap {
                    map: btreemap! {
                        "treasury_allocation_sns_e8s".to_string() => Precise {
                            value: Some(precise::Value::Nat(1000000)),
                        },
                    },
                })),
            }),
        };

        let result = validate_deposit_operation(&governance, missing_icp_arg)
            .await
            .unwrap_err();
        assert!(result.contains("treasury_allocation_icp_e8s must be a Nat value"));

        // Test wrong type for SNS amount
        let wrong_type_arg = ExtensionOperationArg {
            value: Some(Precise {
                value: Some(precise::Value::Map(PreciseMap {
                    map: btreemap! {
                        "treasury_allocation_sns_e8s".to_string() => Precise {
                            value: Some(precise::Value::Text("not a number".to_string())),
                        },
                        "treasury_allocation_icp_e8s".to_string() => Precise {
                            value: Some(precise::Value::Nat(2000000)),
                        },
                    },
                })),
            }),
        };

        let result = validate_deposit_operation(&governance, wrong_type_arg)
            .await
            .unwrap_err();
        assert!(result.contains("treasury_allocation_sns_e8s must be a Nat value"));

        // Test no arguments provided
        let no_args = ExtensionOperationArg { value: None };
        let result = validate_deposit_operation(&governance, no_args)
            .await
            .unwrap_err();
        assert!(result.contains("Deposit operation arguments must be provided"));

        // Test not a map
        let not_map_arg = ExtensionOperationArg {
            value: Some(Precise {
                value: Some(precise::Value::Text("not a map".to_string())),
            }),
        };

        let result = validate_deposit_operation(&governance, not_map_arg)
            .await
            .unwrap_err();
        assert!(result.contains("Deposit operation arguments must be a PreciseMap"));
    }

    #[tokio::test]
    async fn test_validate_register_extension_structural_validation() {
        // Test structural validation of RegisterExtension before treasury manager specific validation
        let governance = setup_governance_with_treasury_balances(100_000_000, 200_000_000);

        fn valid_register_extension() -> RegisterExtension {
            valid_register_extension_payload(CanisterId::from_u64(10000))
        }

        // Test missing chunked_canister_wasm
        let missing_wasm = {
            let mut register_extension = valid_register_extension();
            register_extension.chunked_canister_wasm = None;
            register_extension
        };
        let err = validate_register_extension(&governance, missing_wasm)
            .await
            .unwrap_err();
        assert_eq!(err, "chunked_canister_wasm is required");

        // Test missing store_canister_id
        let missing_store_id = {
            let mut register_extension = valid_register_extension();
            register_extension
                .chunked_canister_wasm
                .as_mut()
                .unwrap()
                .store_canister_id = None;
            register_extension
        };
        let err = validate_register_extension(&governance, missing_store_id)
            .await
            .unwrap_err();
        assert_eq!(err, "chunked_canister_wasm.store_canister_id is required");

        // Test invalid store_canister_id (not a valid principal)
        let invalid_store_id = {
            let mut register_extension = valid_register_extension();
            register_extension
                .chunked_canister_wasm
                .as_mut()
                .unwrap()
                .store_canister_id = Some(PrincipalId::new_user_test_id(0)); // Invalid canister ID
            register_extension
        };
        let err = validate_register_extension(&governance, invalid_store_id)
            .await
            .unwrap_err();
        assert!(err.contains("Invalid store_canister_id"));

        // Test invalid wasm module hash length
        let invalid_hash_length = {
            let mut register_extension = valid_register_extension();
            register_extension
                .chunked_canister_wasm
                .as_mut()
                .unwrap()
                .wasm_module_hash = vec![1; 16]; // Wrong length (should be 32)
            register_extension
        };
        let err = validate_register_extension(&governance, invalid_hash_length)
            .await
            .unwrap_err();
        assert_eq!(
            err,
            "Invalid extension wasm: Invalid wasm module hash length: expected 32 bytes, got 16"
        );

        // Test missing extension_init
        let missing_init = {
            let mut register_extension = valid_register_extension();
            register_extension.extension_init = None;
            register_extension
        };
        let err = validate_register_extension(&governance, missing_init)
            .await
            .unwrap_err();
        assert!(err.contains("RegisterExtension.extension_init is required"));

        // Test wasm not in whitelist (in non-test mode this would fail)
        // Since we're in test mode, this will succeed, so we can't test the whitelist rejection here
        // That would need to be tested in an integration test or with special test setup
    }

    #[tokio::test]
    async fn test_validate_register_extension_treasury_manager_init() {
        // Test that validate_register_extension (init path) validates treasury manager init
        // the same way as validate_deposit_operation validates deposits

        // Set up environment mocks for fiduciary subnet validation (required for treasury manager)
        let mut env = NativeEnvironment::new(Some(CanisterId::from_u64(1000)));
        let store_canister_id = CanisterId::from_u64(2000); // Same as used in mk_register_extension below

        // Mock get_subnet_for_canister response (registry call)
        let subnet_id = SubnetId::from(PrincipalId::new_user_test_id(100));
        env.set_call_canister_response(
            REGISTRY_CANISTER_ID,
            "get_subnet_for_canister",
            Encode!(&GetSubnetForCanisterRequest {
                principal: Some(store_canister_id.get()),
            })
            .unwrap(),
            Ok(Encode!(&Ok::<SubnetForCanister, String>(SubnetForCanister {
                subnet_id: Some(subnet_id.get()),
            }))
            .unwrap()),
        );

        // Mock get_subnet_types_to_subnets response (CMC call) - mark as fiduciary
        env.set_call_canister_response(
            CYCLES_MINTING_CANISTER_ID,
            "get_subnet_types_to_subnets",
            Encode!(&()).unwrap(),
            Ok(Encode!(&SubnetTypesToSubnetsResponse {
                data: vec![
                    (
                        "european".to_string(),
                        vec![SubnetId::from(PrincipalId::new_user_test_id(101))]
                    ),
                    ("fiduciary".to_string(), vec![subnet_id]), // Our subnet is fiduciary
                ],
            })
            .unwrap()),
        );

        // Mock canister_info response (management canister call)
        env.set_call_canister_response(
            CanisterId::ic_00(),
            "canister_info",
            Encode!(&CanisterInfoRequest::new(store_canister_id, Some(1))).unwrap(),
            Ok(Encode!(&CanisterInfoResponse::new(
                0,      // total_num_changes
                vec![], // recent_changes
                None,   // module_hash should be empty
                vec![], // controllers
            ))
            .unwrap()),
        );

        // Start with properly configured ledger balances
        let mut governance = setup_governance_with_treasury_balances(100_000_000, 200_000_000);

        // Replace the environment with our custom mock for subnet validation
        governance.env = Box::new(env);

        // Build a helper to invoke validate_register_extension with a given precise value
        let mk_register_extension = |value: Option<Precise>| {
            let mut extension = valid_register_extension_payload(CanisterId::from_u64(2000));
            extension.extension_init = Some(ExtensionInit { value });
            extension
        };

        // Success case: valid arguments should succeed
        let valid_arg = ExtensionOperationArg {
            value: Some(Precise {
                value: Some(precise::Value::Map(PreciseMap {
                    map: btreemap! {
                        "treasury_allocation_sns_e8s".to_string() => Precise { value: Some(precise::Value::Nat(1000000)) },
                        "treasury_allocation_icp_e8s".to_string() => Precise { value: Some(precise::Value::Nat(2000000)) },
                    },
                })),
            }),
        };
        let init_ok = mk_register_extension(valid_arg.value.clone());
        validate_register_extension(&governance, init_ok)
            .await
            .unwrap();

        // Structural validation failure: missing SNS allocation
        let missing_sns_init = mk_register_extension(Some(Precise {
            value: Some(precise::Value::Map(PreciseMap {
                map: btreemap! {
                    "treasury_allocation_icp_e8s".to_string() => Precise { value: Some(precise::Value::Nat(2000000)) },
                },
            })),
        }));
        let err = validate_register_extension(&governance, missing_sns_init)
            .await
            .unwrap_err();
        assert!(err.contains("treasury_allocation_sns_e8s must be a Nat value"));

        // Structural validation failure: missing ICP allocation
        let missing_icp_init = mk_register_extension(Some(Precise {
            value: Some(precise::Value::Map(PreciseMap {
                map: btreemap! {
                    "treasury_allocation_sns_e8s".to_string() => Precise { value: Some(precise::Value::Nat(1000000)) },
                },
            })),
        }));
        let err = validate_register_extension(&governance, missing_icp_init)
            .await
            .unwrap_err();
        assert!(err.contains("treasury_allocation_icp_e8s must be a Nat value"));

        // Structural validation failure: wrong type
        let wrong_type_init = mk_register_extension(Some(Precise {
            value: Some(precise::Value::Map(PreciseMap {
                map: btreemap! {
                    "treasury_allocation_sns_e8s".to_string() => Precise { value: Some(precise::Value::Text("not a number".to_string())) },
                    "treasury_allocation_icp_e8s".to_string() => Precise { value: Some(precise::Value::Nat(2000000)) },
                },
            })),
        }));
        let err = validate_register_extension(&governance, wrong_type_init)
            .await
            .unwrap_err();
        assert!(err.contains("treasury_allocation_sns_e8s must be a Nat value"));

        // Structural validation failure: no arguments
        let no_args_init = mk_register_extension(None);
        let err = validate_register_extension(&governance, no_args_init)
            .await
            .unwrap_err();
        assert!(err.contains("Deposit operation arguments must be provided"));

        // Structural validation failure: not a map
        let not_map_init = mk_register_extension(Some(Precise {
            value: Some(precise::Value::Text("not a map".to_string())),
        }));
        let err = validate_register_extension(&governance, not_map_init)
            .await
            .unwrap_err();
        assert!(err.contains("Deposit operation arguments must be a PreciseMap"));
    }

    #[tokio::test]
    async fn test_validate_withdraw_operation() {
        let governance = setup_gov_for_tests(true);

        // Test valid withdraw operation - must have empty arguments
        let valid_arg = ExtensionOperationArg { value: None };
        let result = validate_withdraw_operation(&governance, valid_arg.clone())
            .await
            .unwrap();

        match result {
            ValidatedOperationArg::TreasuryManagerWithdraw(withdraw) => {
                // Should just wrap the original
                assert_eq!(withdraw.original.value, None);
            }
            _ => panic!("Expected TreasuryManagerWithdraw variant"),
        }

        // Test with argument - should fail
        let minimal_arg = ExtensionOperationArg {
            value: Some(Precise {
                value: Some(precise::Value::Text("anything".to_string())),
            }),
        };

        let result = validate_withdraw_operation(&governance, minimal_arg)
            .await
            .unwrap_err();
        assert!(result.contains("Withdraw operation does not accept arguments at this time"));
    }

    /// Creates a Governance instance with specific treasury balance expectations for testing
    fn setup_governance_with_treasury_balances(sns_balance: u64, icp_balance: u64) -> Governance {
        let env = NativeEnvironment::new(Some(CanisterId::from_u64(1000)));
        let governance_proto = create_test_governance_proto();

        // Create mocks with configured expectations
        let mut sns_ledger = MockICRC1Ledger::new();
        let mut icp_ledger = MockICRC1Ledger::new();

        // Get the expected subaccounts
        let governance_canister_id = env.canister_id();
        let sns_subaccount = compute_distribution_subaccount_bytes(governance_canister_id.get(), 0);

        // Configure SNS ledger mock
        sns_ledger
            .expect_account_balance()
            .withf(move |account: &Account| {
                account.owner == governance_canister_id.get().0
                    && account.subaccount == Some(sns_subaccount)
            })
            .returning(move |_| Ok(Tokens::from_e8s(sns_balance)));

        // Configure ICP ledger mock
        icp_ledger
            .expect_account_balance()
            .withf(move |account: &Account| {
                account.owner == governance_canister_id.get().0 && account.subaccount.is_none()
            })
            .returning(move |_| Ok(Tokens::from_e8s(icp_balance)));

        Governance::new(
            ValidGovernanceProto::try_from(governance_proto)
                .expect("Failed validating governance proto"),
            Box::new(env),
            Box::new(sns_ledger),
            Box::new(icp_ledger),
            Box::new(MockCMC::default()),
        )
    }

    #[tokio::test]
    async fn test_validate_deposit_operation_treasury_balance_limits() {
        // Test parameters: (label, sns_balance, icp_balance, sns_request, icp_request, expected_result)
        #[allow(clippy::type_complexity)]
        let test_cases: Vec<(&'static str, u64, u64, u64, u64, Result<(), &'static str>)> = vec![
            (
                "Positive: exactly 50%",
                100_000_000,
                200_000_000,
                50_000_000,
                100_000_000,
                Ok(()),
            ),
            (
                "Positive: below 50%",
                100_000_000,
                200_000_000,
                30_000_000,
                60_000_000,
                Ok(()),
            ),
            (
                "Positive: zero amounts",
                100_000_000,
                200_000_000,
                0,
                0,
                Ok(()),
            ),
            (
                "Negative: SNS exceeds 50%",
                100_000_000,
                200_000_000,
                51_000_000,
                50_000_000,
                Err(
                    "SNS treasury deposit request of 0.51000000 Token exceeds 50% of current SNS Token balance",
                ),
            ),
            (
                "Negative: ICP exceeds 50%",
                100_000_000,
                200_000_000,
                40_000_000,
                101_000_000,
                Err(
                    "ICP treasury deposit request of 1.01000000 Token exceeds 50% of current ICP balance",
                ),
            ),
            (
                "Negative: both exceed 50% (SNS checked first)",
                100_000_000,
                200_000_000,
                60_000_000,
                120_000_000,
                Err(
                    "SNS treasury deposit request of 0.60000000 Token exceeds 50% of current SNS Token balance",
                ),
            ),
        ];

        for (label, sns_balance, icp_balance, sns_request, icp_request, expected) in test_cases {
            let governance = setup_governance_with_treasury_balances(sns_balance, icp_balance);

            let arg = ExtensionOperationArg {
                value: Some(Precise {
                    value: Some(precise::Value::Map(PreciseMap {
                        map: btreemap! {
                            "treasury_allocation_sns_e8s".to_string() => Precise {
                                value: Some(precise::Value::Nat(sns_request)),
                            },
                            "treasury_allocation_icp_e8s".to_string() => Precise {
                                value: Some(precise::Value::Nat(icp_request)),
                            },
                        },
                    })),
                }),
            };

            // NOTE: We swallow the result here to make assertions easier below.
            // We test the rest of this function in other tests, this is just for the deposit limits.
            let result = validate_deposit_operation(&governance, arg)
                .await
                .map(|_| ());

            match expected {
                Ok(()) => {
                    assert!(
                        result.is_ok(),
                        "{label}: Expected success for sns_balance={sns_balance}, icp_balance={icp_balance}, sns_request={sns_request}, icp_request={icp_request}, but got: {result:?}"
                    );
                }
                Err(expected_substr) => {
                    let error = result.unwrap_err();
                    assert!(
                        error.contains(expected_substr),
                        "{label}: Expected error containing '{expected_substr}' for sns_balance={sns_balance}, icp_balance={icp_balance}, sns_request={sns_request}, icp_request={icp_request}, but got: {error}"
                    );
                }
            }
        }
    }

    #[test]
    fn test_validated_operation_arg_render() {
        // Test deposit rendering
        let deposit_arg =
            ValidatedOperationArg::TreasuryManagerDeposit(ValidatedDepositOperationArg {
                treasury_allocation_sns_e8s: 1000000,
                treasury_allocation_icp_e8s: 2000000,
                original: Precise {
                    value: Some(precise::Value::Map(PreciseMap {
                        map: btreemap! {
                            "treasury_allocation_sns_e8s".to_string() => Precise {
                                value: Some(precise::Value::Nat(1000000)),
                            },
                            "treasury_allocation_icp_e8s".to_string() => Precise {
                                value: Some(precise::Value::Nat(2000000)),
                            },
                            "other_field".to_string() => Precise {
                                value: Some(precise::Value::Text("Some Value".to_string())),
                            },
                        },
                    })),
                },
            });

        let rendered = deposit_arg.render_for_proposal();
        assert!(rendered.contains("Treasury Deposit"));
        assert!(rendered.contains("1000000"));
        assert!(rendered.contains("2000000"));
        assert!(rendered.contains("Raw Payload"));
        assert!(rendered.contains("treasury_allocation_sns_e8s"));
        assert!(rendered.contains("treasury_allocation_icp_e8s"));
        assert!(rendered.contains("other_field"));
        assert!(rendered.contains("Some Value"));

        // Test withdraw rendering
        let withdraw_arg =
            ValidatedOperationArg::TreasuryManagerWithdraw(ValidatedWithdrawOperationArg {
                original: Precise {
                    value: Some(precise::Value::Map(PreciseMap {
                        map: btreemap! {
                            "test".to_string() => Precise {
                                value: Some(precise::Value::Text("data".to_string())),
                            },
                        },
                    })),
                },
            });

        let rendered = withdraw_arg.render_for_proposal();
        assert!(rendered.contains("Treasury Withdrawal"));
        assert!(rendered.contains("Raw Payload"));
        assert!(rendered.contains("test"));
        assert!(rendered.contains("data"));
    }

    #[test]
    fn test_extension_spec_creation() {
        // Test that extension spec can be created successfully
        let spec = ExtensionSpec {
            name: "test_extension".to_string(),
            version: ExtensionVersion(1),
            topic: Topic::Governance,
            extension_type: ExtensionType::TreasuryManager,
        };

        // Basic functionality test - ensure we can get operations
        let operations = spec.all_operations();
        assert!(!operations.is_empty());
    }

    #[tokio::test]
    async fn test_validated_register_extension_execute_caches_extension() {
        use crate::storage::get_registered_extension_from_cache;

        // Create a simplified test that just verifies the caching functionality
        let extension_canister_id = CanisterId::from_u64(2000);

        // Verify cache is initially empty
        assert_eq!(
            get_registered_extension_from_cache(extension_canister_id),
            None
        );

        // Create test extension spec
        let test_spec = ExtensionSpec {
            name: "Test Treasury Manager".to_string(),
            version: ExtensionVersion(1),
            topic: Topic::TreasuryAssetManagement,
            extension_type: ExtensionType::TreasuryManager,
        };

        // Directly test the caching mechanism (this is what execute() does on line 476)
        crate::storage::cache_registered_extension(extension_canister_id, test_spec.clone());

        // Verify the extension is now cached
        let cached_spec = get_registered_extension_from_cache(extension_canister_id);
        assert!(
            cached_spec.is_some(),
            "Extension should be cached after registration"
        );

        let cached_spec = cached_spec.unwrap();
        assert_eq!(cached_spec.name, test_spec.name);
        assert_eq!(cached_spec.version, test_spec.version);
        assert_eq!(cached_spec.topic, test_spec.topic);
        assert_eq!(cached_spec.extension_type, test_spec.extension_type);
    }

    #[tokio::test]
    async fn test_validate_upgrade_extension_comprehensive() {
        let governance = setup_governance_with_treasury_balances(100_000_000, 200_000_000);

        // Set up a registered extension in cache for testing
        let extension_canister_id = CanisterId::from_u64(2000);
        cache_registered_extension(
            extension_canister_id,
            ExtensionSpec {
                name: "My Test Extension".to_string(),
                version: ExtensionVersion(1),
                topic: Topic::TreasuryAssetManagement,
                extension_type: ExtensionType::TreasuryManager,
            },
        );

        // Helper function for valid upgrade extension
        fn valid_upgrade_extension() -> pb::UpgradeExtension {
            pb::UpgradeExtension {
                extension_canister_id: Some(CanisterId::from_u64(2000).get()),
                canister_upgrade_arg: Some(ExtensionUpgradeArg {
                    value: None, // Valid for treasury manager
                }),
                wasm: Some(pb::Wasm {
                    wasm: Some(pb::wasm::Wasm::Chunked(ChunkedCanisterWasm {
                        wasm_module_hash: vec![
                            128, 15, 128, 73, 49, 167, 207, 220, 204, 215, 20, 218, 174, 6, 171,
                            203, 196, 247, 243, 160, 84, 98, 133, 2, 3, 47, 184, 165, 191, 94, 123,
                            231,
                        ],
                        store_canister_id: Some(CanisterId::from_u64(2000).get()),
                        chunk_hashes_list: vec![vec![
                            128, 15, 128, 73, 49, 167, 207, 220, 204, 215, 20, 218, 174, 6, 171,
                            203, 196, 247, 243, 160, 84, 98, 133, 2, 3, 47, 184, 165, 191, 94, 123,
                            231,
                        ]],
                    })), // KongSwap v2 hash from create_test_allowed_extensions
                }),
            }
        }

        let okay_test = valid_upgrade_extension();
        let result = validate_upgrade_extension(&governance, okay_test).await;
        assert!(result.is_ok(), "{result:?}");
        let validated = result.unwrap();
        assert_eq!(validated.extension_canister_id, extension_canister_id);
        assert_eq!(validated.current_version, ExtensionVersion(1));
        assert_eq!(validated.new_version, ExtensionVersion(2));

        // Test 1: Missing extension_canister_id
        let missing_canister_id = {
            let mut upgrade = valid_upgrade_extension();
            upgrade.extension_canister_id = None;
            upgrade
        };
        let result = validate_upgrade_extension(&governance, missing_canister_id).await;
        assert_eq!(result, Err("extension_canister_id is required".to_string()));

        // Test 2: Invalid extension_canister_id
        let invalid_canister_id = {
            let mut upgrade = valid_upgrade_extension();
            upgrade.extension_canister_id = Some(PrincipalId::new_user_test_id(0)); // Invalid
            upgrade
        };
        let result = validate_upgrade_extension(&governance, invalid_canister_id).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("Invalid extension_canister_id")
        );

        // Test 3: Extension not registered
        let unregistered_extension = {
            let mut upgrade = valid_upgrade_extension();
            upgrade.extension_canister_id = Some(CanisterId::from_u64(9999).get()); // Not in cache
            upgrade
        };
        let result = validate_upgrade_extension(&governance, unregistered_extension).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("is not registered"));

        // Test 4: Missing wasm field
        let missing_wasm = {
            let mut upgrade = valid_upgrade_extension();
            upgrade.wasm = None;
            upgrade
        };
        let result = validate_upgrade_extension(&governance, missing_wasm).await;
        assert_eq!(result, Err("wasm field is required".to_string()));

        // Test 5: Invalid WASM specification (missing inner wasm)
        let invalid_wasm_spec = {
            let mut upgrade = valid_upgrade_extension();
            upgrade.wasm = Some(pb::Wasm { wasm: None }); // Missing inner wasm
            upgrade
        };
        let result = validate_upgrade_extension(&governance, invalid_wasm_spec).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid WASM specification"));

        // Test 6: WASM hash not in allowed extensions (random hash not in test map)
        let invalid_wasm_hash = {
            let mut upgrade = valid_upgrade_extension();
            upgrade.wasm = Some(pb::Wasm {
                wasm: Some(pb::wasm::Wasm::Bytes(vec![
                    99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
                    99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
                ])), // Random hash not in allowed extensions
            });
            upgrade
        };
        let result = validate_upgrade_extension(&governance, invalid_wasm_hash).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid extension wasm"));

        // Test 7: Invalid upgrade argument (treasury manager doesn't support args with values)
        let invalid_upgrade_arg = {
            let mut upgrade = valid_upgrade_extension();
            upgrade.canister_upgrade_arg = Some(ExtensionUpgradeArg {
                value: Some(Precise {
                    value: Some(precise::Value::Text("invalid".to_string())),
                }),
            });
            upgrade
        };
        let result = validate_upgrade_extension(&governance, invalid_upgrade_arg).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid upgrade argument"));

        // Test 8: Extension name mismatch (set up different extension with different name)
        let different_extension_canister_id = CanisterId::from_u64(3000);
        cache_registered_extension(
            different_extension_canister_id,
            ExtensionSpec {
                name: "Different Extension Name".to_string(), // Different name
                version: ExtensionVersion(1),
                topic: Topic::TreasuryAssetManagement,
                extension_type: ExtensionType::TreasuryManager,
            },
        );
        let name_mismatch = {
            let mut upgrade = valid_upgrade_extension();
            upgrade.extension_canister_id = Some(different_extension_canister_id.get());
            upgrade
        };
        let result = validate_upgrade_extension(&governance, name_mismatch).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Extension name mismatch"));

        // Test 9: Version not higher (use v1 hash for upgrade when current is already v1)
        let same_version = {
            let mut upgrade = valid_upgrade_extension();
            upgrade.wasm = Some(pb::Wasm {
                wasm: Some(pb::wasm::Wasm::Chunked(ChunkedCanisterWasm {
                    wasm_module_hash: vec![
                        103, 45, 67, 136, 153, 129, 99, 42, 252, 137, 234, 215, 249, 199, 209, 167,
                        144, 31, 212, 229, 137, 163, 153, 11, 118, 34, 52, 243, 17, 86, 97, 209,
                    ], // KongSwap v1 hash - same version as current
                    store_canister_id: Some(CanisterId::from_u64(2000).get()),
                    chunk_hashes_list: vec![vec![
                        103, 45, 67, 136, 153, 129, 99, 42, 252, 137, 234, 215, 249, 199, 209, 167,
                        144, 31, 212, 229, 137, 163, 153, 11, 118, 34, 52, 243, 17, 86, 97, 209,
                    ]],
                })),
            });
            upgrade
        };
        let result = validate_upgrade_extension(&governance, same_version).await;
        assert_eq!(
            result,
            Err("New extension version 1 must be higher than current version 1".to_string())
        );
    }
}
