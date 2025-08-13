use crate::{
    governance::{Governance, TREASURY_SUBACCOUNT_NONCE},
    logs::INFO,
    pb::{
        sns_root_types::{
            register_extension_response, CanisterCallError, ListSnsCanistersRequest,
            ListSnsCanistersResponse, RegisterExtensionRequest, RegisterExtensionResponse,
        },
        v1::{
            governance_error::ErrorType, precise, ChunkedCanisterWasm, ExecuteExtensionOperation,
            ExtensionInit, ExtensionOperationArg, GovernanceError, Precise, PreciseMap,
            RegisterExtension, Topic,
        },
    },
    types::{Environment, Wasm},
};
use candid::{Decode, Encode, Nat};
use candid_utils::printing;
use ic_base_types::{CanisterId, PrincipalId};
use ic_canister_log::log;
use ic_management_canister_types_private::{
    CanisterInfoRequest, CanisterInfoResponse, CanisterInstallMode,
};
use ic_nervous_system_common::ledger::compute_distribution_subaccount_bytes;
use icrc_ledger_types::icrc1::account::Account;
use lazy_static::lazy_static;
use maplit::btreemap;
use sns_treasury_manager::{
    Allowance, Asset, DepositRequest, TreasuryManagerArg, TreasuryManagerInit, WithdrawRequest,
};

use futures::future::BoxFuture;
use ic_ledger_core::Tokens;
use std::{collections::BTreeMap, fmt::Display};

lazy_static! {
    static ref ALLOWED_EXTENSIONS: BTreeMap<[u8; 32], ExtensionSpec> = btreemap! {};
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

#[derive(Clone, Debug, Eq, PartialEq)]
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
            format!("{:#?}", self)
        };

        format!("#### Raw Payload\n\n{}", render)
    }
}

/// Specification for an extension operation
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionOperationSpec {
    pub name: String,
    pub description: String,
    pub extension_type: ExtensionType,
    pub validate_arg:
        fn(&Governance, ExtensionOperationArg) -> BoxFuture<Result<ValidatedOperationArg, String>>,
}

impl ExtensionOperationSpec {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    async fn validate_operation_arg(
        &self,
        governance: &Governance,
        arg: ExtensionOperationArg,
    ) -> Result<ValidatedOperationArg, String> {
        (self.validate_arg)(governance, arg).await
    }
}

/// Validates treasury manager init arguments
fn validate_treasury_manager_init(
    governance: &Governance,
    init: ExtensionInit,
) -> BoxFuture<Result<ValidatedExtensionInit, String>> {
    Box::pin(async move {
        let ExtensionInit { value } = init;
        validate_deposit_operation_impl(governance, value)
            .await
            .map(ValidatedExtensionInit::TreasuryManager)
    })
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
        .map_err(|e| format!("Failed to get SNS treasury balance: {:?}", e))?;
    let icp_balance = governance
        .nns_ledger
        .account_balance(Account {
            owner: governance.env.canister_id().get().0,
            subaccount: icp_subaccount,
        })
        .await
        .map_err(|e| format!("Failed to get ICP treasury balance: {:?}", e))?;

    let icp_requested = Tokens::from_e8s(structurally_valid.treasury_allocation_icp_e8s);
    let sns_requested = Tokens::from_e8s(structurally_valid.treasury_allocation_sns_e8s);

    // Unwrap is safe, only fails if divisor is zero, which we don't do.
    if sns_requested > sns_balance.checked_div(2).unwrap() {
        return Err(format!(
            "SNS treasury deposit request of {} exceeds 50% of current SNS Token balance of {}",
            sns_requested, sns_balance
        ));
    }

    if icp_requested > icp_balance.checked_div(2).unwrap() {
        return Err(format!(
            "ICP treasury deposit request of {} exceeds 50% of current ICP balance of {}",
            icp_requested, icp_balance
        ));
    }

    Ok(structurally_valid)
}

/// Validates deposit operation arguments
fn validate_deposit_operation(
    governance: &Governance,
    arg: ExtensionOperationArg,
) -> BoxFuture<Result<ValidatedOperationArg, String>> {
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
) -> BoxFuture<Result<ValidatedOperationArg, String>> {
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
                ExtensionOperationSpec {
                    name: "deposit".to_string(),
                    description: "Deposit funds into the treasury manager.".to_string(),
                    extension_type: ExtensionType::TreasuryManager,
                    validate_arg: validate_deposit_operation,
                },
                ExtensionOperationSpec {
                    name: "withdraw".to_string(),
                    description: "Withdraw funds from the treasury manager.".to_string(),
                    extension_type: ExtensionType::TreasuryManager,
                    validate_arg: validate_withdraw_operation,
                },
            ],
            // Future extension types would define their standard operations here
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionVersion(u64);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionSpec {
    pub name: String,
    pub version: ExtensionVersion,
    pub topic: Topic,
    /// The extension types this extension implements (can be multiple)
    pub extension_types: Vec<ExtensionType>,
    // Custom per-extension operations can be added here in the future
    // TODO: Add a way to specify initialization arguments schema for the extension.
    pub validate_init_arg:
        fn(&Governance, ExtensionInit) -> BoxFuture<Result<ValidatedExtensionInit, String>>,
}

impl ExtensionSpec {
    /// Validates that there are no operation name conflicts
    pub fn validate(&self) -> Result<(), String> {
        // This restriction may be relaxed later, but at present each extension type can only
        // have one responsibility.
        if self.extension_types.len() > 1 {
            return Err("ExtensionSpec can only have one extension type at a time".to_string());
        }

        // NOTE - if we support custom operations, we will need validation to prevent
        // name collisions.

        Ok(())
    }

    pub async fn validate_init_arg(
        &self,
        gov: &Governance,
        init: ExtensionInit,
    ) -> Result<ValidatedExtensionInit, String> {
        (self.validate_init_arg)(gov, init).await
    }

    /// Get all operations for this extension
    /// Returns error if there are conflicts
    pub fn all_operations(&self) -> Result<BTreeMap<String, ExtensionOperationSpec>, String> {
        self.validate()?;

        let mut operations = BTreeMap::new();

        // Add standard operations from each extension type
        for ext_type in &self.extension_types {
            for op in ext_type.standard_operations() {
                operations.insert(op.name().to_string(), op);
            }
        }

        Ok(operations)
    }

    /// Get a specific operation by name
    /// Standard operations take precedence to ensure deterministic behavior
    pub fn get_operation(&self, name: &str) -> Option<ExtensionOperationSpec> {
        // validate() ensures no name conflicts, so we can safely look up operations this way
        for ext_type in &self.extension_types {
            for op in ext_type.standard_operations() {
                if op.name() == name {
                    return Some(op);
                }
            }
        }

        None
    }

    pub fn supports_extension_type(&self, extension_type: ExtensionType) -> bool {
        self.extension_types.contains(&extension_type)
    }
}

impl Display for ExtensionSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let operations_str = match self.all_operations() {
            Ok(ops) => ops.keys().cloned().collect::<Vec<_>>().join(", "),
            Err(e) => format!("<invalid: {}>", e),
        };

        write!(
            f,
            "SNS Extension {{ name: {}, topic: {}, types: {:?}, operations: {} }}",
            self.name, self.topic, self.extension_types, operations_str
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
        let context = governance.treasury_manager_deposit_context().await?;

        let ValidatedRegisterExtension {
            spec: _,
            init,
            extension_canister_id,
            wasm,
        } = self;

        governance
            .register_extension_with_root(extension_canister_id)
            .await?;

        // This needs to happen before the canister code is installed.
        let init_blob = match init {
            ValidatedExtensionInit::TreasuryManager(ValidatedDepositOperationArg {
                treasury_allocation_sns_e8s,
                treasury_allocation_icp_e8s,
                original,
            }) => {
                let init_blob = construct_treasury_manager_init_payload(context.clone(), original)
                    .map_err(|err| {
                        GovernanceError::new_with_message(
                            ErrorType::InvalidProposal,
                            format!("Error constructing TreasuryManagerInit payload: {}", err),
                        )
                    })?;

                governance
                    .deposit_treasury_manager(
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

        Ok(())
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
        let payload = candid::Encode!(&RegisterExtensionRequest {
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
                format!(
                    "Root.register_extension failed with code {}: {}",
                    code, description
                ),
            ));
        }

        log!(
            INFO,
            "Root.register_extension succeeded for canister {}",
            extension_canister_id.get()
        );

        Ok(())
    }

    pub async fn deposit_treasury_manager(
        &self,
        treasury_manager_canister_id: CanisterId,
        sns_amount_e8s: u64,
        icp_amount_e8s: u64,
    ) -> Result<(), GovernanceError> {
        let treasury_sns_subaccount = self.sns_treasury_subaccount();
        let treasury_icp_subaccount = self.icp_treasury_subaccount();

        let to = Account {
            owner: treasury_manager_canister_id.get().0,
            subaccount: None,
        };

        self.ledger
            .transfer_funds(
                sns_amount_e8s,
                self.transaction_fee_e8s_or_panic(),
                treasury_sns_subaccount,
                to,
                0,
            )
            .await
            .map(|_| ())
            .map_err(|e| {
                GovernanceError::new_with_message(
                    ErrorType::External,
                    format!("Error making SNS Token treasury transfer: {}", e),
                )
            })?;

        self.nns_ledger
            .transfer_funds(
                icp_amount_e8s,
                icp_ledger::DEFAULT_TRANSFER_FEE.get_e8s(),
                treasury_icp_subaccount,
                to,
                0,
            )
            .await
            .map(|_| ())
            .map_err(|e| {
                GovernanceError::new_with_message(
                    ErrorType::External,
                    format!("Error making ICP treasury transfer: {}", e),
                )
            })?;

        Ok(())
    }
}

pub mod treasury_manager {
    use candid::Nat;
    use sns_treasury_manager::{Account, Allowance, Asset};

    use crate::pb::v1::{precise, Precise, PreciseMap};

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
            return Err(format!("{}Top-level type must be PreciseMap.", PREFIX));
        };

        if map.len() != 2 {
            return Err(format!(
                "{}Top-level type must be PreciseMap with exactly 2 entries.",
                PREFIX
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
                .ok_or_else(|| format!("{}{} must contain a precise value.", PREFIX, field_name))
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

    if cfg!(feature = "test") {
        // In feature test mode, accept any wasm hash and return a test spec
        Ok(ExtensionSpec {
            name: "Test Extension".to_string(),
            version: ExtensionVersion(1),
            topic: Topic::TreasuryAssetManagement,
            extension_types: vec![ExtensionType::TreasuryManager],
            validate_init_arg: validate_treasury_manager_init,
        })
    } else if cfg!(all(test, not(feature = "test"))) {
        // In regular test mode (without feature), use the test allowed extensions
        let test_allowed = create_test_allowed_extensions();
        validate_extension_wasm_with_allowed(wasm_module_hash, &test_allowed)
    } else {
        validate_extension_wasm_with_allowed(wasm_module_hash, &ALLOWED_EXTENSIONS)
    }
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
        // Validate the spec to ensure no conflicting method names.
        spec.validate()?;
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
                format!(
                    "Canister method call Root.list_sns_canisters failed: {:?}",
                    err
                ),
            )
        })
        .and_then(|blob| {
            Decode!(&blob, ListSnsCanistersResponse).map_err(|err| {
                GovernanceError::new_with_message(
                    ErrorType::External,
                    format!("Error decoding Root.list_sns_canisters response: {:?}", err),
                )
            })
        })?;

    let extensions = extensions
        .map(|extensions| extensions.extension_canister_ids)
        .unwrap_or_default();

    Ok(extensions)
}

async fn canister_module_hash(
    env: &dyn Environment,
    canister_id: CanisterId,
) -> Result<Vec<u8>, GovernanceError> {
    let canister_info_arg =
        Encode!(&CanisterInfoRequest::new(canister_id, Some(1),)).map_err(|err| {
            GovernanceError::new_with_message(
                ErrorType::External,
                format!("Error encoding canister_info request.\n{}", err),
            )
        })?;

    let response = env
        .call_canister(CanisterId::ic_00(), "canister_info", canister_info_arg)
        .await
        .map_err(|err: (Option<i32>, String)| {
            GovernanceError::new_with_message(
                ErrorType::External,
                format!("Canister method call IC00.canister_info failed: {:?}", err),
            )
        })
        .and_then(|blob| {
            Decode!(&blob, CanisterInfoResponse).map_err(|err| {
                GovernanceError::new_with_message(
                    ErrorType::External,
                    format!("Error decoding IC00.canister_info response:\n{}", err),
                )
            })
        })?;

    Ok(response.module_hash().unwrap_or_default())
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
    .map_err(|err| format!("Error extracting initial allowances: {}", err))?;

    Ok(allowances)
}

/// Returns `arg_blob` in the Ok result.
pub fn construct_treasury_manager_init_payload(
    context: TreasuryManagerDepositContext,
    value: Precise,
) -> Result<Vec<u8>, String> {
    let allowances = construct_treasury_manager_deposit_allowances(context, value)?;

    let arg = TreasuryManagerArg::Init(TreasuryManagerInit { allowances });
    let arg = candid::encode_one(&arg)
        .map_err(|err| format!("Error encoding TreasuryManagerArg: {}", err))?;

    Ok(arg)
}

/// Returns `arg_blob` in the Ok result.
fn construct_treasury_manager_deposit_payload(
    context: TreasuryManagerDepositContext,
    value: Precise,
) -> Result<Vec<u8>, String> {
    let allowances = construct_treasury_manager_deposit_allowances(context, value)?;

    let arg = DepositRequest { allowances };
    let arg = candid::encode_one(&arg)
        .map_err(|err| format!("Error encoding DepositRequest: {}", err))?;

    Ok(arg)
}

/// Returns `arg_blob` in the Ok result.
fn construct_treasury_manager_withdraw_payload(_value: Precise) -> Result<Vec<u8>, String> {
    let arg = WithdrawRequest {
        withdraw_accounts: None,
    };
    let arg = candid::encode_one(&arg)
        .map_err(|err| format!("Error encoding WithdrawRequest: {}", err))?;

    Ok(arg)
}

pub async fn validate_register_extension(
    governance: &Governance,
    register_extension: RegisterExtension,
) -> Result<ValidatedRegisterExtension, GovernanceError> {
    let RegisterExtension {
        chunked_canister_wasm,
        extension_init,
    } = register_extension;

    // Phase I. Validate all local properties.
    let (spec, wasm, extension_canister_id, init) = (async {
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
            .map_err(|err| format!("Invalid store_canister_id: {}", err))?;

        // Use the store canister to install the extension itself.
        let extension_canister_id = store_canister_id;

        let spec = validate_extension_wasm(&wasm_module_hash)
            .map_err(|err| format!("Invalid extension wasm: {}", err))?;

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
            .map_err(|err| format!("Invalid init argument: {}", err))?;

        Ok::<_, String>((spec, wasm, extension_canister_id, init))
    })
    .await
    .map_err(|err| {
        GovernanceError::new_with_message(
            ErrorType::InvalidProposal,
            format!("Invalid RegisterExtension: {:?}", err),
        )
    })?;

    Ok(ValidatedRegisterExtension {
        wasm,
        extension_canister_id,
        spec,
        init,
    })
}

/// Validates that this is a supported extension operation.
pub(crate) async fn validate_execute_extension_operation(
    governance: &crate::governance::Governance,
    operation: ExecuteExtensionOperation,
) -> Result<ValidatedExecuteExtensionOperation, GovernanceError> {
    let governance_proto = &governance.proto;
    let env = &*governance.env;

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
                format!(
                    "Cannot interpret extension_canister_id as canister ID: {}",
                    err
                ),
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

    let root_canister_id = governance_proto.root_canister_id_or_panic();
    let registered_extensions = list_extensions(env, root_canister_id).await?;

    if !registered_extensions.contains(&extension_canister_id.get()) {
        return Err(GovernanceError::new_with_message(
            ErrorType::NotFound,
            format!(
                "Extension canister {} is not registered with the SNS.",
                extension_canister_id
            ),
        ));
    }

    let wasm_module_hash = canister_module_hash(env, extension_canister_id).await?;

    let extension_spec = match validate_extension_wasm(&wasm_module_hash) {
        Ok(spec) => spec,
        Err(err) => {
            return Err(GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                format!(
                    "Extension canister {} does not have an extension spec despite being \
                        registered with Root: {}",
                    extension_canister_id, err,
                ),
            ));
        }
    };

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
                "Extension canister {} does not have an operation named {}",
                extension_canister_id, operation_name
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
                    "Extension canister {} operation {} validation failed: {}",
                    extension_canister_id, operation_name, err
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

    // 1. Transfer funds from treasury to treasury manager
    governance
        .deposit_treasury_manager(
            extension_canister_id,
            treasury_allocation_sns_e8s,
            treasury_allocation_icp_e8s,
        )
        .await?;

    let context = governance.treasury_manager_deposit_context().await?;
    let arg_blob =
        construct_treasury_manager_deposit_payload(context, original).map_err(|err| {
            GovernanceError::new_with_message(
                ErrorType::PreconditionFailed,
                format!(
                    "Failed to construct treasury manager deposit payload: {}",
                    err
                ),
            )
        })?;

    // 2. Call deposit on treasury manager
    let balances = governance
        .env
        .call_canister(extension_canister_id, "deposit", arg_blob)
        .await
        .map_err(|(code, err)| {
            GovernanceError::new_with_message(
                ErrorType::External,
                format!(
                    "Canister method call {}.deposit failed with code {:?}: {}",
                    extension_canister_id, code, err
                ),
            )
        })
        .and_then(|blob| {
            Decode!(&blob, sns_treasury_manager::TreasuryManagerResult).map_err(|err| {
                GovernanceError::new_with_message(
                    ErrorType::External,
                    format!("Error decoding TreasuryManager.deposit response: {:?}", err),
                )
            })
        })?
        .map_err(|err| {
            GovernanceError::new_with_message(
                ErrorType::External,
                format!("TreasuryManager.deposit failed: {:?}", err),
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
            format!(
                "Failed to construct treasury manager withdraw payload: {}",
                err
            ),
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
                    "Canister method call {}.withdraw failed with code {:?}: {}",
                    extension_canister_id, code, err
                ),
            )
        })
        .and_then(|blob| {
            Decode!(&blob, sns_treasury_manager::TreasuryManagerResult).map_err(|err| {
                GovernanceError::new_with_message(
                    ErrorType::External,
                    format!(
                        "Error decoding TreasuryManager.withdraw response: {:?}",
                        err
                    ),
                )
            })
        })?
        .map_err(|err| {
            GovernanceError::new_with_message(
                ErrorType::External,
                format!("TreasuryManager.withdraw failed: {:?}", err),
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
                    "Canister method call {}.deposit failed with code {:?}: {}",
                    ledger_canister_id, code, err
                ),
            )
        })
        .map(|blob| {
            Decode!(&blob, String).map_err(|err| {
                GovernanceError::new_with_message(
                    ErrorType::External,
                    format!(
                        "Error decoding {}.icrc1_symbol response: {}",
                        ledger_canister_id, err
                    ),
                )
            })
        })??;

    Ok(symbol)
}

/// Helper function to create test allowed extensions map
fn create_test_allowed_extensions() -> BTreeMap<[u8; 32], ExtensionSpec> {
    // Using a predictable test hash
    let test_hash: [u8; 32] = [
        1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];
    btreemap! {
        test_hash => ExtensionSpec {
            name: "My Test Extension".to_string(),
            version: ExtensionVersion(1),
            topic: Topic::TreasuryAssetManagement,
            extension_types: vec![ExtensionType::TreasuryManager],
            validate_init_arg: validate_treasury_manager_init,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance::{Governance, ValidGovernanceProto};
    use crate::pb::sns_root_types::{ListSnsCanistersRequest, ListSnsCanistersResponse};
    use crate::pb::v1::{
        governance, governance::SnsMetadata, Governance as GovernanceProto, NervousSystemParameters,
    };
    use crate::types::test_helpers::NativeEnvironment;
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
        if extension_registered {
            // Get the test hash from our test allowed extensions
            let test_hash: Vec<u8> = vec![
                1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
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
        assert!(error
            .error_message
            .contains("is not registered with the SNS"));
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
        assert!(error
            .error_message
            .contains("does not have an operation named invalid_operation"));
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
            RegisterExtension {
                chunked_canister_wasm: Some(ChunkedCanisterWasm {
                    wasm_module_hash: vec![
                        1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0,
                    ],
                    store_canister_id: Some(CanisterId::from_u64(10000).get()),
                    chunk_hashes_list: vec![],
                }),
                extension_init: Some(ExtensionInit {
                    value: Some(Precise {
                        value: Some(precise::Value::Map(PreciseMap {
                            map: btreemap! {
                                "treasury_allocation_sns_e8s".to_string() => Precise { value: Some(precise::Value::Nat(1000000)) },
                                "treasury_allocation_icp_e8s".to_string() => Precise { value: Some(precise::Value::Nat(2000000)) },
                            },
                        })),
                    }),
                }),
            }
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
        assert_eq!(
            err,
            GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                "Invalid RegisterExtension: \"chunked_canister_wasm is required\""
            )
        );

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
        assert_eq!(
            err,
            GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                "Invalid RegisterExtension: \"chunked_canister_wasm.store_canister_id is required\""
            )
        );

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
        assert!(err.error_message.contains("invalid principal id"));

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
            GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                "Invalid RegisterExtension: \"Invalid extension wasm: Invalid wasm module hash length: expected 32 bytes, got 16\""
            )
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
        assert!(err
            .error_message
            .contains("RegisterExtension.extension_init is required"));

        // Test wasm not in whitelist (in non-test mode this would fail)
        // Since we're in test mode, this will succeed, so we can't test the whitelist rejection here
        // That would need to be tested in an integration test or with special test setup
    }

    #[tokio::test]
    async fn test_validate_register_extension_treasury_manager_init() {
        // Test that validate_register_extension (init path) validates treasury manager init
        // the same way as validate_deposit_operation validates deposits
        let governance = setup_governance_with_treasury_balances(100_000_000, 200_000_000);

        // Build a helper to invoke validate_register_extension with a given precise value
        let mk_register_extension = |value: Option<Precise>| RegisterExtension {
            chunked_canister_wasm: Some(ChunkedCanisterWasm {
                wasm_module_hash: vec![
                    1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ],
                store_canister_id: Some(CanisterId::from_u64(2000).get()),
                chunk_hashes_list: vec![],
            }),
            extension_init: Some(ExtensionInit { value }),
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
        assert!(err
            .error_message
            .contains("treasury_allocation_sns_e8s must be a Nat value"));

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
        assert!(err
            .error_message
            .contains("treasury_allocation_icp_e8s must be a Nat value"));

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
        assert!(err
            .error_message
            .contains("treasury_allocation_sns_e8s must be a Nat value"));

        // Structural validation failure: no arguments
        let no_args_init = mk_register_extension(None);
        let err = validate_register_extension(&governance, no_args_init)
            .await
            .unwrap_err();
        assert!(err
            .error_message
            .contains("Deposit operation arguments must be provided"));

        // Structural validation failure: not a map
        let not_map_init = mk_register_extension(Some(Precise {
            value: Some(precise::Value::Text("not a map".to_string())),
        }));
        let err = validate_register_extension(&governance, not_map_init)
            .await
            .unwrap_err();
        assert!(err
            .error_message
            .contains("Deposit operation arguments must be a PreciseMap"));
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
                100_000_000, 200_000_000, 50_000_000, 100_000_000, Ok(())
            ),
            (
                "Positive: below 50%",
                100_000_000, 200_000_000, 30_000_000, 60_000_000, Ok(())
            ),
            (
                "Positive: zero amounts",
                100_000_000, 200_000_000, 0, 0, Ok(())
            ),
            (
                "Negative: SNS exceeds 50%",
                100_000_000, 200_000_000, 51_000_000, 50_000_000,
                Err("SNS treasury deposit request of 0.51000000 Token exceeds 50% of current SNS Token balance")
            ),
            (
                "Negative: ICP exceeds 50%",
                100_000_000, 200_000_000, 40_000_000, 101_000_000,
                Err("ICP treasury deposit request of 1.01000000 Token exceeds 50% of current ICP balance")
            ),
            (
                "Negative: both exceed 50% (SNS checked first)",
                100_000_000, 200_000_000, 60_000_000, 120_000_000,
                Err("SNS treasury deposit request of 0.60000000 Token exceeds 50% of current SNS Token balance")
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
                    assert!(result.is_ok(),
                        "{}: Expected success for sns_balance={}, icp_balance={}, sns_request={}, icp_request={}, but got: {:?}",
                        label, sns_balance, icp_balance, sns_request, icp_request, result);
                }
                Err(expected_substr) => {
                    let error = result.unwrap_err();
                    assert!(error.contains(expected_substr),
                        "{}: Expected error containing '{}' for sns_balance={}, icp_balance={}, sns_request={}, icp_request={}, but got: {}",
                        label, expected_substr, sns_balance, icp_balance, sns_request, icp_request, error);
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
    fn test_extension_spec_validate_multiple_extension_types() {
        // Test that ExtensionSpec can only have one extension type at a time
        let spec = ExtensionSpec {
            name: "test_extension".to_string(),
            version: ExtensionVersion(1),
            topic: Topic::Governance,
            extension_types: vec![
                ExtensionType::TreasuryManager,
                ExtensionType::TreasuryManager,
            ],
            validate_init_arg: validate_treasury_manager_init,
        };

        let result = spec.validate();
        assert_eq!(
            result.unwrap_err(),
            "ExtensionSpec can only have one extension type at a time"
        );

        // Test that single extension type validates successfully
        let spec = ExtensionSpec {
            name: "test_extension".to_string(),
            version: ExtensionVersion(1),
            topic: Topic::Governance,
            extension_types: vec![ExtensionType::TreasuryManager],
            validate_init_arg: validate_treasury_manager_init,
        };

        assert!(spec.validate().is_ok());
    }
}
