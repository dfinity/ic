use crate::{
    governance::{Governance, TREASURY_SUBACCOUNT_NONCE},
    pb::{
        sns_root_types::{ListSnsCanistersRequest, ListSnsCanistersResponse},
        v1::{
            governance_error::ErrorType, precise, ChunkedCanisterWasm, ExecuteExtensionOperation,
            ExtensionInit, ExtensionOperationArg, GovernanceError, Precise, PreciseMap,
            RegisterExtension, Topic,
        },
    },
    types::{Environment, Wasm},
};
use candid::{Decode, Encode, Nat};
use ic_base_types::{CanisterId, PrincipalId};
use ic_management_canister_types_private::{CanisterInfoRequest, CanisterInfoResponse};
use ic_nervous_system_common::ledger::compute_distribution_subaccount_bytes;
use icrc_ledger_types::icrc1::account::Account;
use lazy_static::lazy_static;
use maplit::btreemap;
use sns_treasury_manager::{
    Allowance, Asset, DepositRequest, TreasuryManagerArg, TreasuryManagerInit,
};

use std::{collections::BTreeMap, fmt::Display};

lazy_static! {
    static ref ALLOWED_EXTENSIONS: BTreeMap<[u8; 32], ExtensionSpec> = btreemap! {};
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

/// Enum that captures all possible validated operation arguments
#[derive(Clone, Debug)]
pub enum ValidatedOperationArg {
    // Treasury Manager operations
    TreasuryManagerDeposit(ValidatedDepositOperationArg),
    TreasuryManagerWithdraw(ValidatedWithdrawOperationArg),
    // Future: other extension type operations would go here
    // VotingCreatePoll(ValidatedCreatePollArg),
    // etc.
    // This one is for generic operations that governance doesn't validate
    Unprocessed(ExtensionOperationArg),
}

impl ValidatedOperationArg {
    /// Returns the original Precise value that was validated
    pub fn get_original_value(&self) -> &ExtensionOperationArg {
        match self {
            Self::TreasuryManagerDeposit(arg) => &arg.original,
            Self::TreasuryManagerWithdraw(arg) => &arg.original,
            Self::Unprocessed(arg) => &arg,
        }
    }

    /// Renders the operation arguments as markdown suitable for proposal display
    pub fn render_for_proposal(&self) -> String {
        match self {
            Self::TreasuryManagerDeposit(args) => args.render_for_proposal(),
            Self::TreasuryManagerWithdraw(args) => args.render_for_proposal(),
            Self::Unprocessed(args) => args.render_for_proposal(),
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

impl RenderablePayload for ExtensionOperationArg {
    fn render_for_proposal(&self) -> String {
        match &self.value {
            Some(value) => format!(
                r#"### Extension Operation

**Raw Payload:**
```
{:#?}
```"#,
                value
            ),
            None => "### Extension Operation\n\n*No payload provided*".to_string(),
        }
    }
}

/// Specification for an extension operation
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationSpec {
    pub name: String,
    pub description: String,
    pub extension_type: ExtensionType,
    pub validate: fn(ExtensionOperationArg) -> Result<ValidatedOperationArg, String>,
}

impl OperationSpec {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    pub fn validate(&self, arg: ExtensionOperationArg) -> Result<ValidatedOperationArg, String> {
        (self.validate)(arg)
    }
}

/// Validates deposit operation arguments
fn validate_deposit_operation(arg: ExtensionOperationArg) -> Result<ValidatedOperationArg, String> {
    ValidatedDepositOperationArg::try_from(arg).map(ValidatedOperationArg::TreasuryManagerDeposit)
}

/// Validates withdraw operation arguments (currently no validation, just passes through)
fn validate_withdraw_operation(
    arg: ExtensionOperationArg,
) -> Result<ValidatedOperationArg, String> {
    ValidatedWithdrawOperationArg::try_from(arg).map(ValidatedOperationArg::TreasuryManagerWithdraw)
}

impl ExtensionType {
    pub fn standard_operations(&self) -> Vec<OperationSpec> {
        match self {
            ExtensionType::TreasuryManager => vec![
                OperationSpec {
                    name: "deposit".to_string(),
                    description: "Deposit funds into the treasury manager.".to_string(),
                    extension_type: ExtensionType::TreasuryManager,
                    validate: validate_deposit_operation,
                },
                OperationSpec {
                    name: "withdraw".to_string(),
                    description: "Withdraw funds from the treasury manager.".to_string(),
                    extension_type: ExtensionType::TreasuryManager,
                    validate: validate_withdraw_operation,
                },
            ],
            // Future extension types would define their standard operations here
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExtensionVersion(u64);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionSpec {
    pub name: String,
    pub version: ExtensionVersion,
    pub topic: Topic,
    /// The extension types this extension implements (can be multiple)
    pub extension_types: Vec<ExtensionType>,
    // Custom per-extension operations can be added here in the future
    // TODO: Add a way to specify initialization arguments schema for the extension.
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

    /// Get all operations (standard + other) for this extension
    /// Returns error if there are conflicts
    pub fn all_operations(&self) -> Result<BTreeMap<String, OperationSpec>, String> {
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
    pub fn get_operation(&self, name: &str) -> Option<OperationSpec> {
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

pub struct ValidatedRegisterExtension {
    pub wasm: Wasm,
    pub spec: ExtensionSpec,
    pub init: ExtensionInit,
}

#[derive(Debug)]
pub struct ValidatedExecuteExtensionOperation {
    pub extension_canister_id: CanisterId,
    pub operation_name: String,
    pub operation_arg: ExtensionOperationArg,
}

impl Governance {
    /// Returns the ICRC-1 subaccounts for the SNS treasury and ICP treasury.
    fn treasury_subaccounts(&self) -> (Option<[u8; 32]>, Option<[u8; 32]>) {
        // See ic_sns_init::distributions::FractionalDeveloperVotingPower.insert_treasury_accounts
        let treasury_sns_subaccount = Some(compute_distribution_subaccount_bytes(
            self.env.canister_id().get(),
            TREASURY_SUBACCOUNT_NONCE,
        ));
        let treasury_icp_subaccount = None;
        (treasury_sns_subaccount, treasury_icp_subaccount)
    }

    async fn construct_treasury_manager_deposit_allowances(
        &self,
        value: Option<Precise>,
    ) -> Result<(Vec<Allowance>, u64, u64), GovernanceError> {
        // See ic_sns_init::distributions::FractionalDeveloperVotingPower.insert_treasury_accounts
        let (treasury_sns_subaccount, treasury_icp_subaccount) = self.treasury_subaccounts();

        let sns_token_symbol = get_sns_token_symbol(&*self.env, self.ledger.canister_id()).await?;

        let (allowances, sns_amount_e8s, icp_amount_e8s) =
            treasury_manager::construct_deposit_allowances(
                value,
                Asset::Token {
                    symbol: sns_token_symbol,
                    ledger_canister_id: self.ledger.canister_id().get().0,
                    ledger_fee_decimals: Nat::from(self.transaction_fee_e8s_or_panic()),
                },
                Asset::Token {
                    symbol: "ICP".to_string(),
                    ledger_canister_id: self.nns_ledger.canister_id().get().0,
                    ledger_fee_decimals: Nat::from(icp_ledger::DEFAULT_TRANSFER_FEE.get_e8s()),
                },
                sns_treasury_manager::Account {
                    owner: self.env.canister_id().get().0,
                    subaccount: treasury_sns_subaccount,
                },
                sns_treasury_manager::Account {
                    owner: self.env.canister_id().get().0,
                    subaccount: treasury_icp_subaccount,
                },
            )
            .map_err(|err| {
                GovernanceError::new_with_message(
                    ErrorType::InvalidProposal,
                    format!("Error extracting initial allowances: {}", err),
                )
            })?;

        Ok((allowances, sns_amount_e8s, icp_amount_e8s))
    }

    /// Returns `(arg_blob, sns_token_amount_e8s, icp_token_amount_e8s)` in the Ok result.
    pub async fn construct_treasury_manager_init_payload(
        &self,
        init: ExtensionInit,
    ) -> Result<(Vec<u8>, u64, u64), GovernanceError> {
        let (allowances, sns_amount_e8s, icp_amount_e8s) = self
            .construct_treasury_manager_deposit_allowances(init.value)
            .await?;

        let arg = TreasuryManagerArg::Init(TreasuryManagerInit { allowances });
        let arg: Vec<u8> = candid::encode_one(&arg).map_err(|err| {
            GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                format!("Error encoding TreasuryManagerArg: {}", err),
            )
        })?;

        Ok((arg, sns_amount_e8s, icp_amount_e8s))
    }

    /// Returns `(arg_blob, sns_token_amount_e8s, icp_token_amount_e8s)` in the Ok result.
    pub async fn construct_treasury_manager_deposit_payload(
        &self,
        arg: ExtensionOperationArg,
    ) -> Result<(Vec<u8>, u64, u64), GovernanceError> {
        let (allowances, sns_amount_e8s, icp_amount_e8s) = self
            .construct_treasury_manager_deposit_allowances(arg.value)
            .await?;

        let arg = DepositRequest { allowances };
        let arg: Vec<u8> = candid::encode_one(&arg).map_err(|err| {
            GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                format!("Error encoding DepositRequest: {}", err),
            )
        })?;

        Ok((arg, sns_amount_e8s, icp_amount_e8s))
    }

    pub async fn deposit_treasury_manager(
        &self,
        treasury_manager_canister_id: CanisterId,
        sns_amount_e8s: u64,
        icp_amount_e8s: u64,
    ) -> Result<(), GovernanceError> {
        let (treasury_sns_subaccount, treasury_icp_subaccount) = self.treasury_subaccounts();

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

impl TryFrom<ExecuteExtensionOperation> for ValidatedExecuteExtensionOperation {
    type Error = String;

    fn try_from(value: ExecuteExtensionOperation) -> Result<Self, Self::Error> {
        let ExecuteExtensionOperation {
            extension_canister_id,
            operation_name,
            operation_arg,
        } = value;

        let Some(extension_canister_id) = extension_canister_id else {
            return Err("extension_canister_id is required.".to_string());
        };

        let extension_canister_id = match CanisterId::try_from_principal_id(extension_canister_id) {
            Ok(id) => id,
            Err(err) => {
                return Err(format!(
                    "Cannot interpret extension_canister_id as canister ID: {}",
                    err
                ));
            }
        };

        let Some(operation_name) = operation_name else {
            return Err("operation_name is required.".to_string());
        };

        let Some(operation_arg) = operation_arg else {
            return Err("operation_arg is required.".to_string());
        };

        Ok(Self {
            extension_canister_id,
            operation_name,
            operation_arg,
        })
    }
}

pub mod treasury_manager {
    use candid::Nat;
    use sns_treasury_manager::{Account, Allowance, Asset};

    use crate::pb::v1::{precise, Precise, PreciseMap};

    /// Returns `(init, sns_token_amount_e8s, icp_token_amount_e8s)` in the Ok result.
    pub fn construct_deposit_allowances(
        arg: Option<Precise>,
        sns_token: Asset,
        icp_token: Asset,
        treasury_sns_account: Account,
        treasury_icp_account: Account,
    ) -> Result<(Vec<Allowance>, u64, u64), String> {
        const PREFIX: &str = "Cannot parse ExtensionInit as TreasuryManagerInit: ";

        let mut map = match arg {
            Some(Precise {
                value: Some(precise::Value::Map(PreciseMap { map })),
            }) => map,
            _ => {
                return Err(format!("{}Top-level type must be PreciseMap.", PREFIX));
            }
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
        Ok((allowances, sns_token_amount_e8s, icp_token_amount_e8s))
    }
}

impl TryFrom<RegisterExtension> for ValidatedRegisterExtension {
    type Error = String;

    fn try_from(value: RegisterExtension) -> Result<Self, Self::Error> {
        let RegisterExtension {
            chunked_canister_wasm,
            extension_init,
        } = value;

        let Some(ChunkedCanisterWasm {
            wasm_module_hash,
            store_canister_id,
            chunk_hashes_list,
        }) = chunked_canister_wasm
        else {
            return Err("chunked_canister_wasm is required".to_string());
        };

        let Some(store_canister_id) = store_canister_id else {
            return Err("chunked_canister_wasm.store_canister_id".to_string());
        };

        let store_canister_id = CanisterId::try_from_principal_id(store_canister_id)
            .map_err(|err| format!("Invalid store_canister_id: {}", err))?;

        let spec = validate_extension_wasm(&wasm_module_hash)
            .map_err(|err| format!("Invalid extension wasm: {err:?}"))?;

        let wasm = Wasm::Chunked {
            wasm_module_hash,
            store_canister_id,
            chunk_hashes_list,
        };

        let Some(init) = extension_init else {
            return Err("RegisterExtension.extension_init is required".to_string());
        };

        Ok(Self { wasm, spec, init })
    }
}

/// Validates an extension WASM against a provided set of allowed extensions.
pub(crate) fn validate_extension_wasm_with_allowed(
    wasm_module_hash: &[u8],
    allowed_extensions: &BTreeMap<[u8; 32], ExtensionSpec>,
) -> Result<ExtensionSpec, String> {
    // Convert the hash to the expected array size if needed
    let hash_array: [u8; 32] = if wasm_module_hash.len() == 32 {
        wasm_module_hash.try_into().unwrap()
    } else {
        return Err(format!(
            "Invalid wasm module hash length: expected 32 bytes, got {}",
            wasm_module_hash.len()
        ));
    };

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

/// Validates an extension WASM against the global ALLOWED_EXTENSIONS.
pub(crate) fn validate_extension_wasm(wasm_module_hash: &[u8]) -> Result<ExtensionSpec, String> {
    #[cfg(any(test, feature = "test"))]
    {
        // In tests, use the test allowed extensions
        let test_allowed = create_test_allowed_extensions();
        validate_extension_wasm_with_allowed(wasm_module_hash, &test_allowed)
    }
    #[cfg(not(any(test, feature = "test")))]
    {
        validate_extension_wasm_with_allowed(wasm_module_hash, &ALLOWED_EXTENSIONS)
    }
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

/// Validates that this is a supported extension operation.
// TODO: Validate the operation arguments as well.
// TODO: Enforce 50% treasury limits.
pub(crate) async fn validate_execute_extension_operation(
    env: &dyn Environment,
    root_canister_id: CanisterId,
    extension_canister_id: CanisterId,
    operation_name: String,
    operation_arg: &ExtensionOperationArg,
) -> Result<ValidatedOperationArg, GovernanceError> {
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
    if extension_spec.extension_types != vec![ExtensionType::TreasuryManager] {
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

    operation_spec
        .validate(operation_arg.clone())
        .map_err(|err| {
            GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                format!(
                    "Extension canister {} operation {} validation failed: {}",
                    extension_canister_id, operation_name, err
                ),
            )
        })
}

/// Validated deposit operation arguments
#[derive(Debug, Clone)]
pub struct ValidatedDepositOperationArg {
    /// Amount of SNS tokens to allocate from treasury
    pub treasury_allocation_sns_e8s: u64,
    /// Amount of ICP tokens to allocate from treasury
    pub treasury_allocation_icp_e8s: u64,
    /// Original Precise value with all fields
    original: ExtensionOperationArg,
}

impl TryFrom<ExtensionOperationArg> for ValidatedDepositOperationArg {
    type Error = String;

    fn try_from(arg: ExtensionOperationArg) -> Result<Self, Self::Error> {
        let ExtensionOperationArg { value: Some(value) } = &arg else {
            return Err("Deposit operation arguments must be provided".to_string());
        };

        let map = match &value.value {
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
            original: arg,
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
    original: ExtensionOperationArg,
}

impl TryFrom<ExtensionOperationArg> for ValidatedWithdrawOperationArg {
    type Error = String;

    fn try_from(arg: ExtensionOperationArg) -> Result<Self, Self::Error> {
        // For now, just ensure arguments are provided
        // No actual validation is performed
        if arg.value.is_none() {
            return Err("Withdraw operation arguments must be provided".to_string());
        }

        Ok(Self { original: arg })
    }
}

impl RenderablePayload for ValidatedWithdrawOperationArg {
    fn render_for_proposal(&self) -> String {
        // Since we're not parsing the fields yet, just show the raw operation
        self.original.render_for_proposal()
    }
}

pub(crate) async fn get_sns_token_symbol(
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

/// Helper function to validate test operations - just returns unprocessed
#[cfg(any(test, feature = "test"))]
fn validate_test_operation(arg: ExtensionOperationArg) -> Result<ValidatedOperationArg, String> {
    Ok(ValidatedOperationArg::Unprocessed(arg))
}

/// Helper function to create test allowed extensions map
#[cfg(any(test, feature = "test"))]
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

        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pb::sns_root_types::{ListSnsCanistersRequest, ListSnsCanistersResponse};
    use crate::types::test_helpers::NativeEnvironment;
    use ic_management_canister_types_private::{CanisterInfoRequest, CanisterInfoResponse};
    use maplit::btreemap;

    /// Helper function to set up common environment mocking for validate_execute_extension_operation tests
    fn setup_env_for_test(
        extension_registered: bool,
    ) -> (
        NativeEnvironment,
        CanisterId,
        CanisterId,
        ExtensionOperationArg,
    ) {
        let mut env = NativeEnvironment::new(Some(CanisterId::from_u64(123)));
        let root_canister_id = CanisterId::from_u64(1000);
        let extension_canister_id = CanisterId::from_u64(2000);

        // Mock list_sns_canisters call
        let extension_canister_ids = if extension_registered {
            vec![extension_canister_id.get()]
        } else {
            vec![] // Empty for unregistered extension tests
        };

        env.set_call_canister_response(
            root_canister_id,
            "list_sns_canisters",
            Encode!(&ListSnsCanistersRequest {}).unwrap(),
            Ok(Encode!(&ListSnsCanistersResponse {
                root: Some(root_canister_id.get()),
                governance: Some(CanisterId::from_u64(3000).get()),
                ledger: Some(CanisterId::from_u64(4000).get()),
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

        // Create a valid operation arg for deposit (works for both deposit and withdraw in tests)
        let operation_arg = ExtensionOperationArg {
            value: Some(Precise {
                value: Some(precise::Value::Map(PreciseMap {
                    map: btreemap! {
                        "treasury_allocation_sns_e8s".to_string() => Precise {
                            value: Some(precise::Value::Nat(1000000))
                        },
                        "treasury_allocation_icp_e8s".to_string() => Precise {
                            value: Some(precise::Value::Nat(2000000))
                        },
                        // For withdraw tests, these fields will be ignored by deposit validator
                        "recipient_principal".to_string() => Precise {
                            value: Some(precise::Value::Text("rdmx6-jaaaa-aaaaa-aaadq-cai".to_string()))
                        },
                        "withdrawal_amount_sns_e8s".to_string() => Precise {
                            value: Some(precise::Value::Nat(1000000))
                        },
                        "withdrawal_amount_icp_e8s".to_string() => Precise {
                            value: Some(precise::Value::Nat(2000000))
                        },
                    },
                })),
            }),
        };

        (env, root_canister_id, extension_canister_id, operation_arg)
    }

    #[test]
    fn test_try_from_execute_extension_operation_success() {
        let operation = ExecuteExtensionOperation {
            extension_canister_id: Some(CanisterId::from_u64(123).get()),
            operation_name: Some("deposit".to_string()),
            operation_arg: Some(ExtensionOperationArg { value: None }),
        };

        let result = ValidatedExecuteExtensionOperation::try_from(operation);
        assert!(result.is_ok());

        let validated = result.unwrap();
        assert_eq!(validated.extension_canister_id, CanisterId::from_u64(123));
        assert_eq!(validated.operation_name, "deposit");
    }

    #[test]
    fn test_try_from_execute_extension_operation_missing_canister_id() {
        let operation = ExecuteExtensionOperation {
            extension_canister_id: None, // Missing
            operation_name: Some("deposit".to_string()),
            operation_arg: Some(ExtensionOperationArg { value: None }),
        };

        let result = ValidatedExecuteExtensionOperation::try_from(operation);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("extension_canister_id is required"));
    }

    #[test]
    fn test_try_from_execute_extension_operation_missing_operation_name() {
        let operation = ExecuteExtensionOperation {
            extension_canister_id: Some(CanisterId::from_u64(123).get()),
            operation_name: None, // Missing
            operation_arg: Some(ExtensionOperationArg { value: None }),
        };

        let result = ValidatedExecuteExtensionOperation::try_from(operation);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("operation_name is required"));
    }

    // Tests for validate_execute_extension_operation with proper environment mocking

    #[tokio::test]
    async fn test_validate_execute_extension_operation_success() {
        let (env, root_canister_id, extension_canister_id, operation_arg) =
            setup_env_for_test(true);

        // Test with valid operation name - should succeed
        let result = validate_execute_extension_operation(
            &env,
            root_canister_id,
            extension_canister_id,
            "deposit".to_string(),
            &operation_arg,
        )
        .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_validate_execute_extension_operation_withdraw_success() {
        let (env, root_canister_id, extension_canister_id, operation_arg) =
            setup_env_for_test(true);

        // Test with withdraw operation - should succeed (since test mode supports withdraw)
        let result = validate_execute_extension_operation(
            &env,
            root_canister_id,
            extension_canister_id,
            "withdraw".to_string(),
            &operation_arg,
        )
        .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_validate_execute_extension_operation_unregistered_extension() {
        let (env, root_canister_id, extension_canister_id, operation_arg) =
            setup_env_for_test(false); // false = extension not registered

        let result = validate_execute_extension_operation(
            &env,
            root_canister_id,
            extension_canister_id,
            "deposit".to_string(),
            &operation_arg,
        )
        .await;

        assert!(result.is_err());
        let error = result.unwrap_err();
        assert_eq!(error.error_type, ErrorType::NotFound as i32);
        assert!(error.error_message.contains("Extension canister"));
        assert!(error
            .error_message
            .contains("is not registered with the SNS"));
    }

    #[tokio::test]
    async fn test_validate_execute_extension_operation_invalid_operation_name() {
        let (env, root_canister_id, extension_canister_id, operation_arg) =
            setup_env_for_test(true);

        // Test with invalid operation name - should fail
        let result = validate_execute_extension_operation(
            &env,
            root_canister_id,
            extension_canister_id,
            "invalid_operation".to_string(),
            &operation_arg,
        )
        .await;

        assert!(result.is_err());
        let error = result.unwrap_err();
        assert_eq!(error.error_type, ErrorType::InvalidProposal as i32);
        assert!(error
            .error_message
            .contains("does not have an operation named invalid_operation"));
    }

    #[test]
    fn test_validate_deposit_operation() {
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

        let result = validate_deposit_operation(valid_arg.clone());
        assert!(result.is_ok());

        match result.unwrap() {
            ValidatedOperationArg::TreasuryManagerDeposit(deposit) => {
                assert_eq!(deposit.treasury_allocation_sns_e8s, 1000000);
                assert_eq!(deposit.treasury_allocation_icp_e8s, 2000000);
            }
            _ => panic!("Expected TreasuryManagerDeposit variant"),
        }

        // Test missing SNS amount
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

        let result = validate_deposit_operation(missing_sns_arg);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("treasury_allocation_sns_e8s must be a Nat value"));

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

        let result = validate_deposit_operation(missing_icp_arg);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("treasury_allocation_icp_e8s must be a Nat value"));

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

        let result = validate_deposit_operation(wrong_type_arg);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("treasury_allocation_sns_e8s must be a Nat value"));

        // Test no arguments provided
        let no_args = ExtensionOperationArg { value: None };
        let result = validate_deposit_operation(no_args);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Deposit operation arguments must be provided"));

        // Test not a map
        let not_map_arg = ExtensionOperationArg {
            value: Some(Precise {
                value: Some(precise::Value::Text("not a map".to_string())),
            }),
        };

        let result = validate_deposit_operation(not_map_arg);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Deposit operation arguments must be a PreciseMap"));
    }

    #[test]
    fn test_validate_withdraw_operation() {
        // Test valid withdraw operation (just needs to have arguments)
        let valid_arg = ExtensionOperationArg {
            value: Some(Precise {
                value: Some(precise::Value::Map(PreciseMap {
                    map: btreemap! {
                        "recipient_principal".to_string() => Precise {
                            value: Some(precise::Value::Text("abc123".to_string())),
                        },
                        "withdrawal_amount_sns_e8s".to_string() => Precise {
                            value: Some(precise::Value::Nat(1000000)),
                        },
                        "withdrawal_amount_icp_e8s".to_string() => Precise {
                            value: Some(precise::Value::Nat(2000000)),
                        },
                    },
                })),
            }),
        };

        let result = validate_withdraw_operation(valid_arg.clone());
        assert!(result.is_ok());

        match result.unwrap() {
            ValidatedOperationArg::TreasuryManagerWithdraw(withdraw) => {
                // Should just wrap the original
                assert_eq!(withdraw.original.value, valid_arg.value);
            }
            _ => panic!("Expected TreasuryManagerWithdraw variant"),
        }

        // Test no arguments provided - should fail
        let no_args = ExtensionOperationArg { value: None };
        let result = validate_withdraw_operation(no_args);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Withdraw operation arguments must be provided"));

        // Test any non-None value should pass (no validation of contents)
        let minimal_arg = ExtensionOperationArg {
            value: Some(Precise {
                value: Some(precise::Value::Text("anything".to_string())),
            }),
        };

        let result = validate_withdraw_operation(minimal_arg.clone());
        assert!(result.is_ok());

        match result.unwrap() {
            ValidatedOperationArg::TreasuryManagerWithdraw(withdraw) => {
                assert_eq!(withdraw.original.value, minimal_arg.value);
            }
            _ => panic!("Expected TreasuryManagerWithdraw variant"),
        }
    }

    #[test]
    fn test_validated_operation_arg_render() {
        // Test deposit rendering
        let deposit_arg =
            ValidatedOperationArg::TreasuryManagerDeposit(ValidatedDepositOperationArg {
                treasury_allocation_sns_e8s: 1000000,
                treasury_allocation_icp_e8s: 2000000,
                original: ExtensionOperationArg {
                    value: Some(Precise {
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
                    }),
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
                original: ExtensionOperationArg {
                    value: Some(Precise {
                        value: Some(precise::Value::Map(PreciseMap {
                            map: btreemap! {
                                "test".to_string() => Precise {
                                    value: Some(precise::Value::Text("data".to_string())),
                                },
                            },
                        })),
                    }),
                },
            });

        let rendered = withdraw_arg.render_for_proposal();
        assert!(rendered.contains("Extension Operation"));
        assert!(rendered.contains("Raw Payload"));
        assert!(rendered.contains("test"));
        assert!(rendered.contains("data"));

        // Test unprocessed rendering
        let unprocessed_arg =
            ValidatedOperationArg::Unprocessed(ExtensionOperationArg { value: None });

        let rendered = unprocessed_arg.render_for_proposal();
        assert!(rendered.contains("No payload provided"));
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
        };

        let result = spec.validate();
        assert!(result.is_err());
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
        };

        assert!(spec.validate().is_ok());
    }
}
