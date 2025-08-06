use crate::{
    governance::{Governance, TREASURY_SUBACCOUNT_NONCE},
    pb::{
        sns_root_types::{ListSnsCanistersRequest, ListSnsCanistersResponse},
        v1::{
            governance_error::ErrorType, ChunkedCanisterWasm, ExecuteExtensionOperation,
            ExtensionInit, ExtensionOperationArg, GovernanceError, Precise, RegisterExtension,
            Topic,
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
pub enum ExtensionKind {
    TreasuryManager,
}

impl Display for ExtensionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TreasuryManager => write!(f, "TreasuryManager"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionOperationSpec {
    pub name: String,
    pub description: String,
    // TODO: Add a way to specify argument schema for the extension operation.
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtensionSpec {
    pub name: String,
    pub topic: Topic,
    pub kind: ExtensionKind,
    pub operations: BTreeMap<String, ExtensionOperationSpec>,
    // TODO: Add a way to specify initialization arguments schema for the extension.
}

impl Display for ExtensionSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SNS Extension {{ name: {}, topic: {}, kind: {}, operations: {} }}",
            self.name,
            self.topic,
            self.kind,
            self.operations
                .keys()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
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

pub(crate) fn validate_extension_wasm(wasm_module_hash: &[u8]) -> Result<ExtensionSpec, String> {
    // In testing, any wasm module hash is allowed.
    if cfg!(test) || cfg!(feature = "test") {
        return Ok(ExtensionSpec {
            name: "My Test Extension".to_string(),
            topic: Topic::TreasuryAssetManagement,
            kind: ExtensionKind::TreasuryManager,
            operations: btreemap! {
                "deposit".to_string() => ExtensionOperationSpec {
                    name: "deposit".to_string(),
                    description: "Deposit funds into the treasury manager.".to_string(),
                },
                "withdraw".to_string() => ExtensionOperationSpec {
                    name: "withdraw".to_string(),
                    description: "Withdraw funds from the treasury manager.".to_string(),
                },
            },
        });
    }

    // In production, check against the allowed extensions.
    if let Some(extension) = ALLOWED_EXTENSIONS.get(wasm_module_hash) {
        return Ok(extension.clone());
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

/// Validates that this is a supported extension operation.
// TODO: Validate the operation arguments as well.
// TODO: Enforce 50% treasury limits.
pub(crate) async fn validate_execute_extension_operation(
    env: &dyn Environment,
    root_canister_id: CanisterId,
    extension_canister_id: CanisterId,
    operation_name: String,
    _operation_arg: &ExtensionOperationArg,
) -> Result<(), GovernanceError> {
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

    let (extension_kind, extension_operations) = match validate_extension_wasm(&wasm_module_hash) {
        Ok(ExtensionSpec {
            kind, operations, ..
        }) => (kind, operations),
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

    if extension_kind != ExtensionKind::TreasuryManager {
        return Err(GovernanceError::new_with_message(
            ErrorType::InvalidProposal,
            "Only TreasuryManager extensions are currently supported.",
        ));
    }

    let Some(ExtensionOperationSpec { name, .. }) = extension_operations.get(&operation_name)
    else {
        return Err(GovernanceError::new_with_message(
            ErrorType::InvalidProposal,
            format!(
                "Extension canister {} does not have an operation named {}",
                extension_canister_id, operation_name
            ),
        ));
    };

    // Now we need a generic way to validate particular extension operations.

    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pb::sns_root_types::{ListSnsCanistersRequest, ListSnsCanistersResponse};
    use crate::types::test_helpers::NativeEnvironment;
    use ic_management_canister_types_private::{CanisterInfoRequest, CanisterInfoResponse};

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
            env.set_call_canister_response(
                CanisterId::ic_00(),
                "canister_info",
                Encode!(&CanisterInfoRequest::new(extension_canister_id, Some(1))).unwrap(),
                Ok(Encode!(&CanisterInfoResponse::new(
                    0,                      // total_num_changes
                    vec![],                 // recent_changes
                    Some(vec![1, 2, 3, 4]), // module_hash - any hash works in test mode
                    vec![],                 // controllers
                ))
                .unwrap()),
            );
        }

        let operation_arg = ExtensionOperationArg { value: None };

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
}
