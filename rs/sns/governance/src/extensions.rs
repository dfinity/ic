use std::{collections::BTreeMap, fmt::Display};

use candid::Nat;
use ic_base_types::CanisterId;
use ic_nervous_system_common::ledger::compute_distribution_subaccount_bytes;
use icrc_ledger_types::icrc1::account::Account;
use lazy_static::lazy_static;
use maplit::btreemap;
use sns_treasury_manager::{Asset, TreasuryManagerArg};

use crate::{
    governance::{Governance, TREASURY_SUBACCOUNT_NONCE},
    pb::v1::{
        governance_error::ErrorType, ChunkedCanisterWasm, ExtensionInit, GovernanceError,
        RegisterExtension, Topic,
    },
    types::Wasm,
};

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
pub struct ExtensionSpec {
    pub name: String,
    pub topic: Topic,
    pub kind: ExtensionKind,
}

impl Display for ExtensionSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SNS Extension {{ name: {}, topic: {}, kind: {} }}",
            self.name, self.topic, self.kind,
        )
    }
}

pub struct ValidatedRegisterExtension {
    pub wasm: Wasm,
    pub spec: ExtensionSpec,
    pub init: ExtensionInit,
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

    /// Returns `(arg_blob, sns_token_amount_e8s, icp_token_amount_e8s)` in the Ok result.
    pub fn construct_treasury_manager_init(
        &self,
        init: ExtensionInit,
    ) -> Result<(Vec<u8>, u64, u64), GovernanceError> {
        // See ic_sns_init::distributions::FractionalDeveloperVotingPower.insert_treasury_accounts
        let (treasury_sns_subaccount, treasury_icp_subaccount) = self.treasury_subaccounts();

        let (init, sns_amount_e8s, icp_amount_e8s) = treasury_manager::construct_init(
            init,
            Asset::Token {
                symbol: "SNS".to_string(),
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
        .map_err(|e| {
            GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                format!("Error extracting initial allowances: {}", e),
            )
        })?;

        let arg = TreasuryManagerArg::Init(init);
        let arg: Vec<u8> = candid::encode_one(&arg).map_err(|err| {
            GovernanceError::new_with_message(
                ErrorType::InvalidProposal,
                format!("Error encoding TreasuryManagerArg: {}", err),
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

pub mod treasury_manager {
    use candid::Nat;
    use sns_treasury_manager::{Account, Allowance, Asset, TreasuryManagerInit};

    use crate::pb::v1::{precise, ExtensionInit, Precise, PreciseMap};

    /// Returns `(init, sns_token_amount_e8s, icp_token_amount_e8s)` in the Ok result.
    pub fn construct_init(
        init: ExtensionInit,
        sns_token: Asset,
        icp_token: Asset,
        treasury_sns_account: Account,
        treasury_icp_account: Account,
    ) -> Result<(TreasuryManagerInit, u64, u64), String> {
        const PREFIX: &str = "Cannot parse ExtensionInit as TreasuryManagerInit: ";

        let mut map = match init {
            ExtensionInit {
                value:
                    Some(Precise {
                        value: Some(precise::Value::Map(PreciseMap { map })),
                    }),
            } => map,
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
        Ok((
            TreasuryManagerInit { allowances },
            sns_token_amount_e8s,
            icp_token_amount_e8s,
        ))
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
