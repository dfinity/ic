use candid::{Decode, Encode, Nat, Principal};
use ic_agent::{
    hash_tree::{Label, LookupResult},
    Agent,
};
use ic_cbor::CertificateToCbor;
use ic_certification::{
    hash_tree::{HashTreeNode, SubtreeLookupResult},
    Certificate, HashTree,
};
use icrc_ledger_types::icrc::generic_value::Hash;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::{BlockIndex, TransferArg, TransferError};
use icrc_ledger_types::icrc2::allowance::{Allowance, AllowanceArgs};
use icrc_ledger_types::icrc2::approve::{ApproveArgs, ApproveError};
use icrc_ledger_types::icrc2::transfer_from::{TransferFromArgs, TransferFromError};
use icrc_ledger_types::icrc3::archive::{ArchivedRange, QueryBlockArchiveFn};
use icrc_ledger_types::icrc3::blocks::{DataCertificate, GetBlocksRequest, GetBlocksResponse};
use icrc_ledger_types::{
    icrc::generic_metadata_value::MetadataValue as Value, icrc3::blocks::BlockRange,
};

#[derive(Debug)]
pub enum Icrc1AgentError {
    AgentError(ic_agent::AgentError),
    CandidError(candid::Error),
    VerificationFailed(String),
}

impl From<ic_agent::AgentError> for Icrc1AgentError {
    fn from(e: ic_agent::AgentError) -> Self {
        Self::AgentError(e)
    }
}

impl From<candid::Error> for Icrc1AgentError {
    fn from(e: candid::Error) -> Self {
        Self::CandidError(e)
    }
}

impl std::fmt::Display for Icrc1AgentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for Icrc1AgentError {}

pub enum CallMode {
    Query,
    Update,
}

/// An Agent to make calls to a [ICRC-1 Ledger](https://github.com/dfinity/ICRC-1).
///
/// Each query method in this agent takes in input
/// the mode to allow to either use a query call or
/// update calls.
#[derive(Clone)]
pub struct Icrc1Agent {
    pub agent: Agent,
    pub ledger_canister_id: Principal,
}

impl Icrc1Agent {
    async fn query<S: Into<String>>(
        &self,
        method_name: S,
        arg: &[u8],
    ) -> Result<Vec<u8>, Icrc1AgentError> {
        self.agent
            .query(&self.ledger_canister_id, method_name)
            .with_arg(arg)
            .call()
            .await
            .map_err(Icrc1AgentError::AgentError)
    }

    async fn update<S: Into<String>>(
        &self,
        method_name: S,
        arg: &[u8],
    ) -> Result<Vec<u8>, Icrc1AgentError> {
        self.agent
            .update(&self.ledger_canister_id, method_name)
            .with_arg(arg)
            .call_and_wait()
            .await
            .map_err(Icrc1AgentError::AgentError)
    }

    /// Returns the balance of the account given as argument.
    pub async fn balance_of(
        &self,
        account: Account,
        mode: CallMode,
    ) -> Result<Nat, Icrc1AgentError> {
        Ok(match mode {
            CallMode::Query => Decode!(
                &self.query("icrc1_balance_of", &Encode!(&account)?).await?,
                Nat
            )?,
            CallMode::Update => Decode!(
                &self.update("icrc1_balance_of", &Encode!(&account)?).await?,
                Nat
            )?,
        })
    }

    /// Returns the number of decimals the token uses (e.g., 8 means to divide the token amount by 100000000 to get its user representation).
    pub async fn decimals(&self, mode: CallMode) -> Result<u8, Icrc1AgentError> {
        Ok(match mode {
            CallMode::Query => Decode!(&self.query("icrc1_decimals", &Encode!()?).await?, u8)?,
            CallMode::Update => Decode!(&self.update("icrc1_decimals", &Encode!()?).await?, u8)?,
        })
    }

    /// Returns the name of the token (e.g., MyToken).
    pub async fn name(&self, mode: CallMode) -> Result<String, Icrc1AgentError> {
        Ok(match mode {
            CallMode::Query => Decode!(&self.query("icrc1_name", &Encode!()?).await?, String)?,
            CallMode::Update => Decode!(&self.update("icrc1_name", &Encode!()?).await?, String)?,
        })
    }

    /// Returns the list of metadata entries for this ledger
    pub async fn metadata(&self, mode: CallMode) -> Result<Vec<(String, Value)>, Icrc1AgentError> {
        Ok(match mode {
            CallMode::Query => Decode!(
                &self.query("icrc1_metadata", &Encode!()?).await?,
                Vec<(String, Value)>
            )?,
            CallMode::Update => Decode!(
                &self.update("icrc1_metadata", &Encode!()?).await?,
                Vec<(String, Value)>
            )?,
        })
    }

    /// Returns the symbol of the token (e.g., ICP).
    pub async fn symbol(&self, mode: CallMode) -> Result<String, Icrc1AgentError> {
        Ok(match mode {
            CallMode::Query => Decode!(&self.query("icrc1_symbol", &Encode!()?).await?, String)?,
            CallMode::Update => Decode!(&self.update("icrc1_symbol", &Encode!()?).await?, String)?,
        })
    }

    /// Returns the balance of the account given as argument.
    pub async fn total_supply(&self, mode: CallMode) -> Result<Nat, Icrc1AgentError> {
        Ok(match mode {
            CallMode::Query => Decode!(&self.query("icrc1_total_supply", &Encode!()?).await?, Nat)?,
            CallMode::Update => {
                Decode!(&self.update("icrc1_total_supply", &Encode!()?).await?, Nat)?
            }
        })
    }

    // Returns the transfer fee.
    pub async fn fee(&self, mode: CallMode) -> Result<Nat, Icrc1AgentError> {
        Ok(match mode {
            CallMode::Query => Decode!(&self.query("icrc1_fee", &Encode!()?).await?, Nat)?,
            CallMode::Update => Decode!(&self.update("icrc1_fee", &Encode!()?).await?, Nat)?,
        })
    }

    // Returns the minting account if this ledger supports minting and burning tokens.
    pub async fn minting_account(
        &self,
        mode: CallMode,
    ) -> Result<Option<Account>, Icrc1AgentError> {
        Ok(match mode {
            CallMode::Query => Decode!(
                &self.query("icrc1_minting_account", &Encode!()?).await?,
                Option<Account>
            )?,
            CallMode::Update => Decode!(
                &self.update("icrc1_minting_account", &Encode!()?).await?,
                Option<Account>
            )?,
        })
    }

    /// Transfers amount of tokens from the account (caller, from_subaccount) to the account (to_principal, to_subaccount).
    pub async fn transfer(
        &self,
        args: TransferArg,
    ) -> Result<Result<Nat, TransferError>, Icrc1AgentError> {
        Ok(
            Decode!(&self.update("icrc1_transfer", &Encode!(&args)?).await?, Result<Nat, TransferError>)?,
        )
    }

    pub async fn approve(
        &self,
        args: ApproveArgs,
    ) -> Result<Result<Nat, ApproveError>, Icrc1AgentError> {
        Ok(
            Decode!(&self.update("icrc2_approve", &Encode!(&args)?).await?, Result<Nat, ApproveError>)?,
        )
    }

    /// Returns the allowance of the `spender` from the `account`.
    pub async fn allowance(
        &self,
        account: Account,
        spender: Account,
        mode: CallMode,
    ) -> Result<Allowance, Icrc1AgentError> {
        let args = AllowanceArgs { account, spender };
        Ok(match mode {
            CallMode::Query => Decode!(
                &self.query("icrc2_allowance", &Encode!(&args)?).await?,
                Allowance
            )?,
            CallMode::Update => Decode!(
                &self.update("icrc2_allowance", &Encode!(&args)?).await?,
                Allowance
            )?,
        })
    }

    pub async fn transfer_from(
        &self,
        args: TransferFromArgs,
    ) -> Result<Result<Nat, TransferFromError>, Icrc1AgentError> {
        Ok(
            Decode!(&self.update("icrc2_transfer_from", &Encode!(&args)?).await?, Result<Nat, TransferFromError>)?,
        )
    }

    pub async fn get_blocks(
        &self,
        args: GetBlocksRequest,
    ) -> Result<GetBlocksResponse, Icrc1AgentError> {
        Ok(Decode!(
            &self.query("get_blocks", &Encode!(&args)?).await?,
            GetBlocksResponse
        )?)
    }

    pub async fn get_blocks_from_archive(
        &self,
        archived_blocks: ArchivedRange<QueryBlockArchiveFn>,
    ) -> Result<BlockRange, Icrc1AgentError> {
        let args = GetBlocksRequest {
            start: archived_blocks.start,
            length: archived_blocks.length,
        };
        Ok(Decode!(
            &self
                .agent
                .query(
                    &archived_blocks.callback.canister_id,
                    &archived_blocks.callback.method
                )
                .with_arg(Encode!(&args)?)
                .call()
                .await
                .map_err(Icrc1AgentError::AgentError)?,
            BlockRange
        )?)
    }

    pub async fn get_data_certificate(&self) -> Result<DataCertificate, Icrc1AgentError> {
        Ok(Decode!(
            &self.query("get_data_certificate", &Encode!()?).await?,
            DataCertificate
        )?)
    }

    /// The function performs the following checks:
    /// 1. Check whether the certificate is valid and has authority over ledger_canister_id.
    /// 2. Check whether the certified data at path ["canister", ledger_canister_id, "certified_data"] is equal to root_hash.
    pub async fn verify_root_hash(
        &self,
        certificate: &Certificate,
        root_hash: &Hash,
    ) -> Result<(), Icrc1AgentError> {
        self.agent
            .verify(certificate, self.ledger_canister_id)
            .map_err(Icrc1AgentError::AgentError)?;

        let certified_data_path: [Label<Vec<u8>>; 3] = [
            "canister".into(),
            self.ledger_canister_id.as_slice().into(),
            "certified_data".into(),
        ];

        let cert_hash = match certificate.tree.lookup_path(&certified_data_path) {
            LookupResult::Found(v) => v,
            _ => {
                return Err(Icrc1AgentError::VerificationFailed(format!(
                    "could not find certified_data for canister: {}",
                    self.ledger_canister_id
                )))
            }
        };

        if cert_hash != root_hash {
            return Err(Icrc1AgentError::VerificationFailed(
                "certified_data does not match the root_hash".to_string(),
            ));
        }
        Ok(())
    }

    /// Returns the hash of the last block in the chain and this block's index.
    /// Returns an error if the hash and/or the index do not pass validation against the IC certificate.
    /// Returns None if the blockchain has no blocks and this can be verified by the certificate.
    pub async fn get_certified_chain_tip(
        &self,
    ) -> Result<Option<(Hash, BlockIndex)>, Icrc1AgentError> {
        let DataCertificate {
            certificate,
            hash_tree,
        } = self.get_data_certificate().await?;
        let certificate = if let Some(certificate) = certificate {
            match Certificate::from_cbor(certificate.as_slice()) {
                Ok(certificate) => certificate,
                Err(e) => {
                    return Err(Icrc1AgentError::VerificationFailed(format!(
                        "Unable to deserialize CBOR encoded Certificate: {}",
                        e
                    )));
                }
            }
        } else {
            return Err(Icrc1AgentError::VerificationFailed(
                "Certificate not found in the DataCertificate".to_string(),
            ));
        };
        let hash_tree: HashTree = match ciborium::de::from_reader(hash_tree.as_slice()) {
            Ok(hash_tree) => hash_tree,
            Err(e) => {
                return Err(Icrc1AgentError::VerificationFailed(format!(
                    "Unable to deserialize CBOR encoded hash_tree: {}",
                    e
                )))
            }
        };
        self.verify_root_hash(&certificate, &hash_tree.digest())
            .await?;

        let last_block_hash_vec = lookup_leaf(&hash_tree, "tip_hash")?;
        if let Some(last_block_hash_vec) = last_block_hash_vec {
            let last_block_hash: Hash = match last_block_hash_vec.clone().try_into() {
                Ok(last_block_hash) => last_block_hash,
                Err(_) => {
                    return Err(Icrc1AgentError::VerificationFailed(format!(
                "DataCertificate last_block_hash bytes: {}, cannot be decoded as last_block_hash",
                hex::encode(last_block_hash_vec)
            )))
                }
            };

            let last_block_index_vec = lookup_leaf(&hash_tree, "last_block_index")?;
            if let Some(last_block_index_vec) = last_block_index_vec {
                let last_block_index_bytes: [u8; 8] = match last_block_index_vec.clone().try_into()
                {
                    Ok(last_block_index_bytes) => last_block_index_bytes,
                    Err(_) => {
                        return Err(Icrc1AgentError::VerificationFailed(format!(
                    "DataCertificate hash_tree bytes: {}, cannot be decoded as last_block_index",
                    hex::encode(last_block_index_vec)
                )))
                    }
                };
                let last_block_index = u64::from_be_bytes(last_block_index_bytes);

                return Ok(Some((last_block_hash, Nat::from(last_block_index))));
            } else {
                return Err(Icrc1AgentError::VerificationFailed(
                    "certified hash_tree contains tip_hash but not last_block_index".to_string(),
                ));
            }
        }

        Ok(None)
    }
}

fn lookup_leaf(hash_tree: &HashTree, leaf_name: &str) -> Result<Option<Vec<u8>>, Icrc1AgentError> {
    match hash_tree.lookup_subtree([leaf_name.as_bytes()]) {
        SubtreeLookupResult::Found(tree) => match tree.as_ref() {
            HashTreeNode::Leaf(result) => Ok(Some(result.clone())),
            _ => Err(Icrc1AgentError::VerificationFailed(format!(
                "`{}` value in the hash_tree should be a leaf",
                leaf_name
            ))),
        },
        SubtreeLookupResult::Absent => Ok(None),
        _ => Err(Icrc1AgentError::VerificationFailed(format!(
            "`{}` not found in the response hash_tree",
            leaf_name
        ))),
    }
}
