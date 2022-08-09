pub mod distributions;
pub mod pb;

use crate::pb::v1::{
    sns_init_payload::InitialTokenDistribution::FractionalDeveloperVotingPower,
    AirdropDistribution, DeveloperDistribution, FractionalDeveloperVotingPower as FractionalDVP,
    SnsInitPayload, SwapDistribution, TreasuryDistribution,
};
use anyhow::anyhow;
use ic_base_types::{CanisterId, PrincipalId};
use ic_icrc1::Account;
use ic_icrc1_ledger::InitArgs as LedgerInitArgs;
use ic_ledger_canister_core::archive::ArchiveOptions;
use ic_ledger_core::Tokens;
use ic_nns_constants::{
    GOVERNANCE_CANISTER_ID as NNS_GOVERNANCE_CANISTER_ID,
    LEDGER_CANISTER_ID as ICP_LEDGER_CANISTER_ID,
};
use ic_sns_governance::init::GovernanceCanisterInitPayloadBuilder;
use ic_sns_governance::pb::v1::governance::SnsMetadata;
use ic_sns_governance::pb::v1::{
    Governance, NervousSystemParameters, Neuron, NeuronPermissionList, NeuronPermissionType,
};
use ic_sns_governance::types::DEFAULT_TRANSFER_FEE;
use ic_sns_root::pb::v1::SnsRootCanister;
use ic_sns_swap::pb::v1::Init;
use lazy_static::lazy_static;
use maplit::{btreemap, hashmap, hashset};
use std::collections::HashSet;
use std::collections::{BTreeMap, HashMap};

/// The maximum number of characters allowed for token symbol.
pub const MAX_TOKEN_SYMBOL_LENGTH: usize = 10;

/// The minimum number of characters allowed for token symbol.
pub const MIN_TOKEN_SYMBOL_LENGTH: usize = 3;

/// The maximum number of characters allowed for token name.
pub const MAX_TOKEN_NAME_LENGTH: usize = 255;

/// The minimum number of characters allowed for token name.
pub const MIN_TOKEN_NAME_LENGTH: usize = 4;

/// SNS parameters default values
pub const MIN_PARTICIPANT_ICP_E8S_DEFAULT: u64 = 100_000_000;

// Token Symbols that can not be used.
lazy_static! {
    static ref BANNED_TOKEN_SYMBOLS: HashSet<&'static str> = hashset! {
        "ICP", "DFINITY"
    };
}

// Token Names that can not be used.
lazy_static! {
    static ref BANNED_TOKEN_NAMES: HashSet<&'static str> = hashset! {
        "internetcomputer", "internetcomputerprotocol"
    };
}

/// The canister IDs of all SNS canisters
#[derive(Debug, Clone)]
pub struct SnsCanisterIds {
    pub governance: PrincipalId,
    pub ledger: PrincipalId,
    pub root: PrincipalId,
    pub swap: PrincipalId,
}

/// The Init payloads for all SNS Canisters
#[derive(Debug, Clone)]
pub struct SnsCanisterInitPayloads {
    pub governance: Governance,
    pub ledger: LedgerInitArgs,
    pub root: SnsRootCanister,
    pub swap: Init,
}

impl SnsInitPayload {
    /// Due to conflict with the prost derived macros on the generated Rust structs, this method
    /// acts like `SnsInitPayload::default()` except that it will provide default "real" values
    /// for default-able parameters.
    pub fn with_default_values() -> Self {
        let nervous_system_parameters_default = NervousSystemParameters::with_default_values();
        Self {
            transaction_fee_e8s: nervous_system_parameters_default.transaction_fee_e8s,
            token_name: None,
            token_symbol: None,
            proposal_reject_cost_e8s: nervous_system_parameters_default.reject_cost_e8s,
            neuron_minimum_stake_e8s: nervous_system_parameters_default.neuron_minimum_stake_e8s,
            initial_token_distribution: None,
            max_icp_e8s: None,
            min_participants: None,
            min_participant_icp_e8s: Some(MIN_PARTICIPANT_ICP_E8S_DEFAULT),
            min_icp_e8s: None,
            max_participant_icp_e8s: None,
            fallback_controller_principal_ids: vec![],
            logo: None,
            url: None,
            name: None,
            description: None,
        }
    }

    /// This gives us some values that work for testing but would not be useful
    /// in a real world scenario.  They are only meant to validate, not be sensible.
    pub fn with_valid_values_for_testing() -> Self {
        Self {
            token_symbol: Some("TEST".to_string()),
            token_name: Some("PlaceHolder".to_string()),
            initial_token_distribution: Some(FractionalDeveloperVotingPower(FractionalDVP {
                developer_distribution: Some(DeveloperDistribution {
                    developer_neurons: Default::default(),
                }),
                treasury_distribution: Some(TreasuryDistribution {
                    total_e8s: 500_000_000,
                }),
                swap_distribution: Some(SwapDistribution {
                    total_e8s: 1_000_000_000,
                    initial_swap_amount_e8s: 1_000_000_000,
                }),
                airdrop_distribution: Some(AirdropDistribution {
                    airdrop_neurons: Default::default(),
                }),
            })),
            max_icp_e8s: Some(1_000_000_000),
            min_participants: Some(1),
            min_icp_e8s: Some(100),
            max_participant_icp_e8s: Some(1_000_000_000),
            fallback_controller_principal_ids: vec!["aa-aaaa".to_string()],
            logo: Some("X".repeat(100)),
            name: Some("ServiceNervousSystemTest".to_string()),
            url: Some("https://internetcomputer.org/".to_string()),
            description: Some("Description of an SNS Project".to_string()),
            ..SnsInitPayload::with_default_values()
        }
    }

    /// Build all the SNS canister's init payloads given the state of the SnsInitPayload and the
    /// provided SnsCanisterIds.
    pub fn build_canister_payloads(
        &self,
        sns_canister_ids: &SnsCanisterIds,
    ) -> anyhow::Result<SnsCanisterInitPayloads> {
        self.validate()?;
        Ok(SnsCanisterInitPayloads {
            governance: self.governance_init_args(sns_canister_ids)?,
            ledger: self.ledger_init_args(sns_canister_ids)?,
            root: self.root_init_args(sns_canister_ids),
            swap: self.swap_init_args(sns_canister_ids),
        })
    }

    /// Construct the params used to initialize a SNS Governance canister.
    fn governance_init_args(
        &self,
        sns_canister_ids: &SnsCanisterIds,
    ) -> anyhow::Result<Governance> {
        let mut governance = GovernanceCanisterInitPayloadBuilder::new().build();
        governance.ledger_canister_id = Some(sns_canister_ids.ledger);
        governance.root_canister_id = Some(sns_canister_ids.root);

        let parameters = governance
            .parameters
            .as_mut()
            .expect("NervousSystemParameters not set");

        let all_permissions = NeuronPermissionList {
            permissions: NeuronPermissionType::all(),
        };
        parameters.neuron_claimer_permissions = Some(all_permissions.clone());
        parameters.neuron_grantable_permissions = Some(all_permissions);
        parameters.neuron_minimum_stake_e8s = self.neuron_minimum_stake_e8s;
        parameters.reject_cost_e8s = self.proposal_reject_cost_e8s;

        governance.sns_metadata = Some(SnsMetadata {
            logo: self.logo.clone(),
            url: self.url.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
        });

        governance.neurons = self.get_initial_neurons(parameters)?;

        Ok(governance)
    }

    /// Construct the params used to initialize a SNS Ledger canister.
    fn ledger_init_args(
        &self,
        sns_canister_ids: &SnsCanisterIds,
    ) -> anyhow::Result<LedgerInitArgs> {
        let root_canister_id = CanisterId::new(sns_canister_ids.root).unwrap();
        let token_symbol = self
            .token_symbol
            .as_ref()
            .expect("Expected token_symbol to be set")
            .clone();
        let token_name = self
            .token_name
            .as_ref()
            .expect("Expected token_name to be set")
            .clone();

        let minting_account = Account {
            owner: sns_canister_ids.governance,
            subaccount: None,
        };
        let initial_balances = self
            .get_all_ledger_accounts(sns_canister_ids)?
            .into_iter()
            .map(|(a, t)| (a, t.get_e8s()))
            .collect();
        let transfer_fee = self
            .transaction_fee_e8s
            .unwrap_or(DEFAULT_TRANSFER_FEE.get_e8s());

        let payload = LedgerInitArgs {
            minting_account,
            initial_balances,
            transfer_fee,
            token_name,
            token_symbol,
            metadata: vec![],
            archive_options: ArchiveOptions {
                trigger_threshold: 2000,
                num_blocks_to_archive: 1000,
                // 1 GB, which gives us 3 GB space when upgrading
                node_max_memory_size_bytes: Some(1024 * 1024 * 1024),
                // 128kb
                max_message_size_bytes: Some(128 * 1024),
                controller_id: root_canister_id.get(),
                // TODO: allow users to set this value
                // 10 Trillion cycles
                cycles_for_archive_creation: Some(10_000_000_000_000),
            },
        };

        Ok(payload)
    }

    /// Construct the params used to initialize a SNS Root canister.
    fn root_init_args(&self, sns_canister_ids: &SnsCanisterIds) -> SnsRootCanister {
        SnsRootCanister {
            governance_canister_id: Some(sns_canister_ids.governance),
            ledger_canister_id: Some(sns_canister_ids.ledger),
            swap_canister_id: Some(sns_canister_ids.swap),
            dapp_canister_ids: vec![],
            archive_canister_ids: vec![],
            latest_ledger_archive_poll_timestamp_seconds: None,
        }
    }

    /// Construct the parameters used to initialize a SNS Swap canister.
    ///
    /// Precondition: self must be valid (see fn validate).
    fn swap_init_args(&self, sns_canister_ids: &SnsCanisterIds) -> Init {
        Init {
            sns_root_canister_id: sns_canister_ids.root.to_string(),
            sns_governance_canister_id: sns_canister_ids.governance.to_string(),
            sns_ledger_canister_id: sns_canister_ids.ledger.to_string(),

            nns_governance_canister_id: NNS_GOVERNANCE_CANISTER_ID.to_string(),
            icp_ledger_canister_id: ICP_LEDGER_CANISTER_ID.to_string(),

            max_icp_e8s: self.max_icp_e8s.expect("Field max_icp_e8 cannot be None"),
            min_participants: self
                .min_participants
                .expect("Field min_participants cannot be None"),
            min_participant_icp_e8s: self
                .min_participant_icp_e8s
                .expect("Field min_participants_icp_e8s cannot be None"),
            max_participant_icp_e8s: self
                .max_participant_icp_e8s
                .expect("Field max_participants_icp_e8s cannot be None"),
            min_icp_e8s: self.min_icp_e8s.expect("Field min_icp_e8s cannot be None"),
            fallback_controller_principal_ids: self.fallback_controller_principal_ids.clone(),
        }
    }

    /// Given `SnsCanisterIds`, get all the ledger accounts of the TokenDistributions. These
    /// accounts represent the allocation of tokens at genesis.
    fn get_all_ledger_accounts(
        &self,
        sns_canister_ids: &SnsCanisterIds,
    ) -> anyhow::Result<HashMap<Account, Tokens>> {
        match &self.initial_token_distribution {
            None => Ok(hashmap! {}),
            Some(FractionalDeveloperVotingPower(f)) => {
                f.get_account_ids_and_tokens(sns_canister_ids)
            }
        }
    }

    /// Return the initial neurons that the user specified. These neurons will exist in
    /// Governance at genesis, with the correct balance in their corresponding ledger
    /// accounts. A map from neuron ID to Neuron is returned.
    fn get_initial_neurons(
        &self,
        parameters: &NervousSystemParameters,
    ) -> anyhow::Result<BTreeMap<String, Neuron>> {
        match &self.initial_token_distribution {
            None => Ok(btreemap! {}),
            Some(FractionalDeveloperVotingPower(f)) => f.get_initial_neurons(parameters),
        }
    }

    /// Validates the SnsInitPayload. This is called before building each SNS canister's
    /// payload and must pass.
    pub fn validate(&self) -> anyhow::Result<Self> {
        let validation_fns = [
            self.validate_token_symbol(),
            self.validate_token_name(),
            self.validate_token_distribution(),
            self.validate_min_participants(),
            self.validate_icp_parameters(),
            self.validate_min_participant_icp_e8s(),
            self.validate_neuron_minimum_stake_e8s(),
            self.validate_proposal_reject_cost_e8s(),
            self.validate_transaction_fee_e8s(),
            self.validate_min_icp_e8s(),
            self.validate_max_participant_icp_e8s(),
            self.validate_fallback_controller_principal_ids(),
            self.validate_url(),
            self.validate_logo(),
            self.validate_description(),
            self.validate_name(),
        ];

        let defect_msg = validation_fns
            .into_iter()
            .filter_map(|validation_fn| match validation_fn {
                Err(msg) => Some(msg),
                Ok(_) => None,
            })
            .collect::<Vec<String>>()
            .join("\n");

        if defect_msg.is_empty() {
            Ok(self.clone())
        } else {
            Err(anyhow!(defect_msg))
        }
    }

    fn validate_token_symbol(&self) -> Result<(), String> {
        let token_symbol = self
            .token_symbol
            .as_ref()
            .ok_or_else(|| "Error: token-symbol must be specified".to_string())?;

        if token_symbol.len() > MAX_TOKEN_SYMBOL_LENGTH {
            return Err(format!(
                "Error: token-symbol must be fewer than {} characters, given character count: {}",
                MAX_TOKEN_SYMBOL_LENGTH,
                token_symbol.len()
            ));
        }

        if token_symbol.len() < MIN_TOKEN_SYMBOL_LENGTH {
            return Err(format!(
                "Error: token-symbol must be greater than {} characters, given character count: {}",
                MIN_TOKEN_SYMBOL_LENGTH,
                token_symbol.len()
            ));
        }

        if token_symbol != token_symbol.trim() {
            return Err("Token symbol must not have leading or trailing whitespaces".to_string());
        }

        if BANNED_TOKEN_SYMBOLS.contains::<str>(&token_symbol.clone().to_uppercase()) {
            return Err("Banned token symbol, please chose another one.".to_string());
        }

        Ok(())
    }

    fn validate_token_name(&self) -> Result<(), String> {
        let token_name = self
            .token_name
            .as_ref()
            .ok_or_else(|| "Error: token-name must be specified".to_string())?;

        if token_name.len() > MAX_TOKEN_NAME_LENGTH {
            return Err(format!(
                "Error: token-name must be fewer than {} characters, given character count: {}",
                MAX_TOKEN_NAME_LENGTH,
                token_name.len()
            ));
        }

        if token_name.len() < MIN_TOKEN_NAME_LENGTH {
            return Err(format!(
                "Error: token-name must be greater than {} characters, given character count: {}",
                MIN_TOKEN_NAME_LENGTH,
                token_name.len()
            ));
        }

        if token_name != token_name.trim() {
            return Err("Token name must not have leading or trailing whitespaces".to_string());
        }

        if BANNED_TOKEN_NAMES.contains::<str>(
            &token_name
                .to_lowercase()
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>(),
        ) {
            return Err("Banned token name, please chose another one.".to_string());
        }

        Ok(())
    }

    fn validate_token_distribution(&self) -> Result<(), String> {
        let initial_token_distribution = self
            .initial_token_distribution
            .as_ref()
            .ok_or_else(|| "Error: initial-token-distribution must be specified".to_string())?;

        match initial_token_distribution {
            FractionalDeveloperVotingPower(f) => f.validate().map_err(|err| err.to_string())?,
        }

        Ok(())
    }

    fn validate_transaction_fee_e8s(&self) -> Result<(), String> {
        match self.transaction_fee_e8s {
            Some(_) => Ok(()),
            None => Err("Error: transaction_fee_e8s must be specified.".to_string()),
        }
    }

    fn validate_proposal_reject_cost_e8s(&self) -> Result<(), String> {
        match self.proposal_reject_cost_e8s {
            Some(_) => Ok(()),
            None => Err("Error: proposal_reject_cost_e8s must be specified.".to_string()),
        }
    }

    fn validate_neuron_minimum_stake_e8s(&self) -> Result<(), String> {
        let neuron_minimum_stake_e8s = self
            .neuron_minimum_stake_e8s
            .expect("Error: neuron_minimum_stake_e8s must be specified.");
        let initial_token_distribution = self
            .initial_token_distribution
            .as_ref()
            .ok_or_else(|| "Error: initial-token-distribution must be specified".to_string())?;

        match initial_token_distribution {
            FractionalDeveloperVotingPower(f) => {
                let developer_distribution = f
                    .developer_distribution
                    .as_ref()
                    .ok_or_else(|| "Error: developer_distribution must be specified".to_string())?;

                let airdrop_distribution = f
                    .airdrop_distribution
                    .as_ref()
                    .ok_or_else(|| "Error: airdrop_distribution must be specified".to_string())?;

                let min_stake_infringing_developer_neurons: Vec<(PrincipalId, u64)> =
                    developer_distribution
                        .developer_neurons
                        .iter()
                        .filter_map(|neuron_distribution| {
                            if neuron_distribution.stake_e8s < neuron_minimum_stake_e8s {
                                // Safe to unwrap due to the checks done above
                                Some((
                                    neuron_distribution.controller.unwrap(),
                                    neuron_distribution.stake_e8s,
                                ))
                            } else {
                                None
                            }
                        })
                        .collect();

                if !min_stake_infringing_developer_neurons.is_empty() {
                    return Err(format!(
                        "Error: {} developer neurons have a stake below the minimum stake ({} e8s):  \n {:?}",
                        min_stake_infringing_developer_neurons.len(),
                        neuron_minimum_stake_e8s,
                        min_stake_infringing_developer_neurons,
                    ));
                }

                let min_stake_infringing_airdrop_neurons: Vec<(PrincipalId, u64)> =
                    airdrop_distribution
                        .airdrop_neurons
                        .iter()
                        .filter_map(|neuron_distribution| {
                            if neuron_distribution.stake_e8s < neuron_minimum_stake_e8s {
                                // Safe to unwrap due to the checks done above
                                Some((
                                    neuron_distribution.controller.unwrap(),
                                    neuron_distribution.stake_e8s,
                                ))
                            } else {
                                None
                            }
                        })
                        .collect();

                if !min_stake_infringing_airdrop_neurons.is_empty() {
                    return Err(format!(
                        "Error: {} airdrop neurons have a stake below the minimum stake ({} e8s):  \n {:?}",
                        min_stake_infringing_airdrop_neurons.len(),
                        neuron_minimum_stake_e8s,
                        min_stake_infringing_airdrop_neurons,
                    ));
                }
            }
        }

        Ok(())
    }

    fn validate_icp_parameters(&self) -> Result<(), String> {
        let max_icp_e8s = self
            .max_icp_e8s
            .ok_or("Error: max_icp_e8s must be specified.")?;
        let min_participants = self.min_participants.ok_or(
            "Error: cannot validate max_icp_e8s because of field min_participants missing.",
        )?;
        let min_participant_icp_e8s = self.min_participant_icp_e8s.ok_or(
            "Error: cannot validate max_icp_e8s because of field min_participant_icp_e8s missing.",
        )?;

        if max_icp_e8s < (min_participants as u64) * min_participant_icp_e8s {
            Err(
                "Target max_icp_e8s must be larger than min_participants * min_participant_icp_e8s"
                    .to_string(),
            )
        } else {
            Ok(())
        }
    }

    /// Must exist and be greater than 0.
    fn validate_min_participants(&self) -> Result<(), String> {
        let min_participants = self
            .min_participants
            .ok_or_else(|| "Error: min_participants must be specified".to_string())?;

        if min_participants < 1 {
            Err("Error: min_participants must be larger than 0".to_string())
        } else {
            Ok(())
        }
    }

    fn validate_min_participant_icp_e8s(&self) -> Result<(), String> {
        let max_icp_e8s = self
            .max_icp_e8s
            .ok_or_else(|| "Error: max_icp_e8s must be specified.".to_string())?;
        let min_participant_icp_e8s = self
            .min_participant_icp_e8s
            .ok_or_else(|| "Error: min_participant_icp_e8s must be specified.".to_string())?;
        let initial_token_distribution = self
            .initial_token_distribution
            .as_ref()
            .ok_or_else(|| "Error: initial-token-distribution must be specified".to_string())?;
        let sale_tokens = match initial_token_distribution {
            FractionalDeveloperVotingPower(fractional_developer_voting_power) => {
                let swap_distribution = fractional_developer_voting_power
                    .swap_distribution
                    .as_ref()
                    .ok_or_else(|| "Error: swap_distribution must be specified".to_string())?;
                swap_distribution.initial_swap_amount_e8s
            }
        };
        let neuron_minimum_stake_e8s = self
            .neuron_minimum_stake_e8s
            .ok_or_else(|| "Error: neuron_minimum_stake_e8s must be specified.".to_string())?;
        let min_participant_token = min_participant_icp_e8s * sale_tokens / max_icp_e8s;
        if min_participant_token < neuron_minimum_stake_e8s {
            Err("Error: min_participant_icp_e8s is too small. If max_icp are obtained, a contribution \
of min_participant_icp would result in a neuron with a stake smaller than \
neuron_minimum_stake".to_string())
        } else {
            Ok(())
        }
    }

    fn validate_min_icp_e8s(&self) -> Result<(), String> {
        let min_icp_e8s = self
            .min_icp_e8s
            .ok_or("Error: min_icp_e8s must be specified.")?;
        let max_icp_e8s = self
            .max_icp_e8s
            .ok_or("Error: max_icp_e8s must be specified to validate min_icp_e8s.")?;
        if min_icp_e8s > max_icp_e8s {
            Err("Error: min_icp_e8s cannot be larger than max_icp_e8s".to_string())
        } else {
            Ok(())
        }
    }

    fn validate_max_participant_icp_e8s(&self) -> Result<(), String> {
        let min_participant_icp_e8s = self.min_participant_icp_e8s.ok_or({
            "Error: min_participant_icp_e8s must be specified to validate max_participant_icp_e8s."
        })?;
        let max_participant_icp_e8s = self
            .max_icp_e8s
            .ok_or("Error: max_icp_e8s must be specified.")?;
        if max_participant_icp_e8s < min_participant_icp_e8s {
            Err(
                "Error: max_participant_icp_e8s can not be smaller than min_participant_e8s"
                    .to_string(),
            )
        } else {
            Ok(())
        }
    }

    fn validate_fallback_controller_principal_ids(&self) -> Result<(), String> {
        if self.fallback_controller_principal_ids.is_empty() {
            return Err(
                "Error: At least one principal ID must be supplied as a fallback controller \
                 in case the initial token swap fails."
                    .to_string(),
            );
        }

        Ok(())
    }

    fn validate_logo(&self) -> Result<(), String> {
        let logo = self
            .logo
            .as_ref()
            .ok_or_else(|| "Error: logo must be specified".to_string())?;

        if logo.len() > SnsMetadata::MAX_LOGO_LENGTH {
            return Err(format!("Error: logo string encoding must be less than {} characters, given character count: {}.", SnsMetadata::MAX_LOGO_LENGTH, logo.len()));
        }

        Ok(())
    }

    fn validate_url(&self) -> Result<(), String> {
        let url = self.url.as_ref().ok_or("Error: url must be specified")?;

        if url.len() > SnsMetadata::MAX_URL_LENGTH {
            return Err(format!(
                "Error: url must be less than {} characters, given character count is {}.",
                SnsMetadata::MAX_URL_LENGTH,
                url.len()
            ));
        } else if url.len() < SnsMetadata::MIN_URL_LENGTH {
            return Err(format!(
                "Error: url must be greater than {} characters, given character count is {}.",
                SnsMetadata::MIN_URL_LENGTH,
                url.len()
            ));
        }

        Ok(())
    }

    fn validate_name(&self) -> Result<(), String> {
        let name = self.name.as_ref().ok_or("Error: name must be specified")?;

        if name.len() > SnsMetadata::MAX_NAME_LENGTH {
            return Err(format!(
                "Error: name must be less than {} characters, given character count is {}.",
                SnsMetadata::MAX_NAME_LENGTH,
                name.len()
            ));
        } else if name.len() < SnsMetadata::MIN_NAME_LENGTH {
            return Err(format!(
                "Error: name must be greater than {} characters, given character count is {}.",
                SnsMetadata::MIN_NAME_LENGTH,
                name.len()
            ));
        }

        Ok(())
    }

    fn validate_description(&self) -> Result<(), String> {
        let description = self
            .description
            .as_ref()
            .ok_or("Error: description must be specified")?;

        if description.len() > SnsMetadata::MAX_DESCRIPTION_LENGTH {
            return Err(format!(
                "Error: description must be less than {} characters, given character count is {}.",
                SnsMetadata::MAX_DESCRIPTION_LENGTH,
                description.len()
            ));
        } else if description.len() < SnsMetadata::MIN_DESCRIPTION_LENGTH {
            return Err(format!("Error: description must be greater than {} characters, given character count is {}.", SnsMetadata::MIN_DESCRIPTION_LENGTH, description.len()));
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::pb::v1::{
        sns_init_payload::InitialTokenDistribution, DeveloperDistribution,
        FractionalDeveloperVotingPower as FractionalDVP, SwapDistribution, TreasuryDistribution,
    };
    use crate::{
        AirdropDistribution, FractionalDeveloperVotingPower, SnsCanisterIds, SnsInitPayload,
        MAX_TOKEN_NAME_LENGTH, MAX_TOKEN_SYMBOL_LENGTH,
    };
    use ic_base_types::ic_types::Principal;
    use ic_base_types::{CanisterId, PrincipalId};
    use ic_icrc1::Account;
    use ic_sns_governance::governance::ValidGovernanceProto;
    use ic_sns_governance::pb::v1::governance::SnsMetadata;

    fn create_valid_initial_token_distribution() -> InitialTokenDistribution {
        FractionalDeveloperVotingPower(FractionalDVP {
            developer_distribution: Some(DeveloperDistribution {
                developer_neurons: Default::default(),
            }),
            treasury_distribution: Some(TreasuryDistribution {
                total_e8s: 500_000_000,
            }),
            swap_distribution: Some(SwapDistribution {
                total_e8s: 1_000_000_000,
                initial_swap_amount_e8s: 1_000_000_000,
            }),
            airdrop_distribution: Some(AirdropDistribution {
                airdrop_neurons: Default::default(),
            }),
        })
    }

    fn get_test_sns_init_payload() -> SnsInitPayload {
        SnsInitPayload {
            transaction_fee_e8s: Some(10_000),
            token_name: Some("ServiceNervousSystem".to_string()),
            token_symbol: Some("SNS".to_string()),
            proposal_reject_cost_e8s: Some(100_000_000),
            neuron_minimum_stake_e8s: Some(100_000_000),
            max_icp_e8s: Some(1_000_000_000),
            min_participants: Some(10),
            initial_token_distribution: Some(create_valid_initial_token_distribution()),
            min_icp_e8s: Some(100),
            max_participant_icp_e8s: Some(1_000_000_000),
            fallback_controller_principal_ids: vec![Principal::from(
                PrincipalId::new_user_test_id(1_552_301),
            )
            .to_text()],
            logo: Some("X".repeat(100)),
            name: Some("ServiceNervousSystem".to_string()),
            description: Some("A project that decentralizes a dapp".to_string()),
            url: Some("https://internetcomputer.org/".to_string()),
            min_participant_icp_e8s: Some(100_000_000),
        }
    }

    fn create_canister_ids() -> SnsCanisterIds {
        SnsCanisterIds {
            governance: CanisterId::from_u64(1).into(),
            ledger: CanisterId::from_u64(2).into(),
            root: CanisterId::from_u64(3).into(),
            swap: CanisterId::from_u64(4).into(),
        }
    }

    #[test]
    fn test_sns_init_payload_validate() {
        // Build a payload that passes validation, then test the parts that wouldn't
        let get_sns_init_payload = || {
            get_test_sns_init_payload()
                .validate()
                .expect("Payload did not pass validation.")
        };

        let mut sns_init_payload = get_sns_init_payload();

        sns_init_payload.token_symbol = Some("S".repeat(MAX_TOKEN_SYMBOL_LENGTH + 1));
        assert!(sns_init_payload.validate().is_err());
        sns_init_payload = get_sns_init_payload();

        sns_init_payload.token_symbol = Some(" ICP".to_string());
        assert!(sns_init_payload.validate().is_err());
        sns_init_payload = get_sns_init_payload();

        sns_init_payload.token_name = Some("S".repeat(MAX_TOKEN_NAME_LENGTH + 1));
        assert!(sns_init_payload.validate().is_err());
        sns_init_payload = get_sns_init_payload();

        sns_init_payload.token_name = Some("Internet Computer".to_string());
        assert!(sns_init_payload.validate().is_err());
        sns_init_payload = get_sns_init_payload();

        sns_init_payload.token_name = Some("InternetComputerProtocol".to_string());
        assert!(sns_init_payload.validate().is_err());
        sns_init_payload = get_sns_init_payload();

        sns_init_payload.transaction_fee_e8s = None;
        assert!(sns_init_payload.validate().is_err());
        sns_init_payload = get_sns_init_payload();

        sns_init_payload.min_participants = Some(0);
        assert!(sns_init_payload.validate().is_err());
        sns_init_payload = get_sns_init_payload();

        sns_init_payload.max_icp_e8s = Some(
            (sns_init_payload
                .min_participants
                .expect("Expected min participants to be Some.") as u64)
                * (sns_init_payload
                    .min_participant_icp_e8s
                    .expect("Expected min_participant_icp_e8s to be Some"))
                - 1,
        );

        sns_init_payload.description = None;
        assert!(sns_init_payload.validate().is_err());
        sns_init_payload = get_sns_init_payload();

        sns_init_payload.description = Some("S".repeat(SnsMetadata::MAX_DESCRIPTION_LENGTH + 1));
        assert!(sns_init_payload.validate().is_err());
        sns_init_payload = get_sns_init_payload();

        sns_init_payload.description = Some("S".repeat(SnsMetadata::MIN_DESCRIPTION_LENGTH - 1));
        assert!(sns_init_payload.validate().is_err());
        sns_init_payload = get_sns_init_payload();

        sns_init_payload.name = None;
        assert!(sns_init_payload.validate().is_err());
        sns_init_payload = get_sns_init_payload();

        sns_init_payload.name = Some("S".repeat(SnsMetadata::MAX_NAME_LENGTH + 1));
        assert!(sns_init_payload.validate().is_err());
        sns_init_payload = get_sns_init_payload();

        sns_init_payload.name = Some("S".repeat(SnsMetadata::MIN_NAME_LENGTH - 1));
        assert!(sns_init_payload.validate().is_err());
        sns_init_payload = get_sns_init_payload();

        sns_init_payload.url = None;
        assert!(sns_init_payload.validate().is_err());
        sns_init_payload = get_sns_init_payload();

        sns_init_payload.url = Some("S".repeat(SnsMetadata::MAX_URL_LENGTH + 1));
        assert!(sns_init_payload.validate().is_err());
        sns_init_payload = get_sns_init_payload();

        sns_init_payload.url = Some("S".repeat(SnsMetadata::MIN_URL_LENGTH - 1));
        assert!(sns_init_payload.validate().is_err());
        sns_init_payload = get_sns_init_payload();

        sns_init_payload.logo = None;
        assert!(sns_init_payload.validate().is_err());
        sns_init_payload = get_sns_init_payload();

        sns_init_payload.logo = Some("S".repeat(SnsMetadata::MAX_LOGO_LENGTH + 1));
        assert!(sns_init_payload.validate().is_err());
        sns_init_payload = get_sns_init_payload();

        sns_init_payload.neuron_minimum_stake_e8s = Some(1_000_000_000);
        assert!(sns_init_payload.validate().is_err());
        sns_init_payload = get_sns_init_payload();

        assert!(sns_init_payload.validate().is_ok());
    }

    #[test]
    fn test_sns_canister_ids_are_used() {
        // Create a SnsInitPayload with some reasonable defaults
        let sns_init_payload = SnsInitPayload {
            token_name: Some("ServiceNervousSystem Coin".to_string()),
            token_symbol: Some("SNS".to_string()),
            proposal_reject_cost_e8s: Some(10_000),
            neuron_minimum_stake_e8s: Some(100_000_000),
            initial_token_distribution: Some(create_valid_initial_token_distribution()),
            ..get_test_sns_init_payload()
        };
        let sns_canister_ids = create_canister_ids();

        // Build all SNS canister's initialization payloads and verify the payload was.
        let build_result = sns_init_payload.build_canister_payloads(&sns_canister_ids);
        let sns_canisters_init_payloads = match build_result {
            Ok(payloads) => payloads,
            Err(e) => panic!("Could not build canister init payloads: {}", e),
        };

        // Assert that the various canister's created have been used
        assert_eq!(
            sns_canisters_init_payloads.governance.ledger_canister_id,
            Some(sns_canister_ids.ledger)
        );
        assert_eq!(
            sns_canisters_init_payloads.governance.root_canister_id,
            Some(sns_canister_ids.root)
        );

        assert_eq!(
            sns_canisters_init_payloads
                .ledger
                .archive_options
                .controller_id,
            sns_canister_ids.root
        );
        assert_eq!(
            sns_canisters_init_payloads.ledger.minting_account,
            Account {
                owner: sns_canister_ids.governance,
                subaccount: None
            }
        );

        assert_eq!(
            sns_canisters_init_payloads.root.governance_canister_id,
            Some(sns_canister_ids.governance)
        );
        assert_eq!(
            sns_canisters_init_payloads.root.ledger_canister_id,
            Some(sns_canister_ids.ledger)
        );
    }

    #[test]
    fn test_governance_init_args_is_valid() {
        // Build an sns_init_payload with defaults for non-governance related configuration.
        let sns_init_payload = SnsInitPayload {
            token_name: Some("ServiceNervousSystem Coin".to_string()),
            token_symbol: Some("SNS".to_string()),
            initial_token_distribution: Some(create_valid_initial_token_distribution()),
            proposal_reject_cost_e8s: Some(10_000),
            neuron_minimum_stake_e8s: Some(100_000_000),
            ..get_test_sns_init_payload()
        };

        // Assert that this payload is valid in the view of the library
        assert!(sns_init_payload.validate().is_ok());

        // Create valid CanisterIds
        let sns_canister_ids = create_canister_ids();

        // Build the SnsCanisterInitPayloads including SNS Governance
        let canister_payloads = sns_init_payload
            .build_canister_payloads(&sns_canister_ids)
            .expect("Expected SnsInitPayload to be a valid payload");

        let governance = canister_payloads.governance;

        // Assert that the Governance canister would accept this init payload
        assert!(ValidGovernanceProto::try_from(governance).is_ok());
    }

    #[test]
    fn test_root_init_args_is_valid() {
        // Build an sns_init_payload with defaults for non-root related configuration.
        let sns_init_payload = SnsInitPayload {
            token_name: Some("ServiceNervousSystem".to_string()),
            token_symbol: Some("SNS".to_string()),
            initial_token_distribution: Some(create_valid_initial_token_distribution()),
            ..get_test_sns_init_payload()
        };

        // Assert that this payload is valid in the view of the library
        sns_init_payload.validate().expect("");
        assert!(sns_init_payload.validate().is_ok());

        // Create valid CanisterIds
        let sns_canister_ids = create_canister_ids();

        // Build the SnsCanisterInitPayloads including SNS Root
        let canister_payloads = sns_init_payload
            .build_canister_payloads(&sns_canister_ids)
            .expect("Expected SnsInitPayload to be a valid payload");

        let root = canister_payloads.root;

        // Assert that the Root canister would accept this init payload
        assert!(root.ledger_canister_id.is_some());
        assert!(root.governance_canister_id.is_some());
    }

    #[test]
    fn test_swap_init_args_is_valid() {
        // Build an sns_init_payload with defaults for non-swap related configuration.
        let sns_init_payload = SnsInitPayload {
            token_name: Some("ServiceNervousSystem".to_string()),
            token_symbol: Some("SNS".to_string()),
            initial_token_distribution: Some(create_valid_initial_token_distribution()),
            ..get_test_sns_init_payload()
        };

        // Assert that this payload is valid in the view of the library
        assert!(sns_init_payload.validate().is_ok());

        // Create valid CanisterIds
        let sns_canister_ids = create_canister_ids();

        // Build the SnsCanisterInitPayloads including SNS Swap
        let canister_payloads = sns_init_payload
            .build_canister_payloads(&sns_canister_ids)
            .expect("Expected SnsInitPayload to be a valid payload");

        let swap = canister_payloads.swap;

        // Assert that the swap canister would accept this payload.
        assert!(swap.is_valid());
    }

    #[test]
    fn test_ledger_init_args_is_valid() {
        // Build an sns_init_payload with defaults for non-ledger related configuration.
        let transaction_fee = 10_000;
        let token_symbol = "SNS".to_string();
        let token_name = "ServiceNervousSystem Coin".to_string();

        let sns_init_payload = SnsInitPayload {
            token_name: Some(token_name.clone()),
            token_symbol: Some(token_symbol.clone()),
            initial_token_distribution: Some(create_valid_initial_token_distribution()),
            transaction_fee_e8s: Some(transaction_fee),
            ..get_test_sns_init_payload()
        };

        // Assert that this payload is valid in the view of the library
        assert!(sns_init_payload.validate().is_ok());

        // Create valid CanisterIds
        let sns_canister_ids = create_canister_ids();

        // Build the SnsCanisterInitPayloads including SNS Ledger
        let canister_payloads = sns_init_payload
            .build_canister_payloads(&sns_canister_ids)
            .expect("Expected SnsInitPayload to be a valid payload");

        let ledger = canister_payloads.ledger;

        // Assert that the Ledger canister would accept this init payload
        assert_eq!(ledger.token_symbol, token_symbol);
        assert_eq!(ledger.token_name, token_name);
        assert_eq!(
            ledger.minting_account,
            Account {
                owner: sns_canister_ids.governance,
                subaccount: None
            }
        );
        assert_eq!(ledger.transfer_fee, transaction_fee);
    }
}
