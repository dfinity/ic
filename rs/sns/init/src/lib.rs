pub mod distributions;
pub mod pb;

use crate::pb::v1::{
    sns_init_payload::InitialTokenDistribution::FractionalDeveloperVotingPower,
    FractionalDeveloperVotingPower as FractionalDVP, SnsInitPayload,
};
use anyhow::anyhow;
use ic_base_types::{CanisterId, PrincipalId};
use ic_icrc1::Account;
use ic_icrc1_index::InitArgs as IndexInitArgs;
use ic_icrc1_ledger::InitArgs as LedgerInitArgs;
use ic_ledger_canister_core::archive::ArchiveOptions;
use ic_ledger_core::Tokens;
use ic_nns_constants::{
    GOVERNANCE_CANISTER_ID as NNS_GOVERNANCE_CANISTER_ID,
    LEDGER_CANISTER_ID as ICP_LEDGER_CANISTER_ID,
};
use ic_sns_governance::init::GovernanceCanisterInitPayloadBuilder;
use ic_sns_governance::pb::v1::governance::{SnsMetadata, Version};
use ic_sns_governance::pb::v1::{
    Governance, NervousSystemParameters, Neuron, NeuronPermissionList, NeuronPermissionType,
    VotingRewardsParameters,
};
use ic_sns_governance::types::DEFAULT_TRANSFER_FEE;
use ic_sns_root::pb::v1::SnsRootCanister;
use ic_sns_swap::pb::v1::Init as SwapInit;
use lazy_static::lazy_static;
use maplit::{btreemap, hashset};
use std::collections::{BTreeMap, HashSet};

#[cfg(feature = "test")]
use std::str::FromStr;

/// The maximum number of characters allowed for token symbol.
pub const MAX_TOKEN_SYMBOL_LENGTH: usize = 10;

/// The minimum number of characters allowed for token symbol.
pub const MIN_TOKEN_SYMBOL_LENGTH: usize = 3;

/// The maximum number of characters allowed for token name.
pub const MAX_TOKEN_NAME_LENGTH: usize = 255;

/// The minimum number of characters allowed for token name.
pub const MIN_TOKEN_NAME_LENGTH: usize = 4;

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
    pub index: PrincipalId,
}

/// The Init payloads for all SNS Canisters
#[derive(Debug, Clone)]
pub struct SnsCanisterInitPayloads {
    pub governance: Governance,
    pub ledger: LedgerInitArgs,
    pub root: SnsRootCanister,
    pub swap: SwapInit,
    pub index: IndexInitArgs,
}

impl SnsInitPayload {
    /// Due to conflict with the prost derived macros on the generated Rust structs, this method
    /// acts like `SnsInitPayload::default()` except that it will provide default "real" values
    /// for default-able parameters.
    pub fn with_default_values() -> Self {
        let nervous_system_parameters_default = NervousSystemParameters::with_default_values();
        let voting_rewards_parameters = nervous_system_parameters_default
            .voting_rewards_parameters
            .as_ref()
            .unwrap();
        Self {
            transaction_fee_e8s: nervous_system_parameters_default.transaction_fee_e8s,
            initial_reward_rate_basis_points: voting_rewards_parameters
                .initial_reward_rate_basis_points,
            final_reward_rate_basis_points: voting_rewards_parameters
                .final_reward_rate_basis_points,
            token_name: None,
            token_symbol: None,
            proposal_reject_cost_e8s: nervous_system_parameters_default.reject_cost_e8s,
            neuron_minimum_stake_e8s: nervous_system_parameters_default.neuron_minimum_stake_e8s,
            neuron_minimum_dissolve_delay_to_vote_seconds: nervous_system_parameters_default
                .neuron_minimum_dissolve_delay_to_vote_seconds,
            initial_token_distribution: None,
            fallback_controller_principal_ids: vec![],
            logo: None,
            url: None,
            name: None,
            description: None,
            sns_initialization_parameters: Some("".to_string()),
        }
    }

    /// This gives us some values that work for testing but would not be useful
    /// in a real world scenario.  They are only meant to validate, not be sensible.
    pub fn with_valid_values_for_testing() -> Self {
        Self {
            token_symbol: Some("TEST".to_string()),
            token_name: Some("PlaceHolder".to_string()),
            initial_token_distribution: Some(FractionalDeveloperVotingPower(
                FractionalDVP::with_valid_values_for_testing(),
            )),
            fallback_controller_principal_ids: vec![PrincipalId::new_user_test_id(5822).to_string()],
            logo: Some("X".repeat(100)),
            name: Some("ServiceNervousSystemTest".to_string()),
            url: Some("https://internetcomputer.org/".to_string()),
            description: Some("Description of an SNS Project".to_string()),
            ..SnsInitPayload::with_default_values()
        }
    }

    /// Build all the SNS canister's init payloads given the state of the SnsInitPayload, the
    /// provided SnsCanisterIds, and the version being deployed.  
    pub fn build_canister_payloads(
        &self,
        sns_canister_ids: &SnsCanisterIds,
        deployed_version: Option<Version>,
    ) -> anyhow::Result<SnsCanisterInitPayloads> {
        self.validate()?;
        Ok(SnsCanisterInitPayloads {
            governance: self.governance_init_args(sns_canister_ids, deployed_version)?,
            ledger: self.ledger_init_args(sns_canister_ids)?,
            root: self.root_init_args(sns_canister_ids),
            swap: self.swap_init_args(sns_canister_ids),
            index: self.index_init_args(sns_canister_ids),
        })
    }

    /// Construct the params used to initialize a SNS Governance canister.
    fn governance_init_args(
        &self,
        sns_canister_ids: &SnsCanisterIds,
        deployed_version: Option<Version>,
    ) -> anyhow::Result<Governance> {
        let mut governance = GovernanceCanisterInitPayloadBuilder::new().build();
        governance.ledger_canister_id = Some(sns_canister_ids.ledger);
        governance.root_canister_id = Some(sns_canister_ids.root);
        governance.swap_canister_id = Some(sns_canister_ids.swap);
        governance.deployed_version = deployed_version;

        let parameters = self.get_nervous_system_parameters();
        governance.parameters = Some(parameters.clone());

        governance.sns_metadata = Some(self.get_sns_metadata());

        governance.neurons = self.get_initial_neurons(&parameters)?;

        governance.sns_initialization_parameters = self
            .sns_initialization_parameters
            .clone()
            .expect("sns_initialization_parameters not set");

        Ok(governance)
    }

    #[cfg(feature = "test")]
    fn maybe_test_balances(&self) -> Vec<(Account, u64)> {
        // Testing has hardcoded the public key of principal
        // jg6qm-uw64t-m6ppo-oluwn-ogr5j-dc5pm-lgy2p-eh6px-hebcd-5v73i-nqe
        // for the button to retrieve tokens.
        let tester = "jg6qm-uw64t-m6ppo-oluwn-ogr5j-dc5pm-lgy2p-eh6px-hebcd-5v73i-nqe";
        let principal = PrincipalId::from_str(tester).unwrap();
        let account = Account {
            owner: principal,
            subaccount: None,
        };
        vec![(account, /* 10k tokens */ 10_000 * /* E8 */ 100_000_000)]
    }

    #[cfg(not(feature = "test"))]
    fn maybe_test_balances(&self) -> Vec<(Account, u64)> {
        vec![]
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
            .chain(self.maybe_test_balances())
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
                max_transactions_per_response: None,
            },
        };

        Ok(payload)
    }

    /// Construct the params used to initialize a SNS Index canister.
    fn index_init_args(&self, sns_canister_ids: &SnsCanisterIds) -> IndexInitArgs {
        IndexInitArgs {
            ledger_id: CanisterId::new(sns_canister_ids.ledger).unwrap(),
        }
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
            index_canister_id: Some(sns_canister_ids.index),
        }
    }

    /// Construct the parameters used to initialize a SNS Swap canister.
    ///
    /// Precondition: self must be valid (see fn validate).
    fn swap_init_args(&self, sns_canister_ids: &SnsCanisterIds) -> SwapInit {
        SwapInit {
            sns_root_canister_id: sns_canister_ids.root.to_string(),
            sns_governance_canister_id: sns_canister_ids.governance.to_string(),
            sns_ledger_canister_id: sns_canister_ids.ledger.to_string(),

            nns_governance_canister_id: NNS_GOVERNANCE_CANISTER_ID.to_string(),
            icp_ledger_canister_id: ICP_LEDGER_CANISTER_ID.to_string(),

            fallback_controller_principal_ids: self.fallback_controller_principal_ids.clone(),
        }
    }

    /// Given `SnsCanisterIds`, get all the ledger accounts of the TokenDistributions. These
    /// accounts represent the allocation of tokens at genesis.
    fn get_all_ledger_accounts(
        &self,
        sns_canister_ids: &SnsCanisterIds,
    ) -> anyhow::Result<BTreeMap<Account, Tokens>> {
        match &self.initial_token_distribution {
            None => Ok(btreemap! {}),
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

    /// Returns a complete NervousSystemParameter struct with its corresponding SnsInitPayload
    /// fields filled out.
    fn get_nervous_system_parameters(&self) -> NervousSystemParameters {
        let nervous_system_parameters = NervousSystemParameters::with_default_values();
        let all_permissions = NeuronPermissionList {
            permissions: NeuronPermissionType::all(),
        };

        let SnsInitPayload {
            transaction_fee_e8s,
            token_name: _,
            token_symbol: _,
            proposal_reject_cost_e8s: reject_cost_e8s,
            neuron_minimum_stake_e8s,
            fallback_controller_principal_ids: _,
            logo: _,
            url: _,
            name: _,
            description: _,
            neuron_minimum_dissolve_delay_to_vote_seconds,
            sns_initialization_parameters: _,
            initial_reward_rate_basis_points,
            final_reward_rate_basis_points,
            initial_token_distribution: _,
        } = self.clone();

        let voting_rewards_parameters = Some(VotingRewardsParameters {
            initial_reward_rate_basis_points,
            final_reward_rate_basis_points,
            ..nervous_system_parameters.voting_rewards_parameters.unwrap()
        });

        NervousSystemParameters {
            neuron_claimer_permissions: Some(all_permissions.clone()),
            neuron_grantable_permissions: Some(all_permissions),
            transaction_fee_e8s,
            reject_cost_e8s,
            neuron_minimum_stake_e8s,
            neuron_minimum_dissolve_delay_to_vote_seconds,
            voting_rewards_parameters,
            ..nervous_system_parameters
        }
    }

    /// Returns an SnsMetadata struct based on configuration of the `SnsInitPayload`.
    fn get_sns_metadata(&self) -> SnsMetadata {
        SnsMetadata {
            logo: self.logo.clone(),
            url: self.url.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
        }
    }

    /// Validates the SnsInitPayload. This is called before building each SNS canister's
    /// payload and must pass.
    pub fn validate(&self) -> anyhow::Result<Self> {
        let validation_fns = [
            self.validate_token_symbol(),
            self.validate_token_name(),
            self.validate_token_distribution(),
            self.validate_neuron_minimum_stake_e8s(),
            self.validate_neuron_minimum_dissolve_delay_to_vote_seconds(),
            self.validate_proposal_reject_cost_e8s(),
            self.validate_transaction_fee_e8s(),
            self.validate_fallback_controller_principal_ids(),
            self.validate_url(),
            self.validate_logo(),
            self.validate_description(),
            self.validate_name(),
            self.validate_initial_reward_rate_basis_points(),
            self.validate_final_reward_rate_basis_points(),
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

        let nervous_system_parameters = self.get_nervous_system_parameters();

        match initial_token_distribution {
            FractionalDeveloperVotingPower(f) => f
                .validate(&nervous_system_parameters)
                .map_err(|err| err.to_string())?,
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

    fn validate_neuron_minimum_dissolve_delay_to_vote_seconds(&self) -> Result<(), String> {
        // As this is not currently configurable, pull the default value from
        let max_dissolve_delay_seconds = *NervousSystemParameters::with_default_values()
            .max_dissolve_delay_seconds
            .as_ref()
            .unwrap();

        let neuron_minimum_dissolve_delay_to_vote_seconds = self
            .neuron_minimum_dissolve_delay_to_vote_seconds
            .ok_or_else(|| {
                "Error: neuron-minimum-dissolve-delay-to-vote-seconds must be specified".to_string()
            })?;

        if neuron_minimum_dissolve_delay_to_vote_seconds > max_dissolve_delay_seconds {
            return Err(format!(
                "The minimum dissolve delay to vote ({}) cannot be greater than the max \
                dissolve delay ({})",
                neuron_minimum_dissolve_delay_to_vote_seconds, max_dissolve_delay_seconds
            ));
        }

        Ok(())
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
        if let Some(logo) = &self.logo {
            SnsMetadata::validate_logo(logo)?;
        }
        Ok(())
    }

    fn validate_url(&self) -> Result<(), String> {
        let url = self.url.as_ref().ok_or("Error: url must be specified")?;
        SnsMetadata::validate_url(url)?;
        Ok(())
    }

    fn validate_name(&self) -> Result<(), String> {
        let name = self.name.as_ref().ok_or("Error: name must be specified")?;
        SnsMetadata::validate_name(name)?;
        Ok(())
    }

    fn validate_description(&self) -> Result<(), String> {
        let description = self
            .description
            .as_ref()
            .ok_or("Error: description must be specified")?;
        SnsMetadata::validate_description(description)?;
        Ok(())
    }

    fn validate_initial_reward_rate_basis_points(&self) -> Result<(), String> {
        let initial_reward_rate_basis_points = self
            .initial_reward_rate_basis_points
            .ok_or("Error: initial_reward_rate_basis_points must be specified")?;
        if initial_reward_rate_basis_points
            > VotingRewardsParameters::INITIAL_REWARD_RATE_BASIS_POINTS_CEILING
        {
            Err(format!(
                "Error: initial_reward_rate_basis_points must be less than or equal to {}",
                VotingRewardsParameters::INITIAL_REWARD_RATE_BASIS_POINTS_CEILING
            ))
        } else {
            Ok(())
        }
    }

    fn validate_final_reward_rate_basis_points(&self) -> Result<(), String> {
        let initial_reward_rate_basis_points = self
            .initial_reward_rate_basis_points
            .ok_or("Error: initial_reward_rate_basis_points must be specified")?;
        let final_reward_rate_basis_points = self
            .final_reward_rate_basis_points
            .ok_or("Error: final_reward_rate_basis_points must be specified")?;
        if final_reward_rate_basis_points > initial_reward_rate_basis_points {
            Err(
                format!(
                    "Error: final_reward_rate_basis_points ({}) must be less than or equal to initial_reward_rate_basis_points ({})", final_reward_rate_basis_points, 
                    initial_reward_rate_basis_points
                )
            )
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod test {
    use crate::pb::v1::FractionalDeveloperVotingPower as FractionalDVP;
    use crate::{
        FractionalDeveloperVotingPower, SnsCanisterIds, SnsInitPayload, MAX_TOKEN_NAME_LENGTH,
        MAX_TOKEN_SYMBOL_LENGTH,
    };
    use ic_base_types::CanisterId;
    use ic_icrc1::Account;
    use ic_sns_governance::governance::ValidGovernanceProto;
    use ic_sns_governance::pb::v1::governance::SnsMetadata;

    fn create_canister_ids() -> SnsCanisterIds {
        SnsCanisterIds {
            governance: CanisterId::from_u64(1).into(),
            ledger: CanisterId::from_u64(2).into(),
            root: CanisterId::from_u64(3).into(),
            swap: CanisterId::from_u64(4).into(),
            index: CanisterId::from_u64(5).into(),
        }
    }

    #[test]
    fn test_sns_init_payload_validate() {
        // Build a payload that passes validation, then test the parts that wouldn't
        let get_sns_init_payload = || {
            SnsInitPayload::with_valid_values_for_testing()
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

        sns_init_payload.logo = Some("S".repeat(SnsMetadata::MAX_LOGO_LENGTH + 1));
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
            ..SnsInitPayload::with_valid_values_for_testing()
        };
        let sns_canister_ids = create_canister_ids();

        // Build all SNS canister's initialization payloads and verify the payload was.
        let build_result = sns_init_payload.build_canister_payloads(&sns_canister_ids, None);
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
            initial_token_distribution: Some(FractionalDeveloperVotingPower(
                FractionalDVP::with_valid_values_for_testing(),
            )),
            proposal_reject_cost_e8s: Some(10_000),
            neuron_minimum_stake_e8s: Some(100_000_000),
            ..SnsInitPayload::with_valid_values_for_testing()
        };

        // Assert that this payload is valid in the view of the library
        assert!(sns_init_payload.validate().is_ok());

        // Create valid CanisterIds
        let sns_canister_ids = create_canister_ids();

        // Build the SnsCanisterInitPayloads including SNS Governance
        let canister_payloads = sns_init_payload
            .build_canister_payloads(&sns_canister_ids, None)
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
            ..SnsInitPayload::with_valid_values_for_testing()
        };

        // Assert that this payload is valid in the view of the library
        assert!(sns_init_payload.validate().is_ok());

        // Create valid CanisterIds
        let sns_canister_ids = create_canister_ids();

        // Build the SnsCanisterInitPayloads including SNS Root
        let canister_payloads = sns_init_payload
            .build_canister_payloads(&sns_canister_ids, None)
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
            ..SnsInitPayload::with_valid_values_for_testing()
        };

        // Assert that this payload is valid in the view of the library
        assert!(sns_init_payload.validate().is_ok());

        // Create valid CanisterIds
        let sns_canister_ids = create_canister_ids();

        // Build the SnsCanisterInitPayloads including SNS Swap
        let canister_payloads = sns_init_payload
            .build_canister_payloads(&sns_canister_ids, None)
            .expect("Expected SnsInitPayload to be a valid payload");

        let swap = canister_payloads.swap;

        // Assert that the swap canister would accept this payload.
        assert!(swap.validate().is_ok());
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
            transaction_fee_e8s: Some(transaction_fee),
            ..SnsInitPayload::with_valid_values_for_testing()
        };

        // Assert that this payload is valid in the view of the library
        assert!(sns_init_payload.validate().is_ok());

        // Create valid CanisterIds
        let sns_canister_ids = create_canister_ids();

        // Build the SnsCanisterInitPayloads including SNS Ledger
        let canister_payloads = sns_init_payload
            .build_canister_payloads(&sns_canister_ids, None)
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

    #[test]
    fn default_voting_rewards_not_set() {
        let default_payload = SnsInitPayload::with_default_values();
        let voting_rewards_parameters = default_payload
            .get_nervous_system_parameters()
            .voting_rewards_parameters
            .unwrap();
        assert_eq!(
            voting_rewards_parameters
                .initial_reward_rate_basis_points
                .unwrap(),
            0
        );
        assert_eq!(
            voting_rewards_parameters
                .final_reward_rate_basis_points
                .unwrap(),
            0
        );
    }

    #[test]
    fn voting_rewards_propagate_to_parameters() {
        let test_payload = SnsInitPayload {
            initial_reward_rate_basis_points: Some(100),
            final_reward_rate_basis_points: Some(200),
            ..SnsInitPayload::with_default_values()
        };
        let voting_rewards_parameters = test_payload
            .get_nervous_system_parameters()
            .voting_rewards_parameters
            .unwrap();

        assert_eq!(
            voting_rewards_parameters.initial_reward_rate_basis_points,
            test_payload.initial_reward_rate_basis_points
        );
        assert_eq!(
            voting_rewards_parameters.final_reward_rate_basis_points,
            test_payload.final_reward_rate_basis_points
        );
    }
}
