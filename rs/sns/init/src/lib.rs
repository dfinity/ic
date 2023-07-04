use crate::pb::v1::{
    sns_init_payload::InitialTokenDistribution::FractionalDeveloperVotingPower,
    FractionalDeveloperVotingPower as FractionalDVP, SnsInitPayload,
};
use anyhow::anyhow;
use ic_base_types::{CanisterId, PrincipalId};
use ic_icrc1_index::InitArgs as IndexInitArgs;
use ic_icrc1_ledger::{InitArgs as LedgerInitArgs, LedgerArgument};
use ic_ledger_canister_core::archive::ArchiveOptions;
use ic_ledger_core::Tokens;
use ic_nns_constants::{
    GOVERNANCE_CANISTER_ID as NNS_GOVERNANCE_CANISTER_ID,
    LEDGER_CANISTER_ID as ICP_LEDGER_CANISTER_ID,
};
use ic_sns_governance::{
    init::GovernanceCanisterInitPayloadBuilder,
    pb::v1::{
        governance::{SnsMetadata, Version},
        Governance, NervousSystemParameters, Neuron, NeuronPermissionList, NeuronPermissionType,
        VotingRewardsParameters,
    },
    types::DEFAULT_TRANSFER_FEE,
};
use ic_sns_root::pb::v1::SnsRootCanister;
use ic_sns_swap::pb::v1::Init as SwapInit;
use icrc_ledger_types::icrc1::account::Account;
use isocountry::CountryCode;
use lazy_static::lazy_static;
use maplit::{btreemap, hashset};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    str::FromStr,
};

pub mod distributions;
pub mod pb;

/// The maximum number of characters allowed for token symbol.
pub const MAX_TOKEN_SYMBOL_LENGTH: usize = 10;

/// The minimum number of characters allowed for token symbol.
pub const MIN_TOKEN_SYMBOL_LENGTH: usize = 3;

/// The maximum number of characters allowed for token name.
pub const MAX_TOKEN_NAME_LENGTH: usize = 255;

/// The minimum number of characters allowed for token name.
pub const MIN_TOKEN_NAME_LENGTH: usize = 4;

/// The maximum count of dapp canisters that can be initially decentralized.
pub const MAX_DAPP_CANISTERS_COUNT: usize = 25;

/// The maximum number of characters allowed for confirmation text.
pub const MAX_CONFIRMATION_TEXT_LENGTH: usize = 1_000;

/// The maximum number of bytes allowed for confirmation text.
pub const MAX_CONFIRMATION_TEXT_BYTES: usize = 8 * MAX_CONFIRMATION_TEXT_LENGTH;

/// The minimum number of characters allowed for confirmation text.
pub const MIN_CONFIRMATION_TEXT_LENGTH: usize = 1;

/// The maximum number of fallback controllers can be included in the SnsInitPayload.
pub const MAX_FALLBACK_CONTROLLER_PRINCIPAL_IDS_COUNT: usize = 15;

pub enum RestrictedCountriesValidationError {
    EmptyList,
    TooManyItems(usize),
    NotIsoComplient(String),
    ContainsDuplicates(String),
}

impl RestrictedCountriesValidationError {
    fn field_name() -> String {
        "SnsInitPayload.restricted_countries".to_string()
    }
}

impl ToString for RestrictedCountriesValidationError {
    fn to_string(&self) -> String {
        let msg = match self {
            Self::EmptyList => {
                "must either be None or include at least one country code".to_string()
            }
            Self::TooManyItems(num_items) => {
                format!(
                    "must include fewer than {} country codes, given country code count: {}",
                    CountryCode::num_country_codes(),
                    num_items,
                )
            }
            Self::NotIsoComplient(item) => {
                format!("must include only ISO 3166-1 alpha-2 country codes, found '{item}'",)
            }
            Self::ContainsDuplicates(item) => {
                format!("must not contain duplicates, found '{item}'")
            }
        };
        format!("{} {msg}", Self::field_name())
    }
}

impl From<RestrictedCountriesValidationError> for Result<(), String> {
    fn from(val: RestrictedCountriesValidationError) -> Self {
        Err(val.to_string())
    }
}

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
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
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
    pub ledger: LedgerArgument,
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
            reward_rate_transition_duration_seconds: voting_rewards_parameters
                .reward_rate_transition_duration_seconds,
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
            max_dissolve_delay_seconds: nervous_system_parameters_default
                .max_dissolve_delay_seconds,
            max_neuron_age_seconds_for_age_bonus: nervous_system_parameters_default
                .max_neuron_age_for_age_bonus,
            max_dissolve_delay_bonus_percentage: nervous_system_parameters_default
                .max_dissolve_delay_bonus_percentage,
            max_age_bonus_percentage: nervous_system_parameters_default.max_age_bonus_percentage,
            initial_voting_period_seconds: nervous_system_parameters_default
                .initial_voting_period_seconds,
            wait_for_quiet_deadline_increase_seconds: nervous_system_parameters_default
                .wait_for_quiet_deadline_increase_seconds,
            dapp_canisters: None,
            confirmation_text: None,
            restricted_countries: None,
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
            logo: Some("data:image/png;base64,aGVsbG8gZnJvbSBkZmluaXR5IQ==".to_string()),
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
        testflight: bool,
    ) -> anyhow::Result<SnsCanisterInitPayloads> {
        self.validate()?;
        Ok(SnsCanisterInitPayloads {
            governance: self.governance_init_args(sns_canister_ids, deployed_version)?,
            ledger: self.ledger_init_args(sns_canister_ids)?,
            root: self.root_init_args(sns_canister_ids, testflight),
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

        governance.sns_initialization_parameters = serde_yaml::to_string(self)
            .map_err(|e| anyhow!(format!("Could not create initialization parameters {}", e)))?;

        Ok(governance)
    }

    #[cfg(feature = "test")]
    fn maybe_test_balances(&self) -> Vec<(Account, u64)> {
        // Testing has hardcoded the public key of principal
        // jg6qm-uw64t-m6ppo-oluwn-ogr5j-dc5pm-lgy2p-eh6px-hebcd-5v73i-nqe
        // for the button to retrieve tokens.
        let tester = "jg6qm-uw64t-m6ppo-oluwn-ogr5j-dc5pm-lgy2p-eh6px-hebcd-5v73i-nqe";
        let principal = PrincipalId::from_str(tester).unwrap().0;
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
    ) -> anyhow::Result<LedgerArgument> {
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
            owner: sns_canister_ids.governance.0,
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
            fee_collector_account: None,
            max_memo_length: None,
            feature_flags: None,
        };

        Ok(LedgerArgument::Init(payload))
    }

    /// Construct the params used to initialize a SNS Index canister.
    fn index_init_args(&self, sns_canister_ids: &SnsCanisterIds) -> IndexInitArgs {
        IndexInitArgs {
            ledger_id: CanisterId::new(sns_canister_ids.ledger).unwrap(),
        }
    }

    /// Construct the params used to initialize a SNS Root canister.
    fn root_init_args(
        &self,
        sns_canister_ids: &SnsCanisterIds,
        testflight: bool,
    ) -> SnsRootCanister {
        let dapp_canister_ids = match self.dapp_canisters.as_ref() {
            None => vec![],
            Some(dapp_canisters) => dapp_canisters
                .canisters
                .iter()
                .map(|canister| canister.id.unwrap())
                .collect(),
        };

        SnsRootCanister {
            governance_canister_id: Some(sns_canister_ids.governance),
            ledger_canister_id: Some(sns_canister_ids.ledger),
            swap_canister_id: Some(sns_canister_ids.swap),
            dapp_canister_ids,
            archive_canister_ids: vec![],
            latest_ledger_archive_poll_timestamp_seconds: None,
            index_canister_id: Some(sns_canister_ids.index),
            testflight,
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

            transaction_fee_e8s: self.transaction_fee_e8s,
            neuron_minimum_stake_e8s: self.neuron_minimum_stake_e8s,
            confirmation_text: self.confirmation_text.clone(),
            restricted_countries: self.restricted_countries.clone(),
            min_participants: None,                      // TODO[NNS1-2339]
            min_icp_e8s: None,                           // TODO[NNS1-2339]
            max_icp_e8s: None,                           // TODO[NNS1-2339]
            min_participant_icp_e8s: None,               // TODO[NNS1-2339]
            max_participant_icp_e8s: None,               // TODO[NNS1-2339]
            swap_start_timestamp_seconds: None,          // TODO[NNS1-2339]
            swap_due_timestamp_seconds: None,            // TODO[NNS1-2339]
            sns_token_e8s: None,                         // TODO[NNS1-2339]
            neuron_basket_construction_parameters: None, // TODO[NNS1-2339]
            nns_proposal_id: None,                       // TODO[NNS1-2339]
            neurons_fund_participants: None,             // TODO[NNS1-2339]
            should_auto_finalize: Some(true),
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
            reward_rate_transition_duration_seconds,
            initial_reward_rate_basis_points,
            final_reward_rate_basis_points,
            initial_token_distribution: _,
            max_dissolve_delay_seconds,
            max_neuron_age_seconds_for_age_bonus: max_neuron_age_for_age_bonus,
            max_dissolve_delay_bonus_percentage,
            max_age_bonus_percentage,
            initial_voting_period_seconds,
            wait_for_quiet_deadline_increase_seconds,
            dapp_canisters: _,
            confirmation_text: _,
            restricted_countries: _,
        } = self.clone();

        let voting_rewards_parameters = Some(VotingRewardsParameters {
            reward_rate_transition_duration_seconds,
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
            max_dissolve_delay_seconds,
            max_neuron_age_for_age_bonus,
            max_dissolve_delay_bonus_percentage,
            max_age_bonus_percentage,
            initial_voting_period_seconds,
            wait_for_quiet_deadline_increase_seconds,
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
            self.validate_reward_rate_transition_duration_seconds(),
            self.validate_max_dissolve_delay_seconds(),
            self.validate_max_neuron_age_seconds_for_age_bonus(),
            self.validate_max_dissolve_delay_bonus_percentage(),
            self.validate_max_age_bonus_percentage(),
            self.validate_initial_voting_period_seconds(),
            self.validate_wait_for_quiet_deadline_increase_seconds(),
            self.validate_dapp_canisters(),
            self.validate_confirmation_text(),
            self.validate_restricted_countries(),
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

        if self.fallback_controller_principal_ids.len()
            > MAX_FALLBACK_CONTROLLER_PRINCIPAL_IDS_COUNT
        {
            return Err(format!(
                "Error: The number of fallback_controller_principal_ids \
                must be less than {}. Current count is {}",
                MAX_FALLBACK_CONTROLLER_PRINCIPAL_IDS_COUNT,
                self.fallback_controller_principal_ids.len()
            ));
        }

        let invalid_principals: Vec<_> = self
            .fallback_controller_principal_ids
            .iter()
            .map(|principal_id_string| {
                (
                    principal_id_string,
                    PrincipalId::from_str(principal_id_string),
                )
            })
            .filter(|pair| pair.1.is_err())
            .map(|pair| pair.0)
            .collect();

        if !invalid_principals.is_empty() {
            return Err(format!(
                "Error: One or more fallback_controller_principal_ids is not a valid principal id. \
                The follow principals are invalid: {:?}", invalid_principals
            ));
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

    fn validate_reward_rate_transition_duration_seconds(&self) -> Result<(), String> {
        let _reward_rate_transition_duration_seconds = self
            .reward_rate_transition_duration_seconds
            .ok_or("Error: reward_rate_transition_duration_seconds must be specified")?;
        Ok(())
    }

    fn validate_max_dissolve_delay_seconds(&self) -> Result<(), String> {
        let _max_dissolve_delay_seconds = self
            .max_dissolve_delay_seconds
            .ok_or("Error: max_dissolve_delay_seconds must be specified")?;
        Ok(())
    }

    fn validate_max_neuron_age_seconds_for_age_bonus(&self) -> Result<(), String> {
        let _max_neuron_age_seconds_for_age_bonus = self
            .max_neuron_age_seconds_for_age_bonus
            .ok_or("Error: max_neuron_age_seconds_for_age_bonus must be specified")?;
        Ok(())
    }

    fn validate_max_dissolve_delay_bonus_percentage(&self) -> Result<(), String> {
        let max_dissolve_delay_bonus_percentage = self
            .max_dissolve_delay_bonus_percentage
            .ok_or("Error: max_dissolve_delay_bonus_percentage must be specified")?;

        if max_dissolve_delay_bonus_percentage
            > NervousSystemParameters::MAX_DISSOLVE_DELAY_BONUS_PERCENTAGE_CEILING
        {
            Err(format!(
                "max_dissolve_delay_bonus_percentage must be less than {}",
                NervousSystemParameters::MAX_DISSOLVE_DELAY_BONUS_PERCENTAGE_CEILING
            ))
        } else {
            Ok(())
        }
    }

    fn validate_max_age_bonus_percentage(&self) -> Result<(), String> {
        let max_age_bonus_percentage = self
            .max_age_bonus_percentage
            .ok_or("Error: max_age_bonus_percentage must be specified")?;
        if max_age_bonus_percentage > NervousSystemParameters::MAX_AGE_BONUS_PERCENTAGE_CEILING {
            Err(format!(
                "max_age_bonus_percentage must be less than {}",
                NervousSystemParameters::MAX_AGE_BONUS_PERCENTAGE_CEILING
            ))
        } else {
            Ok(())
        }
    }

    fn validate_initial_voting_period_seconds(&self) -> Result<(), String> {
        let initial_voting_period_seconds = self
            .initial_voting_period_seconds
            .ok_or("Error: initial_voting_period_seconds must be specified")?;

        if initial_voting_period_seconds
            < NervousSystemParameters::INITIAL_VOTING_PERIOD_SECONDS_FLOOR
        {
            Err(format!(
                "NervousSystemParameters.initial_voting_period_seconds must be greater than {}",
                NervousSystemParameters::INITIAL_VOTING_PERIOD_SECONDS_FLOOR
            ))
        } else if initial_voting_period_seconds
            > NervousSystemParameters::INITIAL_VOTING_PERIOD_SECONDS_CEILING
        {
            Err(format!(
                "NervousSystemParameters.initial_voting_period_seconds must be less than {}",
                NervousSystemParameters::INITIAL_VOTING_PERIOD_SECONDS_CEILING
            ))
        } else {
            Ok(())
        }
    }

    fn validate_wait_for_quiet_deadline_increase_seconds(&self) -> Result<(), String> {
        let wait_for_quiet_deadline_increase_seconds = self
            .wait_for_quiet_deadline_increase_seconds
            .ok_or("Error: wait_for_quiet_deadline_increase_seconds must be specified")?;
        let initial_voting_period_seconds = self
            .initial_voting_period_seconds
            .ok_or("Error: initial_voting_period_seconds must be specified")?;

        if wait_for_quiet_deadline_increase_seconds
            < NervousSystemParameters::WAIT_FOR_QUIET_DEADLINE_INCREASE_SECONDS_FLOOR
        {
            Err(format!(
                "NervousSystemParameters.wait_for_quiet_deadline_increase_seconds must be greater than or equal to {}",
                NervousSystemParameters::WAIT_FOR_QUIET_DEADLINE_INCREASE_SECONDS_FLOOR
            ))
        } else if wait_for_quiet_deadline_increase_seconds
            > NervousSystemParameters::WAIT_FOR_QUIET_DEADLINE_INCREASE_SECONDS_CEILING
        {
            Err(format!(
                "NervousSystemParameters.wait_for_quiet_deadline_increase_seconds must be less than or equal to {}",
                NervousSystemParameters::WAIT_FOR_QUIET_DEADLINE_INCREASE_SECONDS_CEILING
            ))
        // If `wait_for_quiet_deadline_increase_seconds > initial_voting_period_seconds / 2`, any flip (including an initial `yes` vote)
        // will always cause the deadline to be increased. That seems like unreasonable behavior, so we prevent that from being
        // the case.
        } else if wait_for_quiet_deadline_increase_seconds > initial_voting_period_seconds / 2 {
            Err(format!(
                "NervousSystemParameters.wait_for_quiet_deadline_increase_seconds is {}, but must be less than or equal to half the initial voting period, {}",
                initial_voting_period_seconds, initial_voting_period_seconds / 2
            ))
        } else {
            Ok(())
        }
    }

    fn validate_dapp_canisters(&self) -> Result<(), String> {
        let dapp_canisters = match &self.dapp_canisters {
            None => return Ok(()),
            Some(dapp_canisters) => dapp_canisters,
        };

        if dapp_canisters.canisters.len() > MAX_DAPP_CANISTERS_COUNT {
            return Err(format!(
                "Error: The number of dapp_canisters exceeded the maximum allowed canisters at \
                initialization. Count is {}. Maximum allowed is {}.",
                dapp_canisters.canisters.len(),
                MAX_DAPP_CANISTERS_COUNT,
            ));
        }

        for (index, canister) in dapp_canisters.canisters.iter().enumerate() {
            if canister.id.is_none() {
                return Err(format!("Error: dapp_canisters[{}] id field is None", index));
            }
        }

        // Disallow duplicate dapp canisters, because it indicates that
        // the user probably made a mistake (e.g. copy n' paste).
        let unique_dapp_canisters: BTreeSet<_> = dapp_canisters
            .canisters
            .iter()
            .map(|canister| canister.id)
            .collect();
        if unique_dapp_canisters.len() != dapp_canisters.canisters.len() {
            return Err("Error: Duplicate ids found in dapp_canisters".to_string());
        }

        Ok(())
    }

    fn validate_confirmation_text(&self) -> Result<(), String> {
        if let Some(confirmation_text) = &self.confirmation_text {
            if MAX_CONFIRMATION_TEXT_BYTES < confirmation_text.len() {
                return Err(
                    format!(
                        "NervousSystemParameters.confirmation_text must be fewer than {} bytes, given bytes: {}",
                        MAX_CONFIRMATION_TEXT_BYTES,
                        confirmation_text.len(),
                    )
                );
            }
            let confirmation_text_length = confirmation_text.chars().count();
            if confirmation_text_length < MIN_CONFIRMATION_TEXT_LENGTH {
                return Err(
                    format!(
                        "NervousSystemParameters.confirmation_text must be greater than {} characters, given character count: {}",
                        MIN_CONFIRMATION_TEXT_LENGTH,
                        confirmation_text_length,
                    )
                );
            }
            if MAX_CONFIRMATION_TEXT_LENGTH < confirmation_text_length {
                return Err(
                    format!(
                        "NervousSystemParameters.confirmation_text must be fewer than {} characters, given character count: {}",
                        MAX_CONFIRMATION_TEXT_LENGTH,
                        confirmation_text_length,
                    )
                );
            }
        }
        Ok(())
    }

    fn validate_restricted_countries(&self) -> Result<(), String> {
        if let Some(restricted_countries) = &self.restricted_countries {
            if restricted_countries.iso_codes.is_empty() {
                return RestrictedCountriesValidationError::EmptyList.into();
            }
            let num_items = restricted_countries.iso_codes.len();
            if CountryCode::num_country_codes() < num_items {
                return RestrictedCountriesValidationError::TooManyItems(
                    restricted_countries.iso_codes.len(),
                )
                .into();
            }
            let mut unique_iso_codes = BTreeSet::<String>::new();
            for item in &restricted_countries.iso_codes {
                if CountryCode::for_alpha2(item).is_err() {
                    return RestrictedCountriesValidationError::NotIsoComplient(item.clone())
                        .into();
                }
                if !unique_iso_codes.insert(item.clone()) {
                    return RestrictedCountriesValidationError::ContainsDuplicates(item.clone())
                        .into();
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{
        pb::v1::{
            AirdropDistribution, DappCanisters, DeveloperDistribution,
            FractionalDeveloperVotingPower as FractionalDVP, NeuronDistribution,
        },
        FractionalDeveloperVotingPower, RestrictedCountriesValidationError, SnsCanisterIds,
        SnsInitPayload, MAX_CONFIRMATION_TEXT_LENGTH, MAX_DAPP_CANISTERS_COUNT,
        MAX_FALLBACK_CONTROLLER_PRINCIPAL_IDS_COUNT, MAX_TOKEN_NAME_LENGTH,
        MAX_TOKEN_SYMBOL_LENGTH,
    };
    use ic_base_types::{CanisterId, PrincipalId};
    use ic_icrc1_ledger::LedgerArgument;
    use ic_nervous_system_proto::pb::v1::{Canister, Countries};
    use ic_sns_governance::{
        governance::ValidGovernanceProto, pb::v1::governance::SnsMetadata, types::ONE_MONTH_SECONDS,
    };
    use icrc_ledger_types::icrc1::account::Account;
    use isocountry::CountryCode;
    use std::{collections::BTreeMap, convert::TryInto};

    fn create_canister_ids() -> SnsCanisterIds {
        SnsCanisterIds {
            governance: CanisterId::from_u64(1).into(),
            ledger: CanisterId::from_u64(2).into(),
            root: CanisterId::from_u64(3).into(),
            swap: CanisterId::from_u64(4).into(),
            index: CanisterId::from_u64(5).into(),
        }
    }

    fn generate_unique_dapp_canisters(count: usize) -> DappCanisters {
        let canisters = (0..count)
            .into_iter()
            .map(|i| Canister {
                id: Some(CanisterId::from_u64(i as u64).get()),
            })
            .collect();

        DappCanisters { canisters }
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
        let build_result = sns_init_payload.build_canister_payloads(&sns_canister_ids, None, false);
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

        if let LedgerArgument::Init(ledger) = sns_canisters_init_payloads.ledger {
            assert_eq!(ledger.archive_options.controller_id, sns_canister_ids.root);
            assert_eq!(
                ledger.minting_account,
                Account {
                    owner: sns_canister_ids.governance.0,
                    subaccount: None
                }
            );
        } else {
            panic!("bug: expected Init got Upgrade.");
        }

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
            .build_canister_payloads(&sns_canister_ids, None, false)
            .expect("Expected SnsInitPayload to be a valid payload");

        let governance = canister_payloads.governance;

        // Assert that the Governance canister would accept this init payload
        assert!(ValidGovernanceProto::try_from(governance).is_ok());
    }

    #[test]
    fn test_governance_init_args_has_generated_config() {
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
            .build_canister_payloads(&sns_canister_ids, None, false)
            .expect("Expected SnsInitPayload to be a valid payload");

        let governance = canister_payloads.governance;

        // Assert that the Governance canister's params match the SnsInitPayload
        assert_eq!(
            serde_yaml::from_str::<SnsInitPayload>(&governance.sns_initialization_parameters)
                .unwrap(),
            sns_init_payload
        );
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
            .build_canister_payloads(&sns_canister_ids, None, false)
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
            .build_canister_payloads(&sns_canister_ids, None, false)
            .expect("Expected SnsInitPayload to be a valid payload");

        let swap = canister_payloads.swap;

        // Assert that the swap canister would accept this payload.
        assert!(swap.validate().is_ok());
    }

    #[test]
    fn test_confirmation_text_is_valid() {
        // Create valid CanisterIds
        let sns_canister_ids = create_canister_ids();
        // Test that `confirmation_text` is indeed optional.
        {
            let sns_init_payload = SnsInitPayload {
                confirmation_text: None,
                ..SnsInitPayload::with_valid_values_for_testing()
            };
            assert!(sns_init_payload
                .build_canister_payloads(&sns_canister_ids, None, false)
                .is_ok());
        }
        // Test that some non-trivial value of `confirmation_text` validates.
        {
            let sns_init_payload: SnsInitPayload = SnsInitPayload {
                confirmation_text: Some("Please confirm that 2+2=4".to_string()),
                ..SnsInitPayload::with_valid_values_for_testing()
            };
            assert!(sns_init_payload
                .build_canister_payloads(&sns_canister_ids, None, false)
                .is_ok());
        }
        // Test that `confirmation_text` set to an empty string is rejected.
        {
            let sns_init_payload = SnsInitPayload {
                confirmation_text: Some("".to_string()),
                ..SnsInitPayload::with_valid_values_for_testing()
            };
            assert!(sns_init_payload
                .build_canister_payloads(&sns_canister_ids, None, false)
                .is_err());
        }
        // Test that `confirmation_text` set to a very long string is rejected.
        {
            let sns_init_payload = SnsInitPayload {
                confirmation_text: Some(
                    (0..MAX_CONFIRMATION_TEXT_LENGTH + 1)
                        .map(|x| x.to_string())
                        .collect(),
                ),
                ..SnsInitPayload::with_valid_values_for_testing()
            };
            assert!(sns_init_payload
                .build_canister_payloads(&sns_canister_ids, None, false)
                .is_err());
        }
    }

    fn assert_error<T, E>(result: anyhow::Result<T>, expected_error: E)
    where
        T: std::fmt::Debug,
        E: ToString,
    {
        assert_eq!(result.unwrap_err().to_string(), expected_error.to_string())
    }

    #[test]
    fn test_restricted_countries() {
        // Create valid CanisterIds
        let sns_canister_ids = create_canister_ids();
        // Test that `restricted_countries` is indeed optional.
        {
            let sns_init_payload = SnsInitPayload {
                restricted_countries: None,
                ..SnsInitPayload::with_valid_values_for_testing()
            };
            assert!(sns_init_payload
                .build_canister_payloads(&sns_canister_ids, None, false)
                .is_ok());
        }
        // Test that some non-trivial value of `restricted_countries` validates.
        {
            let sns_init_payload = SnsInitPayload {
                restricted_countries: Some(Countries {
                    iso_codes: vec!["CH".to_string()],
                }),
                ..SnsInitPayload::with_valid_values_for_testing()
            };
            assert!(sns_init_payload
                .build_canister_payloads(&sns_canister_ids, None, false)
                .is_ok());
        }
        // Test that multiple countries can be validated.
        {
            let sns_init_payload = SnsInitPayload {
                restricted_countries: Some(Countries {
                    iso_codes: CountryCode::as_array_alpha2()
                        .map(|x| x.alpha2().to_string())
                        .to_vec(),
                }),
                ..SnsInitPayload::with_valid_values_for_testing()
            };
            assert!(sns_init_payload
                .build_canister_payloads(&sns_canister_ids, None, false)
                .is_ok());
        }
        // Check that item count is checked before duplicate analysis.
        {
            let num_items = CountryCode::num_country_codes() + 1;
            let sns_init_payload = SnsInitPayload {
                restricted_countries: Some(Countries {
                    iso_codes: (0..num_items).map(|x| x.to_string()).collect(),
                }),
                ..SnsInitPayload::with_valid_values_for_testing()
            };
            assert_error(
                sns_init_payload.build_canister_payloads(&sns_canister_ids, None, false),
                RestrictedCountriesValidationError::TooManyItems(num_items),
            );
        }
        // Test that empty `iso_codes` list is rejected.
        {
            let sns_init_payload = SnsInitPayload {
                restricted_countries: Some(Countries { iso_codes: vec![] }),
                ..SnsInitPayload::with_valid_values_for_testing()
            };
            assert_error(
                sns_init_payload.build_canister_payloads(&sns_canister_ids, None, false),
                RestrictedCountriesValidationError::EmptyList,
            );
        }
        // Test that a lowercase country code is rejected.
        {
            let item = "ch".to_string();
            let sns_init_payload = SnsInitPayload {
                restricted_countries: Some(Countries {
                    iso_codes: vec![item.clone()],
                }),
                ..SnsInitPayload::with_valid_values_for_testing()
            };
            assert_error(
                sns_init_payload.build_canister_payloads(&sns_canister_ids, None, false),
                RestrictedCountriesValidationError::NotIsoComplient(item),
            );
        }
        // Test that alpha3 is rejected.
        {
            let item = "CHE".to_string();
            let sns_init_payload = SnsInitPayload {
                restricted_countries: Some(Countries {
                    iso_codes: vec![item.clone()],
                }),
                ..SnsInitPayload::with_valid_values_for_testing()
            };
            assert_error(
                sns_init_payload.build_canister_payloads(&sns_canister_ids, None, false),
                RestrictedCountriesValidationError::NotIsoComplient(item),
            );
        }
        // Test that a non-existing country code is rejected.
        {
            let item = "QQ".to_string();
            let sns_init_payload = SnsInitPayload {
                restricted_countries: Some(Countries {
                    iso_codes: vec![item.clone()],
                }),
                ..SnsInitPayload::with_valid_values_for_testing()
            };
            assert_error(
                sns_init_payload.build_canister_payloads(&sns_canister_ids, None, false),
                RestrictedCountriesValidationError::NotIsoComplient(item),
            );
        }
        // Test that duplicate country codes are rejected.
        {
            let item = "CH".to_string();
            let sns_init_payload = SnsInitPayload {
                restricted_countries: Some(Countries {
                    iso_codes: vec![item.clone(), item.clone()],
                }),
                ..SnsInitPayload::with_valid_values_for_testing()
            };
            assert_error(
                sns_init_payload.build_canister_payloads(&sns_canister_ids, None, false),
                RestrictedCountriesValidationError::ContainsDuplicates(item),
            );
        }
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
            .build_canister_payloads(&sns_canister_ids, None, false)
            .expect("Expected SnsInitPayload to be a valid payload");

        // Assert that the Ledger canister would accept this init payload
        if let LedgerArgument::Init(ledger) = canister_payloads.ledger {
            assert_eq!(ledger.token_symbol, token_symbol);
            assert_eq!(ledger.token_name, token_name);
            assert_eq!(
                ledger.minting_account,
                Account {
                    owner: sns_canister_ids.governance.0,
                    subaccount: None
                }
            );
            assert_eq!(ledger.transfer_fee, transaction_fee);
        } else {
            panic!("bug: expected Init got Upgrade.");
        }
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
            reward_rate_transition_duration_seconds: Some(300),
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
        assert_eq!(
            voting_rewards_parameters.reward_rate_transition_duration_seconds,
            test_payload.reward_rate_transition_duration_seconds
        );
    }

    #[test]
    fn test_dapp_canisters_validation() {
        // Build a payload that passes validation, then test the parts that wouldn't
        let get_sns_init_payload = || {
            SnsInitPayload::with_valid_values_for_testing()
                .validate()
                .expect("Payload did not pass validation.")
        };

        let mut sns_init_payload = get_sns_init_payload();
        sns_init_payload.dapp_canisters =
            Some(generate_unique_dapp_canisters(MAX_DAPP_CANISTERS_COUNT + 1));
        assert!(sns_init_payload.validate().is_err());

        sns_init_payload.dapp_canisters =
            Some(generate_unique_dapp_canisters(MAX_DAPP_CANISTERS_COUNT));
        assert!(sns_init_payload.validate().is_ok());

        sns_init_payload.dapp_canisters = None;
        assert!(sns_init_payload.validate().is_ok());

        sns_init_payload.dapp_canisters = Some(DappCanisters {
            canisters: vec![Canister { id: None }],
        });
        assert!(sns_init_payload.validate().is_err());

        let duplicate_dapp_canister = Canister {
            id: Some(CanisterId::from_u64(1).get()),
        };
        sns_init_payload.dapp_canisters = Some(DappCanisters {
            canisters: vec![duplicate_dapp_canister, duplicate_dapp_canister],
        });
        assert!(sns_init_payload.validate().is_err());
    }

    // Create an initial SNS payload that includes Governance and Ledger init payloads. Then
    // iterate over each neuron in the Governance init payload and assert that each neuron's
    // account is present in the Ledger init payload's `initial_balances`.
    #[test]
    fn test_build_canister_payloads_creates_neurons_with_correct_ledger_accounts() {
        let controller1 = PrincipalId::new_user_test_id(2209);
        let airdrop_neuron1 = NeuronDistribution {
            controller: Some(controller1),
            stake_e8s: 100_000_000,
            memo: 5,
            dissolve_delay_seconds: 0,
            vesting_period_seconds: None,
        };
        let controller2 = PrincipalId::new_user_test_id(7184);
        let airdrop_neuron2 = NeuronDistribution {
            controller: Some(controller2),
            stake_e8s: 770_000_000,
            memo: 1644,
            dissolve_delay_seconds: 9053,
            vesting_period_seconds: None,
        };
        let airdrop_neurons = AirdropDistribution {
            airdrop_neurons: vec![airdrop_neuron1, airdrop_neuron2],
        };
        let controller3 = PrincipalId::new_user_test_id(3209);
        let developer_neuron1 = NeuronDistribution {
            controller: Some(controller3),
            stake_e8s: 330_000_000,
            memo: 8721,
            dissolve_delay_seconds: ONE_MONTH_SECONDS * 6,
            vesting_period_seconds: None,
        };
        let developer_neurons = DeveloperDistribution {
            developer_neurons: vec![developer_neuron1],
        };

        let mut fdvp = FractionalDVP::with_valid_values_for_testing();
        fdvp.airdrop_distribution = Some(airdrop_neurons);
        fdvp.developer_distribution = Some(developer_neurons);

        // Build an sns_init_payload with defaults for non-governance related configuration.
        let sns_init_payload = SnsInitPayload {
            token_name: Some("ServiceNervousSystem Coin".to_string()),
            token_symbol: Some("SNS".to_string()),
            initial_token_distribution: Some(FractionalDeveloperVotingPower(fdvp)),
            proposal_reject_cost_e8s: Some(10_000),
            neuron_minimum_stake_e8s: Some(100_000_000),
            ..SnsInitPayload::with_valid_values_for_testing()
        };

        // Assert that this payload is valid in the view of the library
        sns_init_payload
            .validate()
            .expect("Init payload must be valid");

        // Create valid CanisterIds
        let sns_canister_ids = create_canister_ids();

        // Build the SnsCanisterInitPayloads including SNS Governance
        let canister_payloads = sns_init_payload
            .build_canister_payloads(&sns_canister_ids, None, false)
            .expect("Expected SnsInitPayload to be a valid payload");

        let governance = canister_payloads.governance;
        let init_accounts: BTreeMap<Account, u64> =
            if let LedgerArgument::Init(ledger) = canister_payloads.ledger {
                ledger.initial_balances.into_iter().collect()
            } else {
                panic!("bug: expected Init got Upgrade");
            };

        // Assert that the Governance canister would accept this init payload
        assert!(ValidGovernanceProto::try_from(governance.clone()).is_ok());

        // For each neuron, assert that its account exists on the Ledger
        for neuron in governance.neurons.values() {
            let subaccount = neuron.id.clone().unwrap().id;
            let account = Account {
                owner: sns_canister_ids.governance.0,
                subaccount: Some(subaccount.as_slice().try_into().unwrap()),
            };
            let account_balance = *init_accounts
                .get(&account)
                .expect("Neuron must have an account on the Ledger");
            assert_eq!(account_balance, neuron.cached_neuron_stake_e8s);
        }
    }

    #[test]
    fn test_fallback_controller_principal_ids_validation() {
        let generate_pids = |count| -> Vec<String> {
            (0..count)
                .map(|i| PrincipalId::new_user_test_id(i as u64).to_string())
                .collect()
        };

        // Build a payload that passes validation, then test the parts that wouldn't
        let get_sns_init_payload = || {
            SnsInitPayload::with_valid_values_for_testing()
                .validate()
                .expect("Payload did not pass validation.")
        };

        let mut sns_init_payload = get_sns_init_payload();
        sns_init_payload.fallback_controller_principal_ids = generate_pids(0);
        assert!(sns_init_payload.validate().is_err());

        let mut sns_init_payload = get_sns_init_payload();
        sns_init_payload.fallback_controller_principal_ids =
            generate_pids(MAX_FALLBACK_CONTROLLER_PRINCIPAL_IDS_COUNT + 1);
        assert!(sns_init_payload.validate().is_err());

        let mut sns_init_payload = get_sns_init_payload();
        sns_init_payload.fallback_controller_principal_ids = vec![
            "not a valid pid".to_string(),
            "definitely not a valid pid".to_string(),
        ];
        assert!(sns_init_payload.validate().is_err());

        let mut sns_init_payload = get_sns_init_payload();
        sns_init_payload.fallback_controller_principal_ids =
            vec![PrincipalId::new_user_test_id(1).to_string()];
        assert!(sns_init_payload.validate().is_ok());
    }
}
