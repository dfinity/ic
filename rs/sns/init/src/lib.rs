use crate::pb::v1::{
    sns_init_payload::InitialTokenDistribution::FractionalDeveloperVotingPower,
    FractionalDeveloperVotingPower as FractionalDVP, NeuronsFundParticipants, SnsInitPayload,
    SwapDistribution,
};
use candid::Principal;
use ic_base_types::{CanisterId, PrincipalId};
use ic_icrc1_index_ng::{IndexArg, InitArg};
use ic_icrc1_ledger::{InitArgsBuilder as LedgerInitArgsBuilder, LedgerArgument};
use ic_ledger_canister_core::archive::ArchiveOptions;
use ic_ledger_core::Tokens;
use ic_nervous_system_common::ledger_validation;
use ic_nervous_system_common::{DEFAULT_TRANSFER_FEE, E8};
use ic_nervous_system_proto::pb::v1::{Canister, Countries};
use ic_nns_constants::{
    CYCLES_MINTING_CANISTER_ID, EXCHANGE_RATE_CANISTER_ID, GENESIS_TOKEN_CANISTER_ID,
    GOVERNANCE_CANISTER_ID as NNS_GOVERNANCE_CANISTER_ID, IDENTITY_CANISTER_ID,
    LEDGER_CANISTER_ID as ICP_LEDGER_CANISTER_ID, LIFELINE_CANISTER_ID, NNS_UI_CANISTER_ID,
    REGISTRY_CANISTER_ID, ROOT_CANISTER_ID, SNS_WASM_CANISTER_ID,
};
use ic_sns_governance::{
    init::GovernanceCanisterInitPayloadBuilder,
    pb::v1::{
        governance::{SnsMetadata, Version},
        Governance, NervousSystemParameters, Neuron, NeuronPermissionList, NeuronPermissionType,
        VotingRewardsParameters,
    },
};
use ic_sns_root::pb::v1::SnsRootCanister;
use ic_sns_swap::{
    neurons_fund,
    pb::v1::{
        IdealMatchedParticipationFunction, Init as SwapInit, LinearScalingCoefficient,
        NeuronBasketConstructionParameters, NeuronsFundParticipationConstraints,
    },
};
use icrc_ledger_types::{icrc::generic_metadata_value::MetadataValue, icrc1::account::Account};
use isocountry::CountryCode;
use maplit::btreemap;
use pb::v1::DappCanisters;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    num::NonZeroU64,
    str::FromStr,
    string::ToString,
};

pub mod distributions;
pub mod pb;

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

/// The maximum amount of ICP that can be directly contributed to a
/// decentralization swap.
/// Aka, the ceiling for the value `max_direct_icp`.
pub const MAX_DIRECT_ICP_CONTRIBUTION_TO_SWAP: u64 = 1_000_000_000 * E8;

pub const ICRC1_TOKEN_LOGO_KEY: &str = "icrc1:logo";

enum MinDirectParticipationThresholdValidationError {
    // This value must be specified.
    Unspecified,
    // Needs to be greater or equal the minimum amount of ICP collected from direct participants.
    BelowSwapDirectIcpMin {
        min_direct_participation_threshold_icp_e8s: u64,
        min_direct_participation_icp_e8s: u64,
    },
    // Needs to be less than the maximum amount of ICP collected from direct participants.
    AboveSwapDirectIcpMax {
        min_direct_participation_threshold_icp_e8s: u64,
        max_direct_participation_icp_e8s: u64,
    },
}

impl ToString for MinDirectParticipationThresholdValidationError {
    fn to_string(&self) -> String {
        let prefix = "MinDirectParticipationThresholdValidationError: ";
        match self {
            Self::Unspecified => {
                format!(
                    "{}min_direct_participation_threshold_icp_e8s must be specified.",
                    prefix
                )
            }
            Self::BelowSwapDirectIcpMin {
                min_direct_participation_threshold_icp_e8s,
                min_direct_participation_icp_e8s,
            } => {
                format!(
                    "{}min_direct_participation_threshold_icp_e8s ({}) should be greater \
                    than or equal min_direct_participation_icp_e8s ({}).",
                    prefix,
                    min_direct_participation_threshold_icp_e8s,
                    min_direct_participation_icp_e8s,
                )
            }
            Self::AboveSwapDirectIcpMax {
                min_direct_participation_threshold_icp_e8s,
                max_direct_participation_icp_e8s,
            } => {
                format!(
                    "{}min_direct_participation_threshold_icp_e8s ({}) should be less \
                    than or equal max_direct_participation_icp_e8s ({}).",
                    prefix,
                    min_direct_participation_threshold_icp_e8s,
                    max_direct_participation_icp_e8s,
                )
            }
        }
    }
}

enum MaxNeuronsFundParticipationValidationError {
    // This value must be specified.
    Unspecified,
    // Does not make sense if no SNS neurons can be created.
    BelowSingleParticipationLimit {
        max_neurons_fund_participation_icp_e8s: NonZeroU64,
        min_participant_icp_e8s: u64,
    },
    // The Neuron's Fund should never provide more funds than can be contributed directly.
    AboveSwapMaxDirectIcp {
        max_neurons_fund_participation_icp_e8s: u64,
        max_direct_participation_icp_e8s: u64,
    },
}

impl ToString for MaxNeuronsFundParticipationValidationError {
    fn to_string(&self) -> String {
        let prefix = "MaxNeuronsFundParticipationValidationError: ";
        match self {
            Self::Unspecified => {
                format!(
                    "{}max_neurons_fund_participation_icp_e8s must be specified.",
                    prefix
                )
            }
            Self::BelowSingleParticipationLimit {
                max_neurons_fund_participation_icp_e8s,
                min_participant_icp_e8s,
            } => {
                format!(
                    "{}max_neurons_fund_participation_icp_e8s ({} > 0) \
                    should be greater than or equal min_participant_icp_e8s ({}).",
                    prefix, max_neurons_fund_participation_icp_e8s, min_participant_icp_e8s,
                )
            }
            Self::AboveSwapMaxDirectIcp {
                max_neurons_fund_participation_icp_e8s,
                max_direct_participation_icp_e8s,
            } => {
                format!(
                    "{}max_neurons_fund_participation_icp_e8s ({}) \
                    should be less than or equal max_direct_participation_icp_e8s ({}).",
                    prefix,
                    max_neurons_fund_participation_icp_e8s,
                    max_direct_participation_icp_e8s,
                )
            }
        }
    }
}

/// Wraps around `swap::neurons_fund::NeuronsFundParticipationConstraintsValidationError`,
/// extending it with non-local error cases (i.e., those related to fields other than
/// `neurons_fund_participation_constraints` itself).
enum NeuronsFundParticipationConstraintsValidationError {
    SetBeforeProposalExecution,
    RelatedFieldUnspecified(String),
    MinDirectParticipationThresholdValidationError(MinDirectParticipationThresholdValidationError),
    MaxNeuronsFundParticipationValidationError(MaxNeuronsFundParticipationValidationError),
    // "Inherit" the remaining, local error cases.
    Local(neurons_fund::NeuronsFundParticipationConstraintsValidationError),
}

impl ToString for NeuronsFundParticipationConstraintsValidationError {
    fn to_string(&self) -> String {
        let prefix = "NeuronsFundParticipationConstraintsValidationError: ";
        match self {
            Self::SetBeforeProposalExecution => format!(
                "{}neurons_fund_participation_constraints must not be set before \
                the CreateServiceNervousSystem proposal is executed.",
                prefix
            ),
            Self::RelatedFieldUnspecified(related_field_name) => {
                format!("{}{} must be specified.", prefix, related_field_name,)
            }
            Self::MinDirectParticipationThresholdValidationError(error) => {
                format!("{}{}", prefix, error.to_string())
            }
            Self::MaxNeuronsFundParticipationValidationError(error) => {
                format!("{}{}", prefix, error.to_string())
            }
            Self::Local(error) => format!("{}{}", prefix, error.to_string()),
        }
    }
}

impl From<NeuronsFundParticipationConstraintsValidationError> for Result<(), String> {
    fn from(value: NeuronsFundParticipationConstraintsValidationError) -> Self {
        Err(value.to_string())
    }
}

pub enum RestrictedCountriesValidationError {
    EmptyList,
    TooManyItems(usize),
    NotIsoCompliant(String),
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
            Self::NotIsoCompliant(item) => {
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

#[derive(Clone, Copy)]
pub enum NeuronBasketConstructionParametersValidationError {
    ExceedsMaximalDissolveDelay(u64),
    ExceedsU64,
    InadequateBasketSize,
    InadequateDissolveDelay,
    UnexpectedInLegacyFlow,
}

impl NeuronBasketConstructionParametersValidationError {
    fn field_name() -> String {
        "SnsInitPayload.neuron_basket_construction_parameters".to_string()
    }
}

impl ToString for NeuronBasketConstructionParametersValidationError {
    fn to_string(&self) -> String {
        let msg = match self {
            Self::ExceedsMaximalDissolveDelay(max_dissolve_delay_seconds) => {
                format!(
                    "must satisfy (count - 1) * dissolve_delay_interval_seconds \
                    < SnsInitPayload.max_dissolve_delay_seconds = {max_dissolve_delay_seconds}"
                )
            }
            Self::InadequateBasketSize => "basket count must be at least 2".to_string(),
            Self::InadequateDissolveDelay => {
                "dissolve_delay_interval_seconds must be at least 1".to_string()
            }
            Self::ExceedsU64 => {
                format!(
                    "must satisfy (count - 1) * dissolve_delay_interval_seconds \
                    < u64::MAX = {}",
                    u64::MAX
                )
            }
            Self::UnexpectedInLegacyFlow => {
                "must not be set with the legacy flow for SNS decentralization swaps".to_string()
            }
        };
        format!("{} {msg}", Self::field_name())
    }
}

impl From<NeuronBasketConstructionParametersValidationError> for Result<(), String> {
    fn from(val: NeuronBasketConstructionParametersValidationError) -> Self {
        Err(val.to_string())
    }
}

impl From<NeuronsFundParticipants> for ic_sns_swap::pb::v1::NeuronsFundParticipants {
    fn from(value: NeuronsFundParticipants) -> Self {
        Self {
            cf_participants: value
                .participants
                .iter()
                .map(|cf_participant| ic_sns_swap::pb::v1::CfParticipant {
                    hotkey_principal: cf_participant.hotkey_principal.clone(),
                    cf_neurons: cf_participant.cf_neurons.clone(),
                })
                .collect(),
        }
    }
}

#[derive(Clone, Copy)]
pub enum NeuronsFundParticipationValidationError {
    Unspecified,
}

impl NeuronsFundParticipationValidationError {
    fn field_name() -> String {
        "SnsInitPayload.neurons_fund_participation".to_string()
    }
}

impl ToString for NeuronsFundParticipationValidationError {
    fn to_string(&self) -> String {
        let msg = match self {
            Self::Unspecified => "must be specified".to_string(),
        };
        format!("{} {msg}", Self::field_name())
    }
}

impl From<NeuronsFundParticipationValidationError> for Result<(), String> {
    fn from(value: NeuronsFundParticipationValidationError) -> Self {
        Err(value.to_string())
    }
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
#[derive(Debug)]
pub struct SnsCanisterInitPayloads {
    pub governance: Governance,
    pub ledger: LedgerArgument,
    pub root: SnsRootCanister,
    pub swap: SwapInit,
    pub index_ng: Option<IndexArg>,
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
            token_logo: None,
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
            min_participants: None,
            min_icp_e8s: None,
            max_icp_e8s: None,
            min_direct_participation_icp_e8s: None,
            max_direct_participation_icp_e8s: None,
            min_participant_icp_e8s: None,
            max_participant_icp_e8s: None,
            swap_start_timestamp_seconds: None,
            swap_due_timestamp_seconds: None,
            neuron_basket_construction_parameters: None,
            confirmation_text: None,
            restricted_countries: None,
            nns_proposal_id: None,
            neurons_fund_participants: None,
            neurons_fund_participation_constraints: None,
            neurons_fund_participation: None,
        }
    }

    /// This gives us some values that work for testing but would not be useful
    /// in a real world scenario. They are only meant to validate, not be sensible.
    /// These values are "pre-execution", meaning they cannot be used as-is to
    /// create an SNS.
    pub fn with_valid_values_for_testing_pre_execution() -> Self {
        Self {
            nns_proposal_id: None,
            neurons_fund_participants: None,
            swap_start_timestamp_seconds: None,
            swap_due_timestamp_seconds: None,
            neurons_fund_participation_constraints: None,
            ..Self::with_valid_values_for_testing_post_execution()
        }
    }

    /// This gives us some values that work for testing but would not be useful
    /// in a real world scenario. They are only meant to validate, not be sensible.
    /// These values are "post-execution", meaning they can be used to
    /// immediately create an SNS.  
    pub fn with_valid_values_for_testing_post_execution() -> Self {
        Self {
            token_symbol: Some("TEST".to_string()),
            token_name: Some("PlaceHolder".to_string()),
            token_logo: Some("data:image/png;base64,aGVsbG8gZnJvbSBkZmluaXR5IQ==".to_string()),
            initial_token_distribution: Some(FractionalDeveloperVotingPower(
                FractionalDVP::with_valid_values_for_testing(),
            )),
            fallback_controller_principal_ids: vec![PrincipalId::new_user_test_id(5822).to_string()],
            logo: Some("data:image/png;base64,aGVsbG8gZnJvbSBkZmluaXR5IQ==".to_string()),
            name: Some("ServiceNervousSystemTest".to_string()),
            url: Some("https://internetcomputer.org/".to_string()),
            description: Some("Description of an SNS Project".to_string()),

            // TODO(NNS1-2436): Set `confirmation_text` to a non-None value and
            // fix the tests that assume it will be None.
            confirmation_text: None,
            restricted_countries: Some(Countries {
                iso_codes: vec!["CH".to_string()],
            }),
            dapp_canisters: Some(DappCanisters {
                canisters: vec![Canister {
                    id: Some(CanisterId::from_u64(1000).get()),
                }],
            }),
            min_participants: Some(5),
            min_icp_e8s: None,
            max_icp_e8s: None,
            min_direct_participation_icp_e8s: Some(12_300_000_000),
            max_direct_participation_icp_e8s: Some(65_000_000_000),
            min_participant_icp_e8s: Some(6_500_000_000),
            max_participant_icp_e8s: Some(65_000_000_000),
            swap_start_timestamp_seconds: Some(10_000_000),
            swap_due_timestamp_seconds: Some(10_086_400),
            neuron_basket_construction_parameters: Some(NeuronBasketConstructionParameters {
                count: 5,
                dissolve_delay_interval_seconds: 10_001,
            }),
            nns_proposal_id: Some(10),
            neurons_fund_participation: Some(true),
            neurons_fund_participation_constraints: Some(NeuronsFundParticipationConstraints {
                min_direct_participation_threshold_icp_e8s: Some(12_300_000_000),
                max_neurons_fund_participation_icp_e8s: Some(65_000_000_000),
                coefficient_intervals: vec![LinearScalingCoefficient {
                    from_direct_participation_icp_e8s: Some(0),
                    to_direct_participation_icp_e8s: Some(u64::MAX),
                    slope_numerator: Some(1),
                    slope_denominator: Some(1),
                    intercept_icp_e8s: Some(0),
                }],
                ideal_matched_participation_function: Some(IdealMatchedParticipationFunction {
                    // Inlining the expected `serialized_representation` allows avoiding the need
                    // to add `ic_neurons_fund` as a dependency of this crate.
                    serialized_representation: Some(
                        "{\"t_1\":\"33300.000000000\",\"t_2\":\"99900.000000000\",\"t_3\":\"166500.000000000\",\"t_4\":\"200000.0000000000\",\"cap\":\"100000.000000000\"}"
                            .to_string()
                    ),
                }),
            }),
            neurons_fund_participants: None,
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
    ) -> Result<SnsCanisterInitPayloads, String> {
        self.validate_post_execution()?;

        Ok(SnsCanisterInitPayloads {
            governance: self.governance_init_args(sns_canister_ids, deployed_version)?,
            ledger: self.ledger_init_args(sns_canister_ids)?,
            root: self.root_init_args(sns_canister_ids, testflight),
            swap: self.swap_init_args(sns_canister_ids)?,
            index_ng: self.index_ng_init_args(sns_canister_ids),
        })
    }

    /// Construct the params used to initialize a SNS Governance canister.
    fn governance_init_args(
        &self,
        sns_canister_ids: &SnsCanisterIds,
        deployed_version: Option<Version>,
    ) -> Result<Governance, String> {
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
            .map_err(|e| format!("Could not create initialization parameters {}", e))?;

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
    ) -> Result<LedgerArgument, String> {
        let root_canister_id = CanisterId::unchecked_from_principal(sns_canister_ids.root);
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

        let mut payload_builder =
            LedgerInitArgsBuilder::with_symbol_and_name(token_symbol, token_name)
                .with_minting_account(sns_canister_ids.governance.0)
                .with_transfer_fee(
                    self.transaction_fee_e8s
                        .unwrap_or(DEFAULT_TRANSFER_FEE.get_e8s()),
                )
                .with_archive_options(ArchiveOptions {
                    trigger_threshold: 2000,
                    num_blocks_to_archive: 1000,
                    // 1 GB, which gives us 3 GB space when upgrading
                    node_max_memory_size_bytes: Some(1024 * 1024 * 1024),
                    // 128kb
                    max_message_size_bytes: Some(128 * 1024),
                    controller_id: root_canister_id.get(),
                    more_controller_ids: None,
                    // TODO: allow users to set this value
                    // 10 Trillion cycles
                    cycles_for_archive_creation: Some(10_000_000_000_000),
                    max_transactions_per_response: None,
                });

        if let Some(token_logo) = &self.token_logo {
            payload_builder = payload_builder.with_metadata_entry(
                ICRC1_TOKEN_LOGO_KEY.to_string(),
                MetadataValue::Text(token_logo.clone()),
            );
        }

        for (account, amount) in self.get_all_ledger_accounts(sns_canister_ids)? {
            payload_builder = payload_builder.with_initial_balance(account, amount);
        }
        for (account, amount) in self.maybe_test_balances() {
            payload_builder = payload_builder.with_initial_balance(account, amount);
        }
        Ok(LedgerArgument::Init(payload_builder.build()))
    }

    /// Construct the params used to initialize an SNS Index-Ng canister.
    fn index_ng_init_args(&self, sns_canister_ids: &SnsCanisterIds) -> Option<IndexArg> {
        Some(IndexArg::Init(InitArg {
            ledger_id: Principal::from(sns_canister_ids.ledger),
        }))
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

    /// Construct the parameters used to initialize an SNS Swap canister.
    ///
    /// Precondition: Either [`Self::validate_pre_execution`] or [`Self::validate_post_execution`]
    /// (or both) must be `Ok(())`.
    fn swap_init_args(&self, sns_canister_ids: &SnsCanisterIds) -> Result<SwapInit, String> {
        // Safe to cast due to validation
        let min_participants = self
            .min_participants
            .map(|min_participants| min_participants as u32);

        let sns_tokens_e8s = Some(self.get_swap_distribution()?.initial_swap_amount_e8s);

        Ok(SwapInit {
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
            min_participants,
            min_icp_e8s: self.min_icp_e8s,
            max_icp_e8s: self.max_icp_e8s,
            min_direct_participation_icp_e8s: self.min_direct_participation_icp_e8s,
            max_direct_participation_icp_e8s: self.max_direct_participation_icp_e8s,
            min_participant_icp_e8s: self.min_participant_icp_e8s,
            max_participant_icp_e8s: self.max_participant_icp_e8s,
            swap_start_timestamp_seconds: self.swap_start_timestamp_seconds,
            swap_due_timestamp_seconds: self.swap_due_timestamp_seconds,
            sns_token_e8s: sns_tokens_e8s,
            neuron_basket_construction_parameters: self
                .neuron_basket_construction_parameters
                .clone(),
            nns_proposal_id: self.nns_proposal_id,
            should_auto_finalize: Some(true),
            neurons_fund_participation_constraints: self
                .neurons_fund_participation_constraints
                .clone(),
            neurons_fund_participation: self.neurons_fund_participation,
            // This field must not be set at Swap initialization time.
            neurons_fund_participants: None,
        })
    }

    fn get_swap_distribution(&self) -> Result<&SwapDistribution, String> {
        match &self.initial_token_distribution {
            None => Err("Error: initial-token-distribution must be specified".to_string()),
            Some(FractionalDeveloperVotingPower(f)) => f.swap_distribution(),
        }
    }

    /// Given `SnsCanisterIds`, get all the ledger accounts of the TokenDistributions. These
    /// accounts represent the allocation of tokens at genesis.
    fn get_all_ledger_accounts(
        &self,
        sns_canister_ids: &SnsCanisterIds,
    ) -> Result<BTreeMap<Account, Tokens>, String> {
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
    ) -> Result<BTreeMap<String, Neuron>, String> {
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
            min_participants: _,
            min_icp_e8s: _,
            max_icp_e8s: _,
            min_direct_participation_icp_e8s: _,
            max_direct_participation_icp_e8s: _,
            min_participant_icp_e8s: _,
            max_participant_icp_e8s: _,
            swap_start_timestamp_seconds: _,
            swap_due_timestamp_seconds: _,
            neuron_basket_construction_parameters: _,
            nns_proposal_id: _,
            neurons_fund_participants: _,
            token_logo: _,
            neurons_fund_participation_constraints: _,
            neurons_fund_participation: _,
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

    /// Validates all the fields that are shared with CreateServiceNervousSystem.
    /// For use in e.g. the SNS CLI or in NNS Governance before the proposal has
    /// been executed.
    pub fn validate_pre_execution(&self) -> Result<Self, String> {
        let validation_fns = [
            self.validate_token_symbol(),
            self.validate_token_name(),
            self.validate_token_logo(),
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
            self.validate_neuron_basket_construction_params(),
            self.validate_min_participants(),
            self.validate_min_direct_participation_icp_e8s(),
            self.validate_max_direct_participation_icp_e8s(),
            self.validate_min_icp_e8s(),
            self.validate_max_icp_e8s(),
            self.validate_min_participant_icp_e8s(),
            self.validate_max_participant_icp_e8s(),
            // Ensure that the values that can only be known after the execution
            // of the CreateServiceNervousSystem proposal are not set.
            self.validate_nns_proposal_id_pre_execution(),
            self.validate_neurons_fund_participants_pre_execution(),
            self.validate_swap_start_timestamp_seconds_pre_execution(),
            self.validate_swap_due_timestamp_seconds_pre_execution(),
            self.validate_neurons_fund_participation_constraints(true),
            self.validate_neurons_fund_participation(),
        ];

        self.join_validation_results(&validation_fns)
    }

    pub fn validate_post_execution(&self) -> Result<Self, String> {
        let validation_fns = [
            self.validate_token_symbol(),
            self.validate_token_name(),
            self.validate_token_logo(),
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
            self.validate_all_post_execution_swap_parameters_are_set(),
            self.validate_neuron_basket_construction_params(),
            self.validate_min_participants(),
            self.validate_min_icp_e8s(),
            self.validate_max_icp_e8s(),
            self.validate_min_direct_participation_icp_e8s(),
            self.validate_max_direct_participation_icp_e8s(),
            self.validate_min_participant_icp_e8s(),
            self.validate_max_participant_icp_e8s(),
            self.validate_nns_proposal_id(),
            self.validate_neurons_fund_participants(),
            self.validate_swap_start_timestamp_seconds(),
            self.validate_swap_due_timestamp_seconds(),
            self.validate_neurons_fund_participation_constraints(false),
            self.validate_neurons_fund_participation(),
        ];

        self.join_validation_results(&validation_fns)
    }

    fn join_validation_results(
        &self,
        validation_fns: &[Result<(), String>],
    ) -> Result<Self, String> {
        let mut seen_messages = HashSet::new();
        let defect_messages = validation_fns
            .iter()
            .filter_map(|validation_fn| match validation_fn {
                Err(msg) => Some(msg),
                Ok(_) => None,
            })
            .filter(|&x|
                // returns true iff the set did not already contain the value
                seen_messages.insert(x.clone()))
            .cloned()
            .collect::<Vec<String>>()
            .join("\n");

        if defect_messages.is_empty() {
            Ok(self.clone())
        } else {
            Err(defect_messages)
        }
    }

    fn validate_token_symbol(&self) -> Result<(), String> {
        let token_symbol = self
            .token_symbol
            .as_ref()
            .ok_or_else(|| "Error: token-symbol must be specified".to_string())?;

        ledger_validation::validate_token_symbol(token_symbol)
    }

    fn validate_token_name(&self) -> Result<(), String> {
        let token_name = self
            .token_name
            .as_ref()
            .ok_or_else(|| "Error: token-name must be specified".to_string())?;

        ledger_validation::validate_token_name(token_name)
    }

    fn validate_token_logo(&self) -> Result<(), String> {
        let token_logo = self
            .token_logo
            .as_ref()
            .ok_or_else(|| "Error: token_logo must be specified".to_string())?;

        ledger_validation::validate_token_logo(token_logo)
    }

    fn validate_token_distribution(&self) -> Result<(), String> {
        let initial_token_distribution = self
            .initial_token_distribution
            .as_ref()
            .ok_or_else(|| "Error: initial-token-distribution must be specified".to_string())?;

        let nervous_system_parameters = self.get_nervous_system_parameters();

        match initial_token_distribution {
            FractionalDeveloperVotingPower(f) => f.validate(&nervous_system_parameters)?,
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

        let (valid_principals, invalid_principals): (Vec<_>, Vec<_>) = self
            .fallback_controller_principal_ids
            .iter()
            .map(|principal_id_string| {
                (
                    principal_id_string,
                    PrincipalId::from_str(principal_id_string),
                )
            })
            .partition(|item| item.1.is_ok());

        if !invalid_principals.is_empty() {
            return Err(format!(
                "Error: One or more fallback_controller_principal_ids is not a valid principal id. \
                The follow principals are invalid: {:?}", 
                invalid_principals
                    .into_iter()
                    .map(|pair| pair.0)
                    .collect::<Vec<_>>()
            ));
        }

        // At this point, all principals are valid. Dedupe the values
        let unique_principals: BTreeSet<_> = valid_principals
            .iter()
            .filter_map(|pair| pair.1.clone().ok())
            .collect();

        if unique_principals.len() != valid_principals.len() {
            return Err(
                "Error: Duplicate PrincipalIds found in fallback_controller_principal_ids"
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

        SnsMetadata::validate_logo(logo)
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

        let nns_canisters = &[
            NNS_GOVERNANCE_CANISTER_ID,
            ICP_LEDGER_CANISTER_ID,
            REGISTRY_CANISTER_ID,
            ROOT_CANISTER_ID,
            CYCLES_MINTING_CANISTER_ID,
            LIFELINE_CANISTER_ID,
            GENESIS_TOKEN_CANISTER_ID,
            IDENTITY_CANISTER_ID,
            NNS_UI_CANISTER_ID,
            SNS_WASM_CANISTER_ID,
            EXCHANGE_RATE_CANISTER_ID,
        ]
        .map(PrincipalId::from);

        let nns_canisters_listed_as_dapp = dapp_canisters
            .canisters
            .iter()
            .filter_map(|canister| {
                // Will not fail because of previous check
                let id = canister.id.unwrap();
                if nns_canisters.contains(&id) {
                    Some(id)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        if !nns_canisters_listed_as_dapp.is_empty() {
            return Err(format!(
                "Error: The following canisters are listed as dapp canisters, but are \
                NNS canisters: {:?}",
                nns_canisters_listed_as_dapp
            ));
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
                    return RestrictedCountriesValidationError::NotIsoCompliant(item.clone())
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

    fn validate_neuron_basket_construction_params(&self) -> Result<(), String> {
        let neuron_basket_construction_parameters = self
            .neuron_basket_construction_parameters
            .as_ref()
            .ok_or("Error: neuron_basket_construction_parameters must be specified")?;

        // Check that `NeuronBasket` dissolve delay does not exceed
        // the maximum dissolve delay.
        let max_dissolve_delay_seconds = self
            .max_dissolve_delay_seconds
            .ok_or("Error: max_dissolve_delay_seconds must be specified")?;
        // The maximal dissolve delay of a neuron from a basket created by
        // `NeuronBasketConstructionParameters::generate_vesting_schedule`
        // will equal `(count - 1) * dissolve_delay_interval_seconds`.
        let max_neuron_basket_dissolve_delay = neuron_basket_construction_parameters
            .count
            .saturating_sub(1_u64)
            .checked_mul(neuron_basket_construction_parameters.dissolve_delay_interval_seconds);
        if let Some(max_neuron_basket_dissolve_delay) = max_neuron_basket_dissolve_delay {
            if max_neuron_basket_dissolve_delay > max_dissolve_delay_seconds {
                return NeuronBasketConstructionParametersValidationError::ExceedsMaximalDissolveDelay(max_dissolve_delay_seconds)
                    .into();
            }
        } else {
            return NeuronBasketConstructionParametersValidationError::ExceedsU64.into();
        }
        if neuron_basket_construction_parameters.count < 2 {
            return NeuronBasketConstructionParametersValidationError::InadequateBasketSize.into();
        }
        if neuron_basket_construction_parameters.dissolve_delay_interval_seconds < 1 {
            return NeuronBasketConstructionParametersValidationError::InadequateDissolveDelay
                .into();
        }
        Ok(())
    }

    fn validate_min_participants(&self) -> Result<(), String> {
        let min_participants = self
            .min_participants
            .ok_or("Error: min_participants must be specified")?;

        if min_participants == 0 {
            return Err("Error: min_participants must be > 0".to_string());
        }

        // Needed as the SwapInit min_participants field is a u32
        if min_participants > (u32::MAX as u64) {
            return Err(format!(
                "Error: min_participants cannot be greater than {}",
                u32::MAX
            ));
        }

        Ok(())
    }

    fn validate_min_direct_participation_icp_e8s(&self) -> Result<(), String> {
        let min_direct_participation_icp_e8s = self
            .min_direct_participation_icp_e8s
            .ok_or("Error: min_direct_participation_icp_e8s must be specified")?;

        if min_direct_participation_icp_e8s == 0 {
            return Err("Error: min_direct_participation_icp_e8s must be > 0".to_string());
        }

        Ok(())
    }

    fn validate_max_icp_e8s(&self) -> Result<(), String> {
        if self.max_icp_e8s.is_some() {
            return Err(
                "Error: max_icp_e8s cannot be specified now that Matched Funding is enabled"
                    .to_string(),
            );
        }

        Ok(())
    }

    fn validate_min_icp_e8s(&self) -> Result<(), String> {
        if self.min_icp_e8s.is_some() {
            return Err(
                "Error: min_icp_e8s cannot be specified now that Matched Funding is enabled"
                    .to_string(),
            );
        };

        Ok(())
    }

    fn validate_max_direct_participation_icp_e8s(&self) -> Result<(), String> {
        let max_direct_participation_icp_e8s = self
            .max_direct_participation_icp_e8s
            .ok_or("Error: max_direct_participation_icp_e8s must be specified")?;

        let min_direct_participation_icp_e8s = self
            .min_direct_participation_icp_e8s
            .ok_or("Error: min_direct_participation_icp_e8s must be specified")?;

        if max_direct_participation_icp_e8s < min_direct_participation_icp_e8s {
            return Err(format!(
                "max_direct_participation_icp_e8s ({}) must be >= min_direct_participation_icp_e8s ({})",
                max_direct_participation_icp_e8s, min_direct_participation_icp_e8s
            ));
        }

        if max_direct_participation_icp_e8s > MAX_DIRECT_ICP_CONTRIBUTION_TO_SWAP {
            return Err(format!(
                "Error: max_direct_participation_icp_e8s ({}) can be at most {} ICP E8s",
                max_direct_participation_icp_e8s, MAX_DIRECT_ICP_CONTRIBUTION_TO_SWAP
            ));
        }

        let min_participants = self
            .min_participants
            .ok_or("Error: min_participants must be specified")?;

        let min_participant_icp_e8s = self
            .min_participant_icp_e8s
            .ok_or("Error: min_participant_icp_e8s must be specified")?;

        if max_direct_participation_icp_e8s
            < min_participants.saturating_mul(min_participant_icp_e8s)
        {
            return Err(format!(
                "Error: max_direct_participation_icp_e8s ({}) must be >= min_participants ({}) * min_participant_icp_e8s ({})",
                max_direct_participation_icp_e8s, min_participants, min_participant_icp_e8s
            ));
        }

        Ok(())
    }

    fn validate_min_participant_icp_e8s(&self) -> Result<(), String> {
        let min_participant_icp_e8s = self
            .min_participant_icp_e8s
            .ok_or("Error: min_participant_icp_e8s must be specified")?;

        let max_direct_participation_icp_e8s = self
            .max_direct_participation_icp_e8s
            .ok_or("Error: max_direct_participation_icp_e8s must be specified")?;

        let sns_transaction_fee_e8s = self
            .transaction_fee_e8s
            .ok_or("Error: transaction_fee_e8s must be specified")?;

        let neuron_minimum_stake_e8s = self
            .neuron_minimum_stake_e8s
            .ok_or("Error: neuron_minimum_stake_e8s must be specified")?;

        let neuron_basket_construction_parameters_count = self
            .neuron_basket_construction_parameters
            .as_ref()
            .ok_or("Error: neuron_basket_construction_parameters must be specified")?
            .count;

        let sns_tokens_e8s = self
            .get_swap_distribution()
            .map_err(|_| "Error: the SwapDistribution must be specified")?
            .initial_swap_amount_e8s;

        let min_participant_sns_e8s = min_participant_icp_e8s as u128 * sns_tokens_e8s as u128
            / max_direct_participation_icp_e8s as u128;

        if neuron_minimum_stake_e8s <= sns_transaction_fee_e8s {
            return Err(format!(
                "Error: neuron_minimum_stake_e8s={} is too small. It needs to be \
                 greater than the transaction fee ({} e8s)",
                neuron_minimum_stake_e8s, sns_transaction_fee_e8s
            ));
        }

        let min_participant_icp_e8s_big_enough = min_participant_sns_e8s
            >= neuron_basket_construction_parameters_count as u128
                * (neuron_minimum_stake_e8s + sns_transaction_fee_e8s) as u128;

        if !min_participant_icp_e8s_big_enough {
            return Err(format!(
                "Error: min_participant_icp_e8s={} is too small. It needs to be \
                 large enough to ensure that participants will end up with \
                 enough SNS tokens to form {} SNS neurons, each of which \
                 require at least {} SNS e8s, plus {} e8s in transaction \
                 fees. More precisely, the following inequality must hold: \
                 min_participant_icp_e8s >= neuron_basket_count * \
                 (neuron_minimum_stake_e8s + transaction_fee_e8s) * max_icp_e8s / sns_tokens_e8s",
                min_participant_icp_e8s,
                neuron_basket_construction_parameters_count,
                neuron_minimum_stake_e8s,
                sns_transaction_fee_e8s,
            ));
        }

        Ok(())
    }

    fn validate_max_participant_icp_e8s(&self) -> Result<(), String> {
        let max_participant_icp_e8s = self
            .max_participant_icp_e8s
            .ok_or("Error: max_participant_icp_e8s must be specified")?;

        let min_participant_icp_e8s = self
            .min_participant_icp_e8s
            .ok_or("Error: min_participant_icp_e8s must be specified")?;

        if max_participant_icp_e8s < min_participant_icp_e8s {
            return Err(format!(
                "Error: max_participant_icp_e8s ({}) must be >= min_participant_icp_e8s ({})",
                max_participant_icp_e8s, min_participant_icp_e8s
            ));
        }

        let max_direct_participation_icp_e8s = self
            .max_direct_participation_icp_e8s
            .ok_or("Error: max_direct_participation_icp_e8s must be specified")?;

        if max_participant_icp_e8s > max_direct_participation_icp_e8s {
            return Err(format!(
                "max_participant_icp_e8s ({}) must be <= max_direct_participation_icp_e8s ({})",
                max_participant_icp_e8s, max_direct_participation_icp_e8s
            ));
        }

        Ok(())
    }

    fn validate_nns_proposal_id_pre_execution(&self) -> Result<(), String> {
        if self.nns_proposal_id.is_none() {
            Ok(())
        } else {
            Err(format!(
                "Error: nns_proposal_id cannot be specified pre_execution, but was {:?}",
                self.nns_proposal_id
            ))
        }
    }

    fn validate_nns_proposal_id(&self) -> Result<(), String> {
        match self.nns_proposal_id {
            None => Err("Error: nns_proposal_id must be specified".to_string()),
            Some(_) => Ok(()),
        }
    }

    fn validate_neurons_fund_participants_pre_execution(&self) -> Result<(), String> {
        if self.neurons_fund_participants.is_none() {
            Ok(())
        } else {
            Err(format!(
                "Error: neurons_fund_participants cannot be specified pre_execution, but was {:?}",
                self.neurons_fund_participants
            ))
        }
    }

    fn validate_neurons_fund_participants(&self) -> Result<(), String> {
        if self.neurons_fund_participants.is_none() {
            Ok(())
        } else {
            Err(format!(
                "Error: neurons_fund_participants can be set only by Swap; was initialized to {:?}",
                self.neurons_fund_participants
            ))
        }
    }

    fn validate_swap_start_timestamp_seconds_pre_execution(&self) -> Result<(), String> {
        if self.swap_start_timestamp_seconds.is_none() {
            Ok(())
        } else {
            Err(format!(
                "Error: swap_start_timestamp_seconds cannot be specified pre_execution, but was {:?}",
                self.swap_start_timestamp_seconds
            ))
        }
    }

    fn validate_swap_start_timestamp_seconds(&self) -> Result<(), String> {
        match self.swap_start_timestamp_seconds {
            Some(_) => Ok(()),
            None => Err("Error: swap_start_timestamp_seconds must be specified".to_string()),
        }
    }

    fn validate_swap_due_timestamp_seconds_pre_execution(&self) -> Result<(), String> {
        if self.swap_due_timestamp_seconds.is_none() {
            Ok(())
        } else {
            Err(format!(
                "Error: swap_due_timestamp_seconds cannot be specified pre_execution, but was {:?}",
                self.swap_due_timestamp_seconds
            ))
        }
    }

    fn validate_swap_due_timestamp_seconds(&self) -> Result<(), String> {
        let swap_start_timestamp_seconds = self
            .swap_start_timestamp_seconds
            .ok_or("Error: swap_start_timestamp_seconds must be specified")?;

        let swap_due_timestamp_seconds = self
            .swap_due_timestamp_seconds
            .ok_or("Error: swap_due_timestamp_seconds must be specified")?;

        if swap_due_timestamp_seconds < swap_start_timestamp_seconds {
            return Err(format!(
                "Error: swap_due_timestamp_seconds({}) must be after swap_start_timestamp_seconds({})",
                swap_due_timestamp_seconds, swap_start_timestamp_seconds,
            ));
        }

        Ok(())
    }

    pub fn validate_neurons_fund_participation(&self) -> Result<(), String> {
        if self.neurons_fund_participation.is_none() {
            return Result::from(NeuronsFundParticipationValidationError::Unspecified);
        }
        Ok(())
    }

    pub fn validate_neurons_fund_participation_constraints(
        &self,
        is_pre_execution: bool,
    ) -> Result<(), String> {
        // This field must be set by NNS Governance at proposal execution time, not before.
        // This check will also catch the situation in which we are in the legacy (pre-1-prop) flow,
        // in which the `neurons_fund_participation_constraints`` field must not be set at all.
        if is_pre_execution && self.neurons_fund_participation_constraints.is_some() {
            return Result::from(
                NeuronsFundParticipationConstraintsValidationError::SetBeforeProposalExecution,
            );
        }

        let Some(ref neurons_fund_participation_constraints) =
            self.neurons_fund_participation_constraints
        else {
            if self.neurons_fund_participation == Some(true) && !is_pre_execution {
                return Result::from(NeuronsFundParticipationConstraintsValidationError::RelatedFieldUnspecified(
                    "neurons_fund_participation requires neurons_fund_participation_constraints"
                    .to_string(),
                ));
            }
            return Ok(());
        };

        // Validate relationship with min_direct_participation_threshold_icp_e8s
        let Some(min_direct_participation_threshold_icp_e8s) =
            neurons_fund_participation_constraints.min_direct_participation_threshold_icp_e8s
        else {
            return Result::from(NeuronsFundParticipationConstraintsValidationError::MinDirectParticipationThresholdValidationError(
                MinDirectParticipationThresholdValidationError::Unspecified
            ));
        };

        let min_direct_participation_icp_e8s =
            self.min_direct_participation_icp_e8s.ok_or_else(|| {
                NeuronsFundParticipationConstraintsValidationError::RelatedFieldUnspecified(
                    "min_direct_participation_icp_e8s".to_string(),
                )
                .to_string()
            })?;
        if min_direct_participation_threshold_icp_e8s < min_direct_participation_icp_e8s {
            return Result::from(NeuronsFundParticipationConstraintsValidationError::MinDirectParticipationThresholdValidationError(
                MinDirectParticipationThresholdValidationError::BelowSwapDirectIcpMin {
                    min_direct_participation_threshold_icp_e8s,
                    min_direct_participation_icp_e8s,
                }
            ));
        }
        let max_direct_participation_icp_e8s =
            self.max_direct_participation_icp_e8s.ok_or_else(|| {
                NeuronsFundParticipationConstraintsValidationError::RelatedFieldUnspecified(
                    "max_direct_participation_icp_e8s".to_string(),
                )
                .to_string()
            })?;
        if min_direct_participation_threshold_icp_e8s > max_direct_participation_icp_e8s {
            return Result::from(NeuronsFundParticipationConstraintsValidationError::MinDirectParticipationThresholdValidationError(
                MinDirectParticipationThresholdValidationError::AboveSwapDirectIcpMax {
                    min_direct_participation_threshold_icp_e8s,
                    max_direct_participation_icp_e8s,
                }
            ));
        }

        // Validate relationship with max_neurons_fund_participation_icp_e8s
        let Some(max_neurons_fund_participation_icp_e8s) =
            neurons_fund_participation_constraints.max_neurons_fund_participation_icp_e8s
        else {
            return Result::from(NeuronsFundParticipationConstraintsValidationError::MaxNeuronsFundParticipationValidationError(
                MaxNeuronsFundParticipationValidationError::Unspecified
            ));
        };

        let min_participant_icp_e8s = self.min_participant_icp_e8s.ok_or_else(|| {
            NeuronsFundParticipationConstraintsValidationError::RelatedFieldUnspecified(
                "min_participant_icp_e8s".to_string(),
            )
            .to_string()
        })?;
        if 0 < max_neurons_fund_participation_icp_e8s
            && max_neurons_fund_participation_icp_e8s < min_participant_icp_e8s
        {
            let max_neurons_fund_participation_icp_e8s =
                NonZeroU64::new(max_neurons_fund_participation_icp_e8s).unwrap();
            return Result::from(NeuronsFundParticipationConstraintsValidationError::MaxNeuronsFundParticipationValidationError(
                MaxNeuronsFundParticipationValidationError::BelowSingleParticipationLimit {
                    max_neurons_fund_participation_icp_e8s,
                    min_participant_icp_e8s,
                }
            ));
        }
        // Not more than 50% of total contributions should come from the Neurons' Fund.
        let max_direct_participation_icp_e8s =
            self.max_direct_participation_icp_e8s.ok_or_else(|| {
                NeuronsFundParticipationConstraintsValidationError::RelatedFieldUnspecified(
                    "max_direct_participation_icp_e8s".to_string(),
                )
                .to_string()
            })?;
        if max_neurons_fund_participation_icp_e8s > max_direct_participation_icp_e8s {
            return Result::from(NeuronsFundParticipationConstraintsValidationError::MaxNeuronsFundParticipationValidationError(
                MaxNeuronsFundParticipationValidationError::AboveSwapMaxDirectIcp {
                    max_neurons_fund_participation_icp_e8s,
                    max_direct_participation_icp_e8s,
                }
            ));
        }

        neurons_fund_participation_constraints
            .validate()
            .map_err(|err| {
                NeuronsFundParticipationConstraintsValidationError::Local(err).to_string()
            })
    }

    /// Checks that all parameters whose values can only be known after the CreateServiceNervousSystem proposal is executed are present.
    pub fn validate_all_post_execution_swap_parameters_are_set(&self) -> Result<(), String> {
        let mut missing_one_proposal_fields = vec![];
        if self.nns_proposal_id.is_none() {
            missing_one_proposal_fields.push("nns_proposal_id")
        }
        if self.swap_start_timestamp_seconds.is_none() {
            missing_one_proposal_fields.push("swap_start_timestamp_seconds")
        }
        if self.swap_due_timestamp_seconds.is_none() {
            missing_one_proposal_fields.push("swap_due_timestamp_seconds")
        }
        if self.min_direct_participation_icp_e8s.is_none() {
            missing_one_proposal_fields.push("min_direct_participation_icp_e8s")
        }
        if self.max_direct_participation_icp_e8s.is_none() {
            missing_one_proposal_fields.push("max_direct_participation_icp_e8s")
        }

        if missing_one_proposal_fields.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "Error in validate_all_post_execution_swap_parameters_are_set: The one-proposal \
                SNS initialization requires some SnsInitPayload parameters to be Some. But the \
                following fields were set to None: {}",
                missing_one_proposal_fields.join(", ")
            ))
        }
    }

    /// Checks that all parameters used by the one-proposal flow are present, except for those whose values can't be known before the CreateServiceNervousSystem proposal is executed.
    pub fn validate_all_non_legacy_pre_execution_swap_parameters_are_set(
        &self,
    ) -> Result<(), String> {
        let mut missing_one_proposal_fields = vec![];
        if self.min_participants.is_none() {
            missing_one_proposal_fields.push("min_participants")
        }

        if self.min_direct_participation_icp_e8s.is_none() {
            missing_one_proposal_fields.push("min_direct_participation_icp_e8s")
        }

        if self.max_direct_participation_icp_e8s.is_none() {
            missing_one_proposal_fields.push("max_direct_participation_icp_e8s")
        }
        if self.min_participant_icp_e8s.is_none() {
            missing_one_proposal_fields.push("min_participant_icp_e8s")
        }
        if self.max_participant_icp_e8s.is_none() {
            missing_one_proposal_fields.push("max_participant_icp_e8s")
        }
        if self.neuron_basket_construction_parameters.is_none() {
            missing_one_proposal_fields.push("neuron_basket_construction_parameters")
        }
        if self.dapp_canisters.is_none() {
            missing_one_proposal_fields.push("dapp_canisters")
        }
        if self.token_logo.is_none() {
            missing_one_proposal_fields.push("token_logo")
        }

        if missing_one_proposal_fields.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "Error in validate_all_non_legacy_pre_execution_swap_parameters_are_set: The one-\
                proposal SNS initialization requires some SnsInitPayload parameters to be Some. \
                But the following fields were set to None: {}",
                missing_one_proposal_fields.join(", ")
            ))
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{
        pb::v1::{
            AirdropDistribution, DappCanisters, DeveloperDistribution,
            FractionalDeveloperVotingPower as FractionalDVP, NeuronDistribution,
        },
        FractionalDeveloperVotingPower, MaxNeuronsFundParticipationValidationError,
        MinDirectParticipationThresholdValidationError,
        NeuronBasketConstructionParametersValidationError,
        NeuronsFundParticipationConstraintsValidationError, RestrictedCountriesValidationError,
        SnsCanisterIds, SnsInitPayload, ICRC1_TOKEN_LOGO_KEY, MAX_CONFIRMATION_TEXT_LENGTH,
        MAX_DAPP_CANISTERS_COUNT, MAX_FALLBACK_CONTROLLER_PRINCIPAL_IDS_COUNT,
    };
    use ic_base_types::{CanisterId, PrincipalId};
    use ic_icrc1_ledger::LedgerArgument;
    use ic_nervous_system_common::{
        ledger_validation,
        ledger_validation::{MAX_TOKEN_NAME_LENGTH, MAX_TOKEN_SYMBOL_LENGTH},
        ONE_MONTH_SECONDS,
    };
    use ic_nervous_system_proto::pb::v1::{Canister, Countries};
    use ic_nns_constants::{
        CYCLES_MINTING_CANISTER_ID, EXCHANGE_RATE_CANISTER_ID, GENESIS_TOKEN_CANISTER_ID,
        GOVERNANCE_CANISTER_ID as NNS_GOVERNANCE_CANISTER_ID, IDENTITY_CANISTER_ID,
        LEDGER_CANISTER_ID as ICP_LEDGER_CANISTER_ID, LIFELINE_CANISTER_ID, NNS_UI_CANISTER_ID,
        REGISTRY_CANISTER_ID, ROOT_CANISTER_ID, SNS_WASM_CANISTER_ID,
    };
    use ic_sns_governance::{governance::ValidGovernanceProto, pb::v1::governance::SnsMetadata};
    use ic_sns_swap::pb::v1::{
        IdealMatchedParticipationFunction, LinearScalingCoefficient,
        NeuronBasketConstructionParameters, NeuronsFundParticipationConstraints,
    };
    use icrc_ledger_types::{icrc::generic_metadata_value::MetadataValue, icrc1::account::Account};
    use isocountry::CountryCode;
    use std::{
        collections::{BTreeMap, HashSet},
        convert::TryInto,
        num::NonZeroU64,
    };

    #[track_caller]
    fn assert_error<T, E1, E2>(result: Result<T, E1>, expected_error: E2)
    where
        T: std::fmt::Debug,
        E1: ToString,
        E2: ToString,
    {
        match result {
            Ok(result) => panic!("assertion failed: expected Err, got Ok({result:?})"),
            Err(err) => assert_eq!(err.to_string(), expected_error.to_string()),
        }
    }

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
            .map(|i| Canister {
                id: Some(CanisterId::from_u64(i as u64 + 100).get()),
            })
            .collect();

        DappCanisters { canisters }
    }

    #[test]
    fn test_sns_init_payload_validate() {
        // Build a payload that passes validation, then test the parts that wouldn't
        let sns_init_payload = {
            let sns_init_payload = SnsInitPayload::with_valid_values_for_testing_post_execution();
            sns_init_payload.validate_post_execution().unwrap();
            sns_init_payload.validate_pre_execution().unwrap_err();
            sns_init_payload
        };
        {
            let mut sns_init_payload = sns_init_payload.clone();
            sns_init_payload.token_symbol = Some("S".repeat(MAX_TOKEN_SYMBOL_LENGTH + 1));
            sns_init_payload.validate_post_execution().unwrap_err();
            sns_init_payload.validate_pre_execution().unwrap_err();
        }
        {
            let mut sns_init_payload = sns_init_payload.clone();
            sns_init_payload.token_symbol = Some(" ICP".to_string());
            sns_init_payload.validate_post_execution().unwrap_err();
            sns_init_payload.validate_pre_execution().unwrap_err();
        }
        {
            let mut sns_init_payload = sns_init_payload.clone();
            sns_init_payload.token_name = Some("S".repeat(MAX_TOKEN_NAME_LENGTH + 1));
            sns_init_payload.validate_post_execution().unwrap_err();
            sns_init_payload.validate_pre_execution().unwrap_err();
        }
        {
            let mut sns_init_payload = sns_init_payload.clone();
            sns_init_payload.token_name = Some("Internet Computer".to_string());
            sns_init_payload.validate_post_execution().unwrap_err();
            sns_init_payload.validate_pre_execution().unwrap_err();
        }
        {
            let mut sns_init_payload = sns_init_payload.clone();
            sns_init_payload.token_name = Some("InternetComputerProtocol".to_string());
            sns_init_payload.validate_post_execution().unwrap_err();
            sns_init_payload.validate_pre_execution().unwrap_err();
        }
        {
            let mut sns_init_payload = sns_init_payload.clone();
            sns_init_payload.transaction_fee_e8s = None;
            sns_init_payload.validate_post_execution().unwrap_err();
            sns_init_payload.validate_pre_execution().unwrap_err();
        }
        {
            let mut sns_init_payload = sns_init_payload.clone();
            sns_init_payload.description = None;
            sns_init_payload.validate_post_execution().unwrap_err();
            sns_init_payload.validate_pre_execution().unwrap_err();
        }
        {
            let mut sns_init_payload = sns_init_payload.clone();
            sns_init_payload.description =
                Some("S".repeat(SnsMetadata::MAX_DESCRIPTION_LENGTH + 1));
            sns_init_payload.validate_post_execution().unwrap_err();
            sns_init_payload.validate_pre_execution().unwrap_err();
        }
        {
            let mut sns_init_payload = sns_init_payload.clone();
            sns_init_payload.description =
                Some("S".repeat(SnsMetadata::MIN_DESCRIPTION_LENGTH - 1));
            sns_init_payload.validate_post_execution().unwrap_err();
            sns_init_payload.validate_pre_execution().unwrap_err();
        }
        {
            let mut sns_init_payload = sns_init_payload.clone();
            sns_init_payload.name = None;
            sns_init_payload.validate_post_execution().unwrap_err();
            sns_init_payload.validate_pre_execution().unwrap_err();
        }
        {
            let mut sns_init_payload = sns_init_payload.clone();
            sns_init_payload.name = Some("S".repeat(SnsMetadata::MAX_NAME_LENGTH + 1));
            sns_init_payload.validate_post_execution().unwrap_err();
            sns_init_payload.validate_pre_execution().unwrap_err();
        }
        {
            let mut sns_init_payload = sns_init_payload.clone();
            sns_init_payload.name = Some("S".repeat(SnsMetadata::MIN_NAME_LENGTH - 1));
            sns_init_payload.validate_post_execution().unwrap_err();
            sns_init_payload.validate_pre_execution().unwrap_err();
        }
        {
            let mut sns_init_payload = sns_init_payload.clone();
            sns_init_payload.url = None;
            sns_init_payload.validate_post_execution().unwrap_err();
            sns_init_payload.validate_pre_execution().unwrap_err();
        }
        {
            let mut sns_init_payload = sns_init_payload.clone();
            sns_init_payload.url = Some("S".repeat(SnsMetadata::MAX_URL_LENGTH + 1));
            sns_init_payload.validate_post_execution().unwrap_err();
            sns_init_payload.validate_pre_execution().unwrap_err();
        }
        {
            let mut sns_init_payload = sns_init_payload.clone();
            sns_init_payload.url = Some("S".repeat(SnsMetadata::MIN_URL_LENGTH - 1));
            sns_init_payload.validate_post_execution().unwrap_err();
            sns_init_payload.validate_pre_execution().unwrap_err();
        }
        {
            let mut sns_init_payload = sns_init_payload.clone();
            sns_init_payload.logo = Some("S".repeat(ledger_validation::MAX_LOGO_LENGTH + 1));
            sns_init_payload.validate_post_execution().unwrap_err();
            sns_init_payload.validate_pre_execution().unwrap_err();
        }
    }

    #[test]
    fn test_sns_canister_ids_are_used() {
        // Create a SnsInitPayload with some reasonable defaults
        let sns_init_payload = SnsInitPayload {
            token_name: Some("ServiceNervousSystem Coin".to_string()),
            token_symbol: Some("SNS".to_string()),
            proposal_reject_cost_e8s: Some(10_000),
            neuron_minimum_stake_e8s: Some(100_000_000),
            ..SnsInitPayload::with_valid_values_for_testing_post_execution()
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
            ..SnsInitPayload::with_valid_values_for_testing_post_execution()
        };

        // Assert that this payload is valid in the view of the library
        sns_init_payload.validate_post_execution().unwrap();
        sns_init_payload.validate_pre_execution().unwrap_err();

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
        let sns_init_payload = {
            let sns_init_payload = SnsInitPayload::with_valid_values_for_testing_post_execution();
            sns_init_payload.validate_post_execution().unwrap();
            sns_init_payload.validate_pre_execution().unwrap_err();
            sns_init_payload
        };

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
        let sns_init_payload = {
            let sns_init_payload = SnsInitPayload::with_valid_values_for_testing_post_execution();
            sns_init_payload.validate_post_execution().unwrap();
            sns_init_payload.validate_pre_execution().unwrap_err();
            sns_init_payload
        };

        // Create valid CanisterIds
        let sns_canister_ids = create_canister_ids();

        let canister_payloads = sns_init_payload
            .build_canister_payloads(&sns_canister_ids, None, false)
            .expect("Expected SnsInitPayload to be a valid payload");

        let swap_init = canister_payloads.swap;

        // Assert that sns_tokens_e8s was set (as we are in the one-proposal flow)
        swap_init.sns_token_e8s.unwrap();

        // Assert that the Swap canister would accept this payload.
        swap_init.validate().unwrap();
    }

    #[test]
    fn test_confirmation_text_is_valid() {
        // Create valid CanisterIds
        let sns_canister_ids = create_canister_ids();
        // Test that `confirmation_text` is indeed optional.
        {
            let sns_init_payload = SnsInitPayload {
                confirmation_text: None,
                ..SnsInitPayload::with_valid_values_for_testing_post_execution()
            };
            sns_init_payload
                .build_canister_payloads(&sns_canister_ids, None, false)
                .unwrap();
        }
        // Test that some non-trivial value of `confirmation_text` validates.
        {
            let sns_init_payload: SnsInitPayload = SnsInitPayload {
                confirmation_text: Some("Please confirm that 2+2=4".to_string()),
                ..SnsInitPayload::with_valid_values_for_testing_post_execution()
            };
            sns_init_payload
                .build_canister_payloads(&sns_canister_ids, None, false)
                .unwrap();
        }
        // Test that `confirmation_text` set to an empty string is rejected.
        {
            let sns_init_payload = SnsInitPayload {
                confirmation_text: Some("".to_string()),
                ..SnsInitPayload::with_valid_values_for_testing_post_execution()
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
                ..SnsInitPayload::with_valid_values_for_testing_post_execution()
            };
            assert!(sns_init_payload
                .build_canister_payloads(&sns_canister_ids, None, false)
                .is_err());
        }
    }

    #[test]
    fn test_restricted_countries() {
        // Create valid CanisterIds
        let sns_canister_ids = create_canister_ids();
        // Test that `restricted_countries` is indeed optional.
        {
            let sns_init_payload = SnsInitPayload {
                restricted_countries: None,
                ..SnsInitPayload::with_valid_values_for_testing_post_execution()
            };
            sns_init_payload
                .build_canister_payloads(&sns_canister_ids, None, false)
                .unwrap();
        }
        // Test that some non-trivial value of `restricted_countries` validates.
        {
            let sns_init_payload = SnsInitPayload {
                restricted_countries: Some(Countries {
                    iso_codes: vec!["CH".to_string()],
                }),
                ..SnsInitPayload::with_valid_values_for_testing_post_execution()
            };
            sns_init_payload
                .build_canister_payloads(&sns_canister_ids, None, false)
                .unwrap();
        }
        // Test that multiple countries can be validated.
        {
            let sns_init_payload = SnsInitPayload {
                restricted_countries: Some(Countries {
                    iso_codes: CountryCode::as_array_alpha2()
                        .map(|x| x.alpha2().to_string())
                        .to_vec(),
                }),
                ..SnsInitPayload::with_valid_values_for_testing_post_execution()
            };
            sns_init_payload
                .build_canister_payloads(&sns_canister_ids, None, false)
                .unwrap();
        }
        // Check that item count is checked before duplicate analysis.
        {
            let num_items = CountryCode::num_country_codes() + 1;
            let sns_init_payload = SnsInitPayload {
                restricted_countries: Some(Countries {
                    iso_codes: (0..num_items).map(|x| x.to_string()).collect(),
                }),
                ..SnsInitPayload::with_valid_values_for_testing_post_execution()
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
                ..SnsInitPayload::with_valid_values_for_testing_post_execution()
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
                ..SnsInitPayload::with_valid_values_for_testing_post_execution()
            };
            assert_error(
                sns_init_payload.build_canister_payloads(&sns_canister_ids, None, false),
                RestrictedCountriesValidationError::NotIsoCompliant(item),
            );
        }
        // Test that alpha3 is rejected.
        {
            let item = "CHE".to_string();
            let sns_init_payload = SnsInitPayload {
                restricted_countries: Some(Countries {
                    iso_codes: vec![item.clone()],
                }),
                ..SnsInitPayload::with_valid_values_for_testing_post_execution()
            };
            assert_error(
                sns_init_payload.build_canister_payloads(&sns_canister_ids, None, false),
                RestrictedCountriesValidationError::NotIsoCompliant(item),
            );
        }
        // Test that a non-existing country code is rejected.
        {
            let item = "QQ".to_string();
            let sns_init_payload = SnsInitPayload {
                restricted_countries: Some(Countries {
                    iso_codes: vec![item.clone()],
                }),
                ..SnsInitPayload::with_valid_values_for_testing_post_execution()
            };
            assert_error(
                sns_init_payload.build_canister_payloads(&sns_canister_ids, None, false),
                RestrictedCountriesValidationError::NotIsoCompliant(item),
            );
        }
        // Test that duplicate country codes are rejected.
        {
            let item = "CH".to_string();
            let sns_init_payload = SnsInitPayload {
                restricted_countries: Some(Countries {
                    iso_codes: vec![item.clone(), item.clone()],
                }),
                ..SnsInitPayload::with_valid_values_for_testing_post_execution()
            };
            assert_error(
                sns_init_payload.build_canister_payloads(&sns_canister_ids, None, false),
                RestrictedCountriesValidationError::ContainsDuplicates(item),
            );
        }
    }

    #[test]
    fn test_neuron_basket_construction_parameters() {
        let default_dd_limit: u64 = 252_460_800;
        let sns_init_payload = {
            let sns_init_payload = SnsInitPayload::with_valid_values_for_testing_post_execution();
            sns_init_payload.validate_post_execution().unwrap();
            sns_init_payload.validate_pre_execution().unwrap_err();
            sns_init_payload
        };
        // Test that `neuron_basket_construction_parameters` is indeed optional in the legacy flow.
        {
            let sns_init_payload = SnsInitPayload {
                neuron_basket_construction_parameters: None,
                ..sns_init_payload.clone()
            };
            sns_init_payload.validate_post_execution().unwrap_err();
            sns_init_payload.validate_pre_execution().unwrap_err();
        }
        // Test that `neuron_basket_construction_parameters` is not optional in the one-proposal flow.
        {
            let sns_init_payload = SnsInitPayload {
                neuron_basket_construction_parameters: None,
                ..sns_init_payload.clone()
            };
            sns_init_payload.validate_post_execution().unwrap_err();
            sns_init_payload.validate_pre_execution().unwrap_err();
        }
        // Test that `neuron_basket_construction_parameters` is forbidden in
        // the legacy flow and allowed in the one-proposal flow.
        {
            let sns_init_payload = SnsInitPayload {
                neuron_basket_construction_parameters: Some(NeuronBasketConstructionParameters {
                    count: 2_u64,
                    dissolve_delay_interval_seconds: default_dd_limit.saturating_div(10),
                }),
                ..sns_init_payload.clone()
            };
            sns_init_payload.validate_post_execution().unwrap();
            sns_init_payload.validate_pre_execution().unwrap_err();
        }
        // Test that validation fails when
        // (count - 1) * dissolve_delay_interval == 1 + max_dissolve_delay_seconds
        {
            let sns_init_payload = SnsInitPayload {
                max_dissolve_delay_seconds: Some(default_dd_limit),
                neuron_basket_construction_parameters: Some(NeuronBasketConstructionParameters {
                    count: 2_u64,
                    dissolve_delay_interval_seconds: default_dd_limit.saturating_add(1),
                }),
                ..sns_init_payload.clone()
            };
            let expected =
                NeuronBasketConstructionParametersValidationError::ExceedsMaximalDissolveDelay(
                    default_dd_limit,
                );
            assert_error(sns_init_payload.validate_post_execution(), expected);
            sns_init_payload.validate_pre_execution().unwrap_err();
        }
        // Test that validation fails when (count - 1) * dissolve_delay_interval
        // does not fit u64.
        {
            let sns_init_payload = SnsInitPayload {
                max_dissolve_delay_seconds: Some(default_dd_limit),
                neuron_basket_construction_parameters: Some(NeuronBasketConstructionParameters {
                    count: 3_u64,
                    dissolve_delay_interval_seconds: u64::MAX - 1,
                }),
                ..sns_init_payload.clone()
            };
            let expected = NeuronBasketConstructionParametersValidationError::ExceedsU64;
            assert_error(sns_init_payload.validate_post_execution(), expected);
            sns_init_payload.validate_pre_execution().unwrap_err();
        }
        // Test that validation fails when basket count is too low
        {
            let sns_init_payload = SnsInitPayload {
                neuron_basket_construction_parameters: Some(NeuronBasketConstructionParameters {
                    count: 1_u64,
                    dissolve_delay_interval_seconds: 12_345_678_u64, // arbitrary valid value
                }),
                ..sns_init_payload.clone()
            };
            let expected = NeuronBasketConstructionParametersValidationError::InadequateBasketSize;
            assert_error(sns_init_payload.validate_post_execution(), expected);
            sns_init_payload.validate_pre_execution().unwrap_err();
        }
        // Test that validation fails when dissolve_delay_interval_seconds is too low
        {
            let sns_init_payload = SnsInitPayload {
                neuron_basket_construction_parameters: Some(NeuronBasketConstructionParameters {
                    count: 2_u64,
                    dissolve_delay_interval_seconds: 0_u64,
                }),
                ..sns_init_payload.clone()
            };
            let expected =
                NeuronBasketConstructionParametersValidationError::InadequateDissolveDelay;
            assert_error(sns_init_payload.validate_post_execution(), expected);
            sns_init_payload.validate_pre_execution().unwrap_err();
        }
    }

    #[test]
    fn test_ledger_init_args_is_valid() {
        // Build an sns_init_payload with defaults for non-ledger related configuration.
        let transaction_fee = 10_000;
        let token_symbol = "SNS".to_string();
        let token_name = "ServiceNervousSystem Coin".to_string();
        let token_logo = "data:image/png;base64,aGVsbG8gZnJvbSBkZmluaXR5IQ==".to_string();

        let sns_init_payload = SnsInitPayload {
            token_name: Some(token_name.clone()),
            token_symbol: Some(token_symbol.clone()),
            transaction_fee_e8s: Some(transaction_fee),
            token_logo: Some(token_logo.clone()),
            ..SnsInitPayload::with_valid_values_for_testing_post_execution()
        };

        // Assert that this payload is valid in the view of the library
        sns_init_payload.validate_post_execution().unwrap();
        sns_init_payload.validate_pre_execution().unwrap_err();

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
            assert_eq!(
                ledger.metadata,
                vec![(
                    ICRC1_TOKEN_LOGO_KEY.to_string(),
                    MetadataValue::Text(token_logo.clone())
                )]
            )
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
        // Build a payload that passes legacy validation, then test the parts that wouldn't
        let get_sns_init_payload = || {
            SnsInitPayload::with_valid_values_for_testing_post_execution()
                .validate_post_execution()
                .unwrap()
        };

        let mut sns_init_payload = get_sns_init_payload();
        sns_init_payload.dapp_canisters =
            Some(generate_unique_dapp_canisters(MAX_DAPP_CANISTERS_COUNT + 1));
        sns_init_payload.validate_post_execution().unwrap_err();
        sns_init_payload.validate_pre_execution().unwrap_err();

        sns_init_payload.dapp_canisters =
            Some(generate_unique_dapp_canisters(MAX_DAPP_CANISTERS_COUNT));
        sns_init_payload.validate_post_execution().unwrap();
        sns_init_payload.validate_pre_execution().unwrap_err();

        sns_init_payload.dapp_canisters = None;
        // No dapp canisters is okay (practically, this is only needed in testing).
        sns_init_payload.validate_post_execution().unwrap();
        sns_init_payload.validate_pre_execution().unwrap_err();

        sns_init_payload.dapp_canisters = Some(DappCanisters {
            canisters: vec![Canister { id: None }],
        });
        sns_init_payload.validate_post_execution().unwrap_err();
        sns_init_payload.validate_pre_execution().unwrap_err();

        let duplicate_dapp_canister = Canister {
            id: Some(CanisterId::from_u64(1).get()),
        };
        sns_init_payload.dapp_canisters = Some(DappCanisters {
            canisters: vec![duplicate_dapp_canister, duplicate_dapp_canister],
        });
        sns_init_payload.validate_post_execution().unwrap_err();
        sns_init_payload.validate_pre_execution().unwrap_err();
    }

    // Create an initial SNS payload that includes Governance and Ledger init payloads. Then
    // iterate over each neuron in the Governance init payload and assert that each neuron's
    // account is present in the Ledger init payload's `initial_balances`.
    #[test]
    fn test_build_canister_payloads_creates_neurons_with_correct_ledger_accounts() {
        use num_traits::ToPrimitive;

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
            ..SnsInitPayload::with_valid_values_for_testing_post_execution()
        };

        // Assert that this payload is valid in the view of the library
        sns_init_payload
            .validate_post_execution()
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
                ledger
                    .initial_balances
                    .into_iter()
                    .map(|(account, amount)| {
                        (
                            account,
                            amount
                                .0
                                .to_u64()
                                .expect("bug: balance does not fit into u64"),
                        )
                    })
                    .collect()
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
        let sns_init_payload = {
            let sns_init_payload = SnsInitPayload::with_valid_values_for_testing_post_execution();
            sns_init_payload.validate_post_execution().unwrap();
            sns_init_payload.validate_pre_execution().unwrap_err();
            sns_init_payload
        };

        {
            let sns_init_payload = SnsInitPayload {
                fallback_controller_principal_ids: vec![
                    PrincipalId::new_user_test_id(1).to_string()
                ],
                ..sns_init_payload.clone()
            };
            sns_init_payload.validate_post_execution().unwrap();
            sns_init_payload.validate_pre_execution().unwrap_err();
        }

        {
            let sns_init_payload = SnsInitPayload {
                fallback_controller_principal_ids: generate_pids(0),
                ..sns_init_payload.clone()
            };
            sns_init_payload.validate_post_execution().unwrap_err();
            sns_init_payload.validate_pre_execution().unwrap_err();
        }

        {
            let sns_init_payload = SnsInitPayload {
                fallback_controller_principal_ids: generate_pids(
                    MAX_FALLBACK_CONTROLLER_PRINCIPAL_IDS_COUNT + 1,
                ),
                ..sns_init_payload.clone()
            };
            sns_init_payload.validate_post_execution().unwrap_err();
            sns_init_payload.validate_pre_execution().unwrap_err();
        }

        {
            let sns_init_payload = SnsInitPayload {
                fallback_controller_principal_ids: vec![
                    "not a valid pid".to_string(),
                    "definitely not a valid pid".to_string(),
                ],
                ..sns_init_payload.clone()
            };
            sns_init_payload.validate_post_execution().unwrap_err();
            sns_init_payload.validate_pre_execution().unwrap_err();
        }

        {
            let sns_init_payload = SnsInitPayload {
                fallback_controller_principal_ids: vec![
                    PrincipalId::new_user_test_id(1).to_string(),
                    PrincipalId::new_user_test_id(1).to_string(),
                ],
                ..sns_init_payload.clone()
            };
            sns_init_payload.validate_post_execution().unwrap_err();
            sns_init_payload.validate_pre_execution().unwrap_err();
        }
    }

    #[test]
    fn test_token_logo_validation() {
        // Build a payload that passes validation, then test the parts that wouldn't
        let sns_init_payload = {
            let sns_init_payload = SnsInitPayload::with_valid_values_for_testing_post_execution();
            sns_init_payload.validate_post_execution().unwrap();
            sns_init_payload.validate_pre_execution().unwrap_err();
            sns_init_payload
        };

        {
            let sns_init_payload = SnsInitPayload {
                token_logo: Some("data:image/png;base64,aGVsbG8gZnJvbSBkZmluaXR5IQ==".to_string()),
                ..sns_init_payload.clone()
            };
            sns_init_payload.validate_post_execution().unwrap();
            sns_init_payload.validate_pre_execution().unwrap_err();
        }

        // Not-specified
        {
            let sns_init_payload = SnsInitPayload {
                token_logo: None,
                ..sns_init_payload.clone()
            };
            sns_init_payload.validate_post_execution().unwrap_err();
            sns_init_payload.validate_pre_execution().unwrap_err();
        }

        // Exceeds max length
        {
            let sns_init_payload = SnsInitPayload {
                token_logo: Some("S".repeat(ledger_validation::MAX_LOGO_LENGTH + 1)),
                ..sns_init_payload.clone()
            };
            sns_init_payload.validate_post_execution().unwrap_err();
            sns_init_payload.validate_pre_execution().unwrap_err();
        }

        // Illegal image prefix
        {
            let sns_init_payload = SnsInitPayload {
                token_logo: Some("NOT A DATA URL WITH BASE64".to_string()),
                ..sns_init_payload.clone()
            };
            sns_init_payload.validate_post_execution().unwrap_err();
            sns_init_payload.validate_pre_execution().unwrap_err();
        }

        {
            let sns_init_payload = SnsInitPayload {
                token_logo: Some("data:image/png;".to_string()),
                ..sns_init_payload.clone()
            };
            sns_init_payload.validate_post_execution().unwrap_err();
            sns_init_payload.validate_pre_execution().unwrap_err();
        }
    }

    #[test]
    fn pre_and_post_execution_mutually_exclusive() {
        // The result of SnsInitPayload::with_valid_values_for_testing_post_execution() is
        // valid "post-execution"
        let sns_init_payload = SnsInitPayload::with_valid_values_for_testing_post_execution();
        sns_init_payload.validate_pre_execution().unwrap_err();
        sns_init_payload.validate_post_execution().unwrap();
        sns_init_payload
            .validate_all_non_legacy_pre_execution_swap_parameters_are_set()
            .unwrap();
        sns_init_payload
            .validate_all_post_execution_swap_parameters_are_set()
            .unwrap();

        // If we remove the post-execution values, the payload is valid "pre-execution"
        let sns_init_payload = {
            let mut sns_init_payload =
                SnsInitPayload::with_valid_values_for_testing_post_execution();
            sns_init_payload.nns_proposal_id = None;
            sns_init_payload.neurons_fund_participants = None;
            sns_init_payload.swap_start_timestamp_seconds = None;
            sns_init_payload.swap_due_timestamp_seconds = None;
            sns_init_payload.neurons_fund_participation_constraints = None;
            sns_init_payload
        };
        sns_init_payload.validate_pre_execution().unwrap();
        sns_init_payload.validate_post_execution().unwrap_err();
        sns_init_payload
            .validate_all_non_legacy_pre_execution_swap_parameters_are_set()
            .unwrap();
        sns_init_payload
            .validate_all_post_execution_swap_parameters_are_set()
            .unwrap_err();

        // If we remove only some of the pre-execution values, the payload is
        // not valid "pre-execution" or "post-execution"
        let sns_init_payload = SnsInitPayload {
            nns_proposal_id: None,
            swap_start_timestamp_seconds: None,
            ..SnsInitPayload::with_valid_values_for_testing_post_execution()
        };
        sns_init_payload.validate_pre_execution().unwrap_err();
        sns_init_payload.validate_post_execution().unwrap_err();
        sns_init_payload
            .validate_all_non_legacy_pre_execution_swap_parameters_are_set()
            .unwrap();
        sns_init_payload
            .validate_all_post_execution_swap_parameters_are_set()
            .unwrap_err();
    }

    #[test]
    fn test_errors_not_thrown_twice() {
        // Build an sns_init_payload with an invalid initial_token_distribution
        let sns_init_payload = SnsInitPayload {
            initial_token_distribution: None,
            ..SnsInitPayload::with_valid_values_for_testing_post_execution()
        };

        // Assert that this payload is invalid
        let post_execution_error = sns_init_payload.validate_post_execution().unwrap_err();
        let pre_execution_error = sns_init_payload.validate_pre_execution().unwrap_err();

        // Check the error messages to make sure there are no duplicate lines
        {
            let errors = post_execution_error.split("Error: ").collect::<Vec<_>>();
            let errors_set = errors.clone().into_iter().collect::<HashSet<_>>();
            assert!(
                errors.len() == errors_set.len(),
                "Errors not unique: {:?}",
                errors
            );
        }
        {
            let errors = pre_execution_error.split("Error: ").collect::<Vec<_>>();
            let errors_set = errors.clone().into_iter().collect::<HashSet<_>>();
            assert!(
                errors.len() == errors_set.len(),
                "Errors not unique: {:?}",
                errors
            );
        }
    }

    #[test]
    fn test_neurons_fund_participation_constraints_validation_for_pre_execution() {
        let sns_init_payload = SnsInitPayload {
            neurons_fund_participation_constraints: Some(NeuronsFundParticipationConstraints {
                min_direct_participation_threshold_icp_e8s: Some(1_000),
                max_neurons_fund_participation_icp_e8s: Some(10_000),
                coefficient_intervals: vec![],
                ideal_matched_participation_function: Some(IdealMatchedParticipationFunction {
                    serialized_representation: Some("<Test>".to_string()),
                }),
            }),
            ..SnsInitPayload::with_valid_values_for_testing_pre_execution()
        };
        assert_eq!(
            sns_init_payload.validate_pre_execution().map(|_| ()),
            NeuronsFundParticipationConstraintsValidationError::SetBeforeProposalExecution.into(),
        );
    }

    #[test]
    fn test_neurons_fund_participation_constraints_validation_for_post_execution_success() {
        let template_init_payload = SnsInitPayload::with_valid_values_for_testing_post_execution();
        let ideal_matched_participation_function = template_init_payload
            .neurons_fund_participation_constraints
            .as_ref()
            .unwrap()
            .ideal_matched_participation_function
            .clone();
        let sns_init_payload = SnsInitPayload {
            min_direct_participation_icp_e8s: Some(6_000_000_000),
            neurons_fund_participation_constraints: Some(NeuronsFundParticipationConstraints {
                min_direct_participation_threshold_icp_e8s: Some(6_500_000_000),
                max_neurons_fund_participation_icp_e8s: Some(6_500_000_000),
                coefficient_intervals: vec![LinearScalingCoefficient {
                    from_direct_participation_icp_e8s: Some(0),
                    to_direct_participation_icp_e8s: Some(1),
                    slope_numerator: Some(2),
                    slope_denominator: Some(3),
                    intercept_icp_e8s: Some(4),
                }],
                ideal_matched_participation_function,
            }),
            ..template_init_payload
        };
        assert_eq!(
            sns_init_payload.validate_post_execution().map(|_| ()),
            Ok(())
        );
    }

    #[test]
    fn test_neurons_fund_participation_constraints_validation_for_post_execution_fail_due_to_unspecified_min_direct_participation_threshold(
    ) {
        let template_init_payload = SnsInitPayload::with_valid_values_for_testing_post_execution();
        let ideal_matched_participation_function = template_init_payload
            .neurons_fund_participation_constraints
            .as_ref()
            .unwrap()
            .ideal_matched_participation_function
            .clone();
        let sns_init_payload: SnsInitPayload = SnsInitPayload {
            min_direct_participation_icp_e8s: Some(6_000_000_000),
            max_direct_participation_icp_e8s: Some(65_000_000_000),
            neurons_fund_participation_constraints: Some(NeuronsFundParticipationConstraints {
                // `min_direct_participation_threshold_icp_e8s` must be specified, so the payload
                // is *invalid* without it.
                min_direct_participation_threshold_icp_e8s: None,
                max_neurons_fund_participation_icp_e8s: Some(6_500_000_000),
                coefficient_intervals: vec![LinearScalingCoefficient {
                    from_direct_participation_icp_e8s: Some(0),
                    to_direct_participation_icp_e8s: Some(1),
                    slope_numerator: Some(2),
                    slope_denominator: Some(3),
                    intercept_icp_e8s: Some(4),
                }],
                ideal_matched_participation_function,
            }),
            ..template_init_payload
        };
        assert_eq!(
            sns_init_payload.validate_post_execution().map(|_| ()),
            NeuronsFundParticipationConstraintsValidationError::MinDirectParticipationThresholdValidationError(
                MinDirectParticipationThresholdValidationError::Unspecified,
            ).into(),
        );
    }

    #[test]
    fn test_neurons_fund_participation_constraints_validation_for_post_execution_fail_due_to_min_direct_participation_gt_min_direct_participation_threshold(
    ) {
        let template_init_payload = SnsInitPayload::with_valid_values_for_testing_post_execution();
        let ideal_matched_participation_function = template_init_payload
            .neurons_fund_participation_constraints
            .as_ref()
            .unwrap()
            .ideal_matched_participation_function
            .clone();
        let sns_init_payload = SnsInitPayload {
            // `min_direct_participation_icp_e8s > min_direct_participation_threshold_icp_e8s`,
            // so the payload is *invalid*.
            min_direct_participation_icp_e8s: Some(7_000_000_000),
            neurons_fund_participation_constraints: Some(NeuronsFundParticipationConstraints {
                min_direct_participation_threshold_icp_e8s: Some(6_500_000_000),
                max_neurons_fund_participation_icp_e8s: Some(6_500_000_000),
                coefficient_intervals: vec![LinearScalingCoefficient {
                    from_direct_participation_icp_e8s: Some(0),
                    to_direct_participation_icp_e8s: Some(1),
                    slope_numerator: Some(2),
                    slope_denominator: Some(3),
                    intercept_icp_e8s: Some(4),
                }],
                ideal_matched_participation_function,
            }),
            ..template_init_payload
        };
        assert_eq!(
            sns_init_payload.validate_post_execution().map(|_| ()),
            NeuronsFundParticipationConstraintsValidationError::MinDirectParticipationThresholdValidationError(
                MinDirectParticipationThresholdValidationError::BelowSwapDirectIcpMin {
                    min_direct_participation_threshold_icp_e8s: 6_500_000_000,
                    min_direct_participation_icp_e8s: 7_000_000_000,
                },
            ).into(),
        );
    }

    #[test]
    fn test_neurons_fund_participation_constraints_validation_for_post_execution_fail_due_to_max_direct_participation_lt_min_direct_participation_threshold(
    ) {
        let template_init_payload = SnsInitPayload::with_valid_values_for_testing_post_execution();
        let ideal_matched_participation_function = template_init_payload
            .neurons_fund_participation_constraints
            .as_ref()
            .unwrap()
            .ideal_matched_participation_function
            .clone();
        let sns_init_payload: SnsInitPayload = SnsInitPayload {
            min_direct_participation_icp_e8s: Some(6_000_000_000),
            max_direct_participation_icp_e8s: Some(65_000_000_000),
            neurons_fund_participation_constraints: Some(NeuronsFundParticipationConstraints {
                // `max_direct_participation_icp_e8s < min_direct_participation_threshold_icp_e8s`,
                // so the payload is *invalid*.
                min_direct_participation_threshold_icp_e8s: Some(6_500_000_000_000),
                max_neurons_fund_participation_icp_e8s: Some(6_500_000_000),
                coefficient_intervals: vec![LinearScalingCoefficient {
                    from_direct_participation_icp_e8s: Some(0),
                    to_direct_participation_icp_e8s: Some(1),
                    slope_numerator: Some(2),
                    slope_denominator: Some(3),
                    intercept_icp_e8s: Some(4),
                }],
                ideal_matched_participation_function,
            }),
            ..template_init_payload
        };
        assert_eq!(
            sns_init_payload.validate_post_execution().map(|_| ()),
            NeuronsFundParticipationConstraintsValidationError::MinDirectParticipationThresholdValidationError(
                MinDirectParticipationThresholdValidationError::AboveSwapDirectIcpMax {
                    min_direct_participation_threshold_icp_e8s: 6_500_000_000_000,
                    max_direct_participation_icp_e8s: 65_000_000_000,
                },
            ).into(),
        );
    }

    #[test]
    fn test_neurons_fund_participation_constraints_validation_for_post_execution_fail_due_to_unspecified_max_neurons_fund_participation(
    ) {
        let template_init_payload = SnsInitPayload::with_valid_values_for_testing_post_execution();
        let ideal_matched_participation_function = template_init_payload
            .neurons_fund_participation_constraints
            .as_ref()
            .unwrap()
            .ideal_matched_participation_function
            .clone();
        let sns_init_payload: SnsInitPayload = SnsInitPayload {
            min_direct_participation_icp_e8s: Some(6_000_000_000),
            neurons_fund_participation_constraints: Some(NeuronsFundParticipationConstraints {
                min_direct_participation_threshold_icp_e8s: Some(6_500_000_000),
                // `max_neurons_fund_participation_icp_e8s` must be specified, so the payload
                // is *invalid* without it.
                max_neurons_fund_participation_icp_e8s: None,
                coefficient_intervals: vec![LinearScalingCoefficient {
                    from_direct_participation_icp_e8s: Some(0),
                    to_direct_participation_icp_e8s: Some(1),
                    slope_numerator: Some(2),
                    slope_denominator: Some(3),
                    intercept_icp_e8s: Some(4),
                }],
                ideal_matched_participation_function,
            }),
            ..template_init_payload
        };
        assert_eq!(
            sns_init_payload.validate_post_execution().map(|_| ()),
            NeuronsFundParticipationConstraintsValidationError::MaxNeuronsFundParticipationValidationError(
                MaxNeuronsFundParticipationValidationError::Unspecified,
            ).into(),
        );
    }

    #[test]
    fn test_neurons_fund_participation_constraints_validation_for_post_execution_fail_due_to_max_neurons_fund_participation_lt_min_direct_participation(
    ) {
        let template_init_payload = SnsInitPayload::with_valid_values_for_testing_post_execution();
        let ideal_matched_participation_function = template_init_payload
            .neurons_fund_participation_constraints
            .as_ref()
            .unwrap()
            .ideal_matched_participation_function
            .clone();
        let sns_init_payload: SnsInitPayload = SnsInitPayload {
            min_direct_participation_icp_e8s: Some(6_000_000_000),
            min_participant_icp_e8s: Some(6_500_000_000),
            neurons_fund_participation_constraints: Some(NeuronsFundParticipationConstraints {
                min_direct_participation_threshold_icp_e8s: Some(6_500_000_000 - 1),
                // `max_neurons_fund_participation_icp_e8s < min_direct_participation_icp_e8s`,
                // so the payload is *invalid*.
                max_neurons_fund_participation_icp_e8s: Some(6_500_000_000 - 1),
                coefficient_intervals: vec![LinearScalingCoefficient {
                    from_direct_participation_icp_e8s: Some(0),
                    to_direct_participation_icp_e8s: Some(1),
                    slope_numerator: Some(2),
                    slope_denominator: Some(3),
                    intercept_icp_e8s: Some(4),
                }],
                ideal_matched_participation_function,
            }),
            ..template_init_payload
        };
        assert_eq!(
            sns_init_payload.validate_post_execution().map(|_| ()),
            NeuronsFundParticipationConstraintsValidationError::MaxNeuronsFundParticipationValidationError(
                MaxNeuronsFundParticipationValidationError::BelowSingleParticipationLimit {
                    max_neurons_fund_participation_icp_e8s: NonZeroU64::new(6_500_000_000-1).unwrap(),
                    min_participant_icp_e8s: 6_500_000_000,
                },
            ).into(),
        );
    }

    #[test]
    fn test_neurons_fund_participation_constraints_validation_for_post_execution_fail_due_to_max_neurons_fund_participation_lt_max_direct_participation(
    ) {
        let template_init_payload = SnsInitPayload::with_valid_values_for_testing_post_execution();
        let ideal_matched_participation_function = template_init_payload
            .neurons_fund_participation_constraints
            .as_ref()
            .unwrap()
            .ideal_matched_participation_function
            .clone();
        let sns_init_payload: SnsInitPayload = SnsInitPayload {
            min_direct_participation_icp_e8s: Some(6_000_000_000),
            max_direct_participation_icp_e8s: Some(65_000_000_000),
            neurons_fund_participation_constraints: Some(NeuronsFundParticipationConstraints {
                min_direct_participation_threshold_icp_e8s: Some(6_500_000_000),
                // `max_neurons_fund_participation_icp_e8s > max_direct_participation_icp_e8s`,
                // so the payload is *invalid*.
                max_neurons_fund_participation_icp_e8s: Some(65_000_000_000 + 1),
                coefficient_intervals: vec![LinearScalingCoefficient {
                    from_direct_participation_icp_e8s: Some(0),
                    to_direct_participation_icp_e8s: Some(1),
                    slope_numerator: Some(2),
                    slope_denominator: Some(3),
                    intercept_icp_e8s: Some(4),
                }],
                ideal_matched_participation_function,
            }),
            ..template_init_payload
        };
        assert_eq!(
            sns_init_payload.validate_post_execution().map(|_| ()),
            NeuronsFundParticipationConstraintsValidationError::MaxNeuronsFundParticipationValidationError(
                MaxNeuronsFundParticipationValidationError::AboveSwapMaxDirectIcp {
                    max_neurons_fund_participation_icp_e8s: 65_000_000_000+1,
                    max_direct_participation_icp_e8s: 65_000_000_000,
                },
            ).into(),
        );
    }

    // NNS canisters cannot be added as dapp canisters
    #[test]
    fn test_dapp_canisters_cannot_be_nns_canisters() {
        let nns_canisters = &[
            NNS_GOVERNANCE_CANISTER_ID,
            ICP_LEDGER_CANISTER_ID,
            REGISTRY_CANISTER_ID,
            ROOT_CANISTER_ID,
            CYCLES_MINTING_CANISTER_ID,
            LIFELINE_CANISTER_ID,
            GENESIS_TOKEN_CANISTER_ID,
            IDENTITY_CANISTER_ID,
            NNS_UI_CANISTER_ID,
            SNS_WASM_CANISTER_ID,
            EXCHANGE_RATE_CANISTER_ID,
        ]
        .map(|id: CanisterId| PrincipalId::from(id));
        for nns_canister in nns_canisters {
            let sns_init_payload = SnsInitPayload {
                dapp_canisters: Some(DappCanisters {
                    canisters: vec![Canister {
                        id: Some(*nns_canister),
                    }],
                }),
                ..SnsInitPayload::with_valid_values_for_testing_post_execution()
            };

            assert!(
                sns_init_payload.validate_pre_execution().unwrap_err().contains("Error: The following canisters are listed as dapp canisters, but are NNS canisters:"),
            );
        }
    }

    #[test]
    fn test_transaction_fee_must_be_less_than_min_stake() {
        // `neuron_minimum_stake_e8s == transaction_fee_e8s` is invalid
        {
            let sns_init_payload = SnsInitPayload {
                neuron_minimum_stake_e8s: Some(10_000),

                transaction_fee_e8s: Some(10_000),
                ..SnsInitPayload::with_valid_values_for_testing_pre_execution()
            };

            // Assert that this payload is invalid in the view of the library
            let error = sns_init_payload.validate_pre_execution().unwrap_err();
            assert!(error.contains("neuron_minimum_stake_e8s"));
            assert!(error.contains("It needs to be greater than the transaction fee"));
        }

        // `neuron_minimum_stake_e8s < transaction_fee_e8s` is invalid
        {
            let sns_init_payload = SnsInitPayload {
                neuron_minimum_stake_e8s: Some(10_000),
                transaction_fee_e8s: Some(11_000),
                ..SnsInitPayload::with_valid_values_for_testing_pre_execution()
            };

            // Assert that this payload is invalid in the view of the library
            let error = sns_init_payload.validate_pre_execution().unwrap_err();
            assert!(error.contains("neuron_minimum_stake_e8s"));
            assert!(error.contains("It needs to be greater than the transaction fee"));
        }

        // `neuron_minimum_stake_e8s > transaction_fee_e8s` may be valid
        {
            let sns_init_payload = SnsInitPayload {
                neuron_minimum_stake_e8s: Some(11_000),
                transaction_fee_e8s: Some(10_000),
                ..SnsInitPayload::with_valid_values_for_testing_pre_execution()
            };

            // Assert that this payload is valid in the view of the library
            sns_init_payload.validate_pre_execution().unwrap();
        }
    }
}
