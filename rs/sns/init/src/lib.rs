pub mod distributions;

use crate::distributions::InitialTokenDistribution;
use ic_base_types::{CanisterId, PrincipalId};
use ic_nns_constants::{
    GOVERNANCE_CANISTER_ID as NNS_GOVERNANCE_CANISTER_ID,
    LEDGER_CANISTER_ID as ICP_LEDGER_CANISTER_ID,
};
use ic_sns_governance::init::GovernanceCanisterInitPayloadBuilder;
use ic_sns_governance::pb::v1::{
    Governance, NervousSystemParameters, Neuron, NeuronPermissionList, NeuronPermissionType,
};
use ic_sns_governance::types::ONE_DAY_SECONDS;
use ic_sns_root::pb::v1::SnsRootCanister;
use ic_sns_sale::pb::v1::Init;
use ledger_canister::{AccountIdentifier, ArchiveOptions, LedgerCanisterInitPayload, Tokens};
use maplit::{btreemap, hashmap, hashset};
use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, SystemTime};

/// The maximum number of characters allowed for token symbol.
pub const MAX_TOKEN_SYMBOL_LENGTH: usize = 10;

/// The minimum number of characters allowed for token symbol.
pub const MIN_TOKEN_SYMBOL_LENGTH: usize = 3;

/// The maximum number of characters allowed for token name.
pub const MAX_TOKEN_NAME_LENGTH: usize = 255;

/// The minimum number of characters allowed for token name.
pub const MIN_TOKEN_NAME_LENGTH: usize = 4;

/// SNS parameters default values
pub const MIN_PARTICIPANT_ICP_E8S_DEFAULT: u64 = 1;

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
    pub ledger: LedgerCanisterInitPayload,
    pub root: SnsRootCanister,
    pub swap: Init,
}

/// This struct contains all the parameters necessary to initialize an SNS. All fields are optional
/// to avoid future candid compatibility problems. However, for the struct to be "valid", all fields
/// must be populated.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct SnsInitPayload {
    /// The transaction fee that must be paid for ledger transactions (except
    /// minting and burning governance tokens), denominated in e8s (1 token = 100,000,000 e8s).
    pub transaction_fee_e8s: Option<u64>,

    /// The name of the governance token controlled by this SNS, for example "Bitcoin".
    pub token_name: Option<String>,

    /// The symbol of the governance token controlled by this SNS, for example "BTC".
    pub token_symbol: Option<String>,

    /// The number of e8s (10E-8 of a token) that a rejected proposal costs the proposer.
    pub proposal_reject_cost_e8s: Option<u64>,

    /// The minimum number of e8s (10E-8 of a token) that can be staked in a neuron.
    ///
    /// To ensure that staking and disbursing of the neuron work, the chosen value
    /// must be larger than the transaction_fee_e8s.
    pub neuron_minimum_stake_e8s: Option<u64>,

    /// The initial tokens and neurons will be distributed according to the
    /// `InitialTokenDistribution`. This configures the accounts for the
    /// the decentralization swap, and will store distributions for future
    /// use.
    ///
    /// An example of a InitialTokenDistribution:
    ///
    /// InitialTokenDistribution {
    ///     developers: TokenDistribution {
    ///         total_e8s: 500_000_000,
    ///         distributions: {
    ///             "x4vjn-rrapj-c2kqe-a6m2b-7pzdl-ntmc4-riutz-5bylw-2q2bh-ds5h2-lae": 250_000_000,
    ///         }
    ///     },
    ///     treasury: TokenDistribution {
    ///         total_e8s: 500_000_000,
    ///         distributions: {
    ///             "fod6j-klqsi-ljm4t-7v54x-2wd6s-6yduy-spdkk-d2vd4-iet7k-nakfi-qqe": 100_000_000,
    ///         }
    ///     },
    ///     swap: 1_000_000_000
    /// }
    pub initial_token_distribution: Option<InitialTokenDistribution>,

    /// Amount targeted by the sale, if the amount is reach the sale is triggered. Must be at least
    /// min_participants * min_participant_icp_e8.
    pub max_icp_e8s: Option<u64>,

    /// Time when the swap will end. Must be between 1 day and 3 months.
    pub token_sale_timestamp_seconds: Option<u64>,

    /// Minimum number of participants for the sale to take place. Has to larger than zero.
    pub min_participants: Option<u32>,

    /// The minimum amount of icp that each buyer must contribute to participate.
    pub min_participant_icp_e8s: Option<u64>,

    /// The maximum amount of ICP that each buyer can contribute. Must be
    /// greater than or equal to `min_participant_icp_e8s` and less than
    /// or equal to `max_icp_e8s`. Can effectively be disabled by
    /// setting it to `max_icp_e8s`.
    pub max_participant_icp_e8s: Option<u64>,

    /// The total number of ICP that is required for this token sale to
    /// take place. This number divided by the number of SNS tokens for
    /// sale gives the seller's reserve price for the sale, i.e., the
    /// minimum number of ICP per SNS tokens that the seller of SNS
    /// tokens is willing to accept. If this amount is not achieved, the
    /// sale will be aborted (instead of committed) when the due date/time
    /// occurs. Must be smaller than or equal to `max_icp_e8s`.
    pub min_icp_e8s: Option<u64>,
}

impl Default for SnsInitPayload {
    fn default() -> SnsInitPayload {
        let nervous_system_parameters_default = NervousSystemParameters::with_default_values();
        SnsInitPayload {
            transaction_fee_e8s: nervous_system_parameters_default.transaction_fee_e8s,
            token_name: None,
            token_symbol: None,
            proposal_reject_cost_e8s: nervous_system_parameters_default.reject_cost_e8s,
            neuron_minimum_stake_e8s: nervous_system_parameters_default.neuron_minimum_stake_e8s,
            initial_token_distribution: None,
            max_icp_e8s: None,
            token_sale_timestamp_seconds: None,
            min_participants: None,
            min_participant_icp_e8s: Some(MIN_PARTICIPANT_ICP_E8S_DEFAULT),
            min_icp_e8s: None,
            max_participant_icp_e8s: None,
        }
    }
}

impl SnsInitPayload {
    /// Build all the SNS canister's init payloads given the state of the SnsInitPayload and the
    /// provided SnsCanisterIds.
    pub fn build_canister_payloads(
        &self,
        sns_canister_ids: &SnsCanisterIds,
    ) -> Result<SnsCanisterInitPayloads, String> {
        self.validate()?;
        Ok(SnsCanisterInitPayloads {
            governance: self.governance_init_args(sns_canister_ids),
            ledger: self.ledger_init_args(sns_canister_ids)?,
            root: self.root_init_args(sns_canister_ids),
            swap: self.swap_init_args(sns_canister_ids),
        })
    }

    /// Construct the params used to initialize a SNS Governance canister.
    fn governance_init_args(&self, sns_canister_ids: &SnsCanisterIds) -> Governance {
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
        governance.neurons = self.get_initial_neurons(parameters);

        governance
    }

    /// Construct the params used to initialize a SNS Ledger canister.
    fn ledger_init_args(
        &self,
        sns_canister_ids: &SnsCanisterIds,
    ) -> Result<LedgerCanisterInitPayload, String> {
        let root_canister_id = CanisterId::new(sns_canister_ids.root).unwrap();
        let token_symbol = self
            .token_symbol
            .as_ref()
            .expect("Expected token_symbol to be set");
        let token_name = self
            .token_name
            .as_ref()
            .expect("Expected token_name to be set");

        let mut payload = LedgerCanisterInitPayload::builder()
            .minting_account(sns_canister_ids.governance.into())
            .token_symbol_and_name(token_symbol, token_name)
            .archive_options(ArchiveOptions {
                trigger_threshold: 2000,
                num_blocks_to_archive: 1000,
                // 1 GB, which gives us 3 GB space when upgrading
                node_max_memory_size_bytes: Some(1024 * 1024 * 1024),
                // 128kb
                max_message_size_bytes: Some(128 * 1024),
                controller_id: root_canister_id.into(),
                // TODO: allow users to set this value
                // 10 Trillion cycles
                cycles_for_archive_creation: Some(10_000_000_000_000),
            })
            .build()
            .unwrap();

        payload.transfer_fee = self.transaction_fee_e8s.map(Tokens::from_e8s);
        payload.initial_values = self.get_all_ledger_accounts(sns_canister_ids)?;

        let governance_canister_id = CanisterId::new(sns_canister_ids.governance).unwrap();
        let ledger_canister_id = CanisterId::new(sns_canister_ids.ledger).unwrap();
        payload.send_whitelist = hashset! { governance_canister_id, ledger_canister_id };

        Ok(payload)
    }

    /// Construct the params used to initialize a SNS Root canister.
    fn root_init_args(&self, sns_canister_ids: &SnsCanisterIds) -> SnsRootCanister {
        SnsRootCanister {
            governance_canister_id: Some(sns_canister_ids.governance),
            ledger_canister_id: Some(sns_canister_ids.ledger),
        }
    }

    /// Construct the parameters used to initialize a SNS Swap canister.
    ///
    /// Precondition: self must be valid (see fn validate).
    fn swap_init_args(&self, sns_canister_ids: &SnsCanisterIds) -> Init {
        Init {
            sns_governance_canister_id: sns_canister_ids.governance.to_string(),
            nns_governance_canister_id: NNS_GOVERNANCE_CANISTER_ID.to_string(),
            sns_ledger_canister_id: sns_canister_ids.ledger.to_string(),
            icp_ledger_canister_id: ICP_LEDGER_CANISTER_ID.to_string(),
            max_icp_e8s: self.max_icp_e8s.expect("Field max_icp_e8 cannot be None"),
            token_sale_timestamp_seconds: self
                .token_sale_timestamp_seconds
                .expect("Field token_sale_timestamp_seconds cannot be None"),
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
        }
    }

    /// Given `SnsCanisterIds`, get all the ledger accounts of the TokenDistributions. These
    /// accounts represent the allocation of tokens at genesis.
    fn get_all_ledger_accounts(
        &self,
        sns_canister_ids: &SnsCanisterIds,
    ) -> Result<HashMap<AccountIdentifier, Tokens>, String> {
        if let Some(initial_token_distribution) = &self.initial_token_distribution {
            return initial_token_distribution.get_account_ids_and_tokens(sns_canister_ids);
        }

        Ok(hashmap! {})
    }

    /// Return the initial neurons that the user specified. These neurons will exist in
    /// Governance at genesis, with the correct balance in their corresponding ledger
    /// accounts. A map from neuron ID to Neuron is returned.
    fn get_initial_neurons(
        &self,
        parameters: &NervousSystemParameters,
    ) -> BTreeMap<String, Neuron> {
        if let Some(initial_token_distribution) = &self.initial_token_distribution {
            return initial_token_distribution.get_initial_neurons(parameters);
        }

        btreemap! {}
    }

    /// Validates the SnsInitPayload. This is called before building each SNS canister's
    /// payload and must pass.
    pub fn validate(&self) -> Result<Self, String> {
        let validation_fns = [
            self.validate_token_symbol(),
            self.validate_token_name(),
            self.validate_token_distribution(),
            self.validate_min_participants(),
            self.validate_token_sale_timestamp_seconds(),
            self.validate_icp_parameters(),
            self.validate_min_participant_icp_e8s(),
            self.validate_neuron_minimum_stake_e8s(),
            self.validate_proposal_reject_cost_e8s(),
            self.validate_transaction_fee_e8s(),
            self.validate_min_icp_e8s(),
            self.validate_max_participant_icp_e8s(),
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
            Err(defect_msg)
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

        Ok(())
    }

    fn validate_token_distribution(&self) -> Result<(), String> {
        let initial_token_distribution = self
            .initial_token_distribution
            .as_ref()
            .ok_or_else(|| "Error: initial-token-distribution must be specified".to_string())?;

        initial_token_distribution.validate()?;

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
        match self.neuron_minimum_stake_e8s {
            Some(_) => Ok(()),
            None => Err("Error: neuron_minimum_stake must be specified.".to_string()),
        }
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
                "Target icp e8s must be larger than min_participants * min_participant_icp_e8s"
                    .to_string(),
            )
        } else {
            Ok(())
        }
    }

    /// The token sale timestamp must exist, and be between 1 day and 90 days.
    fn validate_token_sale_timestamp_seconds(&self) -> Result<(), String> {
        let token_sale_timestamp_seconds = self
            .token_sale_timestamp_seconds
            .ok_or_else(|| "Error: token_sale_timestamp_seconds must be specified.".to_string())?;

        let one_day_from_now_timestamp = dfn_core::api::now()
            .checked_add(Duration::from_secs(ONE_DAY_SECONDS))
            .expect("Error when calculating Unix time.")
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .expect("Error when calculating Unix time");

        let three_month_from_now_timestamp = dfn_core::api::now()
            .checked_add(Duration::from_secs(90 * ONE_DAY_SECONDS))
            .expect("Error when calcuting Unix time.")
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .expect("Error when calculating Unix time");

        if token_sale_timestamp_seconds < one_day_from_now_timestamp {
            Err(
                "Error: token_sale_timestamp_seconds must be at least one day from now."
                    .to_string(),
            )
        } else if token_sale_timestamp_seconds > three_month_from_now_timestamp {
            Err(
                "Error: token_sale_timestamp_seconds can not be more than three months from now."
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
        match self.min_participant_icp_e8s {
            Some(_) => Ok(()),
            None => Err("Error: min_participant_icp_e8s must be specified.".to_string()),
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
                "Error: max_participant_icp_e8s can not be samller than min_participant_e8s"
                    .to_string(),
            )
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod test {
    use crate::distributions::TokenDistribution;
    use crate::{
        InitialTokenDistribution, SnsCanisterIds, SnsInitPayload, MAX_TOKEN_NAME_LENGTH,
        MAX_TOKEN_SYMBOL_LENGTH,
    };
    use ic_base_types::CanisterId;
    use ic_sns_governance::governance::ValidGovernanceProto;
    use ic_sns_governance::types::ONE_DAY_SECONDS;
    use ledger_canister::{AccountIdentifier, Tokens};
    use maplit::hashset;
    use std::time::{Duration, SystemTime};

    impl Default for InitialTokenDistribution {
        fn default() -> Self {
            InitialTokenDistribution {
                developers: TokenDistribution {
                    total_e8s: 100_000_000,
                    distributions: Default::default(),
                },
                treasury: TokenDistribution {
                    total_e8s: 500_000_000,
                    distributions: Default::default(),
                },
                swap: 1_000_000_000,
            }
        }
    }

    fn get_test_sns_init_payload() -> SnsInitPayload {
        SnsInitPayload {
            max_icp_e8s: Some(1_000_000_000),
            token_sale_timestamp_seconds: SystemTime::now()
                .checked_add(Duration::from_secs(2 * ONE_DAY_SECONDS))
                .expect("Error when calculating Unix time.")
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|duration| duration.as_secs())
                .ok(),
            min_participants: Some(100),
            initial_token_distribution: Some(InitialTokenDistribution::default()),
            min_icp_e8s: Some(100),
            max_participant_icp_e8s: Some(1_000_000_000),
            ..Default::default()
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
            SnsInitPayload {
                token_name: Some("ServiceNervousSystem".to_string()),
                token_symbol: Some("SNS".to_string()),
                initial_token_distribution: Some(InitialTokenDistribution::default()),
                ..get_test_sns_init_payload()
            }
            .validate()
            .expect("Payload did not pass validation.")
        };

        let mut sns_init_payload = get_sns_init_payload();

        sns_init_payload.token_symbol = Some("S".repeat(MAX_TOKEN_SYMBOL_LENGTH + 1));
        assert!(sns_init_payload.validate().is_err());
        sns_init_payload = get_sns_init_payload();

        sns_init_payload.token_name = Some("S".repeat(MAX_TOKEN_NAME_LENGTH + 1));
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
        assert!(sns_init_payload.validate().is_err());
    }

    #[test]
    fn test_sns_canister_ids_are_used() {
        // Create a SnsInitPayload with some reasonable defaults
        let sns_init_payload = SnsInitPayload {
            token_name: Some("ServiceNervousSystem Coin".to_string()),
            token_symbol: Some("SNS".to_string()),
            proposal_reject_cost_e8s: Some(10_000),
            neuron_minimum_stake_e8s: Some(100_000_000),
            initial_token_distribution: Some(InitialTokenDistribution::default()),
            ..get_test_sns_init_payload()
        };
        println!("SnsInitPayload = {:#?}", sns_init_payload);
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
                .unwrap()
                .controller_id,
            sns_canister_ids.root
        );
        assert_eq!(
            sns_canisters_init_payloads.ledger.minting_account,
            AccountIdentifier::new(sns_canister_ids.governance, None)
        );
        assert_eq!(
            sns_canisters_init_payloads.ledger.send_whitelist,
            hashset! {
                CanisterId::new(sns_canister_ids.governance).unwrap(),
                CanisterId::new(sns_canister_ids.ledger).unwrap()
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
            initial_token_distribution: Some(InitialTokenDistribution::default()),
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
            initial_token_distribution: Some(InitialTokenDistribution::default()),
            ..get_test_sns_init_payload()
        };

        // Assert that this payload is valid in the view of the library
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
            initial_token_distribution: Some(InitialTokenDistribution::default()),
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
            initial_token_distribution: Some(InitialTokenDistribution::default()),
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
        assert_eq!(ledger.token_symbol, Some(token_symbol));
        assert_eq!(ledger.token_name, Some(token_name));
        assert_eq!(
            ledger.minting_account,
            AccountIdentifier::new(sns_canister_ids.governance, None)
        );
        assert_eq!(ledger.transfer_fee, Some(Tokens::from_e8s(transaction_fee)));
    }
}
