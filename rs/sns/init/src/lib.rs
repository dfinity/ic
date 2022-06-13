pub mod distributions;

use crate::distributions::InitialTokenDistribution;
use ic_base_types::{CanisterId, PrincipalId};
use ic_sns_governance::init::GovernanceCanisterInitPayloadBuilder;
use ic_sns_governance::pb::v1::{
    Governance, NervousSystemParameters, Neuron, NeuronPermissionList, NeuronPermissionType,
};
use ic_sns_root::pb::v1::SnsRootCanister;
use ledger_canister::{AccountIdentifier, ArchiveOptions, LedgerCanisterInitPayload, Tokens};
use maplit::{btreemap, hashmap, hashset};
use std::collections::{BTreeMap, HashMap};

/// The maximum number of characters allowed for token symbol.
const MAX_TOKEN_SYMBOL_LENGTH: usize = 10;

/// The minimum number of characters allowed for token symbol.
const MIN_TOKEN_SYMBOL_LENGTH: usize = 3;

/// The maximum number of characters allowed for token name.
const MAX_TOKEN_NAME_LENGTH: usize = 255;

/// The minimum number of characters allowed for token name.
const MIN_TOKEN_NAME_LENGTH: usize = 10;

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
}

/// A builder for the SnsInitPayload that provides concise creation and validation.
pub struct SnsInitPayloadBuilder {
    pub(crate) sns_init_payload: SnsInitPayload,
}

impl Default for SnsInitPayloadBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// A builder implementation for the SnsInitPayload that provides concise creation and validation.
impl SnsInitPayloadBuilder {
    pub fn new() -> SnsInitPayloadBuilder {
        Self {
            sns_init_payload: SnsInitPayload {
                ..Default::default()
            },
        }
    }

    pub fn with_transaction_fee_e8s(&mut self, transaction_fee_e8s: u64) -> &mut Self {
        self.sns_init_payload.transaction_fee_e8s = Some(transaction_fee_e8s);
        self
    }

    pub fn with_token_name(&mut self, token_name: String) -> &mut Self {
        self.sns_init_payload.token_name = Some(token_name);
        self
    }

    pub fn with_token_symbol(&mut self, token_symbol: String) -> &mut Self {
        self.sns_init_payload.token_symbol = Some(token_symbol);
        self
    }

    pub fn with_proposal_reject_cost_e8s(&mut self, proposal_reject_cost_e8s: u64) -> &mut Self {
        self.sns_init_payload.proposal_reject_cost_e8s = Some(proposal_reject_cost_e8s);
        self
    }

    pub fn with_neuron_minimum_stake_e8s(&mut self, neuron_minimum_stake_e8s: u64) -> &mut Self {
        self.sns_init_payload.neuron_minimum_stake_e8s = Some(neuron_minimum_stake_e8s);
        self
    }

    pub fn with_initial_token_distribution(
        &mut self,
        initial_token_distribution: InitialTokenDistribution,
    ) -> &mut Self {
        self.sns_init_payload.initial_token_distribution = Some(initial_token_distribution);
        self
    }

    pub fn build(&mut self) -> Result<SnsInitPayload, String> {
        self.sns_init_payload.validate()?;
        Ok(self.sns_init_payload.clone())
    }
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
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

        if let Some(neuron_minimum_stake_e8s) = self.neuron_minimum_stake_e8s {
            parameters.neuron_minimum_stake_e8s = Some(neuron_minimum_stake_e8s);
        }

        if let Some(proposal_reject_cost_e8s) = self.proposal_reject_cost_e8s {
            parameters.reject_cost_e8s = Some(proposal_reject_cost_e8s);
        }

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
                controller_id: root_canister_id,
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
    /// payload and must pass. For a concise pattern, use `SnsInitPayloadBuilder` which
    /// will validate the payload at build time.
    pub fn validate(&self) -> Result<(), String> {
        let validation_fns = [
            self.validate_token_symbol(),
            self.validate_token_name(),
            self.validate_token_distribution(),
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
            Ok(())
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
}

#[cfg(test)]
mod test {
    use crate::distributions::TokenDistribution;
    use crate::{
        InitialTokenDistribution, SnsCanisterIds, SnsInitPayload, SnsInitPayloadBuilder,
        MAX_TOKEN_NAME_LENGTH, MAX_TOKEN_SYMBOL_LENGTH,
    };
    use ic_base_types::{CanisterId, PrincipalId};
    use ic_sns_governance::governance::ValidGovernanceProto;
    use ledger_canister::{AccountIdentifier, Tokens};
    use maplit::hashset;
    use std::str::FromStr;

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

    fn create_canister_ids() -> SnsCanisterIds {
        SnsCanisterIds {
            governance: PrincipalId::from_str(&CanisterId::from_u64(1).to_string()).unwrap(),
            ledger: PrincipalId::from_str(&CanisterId::from_u64(2).to_string()).unwrap(),
            root: PrincipalId::from_str(&CanisterId::from_u64(3).to_string()).unwrap(),
            swap: PrincipalId::from_str(&CanisterId::from_u64(4).to_string()).unwrap(),
        }
    }

    #[test]
    fn test_sns_init_payload_validate() {
        // Build a payload that passes validation, then test the parts that wouldn't
        let mut sns_init_payload = SnsInitPayloadBuilder::new()
            .with_token_symbol("SNS".to_string())
            .with_token_name("ServiceNervousSystem".to_string())
            .with_initial_token_distribution(InitialTokenDistribution::default())
            .build()
            .expect("Expected reasonable values to validate");

        sns_init_payload.token_symbol = Some("S".repeat(MAX_TOKEN_SYMBOL_LENGTH + 1));
        assert!(sns_init_payload.validate().is_err());
        sns_init_payload.token_symbol = Some("SNS".to_string());
        assert!(sns_init_payload.validate().is_ok());

        sns_init_payload.token_name = Some("S".repeat(MAX_TOKEN_NAME_LENGTH + 1));
        assert!(sns_init_payload.validate().is_err());
        sns_init_payload.token_name = Some("SNS Core Developer Team Governance Token".to_string());
        assert!(sns_init_payload.validate().is_ok());
    }

    #[test]
    fn test_sns_init_payload_builder_validates() {
        // Initialize the required parameters to pass validation
        let mut sns_init_payload_builder = SnsInitPayloadBuilder::new();
        sns_init_payload_builder.with_token_name("ServiceNervousSystem".to_string());
        sns_init_payload_builder.with_token_symbol("SNS".to_string());
        sns_init_payload_builder
            .with_initial_token_distribution(InitialTokenDistribution::default());

        // Assert that the builder works with valid state
        assert!(sns_init_payload_builder.build().is_ok());

        // Change one of the parameters to not pass validation
        sns_init_payload_builder.with_token_symbol("S".repeat(MAX_TOKEN_SYMBOL_LENGTH + 1));

        // Ensure that when building, the validation method is called and will produce an error
        let build_result = sns_init_payload_builder.build();
        assert!(build_result.is_err());

        // Change this parameter back and assert that the builder produced values as expected
        sns_init_payload_builder.with_token_symbol("SNS".to_string());
        let build_result = sns_init_payload_builder.build();
        let sns_init_payload = match build_result {
            Ok(result) => result,
            Err(e) => panic!("SnsInitPayloadBuilder failed validation: {}", e),
        };

        assert_eq!(sns_init_payload.token_symbol, Some("SNS".to_string()));
    }

    #[test]
    fn test_sns_canister_ids_are_used() {
        // Create a SnsInitPayload with some reasonable defaults
        let sns_init_payload = SnsInitPayload {
            transaction_fee_e8s: Some(10_000),
            token_name: Some("ServiceNervousSystem Coin".to_string()),
            token_symbol: Some("SNS".to_string()),
            proposal_reject_cost_e8s: Some(10_000),
            neuron_minimum_stake_e8s: Some(100_000_000),
            initial_token_distribution: Some(InitialTokenDistribution::default()),
        };

        // Create valid CanisterIds
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
            CanisterId::new(sns_canister_ids.root).unwrap()
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
        let sns_init_payload = SnsInitPayloadBuilder::new()
            .with_token_symbol("SNS".to_string())
            .with_token_name("ServiceNervousSystem".to_string())
            .with_transaction_fee_e8s(10_000)
            .with_proposal_reject_cost_e8s(10_000)
            .with_neuron_minimum_stake_e8s(100_000_000)
            .with_initial_token_distribution(InitialTokenDistribution::default())
            .build()
            .expect("Expected SnsInitPayloadBuilder to produce a valid payload");

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
        let sns_init_payload = SnsInitPayloadBuilder::new()
            .with_token_symbol("SNS".to_string())
            .with_token_name("ServiceNervousSystem".to_string())
            .with_initial_token_distribution(InitialTokenDistribution::default())
            .build()
            .expect("Expected SnsInitPayloadBuilder to produce a valid payload");

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
    fn test_ledger_init_args_is_valid() {
        // Build an sns_init_payload with defaults for non-ledger related configuration.
        let transaction_fee = 10_000;
        let token_symbol = "SNS".to_string();
        let token_name = "ServiceNervousSystem Coin".to_string();

        let sns_init_payload = SnsInitPayloadBuilder::new()
            .with_transaction_fee_e8s(transaction_fee)
            .with_token_symbol(token_symbol.clone())
            .with_token_name(token_name.clone())
            .with_initial_token_distribution(InitialTokenDistribution::default())
            .build()
            .expect("Expected SnsInitPayloadBuilder to produce a valid payload");

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
