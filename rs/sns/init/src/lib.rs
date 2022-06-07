use ic_base_types::{CanisterId, PrincipalId};
use ic_nervous_system_common::ledger::compute_neuron_staking_subaccount;
use ic_sns_governance::init::GovernanceCanisterInitPayloadBuilder;
use ic_sns_governance::pb::v1::neuron::DissolveState;
use ic_sns_governance::pb::v1::{
    Governance, NervousSystemParameters, Neuron, NeuronPermission, NeuronPermissionList,
    NeuronPermissionType,
};
use ic_sns_root::pb::v1::SnsRootCanister;
use ledger_canister::{
    AccountIdentifier, ArchiveOptions, LedgerCanisterInitPayload, Subaccount, Tokens,
};
use maplit::{btreemap, hashset};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;
use std::time::SystemTime;

/// The maximum number of characters allowed for token symbol.
const MAX_TOKEN_SYMBOL_LENGTH: usize = 10;

/// The maximum number of characters allowed for token name.
const MAX_TOKEN_NAME_LENGTH: usize = 255;

/// The canister IDs of all SNS canisters
#[derive(Debug, Clone)]
pub struct SnsCanisterIds {
    pub governance: PrincipalId,
    pub ledger: PrincipalId,
    pub root: PrincipalId,
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

    pub fn with_transaction_fee_e8s(&mut self, transaction_fee_e8s: Option<u64>) -> &mut Self {
        self.sns_init_payload.transaction_fee_e8s = transaction_fee_e8s;
        self
    }

    pub fn with_token_name(&mut self, token_name: String) -> &mut Self {
        self.sns_init_payload.token_name = token_name;
        self
    }

    pub fn with_token_symbol(&mut self, token_symbol: String) -> &mut Self {
        self.sns_init_payload.token_symbol = token_symbol;
        self
    }

    pub fn with_initial_ledger_accounts(
        &mut self,
        initial_ledger_accounts: HashMap<AccountIdentifier, Tokens>,
    ) -> &mut Self {
        self.sns_init_payload.initial_ledger_accounts = initial_ledger_accounts;
        self
    }

    pub fn with_proposal_reject_cost_e8s(
        &mut self,
        proposal_reject_cost_e8s: Option<u64>,
    ) -> &mut Self {
        self.sns_init_payload.proposal_reject_cost_e8s = proposal_reject_cost_e8s;
        self
    }

    pub fn with_neuron_minimum_stake_e8s(
        &mut self,
        neuron_minimum_stake_e8s: Option<u64>,
    ) -> &mut Self {
        self.sns_init_payload.neuron_minimum_stake_e8s = neuron_minimum_stake_e8s;
        self
    }

    pub fn with_initial_neurons(&mut self, initial_neurons: Vec<NeuronBlueprint>) -> &mut Self {
        self.sns_init_payload.initial_neurons = initial_neurons;
        self
    }

    pub fn build(&mut self) -> Result<SnsInitPayload, String> {
        self.sns_init_payload.validate()?;
        Ok(self.sns_init_payload.clone())
    }
}

#[derive(Clone, Default)]
pub struct SnsInitPayload {
    /// The transaction fee that must be paid for ledger transactions (except
    /// minting and burning governance tokens), denominated in e8s (1 token = 100,000,000 e8s).
    pub transaction_fee_e8s: Option<u64>,

    /// The name of the governance token controlled by this SNS, for example "Bitcoin".
    pub token_name: String,

    /// The symbol of the governance token controlled by this SNS, for example "BTC".
    pub token_symbol: String,

    /// The initial Ledger accounts that the SNS will be initialized with.
    pub initial_ledger_accounts: HashMap<AccountIdentifier, Tokens>,

    /// The number of e8s (10E-8 of a token) that a rejected proposal costs the proposer.
    pub proposal_reject_cost_e8s: Option<u64>,

    /// The minimum number of e8s (10E-8 of a token) that can be staked in a neuron.
    ///
    /// To ensure that staking and disbursing of the neuron work, the chosen value
    /// must be larger than the transaction_fee_e8s.
    pub neuron_minimum_stake_e8s: Option<u64>,

    /// The initial neurons that the SNS will be initialized with specified in the
    /// NeuronBlueprint form.
    pub initial_neurons: Vec<NeuronBlueprint>,
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
            ledger: self.ledger_init_args(sns_canister_ids),
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
    fn ledger_init_args(&self, sns_canister_ids: &SnsCanisterIds) -> LedgerCanisterInitPayload {
        let root_canister_id = CanisterId::new(sns_canister_ids.root).unwrap();

        let mut payload = LedgerCanisterInitPayload::builder()
            .minting_account(sns_canister_ids.governance.into())
            .token_symbol_and_name(&self.token_symbol, &self.token_name)
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
        payload.initial_values = self.get_all_ledger_accounts(sns_canister_ids);

        let governance_canister_id = CanisterId::new(sns_canister_ids.governance).unwrap();
        let ledger_canister_id = CanisterId::new(sns_canister_ids.ledger).unwrap();
        payload.send_whitelist = hashset! { governance_canister_id, ledger_canister_id };

        payload
    }

    /// Construct the params used to initialize a SNS Root canister.
    fn root_init_args(&self, sns_canister_ids: &SnsCanisterIds) -> SnsRootCanister {
        SnsRootCanister {
            governance_canister_id: Some(sns_canister_ids.governance),
            ledger_canister_id: Some(sns_canister_ids.ledger),
        }
    }

    /// Now that the Governance canister id is available, combine `initial_ledger_accounts`
    /// with ledger accounts created from `neuron_blueprints`.
    fn get_all_ledger_accounts(
        &self,
        sns_canister_ids: &SnsCanisterIds,
    ) -> HashMap<AccountIdentifier, Tokens> {
        // Calculate the ledger accounts of the initial neurons
        let neuron_accounts = self
            .initial_neurons
            .clone()
            .into_iter()
            .map(|neuron_blueprint| {
                neuron_blueprint.as_ledger_account(sns_canister_ids.governance)
            });

        // Combine the initial ledger accounts with the ledger accounts of the neurons
        self.initial_ledger_accounts
            .clone()
            .into_iter()
            .chain(neuron_accounts)
            .collect()
    }

    /// Return the initial neurons that the user specified. These neurons will exist in
    /// Governance at genesis, with the correct balance in their corresponding ledger
    /// accounts in the Ledger. A map from neuron ID to Neuron is returned.
    fn get_initial_neurons(
        &self,
        parameters: &NervousSystemParameters,
    ) -> BTreeMap<String, Neuron> {
        self.initial_neurons
            .iter()
            .map(|neuron_blueprint| {
                let neuron = neuron_blueprint.as_neuron(parameters);
                (neuron.id.as_ref().unwrap().to_string(), neuron)
            })
            .collect()
    }

    /// Validates the SnsInitPayload. This is called before building each SNS canister's
    /// payload and must pass. For a concise pattern, use `SnsInitPayloadBuilder` which
    /// will validate the payload at build time.
    pub fn validate(&self) -> Result<(), String> {
        if self.token_symbol.len() > MAX_TOKEN_SYMBOL_LENGTH {
            return Err(format!(
                "Error: token-symbol must be fewer than {} characters, given character count: {}",
                MAX_TOKEN_SYMBOL_LENGTH,
                self.token_symbol.len()
            ));
        }

        if self.token_name.len() > MAX_TOKEN_NAME_LENGTH {
            return Err(format!(
                "Error: token-name must be fewer than {} characters, given character count: {}",
                MAX_TOKEN_NAME_LENGTH,
                self.token_name.len()
            ));
        }

        Ok(())
    }
}

/// Specifies the necessary info from which to create a Neuron
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NeuronBlueprint {
    controller: String,
    nonce: Option<u64>,
    stake_e8s: u64,
    age_seconds: Option<u64>,
    dissolve_delay_seconds: u64,
}

impl NeuronBlueprint {
    /// Build a `Neuron` from the blueprint
    pub fn as_neuron(&self, parameters: &NervousSystemParameters) -> Neuron {
        if let Some(neuron_minimum_stake_e8s) = parameters.neuron_minimum_stake_e8s {
            if self.stake_e8s < neuron_minimum_stake_e8s {
                panic!(
                    "An initial neuron has stake {}, which is less than the configured \
                    neuron_minimum_stake_e8s of {}",
                    self.stake_e8s, neuron_minimum_stake_e8s
                );
            }
        }

        if let Some(max_dissolve_delay_seconds) = parameters.max_dissolve_delay_seconds {
            if self.dissolve_delay_seconds > max_dissolve_delay_seconds {
                panic!(
                    "An initial neuron has dissolve_delay_seconds {}, which is more than the \
                    configured max_dissolve_delay_seconds of {}",
                    self.dissolve_delay_seconds, max_dissolve_delay_seconds
                );
            }
        }

        let permission = NeuronPermission {
            principal: Some(self.controller()),
            permission_type: parameters
                .neuron_claimer_permissions
                .as_ref()
                .unwrap()
                .permissions
                .clone(),
        };

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Neuron {
            id: Some(self.subaccount().into()),
            permissions: vec![permission],
            cached_neuron_stake_e8s: self.stake_e8s,
            neuron_fees_e8s: 0,
            created_timestamp_seconds: now,
            aging_since_timestamp_seconds: now.saturating_sub(self.age_seconds.unwrap_or_default()),
            followees: btreemap! {},
            maturity_e8s_equivalent: 0,
            dissolve_state: Some(DissolveState::DissolveDelaySeconds(
                self.dissolve_delay_seconds,
            )),
        }
    }

    /// Get the ledger account that corresponds with this neuron
    pub fn as_ledger_account(&self, governance_id: PrincipalId) -> (AccountIdentifier, Tokens) {
        let account = AccountIdentifier::new(governance_id, Some(self.subaccount()));
        let tokens = Tokens::from_e8s(self.stake_e8s);

        (account, tokens)
    }

    fn subaccount(&self) -> Subaccount {
        compute_neuron_staking_subaccount(self.controller(), self.nonce.unwrap_or_default())
    }

    fn controller(&self) -> PrincipalId {
        PrincipalId::from_str(&self.controller).unwrap_or_else(|_| {
            panic!(
                "Could not parse neuron controller {} as a PrincipalId",
                &self.controller
            )
        })
    }
}

#[cfg(test)]
mod test {
    use crate::{
        SnsCanisterIds, SnsInitPayload, SnsInitPayloadBuilder, MAX_TOKEN_NAME_LENGTH,
        MAX_TOKEN_SYMBOL_LENGTH,
    };
    use ic_base_types::{CanisterId, PrincipalId};
    use ic_sns_governance::governance::ValidGovernanceProto;
    use ledger_canister::{AccountIdentifier, Tokens};
    use maplit::hashset;
    use std::str::FromStr;

    fn create_canister_ids() -> SnsCanisterIds {
        SnsCanisterIds {
            governance: PrincipalId::from_str(&CanisterId::from_u64(1).to_string()).unwrap(),
            ledger: PrincipalId::from_str(&CanisterId::from_u64(2).to_string()).unwrap(),
            root: PrincipalId::from_str(&CanisterId::from_u64(3).to_string()).unwrap(),
        }
    }

    #[test]
    fn test_sns_init_payload_validate() {
        let mut sns_init_payload = SnsInitPayloadBuilder::new().build().unwrap();

        sns_init_payload.token_symbol = "S".repeat(MAX_TOKEN_SYMBOL_LENGTH + 1);
        assert!(sns_init_payload.validate().is_err());
        sns_init_payload.token_symbol = "SNS".to_string();
        assert!(sns_init_payload.validate().is_ok());

        sns_init_payload.token_name = "S".repeat(MAX_TOKEN_NAME_LENGTH + 1);
        assert!(sns_init_payload.validate().is_err());
        sns_init_payload.token_name = "SNS Core Developer Team Governance Token".to_string();
        assert!(sns_init_payload.validate().is_ok());
    }

    #[test]
    fn test_sns_init_payload_builder_validates() {
        let mut sns_init_payload_builder = SnsInitPayloadBuilder::new();

        sns_init_payload_builder.with_token_symbol("S".repeat(MAX_TOKEN_SYMBOL_LENGTH + 1));

        let build_result = sns_init_payload_builder.build();
        assert!(build_result.is_err());

        sns_init_payload_builder.with_token_symbol("SNS".to_string());
        let build_result = sns_init_payload_builder.build();
        let sns_init_payload = match build_result {
            Ok(result) => result,
            Err(e) => panic!("SnsInitPayloadBuilder failed validation: {}", e),
        };

        assert_eq!(sns_init_payload.token_symbol, "SNS".to_string());
    }

    #[test]
    fn test_sns_canister_ids_are_used() {
        // Create a SnsInitPayload with some reasonable defaults
        let sns_init_payload = SnsInitPayload {
            transaction_fee_e8s: Some(10_000),
            token_name: "ServiceNervousSystem Coin".to_string(),
            token_symbol: "SNS".to_string(),
            initial_ledger_accounts: Default::default(),
            proposal_reject_cost_e8s: Some(10_000),
            neuron_minimum_stake_e8s: Some(100_000_000),
            initial_neurons: vec![],
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
            .with_transaction_fee_e8s(Some(10_000))
            .with_proposal_reject_cost_e8s(Some(10_000))
            .with_neuron_minimum_stake_e8s(Some(100_000_000))
            .with_initial_neurons(vec![])
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
            .with_transaction_fee_e8s(Some(transaction_fee))
            .with_token_symbol(token_symbol.clone())
            .with_token_name(token_name.clone())
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
