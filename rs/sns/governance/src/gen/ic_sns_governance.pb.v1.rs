/// A principal with a particular set of permissions over a neuron.
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NeuronPermission {
    /// The principal that has the permissions.
    #[prost(message, optional, tag = "1")]
    pub principal: ::core::option::Option<::ic_base_types::PrincipalId>,
    /// The list of permissions that this principal has.
    #[prost(enumeration = "NeuronPermissionType", repeated, tag = "2")]
    pub permission_type: ::prost::alloc::vec::Vec<i32>,
}
/// The id of a specific neuron, which equals the neuron's subaccount on the ledger canister
/// (the account that holds the neuron's staked tokens).
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable, Eq, std::hash::Hash)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NeuronId {
    #[prost(bytes = "vec", tag = "1")]
    #[serde(with = "serde_bytes")]
    pub id: ::prost::alloc::vec::Vec<u8>,
}
/// A sequence of NeuronIds, which is used to get prost to generate a type isomorphic to Option<Vec<NeuronId>>.
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NeuronIds {
    #[prost(message, repeated, tag = "1")]
    pub neuron_ids: ::prost::alloc::vec::Vec<NeuronId>,
}
/// The id of a specific proposal.
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable, Eq, Copy)]
#[self_describing]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProposalId {
    #[prost(uint64, tag = "1")]
    pub id: u64,
}
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DisburseMaturityInProgress {
    /// This field is the quantity of maturity in e8s that has been decremented from a Neuron to
    /// be modulated and disbursed as SNS tokens.
    #[prost(uint64, tag = "1")]
    pub amount_e8s: u64,
    #[prost(uint64, tag = "2")]
    pub timestamp_of_disbursement_seconds: u64,
    #[prost(message, optional, tag = "3")]
    pub account_to_disburse_to: ::core::option::Option<Account>,
    #[prost(uint64, optional, tag = "4")]
    pub finalize_disbursement_timestamp_seconds: ::core::option::Option<u64>,
}
/// A neuron in the governance system.
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[compare_default]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Neuron {
    /// The unique id of this neuron.
    #[prost(message, optional, tag = "1")]
    pub id: ::core::option::Option<NeuronId>,
    /// The principal or list of principals with a particular set of permissions over a neuron.
    #[prost(message, repeated, tag = "2")]
    pub permissions: ::prost::alloc::vec::Vec<NeuronPermission>,
    /// The cached record of the neuron's staked governance tokens, measured in
    /// fractions of 10E-8 of a governance token.
    ///
    /// There is a minimum cached state, NervousSystemParameters::neuron_minimum_stake_e8s,
    /// that can be set by each SNS. Neurons that are created by claiming a neuron, spawning a neuron,
    /// or splitting a neuron must have at least that stake (in the case of splitting both the parent neuron
    /// and the new neuron must have at least that stake).
    #[prost(uint64, tag = "3")]
    pub cached_neuron_stake_e8s: u64,
    /// TODO NNS1-1052 - Update if this ticket is done and fees are burned / minted instead of tracked in this attribute.
    ///
    /// The amount of governance tokens that this neuron has forfeited
    /// due to making proposals that were subsequently rejected.
    /// Must be smaller than 'cached_neuron_stake_e8s'. When a neuron is
    /// disbursed, these governance tokens will be burned.
    #[prost(uint64, tag = "4")]
    pub neuron_fees_e8s: u64,
    /// The timestamp, in seconds from the Unix epoch, when the neuron was created.
    #[prost(uint64, tag = "5")]
    pub created_timestamp_seconds: u64,
    /// The timestamp, in seconds from the Unix epoch, when this neuron has entered
    /// the non-dissolving state. This is either the creation time or the last time at
    /// which the neuron has stopped dissolving.
    ///
    /// This value is meaningless when the neuron is dissolving, since a
    /// dissolving neurons always has age zero. The canonical value of
    /// this field for a dissolving neuron is `u64::MAX`.
    #[prost(uint64, tag = "6")]
    pub aging_since_timestamp_seconds: u64,
    /// The neuron's followees, specified as a map of proposal functions IDs to followees neuron IDs.
    /// The map's keys are represented by integers as Protobuf does not support enum keys in maps.
    #[prost(btree_map = "uint64, message", tag = "11")]
    pub followees: ::prost::alloc::collections::BTreeMap<u64, neuron::Followees>,
    /// The accumulated unstaked maturity of the neuron, measured in "e8s equivalent", i.e., in equivalent of
    /// 10E-8 of a governance token.
    ///
    /// The unit is "equivalent" to insist that, while this quantity is on the
    /// same scale as the governance token, maturity is not directly convertible to
    /// governance tokens: conversion requires a minting event and the conversion rate is variable.
    #[prost(uint64, tag = "12")]
    pub maturity_e8s_equivalent: u64,
    /// A percentage multiplier to be applied when calculating the voting power of a neuron.
    /// The multiplier's unit is a integer percentage in the range of 0 to 100. The
    /// voting_power_percentage_multiplier can only be less than 100 for a developer neuron
    /// that is created at SNS initialization.
    #[prost(uint64, tag = "13")]
    pub voting_power_percentage_multiplier: u64,
    /// The ID of the NNS neuron whose Community Fund participation resulted in the
    /// creation of this SNS neuron.
    #[prost(uint64, optional, tag = "14")]
    pub source_nns_neuron_id: ::core::option::Option<u64>,
    /// The accumulated staked maturity of the neuron, in "e8s equivalent" (see
    /// "maturity_e8s_equivalent"). Staked maturity becomes regular maturity once
    /// the neuron is dissolved.
    ///
    /// Contrary to `maturity_e8s_equivalent` this maturity is staked and thus
    /// locked until the neuron is dissolved and contributes to voting power
    /// and rewards. Once the neuron is dissolved, this maturity will be "moved"
    /// to 'maturity_e8s_equivalent' and will be able to be spawned (with maturity
    /// modulation).
    #[prost(uint64, optional, tag = "15")]
    pub staked_maturity_e8s_equivalent: ::core::option::Option<u64>,
    /// If set and true the maturity rewarded to this neuron for voting will be
    /// automatically staked and will contribute to the neuron's voting power.
    #[prost(bool, optional, tag = "16")]
    pub auto_stake_maturity: ::core::option::Option<bool>,
    /// The duration that this neuron is vesting.
    ///
    /// A neuron that is vesting is non-dissolving and cannot start dissolving until the vesting duration has elapsed.
    /// Vesting can be used to lock a neuron more than the max allowed dissolve delay. This allows devs and members of
    /// a particular SNS instance to prove their long-term commitment to the community. For example, the max dissolve delay
    /// for a particular SNS instance might be 1 year, but the devs of the project may set their vesting duration to 3
    /// years and dissolve delay to 1 year in order to prove that they are making a minimum 4 year commitment to the
    /// project.
    #[prost(uint64, optional, tag = "17")]
    pub vesting_period_seconds: ::core::option::Option<u64>,
    /// Disburse maturity operations that are currently underway.
    /// The entries are sorted by `timestamp_of_disbursement_seconds`-values,
    /// with the oldest entries first, i.e. it holds for all i that:
    /// entry\[i\].timestamp_of_disbursement_seconds <= entry\[i+1\].timestamp_of_disbursement_seconds
    #[prost(message, repeated, tag = "18")]
    pub disburse_maturity_in_progress: ::prost::alloc::vec::Vec<DisburseMaturityInProgress>,
    /// The neuron's dissolve state, specifying whether the neuron is dissolving,
    /// non-dissolving, or dissolved.
    ///
    /// At any time, at most only one of `when_dissolved_timestamp_seconds` and
    /// `dissolve_delay_seconds` are specified.
    ///
    /// `NotDissolving`. This is represented by `dissolve_delay_seconds` being
    /// set to a non zero value.
    ///
    /// `Dissolving`. This is represented by `when_dissolved_timestamp_seconds` being
    /// set, and this value is in the future.
    ///
    /// `Dissolved`. All other states represent the dissolved
    /// state. That is, (a) `when_dissolved_timestamp_seconds` is set and in the past,
    /// (b) `when_dissolved_timestamp_seconds` is set to zero, (c) neither value is set.
    #[prost(oneof = "neuron::DissolveState", tags = "7, 8")]
    pub dissolve_state: ::core::option::Option<neuron::DissolveState>,
}
/// Nested message and enum types in `Neuron`.
pub mod neuron {
    /// A list of a neuron's followees for a specific function.
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Followees {
        #[prost(message, repeated, tag = "1")]
        pub followees: ::prost::alloc::vec::Vec<super::NeuronId>,
    }
    /// The neuron's dissolve state, specifying whether the neuron is dissolving,
    /// non-dissolving, or dissolved.
    ///
    /// At any time, at most only one of `when_dissolved_timestamp_seconds` and
    /// `dissolve_delay_seconds` are specified.
    ///
    /// `NotDissolving`. This is represented by `dissolve_delay_seconds` being
    /// set to a non zero value.
    ///
    /// `Dissolving`. This is represented by `when_dissolved_timestamp_seconds` being
    /// set, and this value is in the future.
    ///
    /// `Dissolved`. All other states represent the dissolved
    /// state. That is, (a) `when_dissolved_timestamp_seconds` is set and in the past,
    /// (b) `when_dissolved_timestamp_seconds` is set to zero, (c) neither value is set.
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum DissolveState {
        /// When the dissolve timer is running, this stores the timestamp,
        /// in seconds from the Unix epoch, at which the neuron is dissolved.
        ///
        /// At any time while the neuron is dissolving, the neuron owner
        /// may pause dissolving, in which case `dissolve_delay_seconds`
        /// will get assigned to: `when_dissolved_timestamp_seconds -
        /// <timestamp when the action is taken>`.
        #[prost(uint64, tag = "7")]
        WhenDissolvedTimestampSeconds(u64),
        /// When the dissolve timer is stopped, this stores how much time,
        /// in seconds, the dissolve timer will be started with if the neuron is set back to 'Dissolving'.
        ///
        /// At any time while in this state, the neuron owner may (re)start
        /// dissolving, in which case `when_dissolved_timestamp_seconds`
        /// will get assigned to: `<timestamp when the action is taken> +
        /// dissolve_delay_seconds`.
        #[prost(uint64, tag = "8")]
        DissolveDelaySeconds(u64),
    }
}
/// A NervousSystem function that can be executed by governance as a result of an adopted proposal.
/// Each NervousSystem function has an id and a target canister and target method, that define
/// the method that will be called if the proposal is adopted.
/// Optionally, a validator_canister and a validator_method can be specified that define a method
/// that is called to validate that the proposal's payload is well-formed, prior to putting
/// it up for a vote.
/// TODO NNS1-1133 - Remove if there is no rendering canister/method?
/// Also optionally a rendering_canister and a rendering_method can be specified that define a method
/// that is called to return a pretty-printed version of the proposal's contents so that voters can inspect it.
///
/// Note that the target, validator and rendering methods can all coexist in
/// the same canister or be on different canisters.
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NervousSystemFunction {
    /// The unique id of this function.
    ///
    /// Ids 0-999 are reserved for native governance proposals and can't
    /// be used by generic NervousSystemFunction's.
    #[prost(uint64, tag = "1")]
    pub id: u64,
    /// A short (<256 chars) description of the NervousSystemFunction.
    #[prost(string, tag = "2")]
    pub name: ::prost::alloc::string::String,
    /// An optional description of what the NervousSystemFunction does.
    #[prost(string, optional, tag = "3")]
    pub description: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(oneof = "nervous_system_function::FunctionType", tags = "4, 5")]
    pub function_type: ::core::option::Option<nervous_system_function::FunctionType>,
}
/// Nested message and enum types in `NervousSystemFunction`.
pub mod nervous_system_function {
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct GenericNervousSystemFunction {
        /// The id of the target canister that will be called to execute the proposal.
        #[prost(message, optional, tag = "2")]
        pub target_canister_id: ::core::option::Option<::ic_base_types::PrincipalId>,
        /// The name of the method that will be called to execute the proposal.
        /// The signature of the method must be equivalent to the following:
        /// <method_name>(proposal_data: ProposalData) -> Result<(), String>.
        #[prost(string, optional, tag = "3")]
        pub target_method_name: ::core::option::Option<::prost::alloc::string::String>,
        /// The id of the canister that will be called to validate the proposal before
        /// it is put up for a vote.
        #[prost(message, optional, tag = "4")]
        pub validator_canister_id: ::core::option::Option<::ic_base_types::PrincipalId>,
        /// The name of the method that will be called to validate the proposal
        /// before it is put up for a vote.
        /// The signature of the method must be equivalent to the following:
        /// <method_name>(proposal_data: ProposalData) -> Result<String, String>
        #[prost(string, optional, tag = "5")]
        pub validator_method_name: ::core::option::Option<::prost::alloc::string::String>,
    }
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum FunctionType {
        /// Whether this is a native function (i.e. a Action::Motion or
        /// Action::UpgradeSnsControlledCanister) or one of user-defined
        /// NervousSystemFunctions.
        #[prost(message, tag = "4")]
        NativeNervousSystemFunction(super::Empty),
        /// Whether this is a GenericNervousSystemFunction which can call
        /// any canister.
        #[prost(message, tag = "5")]
        GenericNervousSystemFunction(GenericNervousSystemFunction),
    }
}
/// A proposal function defining a generic proposal, i.e., a proposal
/// that is not build into the standard SNS and calls a canister outside
/// the SNS for execution.
/// The canister and method to call are derived from the `function_id`.
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExecuteGenericNervousSystemFunction {
    /// This enum value determines what canister to call and what
    /// function to call on that canister.
    ///
    /// 'function_id` must be in the range `\[1000--u64:MAX\]` as this
    /// can't be used to execute native functions.
    #[prost(uint64, tag = "1")]
    pub function_id: u64,
    /// The payload of the nervous system function's payload.
    #[prost(bytes = "vec", tag = "2")]
    #[serde(with = "serde_bytes")]
    pub payload: ::prost::alloc::vec::Vec<u8>,
}
/// A proposal function that should guide the future strategy of the SNS's
/// ecosystem but does not have immediate effect in the sense that a method is executed.
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[self_describing]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Motion {
    /// The text of the motion, which can at most be 100kib.
    #[prost(string, tag = "1")]
    pub motion_text: ::prost::alloc::string::String,
}
/// A proposal function that upgrades a canister that is controlled by the
/// SNS governance canister.
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UpgradeSnsControlledCanister {
    /// The id of the canister that is upgraded.
    #[prost(message, optional, tag = "1")]
    pub canister_id: ::core::option::Option<::ic_base_types::PrincipalId>,
    /// The new wasm module that the canister is upgraded to.
    #[prost(bytes = "vec", tag = "2")]
    #[serde(with = "serde_bytes")]
    pub new_canister_wasm: ::prost::alloc::vec::Vec<u8>,
    /// Arguments passed to the post-upgrade method of the new wasm module.
    #[prost(bytes = "vec", optional, tag = "3")]
    #[serde(deserialize_with = "ic_utils::deserialize::deserialize_option_blob")]
    pub canister_upgrade_arg: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    /// Canister install_code mode.
    #[prost(
        enumeration = "::ic_protobuf::types::v1::CanisterInstallMode",
        optional,
        tag = "4"
    )]
    pub mode: ::core::option::Option<i32>,
}
/// A proposal to transfer SNS treasury funds to (optionally a Subaccount of) the
/// target principal.
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TransferSnsTreasuryFunds {
    #[prost(enumeration = "transfer_sns_treasury_funds::TransferFrom", tag = "1")]
    pub from_treasury: i32,
    /// The amount to transfer, in e8s.
    #[prost(uint64, tag = "2")]
    pub amount_e8s: u64,
    /// An optional memo to use for the transfer.
    #[prost(uint64, optional, tag = "3")]
    pub memo: ::core::option::Option<u64>,
    /// The principal to transfer the funds to.
    #[prost(message, optional, tag = "4")]
    pub to_principal: ::core::option::Option<::ic_base_types::PrincipalId>,
    /// An (optional) Subaccount of the principal to transfer the funds to.
    #[prost(message, optional, tag = "5")]
    pub to_subaccount: ::core::option::Option<Subaccount>,
}
/// Nested message and enum types in `TransferSnsTreasuryFunds`.
pub mod transfer_sns_treasury_funds {
    /// Whether to make the transfer from the NNS ledger (in ICP) or
    /// to make the transfer from the SNS ledger (in SNS tokens).
    #[derive(
        candid::CandidType,
        candid::Deserialize,
        comparable::Comparable,
        Clone,
        Copy,
        Debug,
        PartialEq,
        Eq,
        Hash,
        PartialOrd,
        Ord,
        ::prost::Enumeration,
    )]
    #[repr(i32)]
    pub enum TransferFrom {
        Unspecified = 0,
        IcpTreasury = 1,
        SnsTokenTreasury = 2,
    }
    impl TransferFrom {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                TransferFrom::Unspecified => "TRANSFER_FROM_UNSPECIFIED",
                TransferFrom::IcpTreasury => "TRANSFER_FROM_ICP_TREASURY",
                TransferFrom::SnsTokenTreasury => "TRANSFER_FROM_SNS_TOKEN_TREASURY",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
            match value {
                "TRANSFER_FROM_UNSPECIFIED" => Some(Self::Unspecified),
                "TRANSFER_FROM_ICP_TREASURY" => Some(Self::IcpTreasury),
                "TRANSFER_FROM_SNS_TOKEN_TREASURY" => Some(Self::SnsTokenTreasury),
                _ => None,
            }
        }
    }
}
/// A proposal function that changes the ledger's parameters.
/// Fields with None values will remain unchanged.
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ManageLedgerParameters {
    #[prost(uint64, optional, tag = "1")]
    pub transfer_fee: ::core::option::Option<u64>,
    #[prost(string, optional, tag = "2")]
    pub token_name: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag = "3")]
    pub token_symbol: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag = "4")]
    pub token_logo: ::core::option::Option<::prost::alloc::string::String>,
}
/// A proposal to mint SNS tokens to (optionally a Subaccount of) the
/// target principal.
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MintSnsTokens {
    /// The amount to transfer, in e8s.
    #[prost(uint64, optional, tag = "1")]
    pub amount_e8s: ::core::option::Option<u64>,
    /// An optional memo to use for the transfer.
    #[prost(uint64, optional, tag = "2")]
    pub memo: ::core::option::Option<u64>,
    /// The principal to transfer the funds to.
    #[prost(message, optional, tag = "3")]
    pub to_principal: ::core::option::Option<::ic_base_types::PrincipalId>,
    /// An (optional) Subaccount of the principal to transfer the funds to.
    #[prost(message, optional, tag = "4")]
    pub to_subaccount: ::core::option::Option<Subaccount>,
}
/// A proposal function to change the values of SNS metadata.
/// Fields with None values will remain unchanged.
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ManageSnsMetadata {
    /// Base64 representation of the logo. Max length is 341334 characters, roughly 256 Kb.
    #[prost(string, optional, tag = "1")]
    pub logo: ::core::option::Option<::prost::alloc::string::String>,
    /// Url string, must be between 10 and 256 characters.
    #[prost(string, optional, tag = "2")]
    pub url: ::core::option::Option<::prost::alloc::string::String>,
    /// Name string, must be between 4 and 255 characters.
    #[prost(string, optional, tag = "3")]
    pub name: ::core::option::Option<::prost::alloc::string::String>,
    /// Description string, must be between 10 and 10000 characters.
    #[prost(string, optional, tag = "4")]
    pub description: ::core::option::Option<::prost::alloc::string::String>,
}
/// A proposal function to upgrade the SNS to the next version.  The versions are such that only
/// one kind of canister will update at the same time.
/// This returns an error if the canister cannot be upgraded or no upgrades are available.
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UpgradeSnsToNextVersion {}
/// A proposal to register a list of dapps in the root canister.
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RegisterDappCanisters {
    /// The canister IDs to be registered (i.e. under the management of the SNS).
    /// The canisters must be already controlled by the SNS root canister before
    /// making this proposal. Any controllers besides the root canister will be
    /// removed when the proposal is executed.
    /// At least one canister ID is required.
    #[prost(message, repeated, tag = "1")]
    pub canister_ids: ::prost::alloc::vec::Vec<::ic_base_types::PrincipalId>,
}
/// A proposal to remove a list of dapps from the SNS and assign them to new controllers
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeregisterDappCanisters {
    /// The canister IDs to be deregistered (i.e. removed from the management of the SNS).
    #[prost(message, repeated, tag = "1")]
    pub canister_ids: ::prost::alloc::vec::Vec<::ic_base_types::PrincipalId>,
    /// The new controllers for the deregistered canisters.
    #[prost(message, repeated, tag = "2")]
    pub new_controllers: ::prost::alloc::vec::Vec<::ic_base_types::PrincipalId>,
}
/// A proposal to manage the settings of one or more dapp canisters.
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ManageDappCanisterSettings {
    /// The canister IDs of the dapp canisters to be modified.
    #[prost(message, repeated, tag = "1")]
    pub canister_ids: ::prost::alloc::vec::Vec<::ic_base_types::PrincipalId>,
    /// Below are fields under CanisterSettings defined at
    /// <https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-candid.>
    #[prost(uint64, optional, tag = "2")]
    pub compute_allocation: ::core::option::Option<u64>,
    #[prost(uint64, optional, tag = "3")]
    pub memory_allocation: ::core::option::Option<u64>,
    #[prost(uint64, optional, tag = "4")]
    pub freezing_threshold: ::core::option::Option<u64>,
    #[prost(uint64, optional, tag = "5")]
    pub reserved_cycles_limit: ::core::option::Option<u64>,
    #[prost(enumeration = "LogVisibility", optional, tag = "6")]
    pub log_visibility: ::core::option::Option<i32>,
    #[prost(uint64, optional, tag = "7")]
    pub wasm_memory_limit: ::core::option::Option<u64>,
}
/// A proposal is the immutable input of a proposal submission.
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[compare_default]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Proposal {
    /// The proposal's title as a text, which can be at most 256 bytes.
    #[prost(string, tag = "1")]
    pub title: ::prost::alloc::string::String,
    /// The description of the proposal which is a short text, composed
    /// using a maximum of 30000 bytes of characters.
    #[prost(string, tag = "2")]
    pub summary: ::prost::alloc::string::String,
    /// The web address of additional content required to evaluate the
    /// proposal, specified using HTTPS. The URL string must not be longer than
    /// 2000 bytes.
    #[prost(string, tag = "3")]
    pub url: ::prost::alloc::string::String,
    /// The action that the proposal proposes to take on adoption.
    ///
    /// Each action is associated with an function id that can be used for following.
    /// Native (typed) actions each have an id in the range \[0-999\], while
    /// NervousSystemFunctions with a `function_type` of GenericNervousSystemFunction
    /// are each associated with an id in the range \[1000-u64:MAX\].
    ///
    /// See `impl From<&Action> for u64` in src/types.rs for the implementation
    /// of this mapping.
    #[prost(
        oneof = "proposal::Action",
        tags = "4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18"
    )]
    pub action: ::core::option::Option<proposal::Action>,
}
/// Nested message and enum types in `Proposal`.
pub mod proposal {
    /// The action that the proposal proposes to take on adoption.
    ///
    /// Each action is associated with an function id that can be used for following.
    /// Native (typed) actions each have an id in the range \[0-999\], while
    /// NervousSystemFunctions with a `function_type` of GenericNervousSystemFunction
    /// are each associated with an id in the range \[1000-u64:MAX\].
    ///
    /// See `impl From<&Action> for u64` in src/types.rs for the implementation
    /// of this mapping.
    #[derive(
        candid::CandidType, candid::Deserialize, comparable::Comparable, strum_macros::EnumIter,
    )]
    #[allow(clippy::large_enum_variant)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Action {
        /// The `Unspecified` action is used as a fallback when
        /// following. That is, if no followees are specified for a given
        /// action, the followees for this action are used instead.
        ///
        /// Id = 0.
        #[prost(message, tag = "4")]
        Unspecified(super::Empty),
        /// A motion that should guide the future strategy of the SNS's ecosystem
        /// but does not have immediate effect in the sense that a method is executed.
        ///
        /// Id = 1.
        #[prost(message, tag = "5")]
        Motion(super::Motion),
        /// Change the nervous system's parameters.
        /// Note that a change of a parameter will only affect future actions where
        /// this parameter is relevant.
        /// For example, NervousSystemParameters::neuron_minimum_stake_e8s specifies the
        /// minimum amount of stake a neuron must have, which is checked at the time when
        /// the neuron is created. If this NervousSystemParameter is decreased, all neurons
        /// created after this change will have at least the new minimum stake. However,
        /// neurons created before this change may have less stake.
        ///
        /// Id = 2.
        #[prost(message, tag = "6")]
        ManageNervousSystemParameters(super::NervousSystemParameters),
        /// Upgrade a canister that is controlled by the SNS governance canister.
        ///
        /// Id = 3.
        #[prost(message, tag = "7")]
        UpgradeSnsControlledCanister(super::UpgradeSnsControlledCanister),
        /// Add a new NervousSystemFunction, of generic type,  to be executable by proposal.
        ///
        /// Id = 4.
        #[prost(message, tag = "8")]
        AddGenericNervousSystemFunction(super::NervousSystemFunction),
        /// Remove a NervousSystemFunction, of generic type, from being executable by proposal.
        ///
        /// Id = 5.
        #[prost(uint64, tag = "9")]
        RemoveGenericNervousSystemFunction(u64),
        /// Execute a method outside the SNS canisters.
        ///
        /// Id = \[1000-u64::MAX\].
        #[prost(message, tag = "10")]
        ExecuteGenericNervousSystemFunction(super::ExecuteGenericNervousSystemFunction),
        /// Execute an upgrade to next version on the blessed SNS upgrade path.
        ///
        /// Id = 7.
        #[prost(message, tag = "11")]
        UpgradeSnsToNextVersion(super::UpgradeSnsToNextVersion),
        /// Modify values of SnsMetadata.
        ///
        /// Id = 8
        #[prost(message, tag = "12")]
        ManageSnsMetadata(super::ManageSnsMetadata),
        /// Transfer SNS treasury funds (ICP or SNS token) to an account.
        /// Id = 9.
        #[prost(message, tag = "13")]
        TransferSnsTreasuryFunds(super::TransferSnsTreasuryFunds),
        /// Register one or more dapp canister(s) in the SNS root canister.
        ///
        /// Id = 10.
        #[prost(message, tag = "14")]
        RegisterDappCanisters(super::RegisterDappCanisters),
        /// Deregister one or more dapp canister(s) in the SNS root canister.
        ///
        /// Id = 11.
        #[prost(message, tag = "15")]
        DeregisterDappCanisters(super::DeregisterDappCanisters),
        /// Mint SNS tokens to an account.
        ///
        /// Id = 12.
        #[prost(message, tag = "16")]
        MintSnsTokens(super::MintSnsTokens),
        /// Change some parameters on the ledger.
        ///
        /// Id = 13
        #[prost(message, tag = "17")]
        ManageLedgerParameters(super::ManageLedgerParameters),
        /// Change canister settings for one or more dapp canister(s).
        ///
        /// Id = 14.
        #[prost(message, tag = "18")]
        ManageDappCanisterSettings(super::ManageDappCanisterSettings),
    }
}
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[compare_default]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GovernanceError {
    #[prost(enumeration = "governance_error::ErrorType", tag = "1")]
    pub error_type: i32,
    #[prost(string, tag = "2")]
    pub error_message: ::prost::alloc::string::String,
}
/// Nested message and enum types in `GovernanceError`.
pub mod governance_error {
    #[derive(
        candid::CandidType,
        candid::Deserialize,
        comparable::Comparable,
        Clone,
        Copy,
        Debug,
        PartialEq,
        Eq,
        Hash,
        PartialOrd,
        Ord,
        ::prost::Enumeration,
    )]
    #[repr(i32)]
    pub enum ErrorType {
        Unspecified = 0,
        /// This operation is not available, e.g., not implemented.
        Unavailable = 1,
        /// The caller is not authorized to perform this operation.
        NotAuthorized = 2,
        /// Some entity required for the operation (for example, a neuron) was not found.
        NotFound = 3,
        /// The command was missing or invalid. This is a permanent error.
        InvalidCommand = 4,
        /// The neuron is dissolving or dissolved and the operation requires it to
        /// be non-dissolving.
        RequiresNotDissolving = 5,
        /// The neuron is non-dissolving or dissolved and the operation requires
        /// it to be dissolving.
        RequiresDissolving = 6,
        /// The neuron is non-dissolving or dissolving and the operation
        /// requires it to be dissolved.
        RequiresDissolved = 7,
        /// TODO NNS1-1013 Need to update the error cases and use this error
        /// type with the implemented method
        ///
        /// An attempt to add or remove a NeuronPermissionType failed.
        AccessControlList = 8,
        /// Some canister side resource is exhausted, so this operation cannot be
        /// performed.
        ResourceExhausted = 9,
        /// Some precondition for executing this method is not met.
        PreconditionFailed = 10,
        /// Executing this method failed for some reason external to the
        /// governance canister.
        External = 11,
        /// A neuron has an ongoing neuron operation and thus can't be
        /// changed.
        NeuronLocked = 12,
        /// There aren't sufficient funds to perform the operation.
        InsufficientFunds = 13,
        /// The principal provided is invalid.
        InvalidPrincipal = 14,
        /// The proposal is invalid.
        InvalidProposal = 15,
        /// The NeuronId is invalid.
        InvalidNeuronId = 16,
        /// This indicates that we have a bug. It should be impossible for users to provoke this.
        ///
        /// For example, supposed you put some auxiliary data into a ProposalData during proposal
        /// submission. That data is supposed to be used during execution of the proposal. But during
        /// execution, the auxiliary data is invalid (e.g. absent).
        InconsistentInternalData = 17,
        /// Users cannot provoke this.
        ///
        /// E.g. 1 / E8 somehow provokes a divide by zero error, even though E8 is a positive number.
        ///
        /// This is a generalization of INCONSISTENT_INTERNAL_DATA.
        UnreachableCode = 18,
    }
    impl ErrorType {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                ErrorType::Unspecified => "ERROR_TYPE_UNSPECIFIED",
                ErrorType::Unavailable => "ERROR_TYPE_UNAVAILABLE",
                ErrorType::NotAuthorized => "ERROR_TYPE_NOT_AUTHORIZED",
                ErrorType::NotFound => "ERROR_TYPE_NOT_FOUND",
                ErrorType::InvalidCommand => "ERROR_TYPE_INVALID_COMMAND",
                ErrorType::RequiresNotDissolving => "ERROR_TYPE_REQUIRES_NOT_DISSOLVING",
                ErrorType::RequiresDissolving => "ERROR_TYPE_REQUIRES_DISSOLVING",
                ErrorType::RequiresDissolved => "ERROR_TYPE_REQUIRES_DISSOLVED",
                ErrorType::AccessControlList => "ERROR_TYPE_ACCESS_CONTROL_LIST",
                ErrorType::ResourceExhausted => "ERROR_TYPE_RESOURCE_EXHAUSTED",
                ErrorType::PreconditionFailed => "ERROR_TYPE_PRECONDITION_FAILED",
                ErrorType::External => "ERROR_TYPE_EXTERNAL",
                ErrorType::NeuronLocked => "ERROR_TYPE_NEURON_LOCKED",
                ErrorType::InsufficientFunds => "ERROR_TYPE_INSUFFICIENT_FUNDS",
                ErrorType::InvalidPrincipal => "ERROR_TYPE_INVALID_PRINCIPAL",
                ErrorType::InvalidProposal => "ERROR_TYPE_INVALID_PROPOSAL",
                ErrorType::InvalidNeuronId => "ERROR_TYPE_INVALID_NEURON_ID",
                ErrorType::InconsistentInternalData => "ERROR_TYPE_INCONSISTENT_INTERNAL_DATA",
                ErrorType::UnreachableCode => "ERROR_TYPE_UNREACHABLE_CODE",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
            match value {
                "ERROR_TYPE_UNSPECIFIED" => Some(Self::Unspecified),
                "ERROR_TYPE_UNAVAILABLE" => Some(Self::Unavailable),
                "ERROR_TYPE_NOT_AUTHORIZED" => Some(Self::NotAuthorized),
                "ERROR_TYPE_NOT_FOUND" => Some(Self::NotFound),
                "ERROR_TYPE_INVALID_COMMAND" => Some(Self::InvalidCommand),
                "ERROR_TYPE_REQUIRES_NOT_DISSOLVING" => Some(Self::RequiresNotDissolving),
                "ERROR_TYPE_REQUIRES_DISSOLVING" => Some(Self::RequiresDissolving),
                "ERROR_TYPE_REQUIRES_DISSOLVED" => Some(Self::RequiresDissolved),
                "ERROR_TYPE_ACCESS_CONTROL_LIST" => Some(Self::AccessControlList),
                "ERROR_TYPE_RESOURCE_EXHAUSTED" => Some(Self::ResourceExhausted),
                "ERROR_TYPE_PRECONDITION_FAILED" => Some(Self::PreconditionFailed),
                "ERROR_TYPE_EXTERNAL" => Some(Self::External),
                "ERROR_TYPE_NEURON_LOCKED" => Some(Self::NeuronLocked),
                "ERROR_TYPE_INSUFFICIENT_FUNDS" => Some(Self::InsufficientFunds),
                "ERROR_TYPE_INVALID_PRINCIPAL" => Some(Self::InvalidPrincipal),
                "ERROR_TYPE_INVALID_PROPOSAL" => Some(Self::InvalidProposal),
                "ERROR_TYPE_INVALID_NEURON_ID" => Some(Self::InvalidNeuronId),
                "ERROR_TYPE_INCONSISTENT_INTERNAL_DATA" => Some(Self::InconsistentInternalData),
                "ERROR_TYPE_UNREACHABLE_CODE" => Some(Self::UnreachableCode),
                _ => None,
            }
        }
    }
}
/// A ballot recording a neuron's vote and voting power.
/// A ballot's vote can be set by a direct vote from the neuron or can be set
/// automatically caused by a neuron following other neurons.
///
/// Once a ballot's vote is set it cannot be changed.
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[self_describing]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Ballot {
    /// The ballot's vote.
    #[prost(enumeration = "Vote", tag = "1")]
    pub vote: i32,
    /// The voting power associated with the ballot. The voting power of a ballot
    /// associated with a neuron and a proposal is set at the proposal's creation
    /// time to the neuron's voting power at that time.
    #[prost(uint64, tag = "2")]
    pub voting_power: u64,
    /// The time when the ballot's vote was populated with a decision (YES or NO, not
    /// UNDECIDED) in seconds since the UNIX epoch. This is only meaningful once a
    /// decision has been made and set to zero when the proposal associated with the
    /// ballot is created.
    #[prost(uint64, tag = "3")]
    pub cast_timestamp_seconds: u64,
}
/// A tally of votes associated with a proposal.
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[self_describing]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Tally {
    /// The time when this tally was made, in seconds from the Unix epoch.
    #[prost(uint64, tag = "1")]
    pub timestamp_seconds: u64,
    /// The number of yes votes, in voting power unit.
    #[prost(uint64, tag = "2")]
    pub yes: u64,
    /// The number of no votes, in voting power unit.
    #[prost(uint64, tag = "3")]
    pub no: u64,
    /// The total voting power unit of eligible neurons that can vote
    /// on the proposal that this tally is associated with (i.e., the sum
    /// of the voting power of yes, no, and undecided votes).
    /// This should always be greater than or equal to yes + no.
    #[prost(uint64, tag = "4")]
    pub total: u64,
}
/// The wait-for-quiet state associated with a proposal, storing the
/// data relevant to the "wait-for-quiet" implementation.
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct WaitForQuietState {
    /// The current deadline of the proposal associated with this
    /// WaitForQuietState, in seconds from the Unix epoch.
    #[prost(uint64, tag = "1")]
    pub current_deadline_timestamp_seconds: u64,
}
/// The ProposalData that contains everything related to a proposal:
/// the proposal itself (immutable), as well as mutable data such as ballots.
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProposalData {
    /// The proposal's action.
    /// Types 0-999 are reserved for current (and future) core governance
    /// proposals that are of type NativeNervousSystemFunction.
    ///
    /// If the proposal is not a core governance proposal, the action will
    /// be the same as the id of the NervousSystemFunction.
    ///
    /// Current set of reserved ids:
    /// Id 0 - Unspecified catch all id for following purposes.
    /// Id 1 - Motion proposals.
    /// Id 2 - ManageNervousSystemParameters proposals.
    /// Id 3 - UpgradeSnsControlledCanister proposals.
    /// Id 4 - AddGenericNervousSystemFunction proposals.
    /// Id 5 - RemoveGenericNervousSystemFunction proposals.
    /// Id 6 - ExecuteGenericNervousSystemFunction proposals.
    /// Id 7 - UpgradeSnsToNextVersion proposals.
    /// Id 8 - ManageSnsMetadata proposals.
    /// Id 9 - TransferSnsTreasuryFunds proposals.
    /// Id 13 - ManageLedgerParameters proposals.
    #[prost(uint64, tag = "1")]
    pub action: u64,
    /// This is stored here temporarily. It is also stored on the map
    /// that contains proposals.
    ///
    /// The unique id for this proposal.
    #[prost(message, optional, tag = "2")]
    pub id: ::core::option::Option<ProposalId>,
    /// The NeuronId of the Neuron that made this proposal.
    #[prost(message, optional, tag = "3")]
    pub proposer: ::core::option::Option<NeuronId>,
    /// The amount of governance tokens in e8s to be
    /// charged to the proposer if the proposal is rejected.
    #[prost(uint64, tag = "4")]
    pub reject_cost_e8s: u64,
    /// The proposal originally submitted.
    #[prost(message, optional, tag = "5")]
    pub proposal: ::core::option::Option<Proposal>,
    /// The timestamp, in seconds from the Unix epoch,
    /// when this proposal was made.
    #[prost(uint64, tag = "6")]
    pub proposal_creation_timestamp_seconds: u64,
    /// The ballots associated with a proposal, given as a map which
    /// maps the neurons' NeuronId to the neurons' ballots. This is
    /// only present as long as the proposal is not settled with
    /// respect to rewards.
    #[prost(btree_map = "string, message", tag = "7")]
    pub ballots: ::prost::alloc::collections::BTreeMap<::prost::alloc::string::String, Ballot>,
    /// The latest tally. The tally is computed only for open proposals when
    /// they are processed. Once a proposal is decided, i.e.,
    /// ProposalDecisionStatus isn't open anymore, the tally never changes
    /// again. (But the ballots may still change as neurons may vote after
    /// the proposal has been decided.)
    #[prost(message, optional, tag = "8")]
    pub latest_tally: ::core::option::Option<Tally>,
    /// The timestamp, in seconds since the Unix epoch, when this proposal
    /// was adopted or rejected. If not specified, the proposal is still 'open'.
    #[prost(uint64, tag = "9")]
    pub decided_timestamp_seconds: u64,
    /// The timestamp, in seconds since the Unix epoch, when the (previously
    /// adopted) proposal has been executed. If not specified (i.e., still has
    /// the default value zero), the proposal has not (yet) been executed
    /// successfully.
    #[prost(uint64, tag = "10")]
    pub executed_timestamp_seconds: u64,
    /// The timestamp, in seconds since the Unix epoch, when the (previously
    /// adopted) proposal has failed to be executed. If not specified (i.e.,
    /// still has the default value zero), the proposal has not (yet) failed
    /// to execute.
    #[prost(uint64, tag = "11")]
    pub failed_timestamp_seconds: u64,
    /// The reason why the (previously adopted) proposal has failed to execute.
    /// If not specified, the proposal has not (yet) failed to execute.
    #[prost(message, optional, tag = "12")]
    pub failure_reason: ::core::option::Option<GovernanceError>,
    /// OBSOLETE: Superseded by reward_event_end_timestamp_seconds. However, old
    /// proposals use this (old) field, not the new one, since they predate the new
    /// field. Therefore, to correctly detect whether a proposal has been rewarded,
    /// both fields must be consulted. That is what the has_been_rewarded method
    /// does, so use that.
    ///
    /// The reward event round at which rewards for votes on this proposal
    /// were distributed.
    ///
    /// Rounds start at one: a value of zero indicates that
    /// no reward event taking this proposal into consideration happened yet.
    ///
    /// This field matches field round in RewardEvent.
    #[prost(uint64, tag = "13")]
    pub reward_event_round: u64,
    /// The proposal's wait-for-quiet state. This needs to be saved in stable memory.
    #[prost(message, optional, tag = "14")]
    pub wait_for_quiet_state: ::core::option::Option<WaitForQuietState>,
    /// The proposal's payload rendered as text, for display in text/UI frontends.
    /// This is set if the proposal is considered valid at time of submission.
    ///
    /// Proposals with action of type NativeNervousSystemFunction (action 0-999)
    /// render the payload in Markdown.
    ///
    /// Proposals with action of type GenericNervousSystemFunction provide no
    /// guarantee on the style of rendering as this is performed by the
    /// GenericNervousSystemFunction validator_canister.
    #[prost(string, optional, tag = "15")]
    pub payload_text_rendering: ::core::option::Option<::prost::alloc::string::String>,
    /// Deprecated. From now on, this field will be set to true when new proposals
    /// are created. However, there ARE old proposals where this is set to false.
    ///
    /// When set to false, the proposal skips past the ReadyToSettle reward status
    /// directly to Settled
    ///
    /// TODO(NNS1-2731): Delete this.
    #[prost(bool, tag = "16")]
    pub is_eligible_for_rewards: bool,
    /// The initial voting period of the proposal, identical in meaning to the one in
    /// NervousSystemParameters, and duplicated here so the parameters can be changed
    /// without affecting existing proposals.
    #[prost(uint64, tag = "17")]
    pub initial_voting_period_seconds: u64,
    /// The wait_for_quiet_deadline_increase_seconds of the proposal, identical in
    /// meaning to the one in NervousSystemParameters, and duplicated here so the
    /// parameters can be changed without affecting existing proposals.
    #[prost(uint64, tag = "18")]
    pub wait_for_quiet_deadline_increase_seconds: u64,
    /// If populated, then the proposal is considered "settled" in terms of voting
    /// rewards. Prior to distribution of rewards, but after votes are no longer
    /// accepted, it is considered "ready to settle".
    #[prost(uint64, optional, tag = "19")]
    pub reward_event_end_timestamp_seconds: ::core::option::Option<u64>,
    /// Minimum "yes" votes needed for proposal adoption, as a fraction of the
    /// total voting power. Example: 300 basis points represents a requirement that
    /// 3% of the total voting power votes to adopt the proposal.
    #[prost(message, optional, tag = "20")]
    pub minimum_yes_proportion_of_total:
        ::core::option::Option<::ic_nervous_system_proto::pb::v1::Percentage>,
    /// Minimum "yes" votes needed for proposal adoption, as a fraction of the
    /// exercised voting power. Example: 50_000 basis points represents a
    /// requirement that 50% of the exercised voting power votes to adopt the
    /// proposal.
    #[prost(message, optional, tag = "21")]
    pub minimum_yes_proportion_of_exercised:
        ::core::option::Option<::ic_nervous_system_proto::pb::v1::Percentage>,
    /// In general, this holds data retrieved at proposal submission/creation time and used later
    /// during execution. This varies based on the action of the proposal.
    #[prost(oneof = "proposal_data::ActionAuxiliary", tags = "22, 23")]
    pub action_auxiliary: ::core::option::Option<proposal_data::ActionAuxiliary>,
}
/// Nested message and enum types in `ProposalData`.
pub mod proposal_data {
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct TransferSnsTreasuryFundsActionAuxiliary {
        #[prost(message, optional, tag = "1")]
        pub valuation: ::core::option::Option<super::Valuation>,
    }
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct MintSnsTokensActionAuxiliary {
        #[prost(message, optional, tag = "1")]
        pub valuation: ::core::option::Option<super::Valuation>,
    }
    /// In general, this holds data retrieved at proposal submission/creation time and used later
    /// during execution. This varies based on the action of the proposal.
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum ActionAuxiliary {
        #[prost(message, tag = "22")]
        TransferSnsTreasuryFunds(TransferSnsTreasuryFundsActionAuxiliary),
        #[prost(message, tag = "23")]
        MintSnsTokens(MintSnsTokensActionAuxiliary),
    }
}
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Valuation {
    #[prost(enumeration = "valuation::Token", optional, tag = "1")]
    pub token: ::core::option::Option<i32>,
    #[prost(message, optional, tag = "2")]
    pub account: ::core::option::Option<Account>,
    #[prost(uint64, optional, tag = "3")]
    pub timestamp_seconds: ::core::option::Option<u64>,
    #[prost(message, optional, tag = "4")]
    pub valuation_factors: ::core::option::Option<valuation::ValuationFactors>,
}
/// Nested message and enum types in `Valuation`.
pub mod valuation {
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct ValuationFactors {
        #[prost(message, optional, tag = "1")]
        pub tokens: ::core::option::Option<::ic_nervous_system_proto::pb::v1::Tokens>,
        #[prost(message, optional, tag = "2")]
        pub icps_per_token: ::core::option::Option<::ic_nervous_system_proto::pb::v1::Decimal>,
        #[prost(message, optional, tag = "3")]
        pub xdrs_per_icp: ::core::option::Option<::ic_nervous_system_proto::pb::v1::Decimal>,
    }
    #[derive(
        candid::CandidType,
        candid::Deserialize,
        comparable::Comparable,
        Clone,
        Copy,
        Debug,
        PartialEq,
        Eq,
        Hash,
        PartialOrd,
        Ord,
        ::prost::Enumeration,
    )]
    #[repr(i32)]
    pub enum Token {
        Unspecified = 0,
        Icp = 1,
        SnsToken = 2,
    }
    impl Token {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                Token::Unspecified => "TOKEN_UNSPECIFIED",
                Token::Icp => "TOKEN_ICP",
                Token::SnsToken => "TOKEN_SNS_TOKEN",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
            match value {
                "TOKEN_UNSPECIFIED" => Some(Self::Unspecified),
                "TOKEN_ICP" => Some(Self::Icp),
                "TOKEN_SNS_TOKEN" => Some(Self::SnsToken),
                _ => None,
            }
        }
    }
}
/// The nervous system's parameters, which are parameters that can be changed, via proposals,
/// by each nervous system community.
/// For some of the values there are specified minimum values (floor) or maximum values
/// (ceiling). The motivation for this is a) to prevent that the nervous system accidentally
/// chooses parameters that result in an un-upgradable (and thus stuck) governance canister
/// and b) to prevent the canister from growing too big (which could harm the other canisters
/// on the subnet).
///
/// Required invariant: the canister code assumes that all system parameters are always set.
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NervousSystemParameters {
    /// The number of e8s (10E-8 of a token) that a rejected
    /// proposal costs the proposer.
    #[prost(uint64, optional, tag = "1")]
    pub reject_cost_e8s: ::core::option::Option<u64>,
    /// The minimum number of e8s (10E-8 of a token) that can be staked in a neuron.
    ///
    /// To ensure that staking and disbursing of the neuron work, the chosen value
    /// must be larger than the transaction_fee_e8s.
    #[prost(uint64, optional, tag = "2")]
    pub neuron_minimum_stake_e8s: ::core::option::Option<u64>,
    /// The transaction fee that must be paid for ledger transactions (except
    /// minting and burning governance tokens).
    #[prost(uint64, optional, tag = "3")]
    pub transaction_fee_e8s: ::core::option::Option<u64>,
    /// The maximum number of proposals to keep, per action. When the
    /// total number of proposals for a given action is greater than this
    /// number, the oldest proposals that have reached final decision state
    /// (rejected, executed, or failed) and final rewards status state
    /// (settled) may be deleted.
    ///
    /// The number must be larger than zero and at most be as large as the
    /// defined ceiling MAX_PROPOSALS_TO_KEEP_PER_ACTION_CEILING.
    #[prost(uint32, optional, tag = "4")]
    pub max_proposals_to_keep_per_action: ::core::option::Option<u32>,
    /// The initial voting period of a newly created proposal.
    /// A proposal's voting period may then be further increased during
    /// a proposal's lifecycle due to the wait-for-quiet algorithm.
    ///
    /// The voting period must be between (inclusive) the defined floor
    /// INITIAL_VOTING_PERIOD_SECONDS_FLOOR and ceiling
    /// INITIAL_VOTING_PERIOD_SECONDS_CEILING.
    #[prost(uint64, optional, tag = "5")]
    pub initial_voting_period_seconds: ::core::option::Option<u64>,
    /// The wait for quiet algorithm extends the voting period of a proposal when
    /// there is a flip in the majority vote during the proposal's voting period.
    /// This parameter determines the maximum time period that the voting period
    /// may be extended after a flip. If there is a flip at the very end of the
    /// original proposal deadline, the remaining time will be set to this parameter.
    /// If there is a flip before or after the original deadline, the deadline will
    /// extended by somewhat less than this parameter.
    /// The maximum total voting period extension is 2 * wait_for_quiet_deadline_increase_seconds.
    /// For more information, see the wiki page on the wait-for-quiet algorithm:
    /// <https://wiki.internetcomputer.org/wiki/Network_Nervous_System#Proposal_decision_and_wait-for-quiet>
    #[prost(uint64, optional, tag = "18")]
    pub wait_for_quiet_deadline_increase_seconds: ::core::option::Option<u64>,
    /// TODO NNS1-2169: This field currently has no effect.
    /// TODO NNS1-2169: Design and implement this feature.
    ///
    /// The set of default followees that every newly created neuron will follow
    /// per function. This is specified as a mapping of proposal functions to followees.
    ///
    /// If unset, neurons will have no followees by default.
    /// The set of followees for each function can be at most of size
    /// max_followees_per_function.
    #[prost(message, optional, tag = "6")]
    pub default_followees: ::core::option::Option<DefaultFollowees>,
    /// The maximum number of allowed neurons. When this maximum is reached, no new
    /// neurons will be created until some are removed.
    ///
    /// This number must be larger than zero and at most as large as the defined
    /// ceiling MAX_NUMBER_OF_NEURONS_CEILING.
    #[prost(uint64, optional, tag = "7")]
    pub max_number_of_neurons: ::core::option::Option<u64>,
    /// The minimum dissolve delay a neuron must have to be eligible to vote.
    ///
    /// The chosen value must be smaller than max_dissolve_delay_seconds.
    #[prost(uint64, optional, tag = "8")]
    pub neuron_minimum_dissolve_delay_to_vote_seconds: ::core::option::Option<u64>,
    /// The maximum number of followees each neuron can establish for each nervous system function.
    ///
    /// This number can be at most as large as the defined ceiling
    /// MAX_FOLLOWEES_PER_FUNCTION_CEILING.
    #[prost(uint64, optional, tag = "9")]
    pub max_followees_per_function: ::core::option::Option<u64>,
    /// The maximum dissolve delay that a neuron can have. That is, the maximum
    /// that a neuron's dissolve delay can be increased to. The maximum is also enforced
    /// when saturating the dissolve delay bonus in the voting power computation.
    #[prost(uint64, optional, tag = "10")]
    pub max_dissolve_delay_seconds: ::core::option::Option<u64>,
    /// The age of a neuron that saturates the age bonus for the voting power computation.
    #[prost(uint64, optional, tag = "12")]
    pub max_neuron_age_for_age_bonus: ::core::option::Option<u64>,
    /// The max number of proposals for which ballots are still stored, i.e.,
    /// unsettled proposals. If this number of proposals is reached, new proposals
    /// can only be added in exceptional cases (for few proposals it is defined
    /// that they are allowed even if resources are low to guarantee that the relevant
    /// canisters can be upgraded).
    ///
    /// This number must be larger than zero and at most as large as the defined
    /// ceiling MAX_NUMBER_OF_PROPOSALS_WITH_BALLOTS_CEILING.
    #[prost(uint64, optional, tag = "14")]
    pub max_number_of_proposals_with_ballots: ::core::option::Option<u64>,
    /// The default set of neuron permissions granted to the principal claiming a neuron.
    #[prost(message, optional, tag = "15")]
    pub neuron_claimer_permissions: ::core::option::Option<NeuronPermissionList>,
    /// The superset of neuron permissions a principal with permission
    /// `NeuronPermissionType::ManagePrincipals` for a given neuron can grant to another
    /// principal for this same neuron.
    /// If this set changes via a ManageNervousSystemParameters proposal, previous
    /// neurons' permissions will be unchanged and only newly granted permissions will be affected.
    #[prost(message, optional, tag = "16")]
    pub neuron_grantable_permissions: ::core::option::Option<NeuronPermissionList>,
    /// The maximum number of principals that can have permissions for a neuron
    #[prost(uint64, optional, tag = "17")]
    pub max_number_of_principals_per_neuron: ::core::option::Option<u64>,
    /// When this field is not populated, voting rewards are "disabled". Once this
    /// is set, it probably should not be changed, because the results would
    /// probably be pretty confusing.
    #[prost(message, optional, tag = "19")]
    pub voting_rewards_parameters: ::core::option::Option<VotingRewardsParameters>,
    /// E.g. if a large dissolve delay can double the voting power of a neuron,
    /// then this field would have a value of 100, indicating a maximum of
    /// 100% additional voting power.
    ///
    /// For no bonus, this should be set to 0.
    ///
    /// To achieve functionality equivalent to NNS, this should be set to 100.
    #[prost(uint64, optional, tag = "20")]
    pub max_dissolve_delay_bonus_percentage: ::core::option::Option<u64>,
    /// Analogous to the previous field (see the previous comment),
    /// but this one relates to neuron age instead of dissolve delay.
    ///
    /// To achieve functionality equivalent to NNS, this should be set to 25.
    #[prost(uint64, optional, tag = "21")]
    pub max_age_bonus_percentage: ::core::option::Option<u64>,
    /// By default, maturity modulation is enabled; however, an SNS can use this
    /// field to disable it. When disabled, this canister will still poll the
    /// Cycles Minting Canister (CMC), and store the value received therefrom.
    /// However, the fetched value does not get used when this is set to true.
    ///
    /// The reason we call this "disabled" instead of (positive) "enabled" is so
    /// that the PB default (bool fields are false) and our application default
    /// (enabled) agree.
    #[prost(bool, optional, tag = "22")]
    pub maturity_modulation_disabled: ::core::option::Option<bool>,
}
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct VotingRewardsParameters {
    /// The amount of time between reward events.
    ///
    /// Must be > 0.
    ///
    /// During such periods, proposals enter the ReadyToSettle state. Once the
    /// round is over, voting for those proposals entitle voters to voting
    /// rewards. Such rewards are calculated by the governance canister's
    /// heartbeat.
    ///
    /// This is a nominal amount. That is, the actual time between reward
    /// calculations and distribution cannot be guaranteed to be perfectly
    /// periodic, but actual inter-reward periods are generally expected to be
    /// within a few seconds of this.
    ///
    /// This supersedes super.reward_distribution_period_seconds.
    #[prost(uint64, optional, tag = "1")]
    pub round_duration_seconds: ::core::option::Option<u64>,
    /// The amount of time that the growth rate changes (presumably, decreases)
    /// from the initial growth rate to the final growth rate. (See the two
    /// *_reward_rate_basis_points fields bellow.) The transition is quadratic, and
    /// levels out at the end of the growth rate transition period.
    #[prost(uint64, optional, tag = "3")]
    pub reward_rate_transition_duration_seconds: ::core::option::Option<u64>,
    /// The amount of rewards is proportional to token_supply * current_rate. In
    /// turn, current_rate is somewhere between `initial_reward_rate_basis_points`
    /// and `final_reward_rate_basis_points`. In the first reward period, it is the
    /// initial growth rate, and after the growth rate transition period has elapsed,
    /// the growth rate becomes the final growth rate, and remains at that value for
    /// the rest of time. The transition between the initial and final growth rates is
    /// quadratic, and levels out at the end of the growth rate transition period.
    ///
    /// (A basis point is one in ten thousand.)
    #[prost(uint64, optional, tag = "4")]
    pub initial_reward_rate_basis_points: ::core::option::Option<u64>,
    #[prost(uint64, optional, tag = "5")]
    pub final_reward_rate_basis_points: ::core::option::Option<u64>,
}
/// The set of default followees that every newly created neuron will follow per function.
/// This is specified as a mapping of proposal functions to followees for that function.
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DefaultFollowees {
    #[prost(btree_map = "uint64, message", tag = "1")]
    pub followees: ::prost::alloc::collections::BTreeMap<u64, neuron::Followees>,
}
/// A wrapper for a list of neuron permissions.
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NeuronPermissionList {
    #[prost(enumeration = "NeuronPermissionType", repeated, tag = "1")]
    pub permissions: ::prost::alloc::vec::Vec<i32>,
}
/// A record of when voting rewards were determined, and neuron maturity
/// increased for participation in voting on proposals.
///
/// This has diverged from NNS: this uses the same tag for different fields.
/// Therefore, we cannot simply move one of the definitions to a shared library.
///
/// To make it a little easier to eventually deduplicate NNS and SNS governance
/// code, tags should be chosen so that it is new to BOTH this and the NNS
/// RewardEvent. (This also applies to other message definitions.)
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RewardEvent {
    /// DEPRECATED: Use end_timestamp_seconds instead.
    ///
    /// Rewards are (calculated and) distributed periodically in "rounds". Round 1
    /// begins at start_time and ends at start_time + 1 * round_duration, where
    /// start_time and round_duration are specified in VotingRewardsParameters.
    /// Similarly, round 2 begins at the end of round number 1, and ends at
    /// start_time + 2 * round_duration. Etc. There is no round 0.
    ///
    /// In the context of rewards, SNS start_time is analogous to NNS genesis time.
    ///
    /// On rare occasions, the reward event may cover several reward periods, when
    /// it was not possible to process a reward event for a while. This means that
    /// successive values in this field might not be consecutive, but they usually
    /// are.
    #[prost(uint64, tag = "1")]
    pub round: u64,
    /// Not to be confused with round_end_timestampe_seconds. This is just used to
    /// record when the calculation (of voting rewards) was performed, not the time
    /// range/events (i.e. proposals) that was operated on.
    #[prost(uint64, tag = "2")]
    pub actual_timestamp_seconds: u64,
    /// The list of proposals that were taken into account during
    /// this reward event.
    #[prost(message, repeated, tag = "3")]
    pub settled_proposals: ::prost::alloc::vec::Vec<ProposalId>,
    /// The total amount of reward that was distributed during this reward event.
    ///
    /// The unit is "e8s equivalent" to insist that, while this quantity is on
    /// the same scale as governance tokens, maturity is not directly convertible
    /// to governance tokens: conversion requires a minting event.
    #[prost(uint64, tag = "4")]
    pub distributed_e8s_equivalent: u64,
    /// All proposals that were "ready to settle" up to this time were
    /// considered.
    ///
    /// If a proposal is "ready to settle", it simply means that votes are no
    /// longer accepted (votes can still be accepted for reward purposes after the
    /// proposal is decided), but rewards have not yet been given yet (on account
    /// of the proposal).
    ///
    /// The reason this should be used instead of `round` is that the duration of a
    /// round can be changed via proposal. Such changes cause round numbers to be
    /// not comparable without also knowing the associated round duration.
    ///
    /// Being able to change round duration does not exist in NNS (yet), and there
    /// is (currently) no intention to add that feature, but it could be done by
    /// making similar changes.
    #[prost(uint64, optional, tag = "5")]
    pub end_timestamp_seconds: ::core::option::Option<u64>,
    /// In some cases, the rewards that would have been distributed in one round are
    /// "rolled over" into the next reward event. This field keeps track of how many
    /// rounds have passed since the last time rewards were distributed (rather
    /// than being rolled over).
    ///
    /// For the genesis pseudo-reward event, this field will be zero.
    ///
    /// In normal operation, this field will almost always be 1. There are two
    /// reasons that rewards might not be distributed in a given round.
    ///
    /// 1. "Missed" rounds: there was a long period when we did calculate rewards
    ///     (longer than 1 round). (I.e. distribute_rewards was not called by
    ///     heartbeat for whatever reason, most likely some kind of bug.)
    ///
    /// 2. Rollover: We tried to distribute rewards, but there were no proposals
    ///     settled to distribute rewards for.
    ///
    /// In both of these cases, the rewards purse rolls over into the next round.
    #[prost(uint64, optional, tag = "6")]
    pub rounds_since_last_distribution: ::core::option::Option<u64>,
    /// The total amount of rewards that was available during the reward event.
    ///
    /// The e8s_equivalent_to_be_rolled_over method returns this when
    /// there are no proposals (per the settled_proposals field).
    ///
    /// This is mostly copied from NNS.
    ///
    /// Warning: There is a field with the same name in NNS, but different tags are
    /// used. Also, this uses the `optional` keyword (whereas, the NNS analog does
    /// not).
    #[prost(uint64, optional, tag = "8")]
    pub total_available_e8s_equivalent: ::core::option::Option<u64>,
}
/// The representation of the whole governance system, containing all
/// information about the governance system that must be kept
/// across upgrades of the governance system, i.e. kept in stable memory.
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[compare_default]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Governance {
    /// The current set of neurons registered in governance as a map from
    /// neuron IDs to neurons.
    #[prost(btree_map = "string, message", tag = "1")]
    pub neurons: ::prost::alloc::collections::BTreeMap<::prost::alloc::string::String, Neuron>,
    /// The current set of proposals registered in governance as a map
    /// from proposal IDs to the proposals' data.
    #[prost(btree_map = "uint64, message", tag = "2")]
    pub proposals: ::prost::alloc::collections::BTreeMap<u64, ProposalData>,
    /// The nervous system parameters that define and can be set by
    /// each nervous system.
    #[prost(message, optional, tag = "8")]
    pub parameters: ::core::option::Option<NervousSystemParameters>,
    /// TODO IC-1168: update when rewards are introduced
    ///   The latest reward event.
    #[prost(message, optional, tag = "9")]
    pub latest_reward_event: ::core::option::Option<RewardEvent>,
    /// The in-flight neuron ledger commands as a map from neuron IDs
    /// to commands.
    ///
    /// Whenever we change a neuron in a way that must not interleave
    /// with another neuron change, we store the neuron and the issued
    /// command in this map and remove it when the command is complete.
    ///
    /// An entry being present in this map acts like a "lock" on the neuron
    /// and thus prevents concurrent changes that might happen due to the
    /// interleaving of user requests and callback execution.
    ///
    /// If there are no ongoing requests, this map should be empty.
    ///
    /// If something goes fundamentally wrong (say we trap at some point
    /// after issuing a transfer call) the neuron(s) involved are left in a
    /// "locked" state, meaning new operations can't be applied without
    /// reconciling the state.
    ///
    /// Because we know exactly what was going on, we should have the
    /// information necessary to reconcile the state, using custom code
    /// added on upgrade, if necessary.
    #[prost(btree_map = "string, message", tag = "10")]
    pub in_flight_commands: ::prost::alloc::collections::BTreeMap<
        ::prost::alloc::string::String,
        governance::NeuronInFlightCommand,
    >,
    /// The timestamp that is considered genesis for the governance
    /// system, in seconds since the Unix epoch. That is, the time
    /// at which `canister_init` was run for the governance canister.
    #[prost(uint64, tag = "11")]
    pub genesis_timestamp_seconds: u64,
    #[prost(message, optional, tag = "13")]
    pub metrics: ::core::option::Option<governance::GovernanceCachedMetrics>,
    /// The canister ID of the ledger canister.
    #[prost(message, optional, tag = "16")]
    pub ledger_canister_id: ::core::option::Option<::ic_base_types::PrincipalId>,
    /// The canister ID of the root canister.
    #[prost(message, optional, tag = "17")]
    pub root_canister_id: ::core::option::Option<::ic_base_types::PrincipalId>,
    /// ID to NervousSystemFunction (which has an id field).
    #[prost(btree_map = "uint64, message", tag = "18")]
    pub id_to_nervous_system_functions:
        ::prost::alloc::collections::BTreeMap<u64, NervousSystemFunction>,
    #[prost(enumeration = "governance::Mode", tag = "19")]
    pub mode: i32,
    /// The canister ID of the swap canister.
    ///
    /// When this is unpopulated, mode should be Normal, and when this is
    /// populated, mode should be PreInitializationSwap.
    #[prost(message, optional, tag = "20")]
    pub swap_canister_id: ::core::option::Option<::ic_base_types::PrincipalId>,
    #[prost(message, optional, tag = "21")]
    pub sns_metadata: ::core::option::Option<governance::SnsMetadata>,
    /// The initialization parameters used to spawn an SNS
    #[prost(string, tag = "22")]
    pub sns_initialization_parameters: ::prost::alloc::string::String,
    /// Current version that this SNS is running.
    #[prost(message, optional, tag = "23")]
    pub deployed_version: ::core::option::Option<governance::Version>,
    /// Version SNS is in process of upgrading to.
    #[prost(message, optional, tag = "24")]
    pub pending_version: ::core::option::Option<governance::UpgradeInProgress>,
    /// True if the heartbeat function is currently finalizing disburse maturity, meaning
    /// that it should finish before being called again.
    #[prost(bool, optional, tag = "25")]
    pub is_finalizing_disburse_maturity: ::core::option::Option<bool>,
    #[prost(message, optional, tag = "26")]
    pub maturity_modulation: ::core::option::Option<governance::MaturityModulation>,
}
/// Nested message and enum types in `Governance`.
pub mod governance {
    /// The commands that require a neuron lock.
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct NeuronInFlightCommand {
        /// The timestamp at which the command was issued, for debugging
        /// purposes.
        #[prost(uint64, tag = "1")]
        pub timestamp: u64,
        #[prost(
            oneof = "neuron_in_flight_command::Command",
            tags = "2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 20"
        )]
        pub command: ::core::option::Option<neuron_in_flight_command::Command>,
    }
    /// Nested message and enum types in `NeuronInFlightCommand`.
    pub mod neuron_in_flight_command {
        /// A general place holder for sync commands. The neuron lock is
        /// never left holding a sync command (as it either succeeds to
        /// acquire the lock and releases it in the same call, or never
        /// acquires it in the first place), but it still must be acquired
        /// to prevent interleaving with another async command. Thus there's
        /// no value in actually storing the command itself, and this placeholder
        /// can generally be used in all sync cases.
        #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct SyncCommand {}
        #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Oneof)]
        pub enum Command {
            #[prost(message, tag = "2")]
            Disburse(super::super::manage_neuron::Disburse),
            #[prost(message, tag = "3")]
            Split(super::super::manage_neuron::Split),
            #[prost(message, tag = "4")]
            MergeMaturity(super::super::manage_neuron::MergeMaturity),
            #[prost(message, tag = "5")]
            DisburseMaturity(super::super::manage_neuron::DisburseMaturity),
            #[prost(message, tag = "6")]
            ClaimOrRefreshNeuron(super::super::manage_neuron::ClaimOrRefresh),
            #[prost(message, tag = "7")]
            AddNeuronPermissions(super::super::manage_neuron::AddNeuronPermissions),
            #[prost(message, tag = "8")]
            RemoveNeuronPermissions(super::super::manage_neuron::RemoveNeuronPermissions),
            #[prost(message, tag = "9")]
            Configure(super::super::manage_neuron::Configure),
            #[prost(message, tag = "10")]
            Follow(super::super::manage_neuron::Follow),
            #[prost(message, tag = "11")]
            MakeProposal(super::super::Proposal),
            #[prost(message, tag = "12")]
            RegisterVote(super::super::manage_neuron::RegisterVote),
            #[prost(message, tag = "13")]
            FinalizeDisburseMaturity(super::super::manage_neuron::FinalizeDisburseMaturity),
            #[prost(message, tag = "20")]
            SyncCommand(SyncCommand),
        }
    }
    /// Metrics that are too costly to compute each time when they are
    /// requested.
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[compare_default]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct GovernanceCachedMetrics {
        /// The timestamp when these metrics were computed, as seconds since
        /// Unix epoch.
        #[prost(uint64, tag = "1")]
        pub timestamp_seconds: u64,
        /// The total supply of governance tokens in the ledger canister.
        #[prost(uint64, tag = "2")]
        pub total_supply_governance_tokens: u64,
        /// The number of dissolving neurons (i.e., in NeuronState::Dissolving).
        #[prost(uint64, tag = "3")]
        pub dissolving_neurons_count: u64,
        /// The number of staked governance tokens in dissolving neurons
        /// (i.e., in NeuronState::Dissolving) grouped by the neurons' dissolve delay
        /// rounded to years.
        /// This is given as a map from dissolve delays (rounded to years)
        /// to the sum of staked tokens in the dissolving neurons that have this
        /// dissolve delay.
        #[prost(btree_map = "uint64, double", tag = "4")]
        pub dissolving_neurons_e8s_buckets: ::prost::alloc::collections::BTreeMap<u64, f64>,
        /// The number of dissolving neurons (i.e., in NeuronState::Dissolving)
        /// grouped by their dissolve delay rounded to years.
        /// This is given as a map from dissolve delays (rounded to years) to
        /// the number of dissolving neurons that have this dissolve delay.
        #[prost(btree_map = "uint64, uint64", tag = "5")]
        pub dissolving_neurons_count_buckets: ::prost::alloc::collections::BTreeMap<u64, u64>,
        /// The number of non-dissolving neurons (i.e., in NeuronState::NotDissolving).
        #[prost(uint64, tag = "6")]
        pub not_dissolving_neurons_count: u64,
        /// The number of staked governance tokens in non-dissolving neurons
        /// (i.e., in NeuronState::NotDissolving) grouped by the neurons' dissolve delay
        /// rounded to years.
        /// This is given as a map from dissolve delays (rounded to years)
        /// to the sum of staked tokens in the non-dissolving neurons that have this
        /// dissolve delay.
        #[prost(btree_map = "uint64, double", tag = "7")]
        pub not_dissolving_neurons_e8s_buckets: ::prost::alloc::collections::BTreeMap<u64, f64>,
        /// The number of non-dissolving neurons (i.e., in NeuronState::NotDissolving)
        /// grouped by their dissolve delay rounded to years.
        /// This is given as a map from dissolve delays (rounded to years) to
        /// the number of non-dissolving neurons that have this dissolve delay.
        #[prost(btree_map = "uint64, uint64", tag = "8")]
        pub not_dissolving_neurons_count_buckets: ::prost::alloc::collections::BTreeMap<u64, u64>,
        /// The number of dissolved neurons (i.e., in NeuronState::Dissolved).
        #[prost(uint64, tag = "9")]
        pub dissolved_neurons_count: u64,
        /// The number of staked governance tokens in dissolved neurons
        /// (i.e., in NeuronState::Dissolved).
        #[prost(uint64, tag = "10")]
        pub dissolved_neurons_e8s: u64,
        /// The number of neurons that are garbage collectable, i.e., that
        /// have a cached stake smaller than the ledger transaction fee.
        #[prost(uint64, tag = "11")]
        pub garbage_collectable_neurons_count: u64,
        /// The number of neurons that have an invalid stake, i.e., that
        /// have a cached stake that is larger than zero but smaller than the
        /// minimum neuron stake defined in the nervous system parameters.
        #[prost(uint64, tag = "12")]
        pub neurons_with_invalid_stake_count: u64,
        /// The total amount of governance tokens that are staked in neurons,
        /// measured in fractions of 10E-8 of a governance token.
        #[prost(uint64, tag = "13")]
        pub total_staked_e8s: u64,
        /// TODO: rather than taking six months, it would be more interesting to take the respective SNS's eligibility boarder here.
        /// The number of neurons with a dissolve delay of less than six months.
        #[prost(uint64, tag = "14")]
        pub neurons_with_less_than_6_months_dissolve_delay_count: u64,
        /// The number of governance tokens in neurons with a dissolve delay of
        /// less than six months.
        #[prost(uint64, tag = "15")]
        pub neurons_with_less_than_6_months_dissolve_delay_e8s: u64,
    }
    /// Metadata about this SNS.
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct SnsMetadata {
        /// The logo for the SNS project represented as a base64 encoded string.
        #[prost(string, optional, tag = "1")]
        pub logo: ::core::option::Option<::prost::alloc::string::String>,
        /// Url to the dapp controlled by the SNS project.
        #[prost(string, optional, tag = "2")]
        pub url: ::core::option::Option<::prost::alloc::string::String>,
        /// Name of the SNS project. This may differ from the name of the associated token.
        #[prost(string, optional, tag = "3")]
        pub name: ::core::option::Option<::prost::alloc::string::String>,
        /// Description of the SNS project.
        #[prost(string, optional, tag = "4")]
        pub description: ::core::option::Option<::prost::alloc::string::String>,
    }
    /// A version of the SNS defined by the WASM hashes of its canisters.
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Version {
        /// The hash of the Root canister WASM.
        #[prost(bytes = "vec", tag = "1")]
        #[serde(with = "serde_bytes")]
        pub root_wasm_hash: ::prost::alloc::vec::Vec<u8>,
        /// The hash of the Governance canister WASM.
        #[prost(bytes = "vec", tag = "2")]
        #[serde(with = "serde_bytes")]
        pub governance_wasm_hash: ::prost::alloc::vec::Vec<u8>,
        /// The hash of the Ledger canister WASM.
        #[prost(bytes = "vec", tag = "3")]
        #[serde(with = "serde_bytes")]
        pub ledger_wasm_hash: ::prost::alloc::vec::Vec<u8>,
        /// The hash of the Swap canister WASM.
        #[prost(bytes = "vec", tag = "4")]
        #[serde(with = "serde_bytes")]
        pub swap_wasm_hash: ::prost::alloc::vec::Vec<u8>,
        /// The hash of the Ledger Archive canister WASM.
        #[prost(bytes = "vec", tag = "5")]
        #[serde(with = "serde_bytes")]
        pub archive_wasm_hash: ::prost::alloc::vec::Vec<u8>,
        /// The hash of the Index canister WASM.
        #[prost(bytes = "vec", tag = "6")]
        #[serde(with = "serde_bytes")]
        pub index_wasm_hash: ::prost::alloc::vec::Vec<u8>,
    }
    /// An upgrade in progress, defined as a version target and a time at which it is considered failed.
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct UpgradeInProgress {
        /// Version to  be upgraded to
        #[prost(message, optional, tag = "1")]
        pub target_version: ::core::option::Option<Version>,
        /// Seconds since UNIX epoch to mark this as a failed version if not in sync with current version
        #[prost(uint64, tag = "2")]
        pub mark_failed_at_seconds: u64,
        /// Lock to avoid checking over and over again.  Also, it is a counter for how many times we have attempted to check,
        /// allowing us to fail in case we otherwise have gotten stuck.
        #[prost(uint64, tag = "3")]
        pub checking_upgrade_lock: u64,
        /// The proposal that initiated this upgrade
        #[prost(uint64, tag = "4")]
        pub proposal_id: u64,
    }
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct MaturityModulation {
        /// When X maturity is disbursed, the amount that goes to the destination
        /// account is X * (1 + y) where y = current_basis_points / 10_000.
        ///
        /// Fetched from the cycles minting canister (same as NNS governance).
        ///
        /// There is a positive relationship between the price of ICP (in XDR) and
        /// this value.
        #[prost(int32, optional, tag = "1")]
        pub current_basis_points: ::core::option::Option<i32>,
        /// When current_basis_points was last updated (seconds since UNIX epoch).
        #[prost(uint64, optional, tag = "2")]
        pub updated_at_timestamp_seconds: ::core::option::Option<u64>,
    }
    #[derive(
        candid::CandidType,
        candid::Deserialize,
        comparable::Comparable,
        strum_macros::EnumIter,
        Clone,
        Copy,
        Debug,
        PartialEq,
        Eq,
        Hash,
        PartialOrd,
        Ord,
        ::prost::Enumeration,
    )]
    #[repr(i32)]
    pub enum Mode {
        /// This forces people to explicitly populate the mode field.
        Unspecified = 0,
        /// All operations are allowed.
        Normal = 1,
        /// In this mode, various operations are not allowed in order to ensure the
        /// integrity of the initial token swap.
        PreInitializationSwap = 2,
    }
    impl Mode {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                Mode::Unspecified => "MODE_UNSPECIFIED",
                Mode::Normal => "MODE_NORMAL",
                Mode::PreInitializationSwap => "MODE_PRE_INITIALIZATION_SWAP",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
            match value {
                "MODE_UNSPECIFIED" => Some(Self::Unspecified),
                "MODE_NORMAL" => Some(Self::Normal),
                "MODE_PRE_INITIALIZATION_SWAP" => Some(Self::PreInitializationSwap),
                _ => None,
            }
        }
    }
}
/// Request message for 'get_metadata'.
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetMetadataRequest {}
/// Response message for 'get_metadata'.
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetMetadataResponse {
    #[prost(string, optional, tag = "1")]
    pub logo: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag = "2")]
    pub url: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag = "3")]
    pub name: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag = "4")]
    pub description: ::core::option::Option<::prost::alloc::string::String>,
}
/// Request message for 'get_sns_initialization_parameters'
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetSnsInitializationParametersRequest {}
/// Response message for 'get_sns_initialization_parameters'
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetSnsInitializationParametersResponse {
    #[prost(string, tag = "1")]
    pub sns_initialization_parameters: ::prost::alloc::string::String,
}
/// Request for the SNS's currently running version.
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetRunningSnsVersionRequest {}
/// Response with the SNS's currently running version and any upgrades
/// that are in progress.
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetRunningSnsVersionResponse {
    /// The currently deployed version of the SNS.
    #[prost(message, optional, tag = "1")]
    pub deployed_version: ::core::option::Option<governance::Version>,
    /// The upgrade in progress, if any.
    #[prost(message, optional, tag = "2")]
    pub pending_version: ::core::option::Option<governance::UpgradeInProgress>,
}
/// Request to fail an upgrade proposal that is Adopted but not Executed or
/// Failed if it is past the time when it should have been marked as failed.
/// This is useful in the case where the asynchronous process may have failed to
/// complete
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FailStuckUpgradeInProgressRequest {}
/// Response to FailStuckUpgradeInProgressRequest
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FailStuckUpgradeInProgressResponse {}
/// Empty message to use in oneof fields that represent empty
/// enums.
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Empty {}
/// An operation that modifies a neuron.
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ManageNeuron {
    /// The modified neuron's subaccount which also serves as the neuron's ID.
    #[prost(bytes = "vec", tag = "1")]
    #[serde(with = "serde_bytes")]
    pub subaccount: ::prost::alloc::vec::Vec<u8>,
    #[prost(
        oneof = "manage_neuron::Command",
        tags = "2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13"
    )]
    pub command: ::core::option::Option<manage_neuron::Command>,
}
/// Nested message and enum types in `ManageNeuron`.
pub mod manage_neuron {
    /// The operation that increases a neuron's dissolve delay. It can be
    /// increased up to a maximum defined in the nervous system parameters.
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct IncreaseDissolveDelay {
        /// The additional dissolve delay that should be added to the neuron's
        /// current dissolve delay.
        #[prost(uint32, tag = "1")]
        pub additional_dissolve_delay_seconds: u32,
    }
    /// The operation that starts dissolving a neuron, i.e., changes a neuron's
    /// state such that it is dissolving.
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct StartDissolving {}
    /// The operation that stops dissolving a neuron, i.e., changes a neuron's
    /// state such that it is non-dissolving.
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct StopDissolving {}
    /// An (idempotent) alternative to IncreaseDissolveDelay where the dissolve delay
    /// is passed as an absolute timestamp in seconds since the Unix epoch.
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct SetDissolveTimestamp {
        /// The time when the neuron (newly) should become dissolved, in seconds
        /// since the Unix epoch.
        #[prost(uint64, tag = "1")]
        pub dissolve_timestamp_seconds: u64,
    }
    /// Changes auto-stake maturity for this Neuron. While on, auto-stake
    /// maturity will cause all the maturity generated by voting rewards
    /// to this neuron to be automatically staked and contribute to the
    /// voting power of the neuron.
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct ChangeAutoStakeMaturity {
        #[prost(bool, tag = "1")]
        pub requested_setting_for_auto_stake_maturity: bool,
    }
    /// Commands that only configure a given neuron, but do not interact
    /// with the outside world. They all require the caller to have
    /// `NeuronPermissionType::ConfigureDissolveState` for the neuron.
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Configure {
        #[prost(oneof = "configure::Operation", tags = "1, 2, 3, 4, 5")]
        pub operation: ::core::option::Option<configure::Operation>,
    }
    /// Nested message and enum types in `Configure`.
    pub mod configure {
        #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Oneof)]
        pub enum Operation {
            #[prost(message, tag = "1")]
            IncreaseDissolveDelay(super::IncreaseDissolveDelay),
            #[prost(message, tag = "2")]
            StartDissolving(super::StartDissolving),
            #[prost(message, tag = "3")]
            StopDissolving(super::StopDissolving),
            #[prost(message, tag = "4")]
            SetDissolveTimestamp(super::SetDissolveTimestamp),
            #[prost(message, tag = "5")]
            ChangeAutoStakeMaturity(super::ChangeAutoStakeMaturity),
        }
    }
    /// The operation that disburses a given number of tokens or all of a
    /// neuron's tokens (if no argument is provided) to a given ledger account.
    /// Thereby, the neuron's accumulated fees are burned and (if relevant in
    /// the given nervous system) the token equivalent of the neuron's accumulated
    /// maturity are minted and also transferred to the specified account.
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Disburse {
        /// The (optional) amount to disburse out of the neuron. If not specified the cached
        /// stake is used.
        #[prost(message, optional, tag = "1")]
        pub amount: ::core::option::Option<disburse::Amount>,
        /// The ledger account to which the disbursed tokens are transferred.
        #[prost(message, optional, tag = "2")]
        pub to_account: ::core::option::Option<super::Account>,
    }
    /// Nested message and enum types in `Disburse`.
    pub mod disburse {
        #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct Amount {
            #[prost(uint64, tag = "1")]
            pub e8s: u64,
        }
    }
    /// The operation that splits a neuron (called 'parent neuron'), or rather a neuron's stake,
    /// into two neurons.
    /// Specifically, the parent neuron's stake is decreased by the specified amount of
    /// governance tokens and a new 'child neuron' is created with a stake that equals
    /// this amount minus the transaction fee. The child neuron inherits from the parent neuron
    /// the permissions (i.e., principals that can change the neuron), the age, the followees, and
    /// the dissolve state. The parent neuron's fees and maturity (if applicable in the given
    /// nervous system) remain in the parent neuron and the child neuron's fees and maturity
    /// are initialized to be zero.
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Split {
        /// The amount of governance tokens (in measured in fractions of 10E-8 of
        /// a governance token) to be split to the child neuron.
        #[prost(uint64, tag = "1")]
        pub amount_e8s: u64,
        /// The nonce that is used to compute the child neuron's
        /// subaccount which also serves as the child neuron's ID. This nonce
        /// is also used as the memo field in the ledger transfer that transfers
        /// the stake from the parent to the child neuron.
        #[prost(uint64, tag = "2")]
        pub memo: u64,
    }
    /// The operation that merges a given percentage of a neuron's maturity (if applicable
    /// to the nervous system) to the neuron's stake.
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct MergeMaturity {
        /// The percentage of maturity to merge, from 1 to 100.
        #[prost(uint32, tag = "1")]
        pub percentage_to_merge: u32,
    }
    /// Stake the maturity of a neuron.
    /// The caller can choose a percentage of of the current maturity to stake.
    /// If 'percentage_to_stake' is not provided, all of the neuron's current
    /// maturity will be staked.
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct StakeMaturity {
        /// The percentage of maturity to stake, from 1 to 100 (inclusive).
        #[prost(uint32, optional, tag = "1")]
        pub percentage_to_stake: ::core::option::Option<u32>,
    }
    /// Disburse the maturity of a neuron to any ledger account. If an account
    /// is not specified, the caller's account will be used. The caller can choose
    /// a percentage of the current maturity to disburse to the ledger account. The
    /// resulting amount to disburse must be greater than or equal to the
    /// transaction fee.
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct DisburseMaturity {
        /// The percentage to disburse, from 1 to 100
        #[prost(uint32, tag = "1")]
        pub percentage_to_disburse: u32,
        /// The (optional) principal to which to transfer the stake.
        #[prost(message, optional, tag = "2")]
        pub to_account: ::core::option::Option<super::Account>,
    }
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct FinalizeDisburseMaturity {
        /// The amount to be disbursed in e8s of the governance token.
        #[prost(uint64, tag = "1")]
        pub amount_to_be_disbursed_e8s: u64,
        /// The principal to which to transfer the stake (required).
        #[prost(message, optional, tag = "2")]
        pub to_account: ::core::option::Option<super::Account>,
    }
    /// The operation that adds a new follow relation to a neuron, specifying
    /// that it follows a set of followee neurons for a given proposal function.
    /// If the neuron already has a defined follow relation for this proposal
    /// function, then the current list is replaced with the new list (not added).
    /// If the provided followee list is empty, the follow relation for this
    /// proposal function is removed.
    ///
    /// A follow relation has the effect that the governance canister will
    /// automatically cast a vote for the following neuron for proposals of
    /// the given function if a majority of the specified followees vote in the
    /// same way.
    /// In more detail, once a majority of the followees vote to adopt
    /// or reject a proposal belonging to the specified function, the neuron
    /// votes the same way. If it becomes impossible for a majority of
    /// the followees to adopt (for example, because they are split 50-50
    /// between adopt and reject), then the neuron votes to reject.
    /// If a rule is specified where the proposal function is UNSPECIFIED,
    /// then it becomes a catch-all follow rule, which will be used to vote
    /// automatically on proposals with actions for which no
    /// specific rule has been specified.
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Follow {
        /// The function id of the proposal function defining for which proposals
        /// this follow relation is relevant.
        #[prost(uint64, tag = "1")]
        pub function_id: u64,
        /// The list of followee neurons, specified by their neuron ID.
        #[prost(message, repeated, tag = "2")]
        pub followees: ::prost::alloc::vec::Vec<super::NeuronId>,
    }
    /// The operation that registers a given vote from the neuron for a given
    /// proposal (a directly cast vote as opposed to a vote that is cast as
    /// a result of a follow relation).
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct RegisterVote {
        /// The ID of the proposal that the vote is cast for.
        #[prost(message, optional, tag = "1")]
        pub proposal: ::core::option::Option<super::ProposalId>,
        /// The vote that is cast to adopt or reject the proposal.
        #[prost(enumeration = "super::Vote", tag = "2")]
        pub vote: i32,
    }
    /// The operation that claims a new neuron (if it does not exist yet) or
    /// refreshes the stake of the neuron (if it already exists).
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct ClaimOrRefresh {
        #[prost(oneof = "claim_or_refresh::By", tags = "2, 3")]
        pub by: ::core::option::Option<claim_or_refresh::By>,
    }
    /// Nested message and enum types in `ClaimOrRefresh`.
    pub mod claim_or_refresh {
        /// (see MemoAndController below)
        #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct MemoAndController {
            /// The memo(nonce) that is used to compute the neuron's subaccount
            /// (where the tokens were staked to).
            #[prost(uint64, tag = "1")]
            pub memo: u64,
            /// The principal for which the neuron should be claimed.
            #[prost(message, optional, tag = "2")]
            pub controller: ::core::option::Option<::ic_base_types::PrincipalId>,
        }
        #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Oneof)]
        pub enum By {
            /// The memo and principal used to define the neuron to be claimed
            /// or refreshed. Specifically, the memo (nonce) and the given principal
            /// (called 'controller' or 'claimer') are used to compute the ledger
            /// subaccount to which the staked tokens to be used for claiming or
            /// refreshing a neuron were transferred to.
            /// If 'controller' is omitted, the id of the principal who calls this
            /// operation will be used.
            #[prost(message, tag = "2")]
            MemoAndController(MemoAndController),
            /// The neuron ID of a neuron that should be refreshed. This just serves
            /// as an alternative way to specify a neuron to be refreshed, but cannot
            /// be used to claim new neurons.
            #[prost(message, tag = "3")]
            NeuronId(super::super::Empty),
        }
    }
    /// Add a set of permissions to the Neuron for the given PrincipalId. These
    /// permissions must be a subset of `NervousSystemParameters::neuron_grantable_permissions`.
    /// If the PrincipalId doesn't have existing permissions, a new entry will be added for it
    /// with the provided permissions. If a principalId already has permissions for the neuron,
    /// the new permissions will be added to the existing set.
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct AddNeuronPermissions {
        /// The PrincipalId that the permissions will be granted to.
        #[prost(message, optional, tag = "1")]
        pub principal_id: ::core::option::Option<::ic_base_types::PrincipalId>,
        /// The set of permissions that will be granted to the PrincipalId.
        #[prost(message, optional, tag = "2")]
        pub permissions_to_add: ::core::option::Option<super::NeuronPermissionList>,
    }
    /// Remove a set of permissions from the Neuron for the given PrincipalId. If a PrincipalId has all of
    /// its permissions removed, it will be removed from the neuron's permissions list. This is a dangerous
    /// operation as its possible to remove all permissions for a neuron and no longer be able to modify
    /// it's state, i.e. disbursing the neuron back into the governance token.
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct RemoveNeuronPermissions {
        /// The PrincipalId that the permissions will be revoked from.
        #[prost(message, optional, tag = "1")]
        pub principal_id: ::core::option::Option<::ic_base_types::PrincipalId>,
        /// The set of permissions that will be revoked from the PrincipalId.
        #[prost(message, optional, tag = "2")]
        pub permissions_to_remove: ::core::option::Option<super::NeuronPermissionList>,
    }
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::large_enum_variant)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Command {
        #[prost(message, tag = "2")]
        Configure(Configure),
        #[prost(message, tag = "3")]
        Disburse(Disburse),
        #[prost(message, tag = "4")]
        Follow(Follow),
        /// Making a proposal is defined by a proposal, which contains the proposer neuron.
        /// Making a proposal will implicitly cast a yes vote for the proposing neuron.
        #[prost(message, tag = "5")]
        MakeProposal(super::Proposal),
        #[prost(message, tag = "6")]
        RegisterVote(RegisterVote),
        #[prost(message, tag = "7")]
        Split(Split),
        #[prost(message, tag = "8")]
        ClaimOrRefresh(ClaimOrRefresh),
        #[prost(message, tag = "9")]
        MergeMaturity(MergeMaturity),
        #[prost(message, tag = "10")]
        DisburseMaturity(DisburseMaturity),
        #[prost(message, tag = "11")]
        AddNeuronPermissions(AddNeuronPermissions),
        #[prost(message, tag = "12")]
        RemoveNeuronPermissions(RemoveNeuronPermissions),
        #[prost(message, tag = "13")]
        StakeMaturity(StakeMaturity),
    }
}
/// The response of a ManageNeuron command.
/// There is a dedicated response type for each `ManageNeuron.command` field.
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ManageNeuronResponse {
    #[prost(
        oneof = "manage_neuron_response::Command",
        tags = "1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13"
    )]
    pub command: ::core::option::Option<manage_neuron_response::Command>,
}
/// Nested message and enum types in `ManageNeuronResponse`.
pub mod manage_neuron_response {
    /// The response to the ManageNeuron command 'configure'.
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct ConfigureResponse {}
    /// The response to the ManageNeuron command 'disburse'.
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct DisburseResponse {
        /// The block height of the ledger where the tokens were disbursed to the
        /// given account.
        #[prost(uint64, tag = "1")]
        pub transfer_block_height: u64,
    }
    /// The response to the ManageNeuron command 'merge_maturity'.
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct MergeMaturityResponse {
        /// The maturity that was merged in fractions of
        /// 10E-8 of a governance token.
        #[prost(uint64, tag = "1")]
        pub merged_maturity_e8s: u64,
        /// The resulting cached stake of the modified neuron
        /// in fractions of 10E-8 of a governance token.
        #[prost(uint64, tag = "2")]
        pub new_stake_e8s: u64,
    }
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct DisburseMaturityResponse {
        /// This field is deprecated and is populated with the same value as `amount_deducted_e8s`.
        #[prost(uint64, tag = "2")]
        pub amount_disbursed_e8s: u64,
        /// The amount of maturity in e8s of the governance token deducted from the Neuron.
        /// This amount will undergo maturity modulation if enabled, and may be increased or
        /// decreased at the time of disbursement.
        #[prost(uint64, optional, tag = "3")]
        pub amount_deducted_e8s: ::core::option::Option<u64>,
    }
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct StakeMaturityResponse {
        #[prost(uint64, tag = "1")]
        pub maturity_e8s: u64,
        #[prost(uint64, tag = "2")]
        pub staked_maturity_e8s: u64,
    }
    /// The response to the ManageNeuron command 'follow'.
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct FollowResponse {}
    /// The response to the ManageNeuron command 'make_proposal'.
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct MakeProposalResponse {
        /// The ID of the created proposal.
        #[prost(message, optional, tag = "1")]
        pub proposal_id: ::core::option::Option<super::ProposalId>,
    }
    /// The response to the ManageNeuron command 'register_vote'.
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct RegisterVoteResponse {}
    /// The response to the ManageNeuron command 'split'.
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct SplitResponse {
        /// The ID of the 'child neuron' that was newly created.
        #[prost(message, optional, tag = "1")]
        pub created_neuron_id: ::core::option::Option<super::NeuronId>,
    }
    /// The response to the ManageNeuron command 'claim_or_refresh'.
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct ClaimOrRefreshResponse {
        /// The neuron ID of the neuron that was newly claimed or
        /// refreshed.
        #[prost(message, optional, tag = "1")]
        pub refreshed_neuron_id: ::core::option::Option<super::NeuronId>,
    }
    /// The response to the ManageNeuron command 'add_neuron_permissions'.
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct AddNeuronPermissionsResponse {}
    /// The response to the ManageNeuron command 'remove_neuron_permissions'.
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct RemoveNeuronPermissionsResponse {}
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Command {
        #[prost(message, tag = "1")]
        Error(super::GovernanceError),
        #[prost(message, tag = "2")]
        Configure(ConfigureResponse),
        #[prost(message, tag = "3")]
        Disburse(DisburseResponse),
        #[prost(message, tag = "4")]
        Follow(FollowResponse),
        #[prost(message, tag = "5")]
        MakeProposal(MakeProposalResponse),
        #[prost(message, tag = "6")]
        RegisterVote(RegisterVoteResponse),
        #[prost(message, tag = "7")]
        Split(SplitResponse),
        #[prost(message, tag = "8")]
        ClaimOrRefresh(ClaimOrRefreshResponse),
        #[prost(message, tag = "9")]
        MergeMaturity(MergeMaturityResponse),
        #[prost(message, tag = "10")]
        DisburseMaturity(DisburseMaturityResponse),
        #[prost(message, tag = "11")]
        AddNeuronPermission(AddNeuronPermissionsResponse),
        #[prost(message, tag = "12")]
        RemoveNeuronPermission(RemoveNeuronPermissionsResponse),
        #[prost(message, tag = "13")]
        StakeMaturity(StakeMaturityResponse),
    }
}
/// An operation that attempts to get a neuron by a given neuron ID.
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetNeuron {
    #[prost(message, optional, tag = "1")]
    pub neuron_id: ::core::option::Option<NeuronId>,
}
/// A response to the GetNeuron command.
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetNeuronResponse {
    /// The response to a GetNeuron command is either an error or
    /// the requested neuron.
    #[prost(oneof = "get_neuron_response::Result", tags = "1, 2")]
    pub result: ::core::option::Option<get_neuron_response::Result>,
}
/// Nested message and enum types in `GetNeuronResponse`.
pub mod get_neuron_response {
    /// The response to a GetNeuron command is either an error or
    /// the requested neuron.
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Result {
        #[prost(message, tag = "1")]
        Error(super::GovernanceError),
        #[prost(message, tag = "2")]
        Neuron(super::Neuron),
    }
}
/// An operation that attempts to get a proposal by a given proposal ID.
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetProposal {
    #[prost(message, optional, tag = "1")]
    pub proposal_id: ::core::option::Option<ProposalId>,
}
/// A response to the GetProposal command.
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetProposalResponse {
    /// The response to a GetProposal command is either an error or
    /// the proposal data corresponding to the requested proposal.
    #[prost(oneof = "get_proposal_response::Result", tags = "1, 2")]
    pub result: ::core::option::Option<get_proposal_response::Result>,
}
/// Nested message and enum types in `GetProposalResponse`.
pub mod get_proposal_response {
    /// The response to a GetProposal command is either an error or
    /// the proposal data corresponding to the requested proposal.
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::large_enum_variant)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Result {
        #[prost(message, tag = "1")]
        Error(super::GovernanceError),
        #[prost(message, tag = "2")]
        Proposal(super::ProposalData),
    }
}
/// An operation that lists the proposalData for all proposals tracked
/// in the Governance state in a paginated fashion. The ballots are cleared for
/// better readability. (To get a given proposal's ballots, use GetProposal).
/// Listing of all proposals can be accomplished using `limit` and `before_proposal`.
/// Proposals are stored using an increasing id where the most recent proposals
/// have the highest ids. ListProposals reverses the list and paginates backwards
/// using `before_proposal`, so the first element returned is the latest proposal.
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListProposals {
    /// Limit the number of Proposals returned in each page, from 1 to 100.
    /// If a value outside of this range is provided, 100 will be used.
    #[prost(uint32, tag = "1")]
    pub limit: u32,
    /// The proposal ID specifying which proposals to return.
    /// This should be set to the last proposal of the previously returned page and
    /// will not be included in the current page.
    /// If this is specified, then only the proposals that have a proposal ID strictly
    /// lower than the specified one are returned. If this is not specified
    /// then the list of proposals starts with the most recent proposal's ID.
    #[prost(message, optional, tag = "2")]
    pub before_proposal: ::core::option::Option<ProposalId>,
    /// A list of proposal types, specifying that proposals of the given
    /// types should be excluded in this list.
    #[prost(uint64, repeated, tag = "3")]
    pub exclude_type: ::prost::alloc::vec::Vec<u64>,
    /// A list of proposal reward statuses, specifying that only proposals that
    /// that have one of the define reward statuses should be included
    /// in the list.
    /// If this list is empty, no restriction is applied.
    ///
    /// Example: If users are only interested in proposals for which they can
    /// receive voting rewards they can use this to filter for proposals
    /// with reward status PROPOSAL_REWARD_STATUS_ACCEPT_VOTES.
    #[prost(enumeration = "ProposalRewardStatus", repeated, tag = "4")]
    pub include_reward_status: ::prost::alloc::vec::Vec<i32>,
    /// A list of proposal decision statuses, specifying that only proposals that
    /// that have one of the define decision statuses should be included
    /// in the list.
    /// If this list is empty, no restriction is applied.
    #[prost(enumeration = "ProposalDecisionStatus", repeated, tag = "5")]
    pub include_status: ::prost::alloc::vec::Vec<i32>,
}
/// A response to the ListProposals command.
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListProposalsResponse {
    /// The returned list of proposals' ProposalData.
    #[prost(message, repeated, tag = "1")]
    pub proposals: ::prost::alloc::vec::Vec<ProposalData>,
    /// Whether ballots cast by the caller are included in the returned proposals.
    #[prost(bool, optional, tag = "2")]
    pub include_ballots_by_caller: ::core::option::Option<bool>,
}
/// An operation that lists all neurons tracked in the Governance state in a
/// paginated fashion.
/// Listing of all neurons can be accomplished using `limit` and `start_page_at`.
/// To only list neurons associated with a given principal, use `of_principal`.
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListNeurons {
    /// Limit the number of Neurons returned in each page, from 1 to 100.
    /// If a value outside of this range is provided, 100 will be used.
    #[prost(uint32, tag = "1")]
    pub limit: u32,
    /// Used to indicate where the next page of Neurons should start. Should be
    /// set to the last neuron of the previously returned page and will not be
    /// included in the next page. If not set, ListNeurons will return a page of
    /// size limit starting at the "0th" Neuron. Neurons are not kept in any specific
    /// order, but their ordering is deterministic, so this can be used to return all
    /// the neurons one page at a time.
    #[prost(message, optional, tag = "2")]
    pub start_page_at: ::core::option::Option<NeuronId>,
    /// A principal ID, specifying that only neurons for which this principal has
    /// any permissions should be included in the list.
    /// If this is not specified, no restriction is applied.
    #[prost(message, optional, tag = "3")]
    pub of_principal: ::core::option::Option<::ic_base_types::PrincipalId>,
}
/// A response to the ListNeurons command.
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListNeuronsResponse {
    /// The returned list of neurons.
    #[prost(message, repeated, tag = "1")]
    pub neurons: ::prost::alloc::vec::Vec<Neuron>,
}
/// The response to the list_nervous_system_functions query.
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListNervousSystemFunctionsResponse {
    /// Current set of nervous system function, both native and user-defined,
    /// that can be executed by proposal.
    #[prost(message, repeated, tag = "1")]
    pub functions: ::prost::alloc::vec::Vec<NervousSystemFunction>,
    /// Set of nervous system function ids that are reserved and cannot be
    /// used to add new NervousSystemFunctions.
    #[prost(uint64, repeated, tag = "2")]
    pub reserved_ids: ::prost::alloc::vec::Vec<u64>,
}
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SetMode {
    #[prost(enumeration = "governance::Mode", tag = "1")]
    pub mode: i32,
}
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SetModeResponse {}
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetMode {}
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetModeResponse {
    #[prost(enumeration = "governance::Mode", optional, tag = "1")]
    pub mode: ::core::option::Option<i32>,
}
/// The request for the `claim_swap_neurons` method.
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ClaimSwapNeuronsRequest {
    /// The set of parameters that define the neurons created in `claim_swap_neurons`. For
    /// each NeuronRecipe, one neuron will be created.
    #[prost(message, optional, tag = "2")]
    pub neuron_recipes: ::core::option::Option<claim_swap_neurons_request::NeuronRecipes>,
}
/// Nested message and enum types in `ClaimSwapNeuronsRequest`.
pub mod claim_swap_neurons_request {
    /// Replacement for NeuronParameters. Contains the information needed to set up
    /// a neuron for a swap participant.
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct NeuronRecipe {
        /// The principal that should be the controller of the SNS neuron
        #[prost(message, optional, tag = "1")]
        pub controller: ::core::option::Option<::ic_base_types::PrincipalId>,
        /// The ID of the SNS neuron
        #[prost(message, optional, tag = "2")]
        pub neuron_id: ::core::option::Option<super::NeuronId>,
        /// The SNS neuron's stake in e8s (10E-8 of a token)
        #[prost(uint64, optional, tag = "3")]
        pub stake_e8s: ::core::option::Option<u64>,
        /// The duration in seconds that the neuron's dissolve delay will be set to.
        #[prost(uint64, optional, tag = "4")]
        pub dissolve_delay_seconds: ::core::option::Option<u64>,
        /// The neurons this neuron should follow
        #[prost(message, optional, tag = "5")]
        pub followees: ::core::option::Option<super::NeuronIds>,
        #[prost(oneof = "neuron_recipe::Participant", tags = "6, 7")]
        pub participant: ::core::option::Option<neuron_recipe::Participant>,
    }
    /// Nested message and enum types in `NeuronRecipe`.
    pub mod neuron_recipe {
        /// The info that for a participant in the Neurons' Fund
        #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct NeuronsFund {
            /// The neuron ID of the NNS neuron that participated in the Neurons' Fund.
            #[prost(uint64, optional, tag = "1")]
            pub nns_neuron_id: ::core::option::Option<u64>,
            /// The controller of the NNS neuron that participated in the Neurons' Fund.
            #[prost(message, optional, tag = "2")]
            pub nns_neuron_controller: ::core::option::Option<::ic_base_types::PrincipalId>,
            /// The hotkeys of the NNS neuron that participated in the Neurons' Fund.
            #[prost(message, optional, tag = "3")]
            pub nns_neuron_hotkeys:
                ::core::option::Option<::ic_nervous_system_proto::pb::v1::Principals>,
        }
        /// The info that for a direct participant
        #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct Direct {}
        #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
        #[allow(clippy::derive_partial_eq_without_eq)]
        #[derive(Clone, PartialEq, ::prost::Oneof)]
        pub enum Participant {
            #[prost(message, tag = "6")]
            Direct(Direct),
            #[prost(message, tag = "7")]
            NeuronsFund(NeuronsFund),
        }
    }
    /// Needed to cause prost to generate a type isomorphic to
    /// Optional<Vec<NeuronRecipe>>.
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct NeuronRecipes {
        #[prost(message, repeated, tag = "1")]
        pub neuron_recipes: ::prost::alloc::vec::Vec<NeuronRecipe>,
    }
}
/// The response for the `claim_swap_neurons` method.
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ClaimSwapNeuronsResponse {
    /// ClaimSwapNeurons will either return an error, in which
    /// no requested neurons were claimed, or a vector with
    /// various neuron statuses for the requested neuron ids.
    #[prost(
        oneof = "claim_swap_neurons_response::ClaimSwapNeuronsResult",
        tags = "4, 5"
    )]
    pub claim_swap_neurons_result:
        ::core::option::Option<claim_swap_neurons_response::ClaimSwapNeuronsResult>,
}
/// Nested message and enum types in `ClaimSwapNeuronsResponse`.
pub mod claim_swap_neurons_response {
    /// The ok result from `claim_swap_neurons. For every requested neuron,
    /// a SwapNeuron message is returned, and should equal the count of
    /// `ClaimSwapNeuronsRequest.neuron_recipes`.
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct ClaimedSwapNeurons {
        #[prost(message, repeated, tag = "1")]
        pub swap_neurons: ::prost::alloc::vec::Vec<SwapNeuron>,
    }
    /// SwapNeuron associates the status of a neuron attempting to be
    /// claimed with a NeuronId. The `id` field will correspond with a
    /// `ClaimSwapNeuronsRequest.neuron_recipes.neuron_id` field in
    /// the request object used in `claim_swap_neurons`.
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct SwapNeuron {
        #[prost(message, optional, tag = "1")]
        pub id: ::core::option::Option<super::NeuronId>,
        /// The status of claiming of a requested Sale neuron.
        #[prost(enumeration = "super::ClaimedSwapNeuronStatus", tag = "2")]
        pub status: i32,
    }
    /// ClaimSwapNeurons will either return an error, in which
    /// no requested neurons were claimed, or a vector with
    /// various neuron statuses for the requested neuron ids.
    #[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum ClaimSwapNeuronsResult {
        #[prost(message, tag = "4")]
        Ok(ClaimedSwapNeurons),
        #[prost(enumeration = "super::ClaimSwapNeuronsError", tag = "5")]
        Err(i32),
    }
}
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetMaturityModulationRequest {}
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetMaturityModulationResponse {
    #[prost(message, optional, tag = "1")]
    pub maturity_modulation: ::core::option::Option<governance::MaturityModulation>,
}
/// A request to add maturity to a neuron. The associated endpoint is only
/// available when governance is compiled with the `test` feature enabled.
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AddMaturityRequest {
    #[prost(message, optional, tag = "1")]
    pub id: ::core::option::Option<NeuronId>,
    #[prost(uint64, optional, tag = "2")]
    pub amount_e8s: ::core::option::Option<u64>,
}
/// The response to a request to add maturity to a neuron. The associated endpoint is only
/// available when governance is compiled with the `test` feature enabled.
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AddMaturityResponse {
    #[prost(uint64, optional, tag = "1")]
    pub new_maturity_e8s: ::core::option::Option<u64>,
}
/// A request to mint tokens for a particular principal. The associated endpoint
/// is only available on SNS governance, and only then when SNS governance is
/// compiled with the `test` feature enabled.
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MintTokensRequest {
    #[prost(message, optional, tag = "1")]
    pub recipient: ::core::option::Option<Account>,
    #[prost(uint64, optional, tag = "2")]
    pub amount_e8s: ::core::option::Option<u64>,
}
/// The response to a request to mint tokens for a particular principal. The
/// associated endpoint is only available on SNS governance, and only then when
/// SNS governance is compiled with the `test` feature enabled.
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MintTokensResponse {}
/// A Ledger subaccount.
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Subaccount {
    #[prost(bytes = "vec", tag = "1")]
    #[serde(with = "serde_bytes")]
    pub subaccount: ::prost::alloc::vec::Vec<u8>,
}
/// A Ledger account identified by the owner of the account `of` and
/// the `subaccount`. If the `subaccount` is not specified then the default
/// one is used.
#[derive(candid::CandidType, candid::Deserialize, comparable::Comparable)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Account {
    /// The owner of the account.
    #[prost(message, optional, tag = "1")]
    pub owner: ::core::option::Option<::ic_base_types::PrincipalId>,
    /// The subaccount of the account. If not set then the default
    /// subaccount (all bytes set to 0) is used.
    #[prost(message, optional, tag = "2")]
    pub subaccount: ::core::option::Option<Subaccount>,
}
/// The different types of neuron permissions, i.e., privileges to modify a neuron,
/// that principals can have.
#[derive(
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    clap::ArgEnum,
    strum_macros::EnumIter,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    ::prost::Enumeration,
)]
#[repr(i32)]
pub enum NeuronPermissionType {
    /// Unused, here for PB lint purposes.
    Unspecified = 0,
    /// The principal has permission to configure the neuron's dissolve state. This includes
    /// start dissolving, stop dissolving, and increasing the dissolve delay for the neuron.
    ConfigureDissolveState = 1,
    /// The principal has permission to add additional principals to modify the neuron.
    /// The nervous system parameter `NervousSystemParameters::neuron_grantable_permissions`
    /// determines the maximum set of privileges that a principal can grant to another principal in
    /// the given SNS.
    ManagePrincipals = 2,
    /// The principal has permission to submit proposals on behalf of the neuron.
    /// Submitting proposals can change a neuron's stake and thus this
    /// is potentially a balance changing operation.
    SubmitProposal = 3,
    /// The principal has permission to vote and follow other neurons on behalf of the neuron.
    Vote = 4,
    /// The principal has permission to disburse the neuron.
    Disburse = 5,
    /// The principal has permission to split the neuron.
    Split = 6,
    /// The principal has permission to merge the neuron's maturity into
    /// the neuron's stake.
    MergeMaturity = 7,
    /// The principal has permission to disburse the neuron's maturity to a
    /// given ledger account.
    DisburseMaturity = 8,
    /// The principal has permission to stake the neuron's maturity.
    StakeMaturity = 9,
    /// The principal has permission to grant/revoke permission to vote and submit
    /// proposals on behalf of the neuron to other principals.
    ManageVotingPermission = 10,
}
impl NeuronPermissionType {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            NeuronPermissionType::Unspecified => "NEURON_PERMISSION_TYPE_UNSPECIFIED",
            NeuronPermissionType::ConfigureDissolveState => {
                "NEURON_PERMISSION_TYPE_CONFIGURE_DISSOLVE_STATE"
            }
            NeuronPermissionType::ManagePrincipals => "NEURON_PERMISSION_TYPE_MANAGE_PRINCIPALS",
            NeuronPermissionType::SubmitProposal => "NEURON_PERMISSION_TYPE_SUBMIT_PROPOSAL",
            NeuronPermissionType::Vote => "NEURON_PERMISSION_TYPE_VOTE",
            NeuronPermissionType::Disburse => "NEURON_PERMISSION_TYPE_DISBURSE",
            NeuronPermissionType::Split => "NEURON_PERMISSION_TYPE_SPLIT",
            NeuronPermissionType::MergeMaturity => "NEURON_PERMISSION_TYPE_MERGE_MATURITY",
            NeuronPermissionType::DisburseMaturity => "NEURON_PERMISSION_TYPE_DISBURSE_MATURITY",
            NeuronPermissionType::StakeMaturity => "NEURON_PERMISSION_TYPE_STAKE_MATURITY",
            NeuronPermissionType::ManageVotingPermission => {
                "NEURON_PERMISSION_TYPE_MANAGE_VOTING_PERMISSION"
            }
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "NEURON_PERMISSION_TYPE_UNSPECIFIED" => Some(Self::Unspecified),
            "NEURON_PERMISSION_TYPE_CONFIGURE_DISSOLVE_STATE" => Some(Self::ConfigureDissolveState),
            "NEURON_PERMISSION_TYPE_MANAGE_PRINCIPALS" => Some(Self::ManagePrincipals),
            "NEURON_PERMISSION_TYPE_SUBMIT_PROPOSAL" => Some(Self::SubmitProposal),
            "NEURON_PERMISSION_TYPE_VOTE" => Some(Self::Vote),
            "NEURON_PERMISSION_TYPE_DISBURSE" => Some(Self::Disburse),
            "NEURON_PERMISSION_TYPE_SPLIT" => Some(Self::Split),
            "NEURON_PERMISSION_TYPE_MERGE_MATURITY" => Some(Self::MergeMaturity),
            "NEURON_PERMISSION_TYPE_DISBURSE_MATURITY" => Some(Self::DisburseMaturity),
            "NEURON_PERMISSION_TYPE_STAKE_MATURITY" => Some(Self::StakeMaturity),
            "NEURON_PERMISSION_TYPE_MANAGE_VOTING_PERMISSION" => Some(Self::ManageVotingPermission),
            _ => None,
        }
    }
}
/// The types of votes a neuron can issue.
#[derive(
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    ::prost::Enumeration,
)]
#[repr(i32)]
pub enum Vote {
    /// This exists because proto3 defaults to the 0 value on enums.
    /// This is not a valid choice, i.e., a vote with this choice will
    /// not be counted.
    Unspecified = 0,
    /// A vote for a proposal to be adopted.
    Yes = 1,
    /// A vote for a proposal to be rejected.
    No = 2,
}
impl Vote {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Vote::Unspecified => "VOTE_UNSPECIFIED",
            Vote::Yes => "VOTE_YES",
            Vote::No => "VOTE_NO",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "VOTE_UNSPECIFIED" => Some(Self::Unspecified),
            "VOTE_YES" => Some(Self::Yes),
            "VOTE_NO" => Some(Self::No),
            _ => None,
        }
    }
}
#[derive(
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    ::prost::Enumeration,
)]
#[repr(i32)]
pub enum LogVisibility {
    Unspecified = 0,
    /// The log is visible to the controllers of the dapp canister.
    Controllers = 1,
    /// The log is visible to the public.
    Public = 2,
}
impl LogVisibility {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            LogVisibility::Unspecified => "LOG_VISIBILITY_UNSPECIFIED",
            LogVisibility::Controllers => "LOG_VISIBILITY_CONTROLLERS",
            LogVisibility::Public => "LOG_VISIBILITY_PUBLIC",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "LOG_VISIBILITY_UNSPECIFIED" => Some(Self::Unspecified),
            "LOG_VISIBILITY_CONTROLLERS" => Some(Self::Controllers),
            "LOG_VISIBILITY_PUBLIC" => Some(Self::Public),
            _ => None,
        }
    }
}
#[derive(
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    ::prost::Enumeration,
)]
#[repr(i32)]
pub enum ProposalDecisionStatus {
    Unspecified = 0,
    /// The proposal is open for voting and a decision (adopt/reject) has yet to be made.
    Open = 1,
    /// The proposal has been rejected.
    Rejected = 2,
    /// The proposal has been adopted but either execution has not yet started
    /// or it has started but its outcome is not yet known.
    Adopted = 3,
    /// The proposal was adopted and successfully executed.
    Executed = 4,
    /// The proposal was adopted, but execution failed.
    Failed = 5,
}
impl ProposalDecisionStatus {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            ProposalDecisionStatus::Unspecified => "PROPOSAL_DECISION_STATUS_UNSPECIFIED",
            ProposalDecisionStatus::Open => "PROPOSAL_DECISION_STATUS_OPEN",
            ProposalDecisionStatus::Rejected => "PROPOSAL_DECISION_STATUS_REJECTED",
            ProposalDecisionStatus::Adopted => "PROPOSAL_DECISION_STATUS_ADOPTED",
            ProposalDecisionStatus::Executed => "PROPOSAL_DECISION_STATUS_EXECUTED",
            ProposalDecisionStatus::Failed => "PROPOSAL_DECISION_STATUS_FAILED",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "PROPOSAL_DECISION_STATUS_UNSPECIFIED" => Some(Self::Unspecified),
            "PROPOSAL_DECISION_STATUS_OPEN" => Some(Self::Open),
            "PROPOSAL_DECISION_STATUS_REJECTED" => Some(Self::Rejected),
            "PROPOSAL_DECISION_STATUS_ADOPTED" => Some(Self::Adopted),
            "PROPOSAL_DECISION_STATUS_EXECUTED" => Some(Self::Executed),
            "PROPOSAL_DECISION_STATUS_FAILED" => Some(Self::Failed),
            _ => None,
        }
    }
}
/// A proposal's status, with respect to reward distribution.
#[derive(
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    ::prost::Enumeration,
)]
#[repr(i32)]
pub enum ProposalRewardStatus {
    Unspecified = 0,
    /// The proposal still accepts votes, for the purpose of
    /// voting rewards. This implies nothing on the
    /// ProposalDecisionStatus, i.e., a proposal can be decided
    /// due to an absolute majority being in favor or against it,
    /// but other neuron holders can still cast their vote to get rewards.
    AcceptVotes = 1,
    /// The proposal no longer accepts votes. It is due to settle
    /// rewards at the next reward event.
    ReadyToSettle = 2,
    /// The proposal has been taken into account in a reward event, i.e.,
    /// the associated rewards have been settled.
    Settled = 3,
}
impl ProposalRewardStatus {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            ProposalRewardStatus::Unspecified => "PROPOSAL_REWARD_STATUS_UNSPECIFIED",
            ProposalRewardStatus::AcceptVotes => "PROPOSAL_REWARD_STATUS_ACCEPT_VOTES",
            ProposalRewardStatus::ReadyToSettle => "PROPOSAL_REWARD_STATUS_READY_TO_SETTLE",
            ProposalRewardStatus::Settled => "PROPOSAL_REWARD_STATUS_SETTLED",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "PROPOSAL_REWARD_STATUS_UNSPECIFIED" => Some(Self::Unspecified),
            "PROPOSAL_REWARD_STATUS_ACCEPT_VOTES" => Some(Self::AcceptVotes),
            "PROPOSAL_REWARD_STATUS_READY_TO_SETTLE" => Some(Self::ReadyToSettle),
            "PROPOSAL_REWARD_STATUS_SETTLED" => Some(Self::Settled),
            _ => None,
        }
    }
}
/// An enum for representing the various statuses a Neuron being claimed by the
/// `claim_swap_neurons` API may have. The status is reported back to callers of
/// the API (mainly the SNS Sale canister) to indicate the success of the
/// operation.
#[derive(
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    ::prost::Enumeration,
)]
#[repr(i32)]
pub enum ClaimedSwapNeuronStatus {
    /// Unspecified represents the default value for unknown enum values when deserializing.
    /// This value is unused.
    Unspecified = 0,
    /// The Neuron was successfully created and added to Governance. Future
    /// attempts to claim the same Neuron will result in
    /// `ClaimedSwapNeuronStatus::AlreadyExists`.
    Success = 1,
    /// The Neuron could not be created because one or more of its
    /// construction parameters are invalid, i.e. its stake was not
    /// above the required minimum neuron stake. Additional retries will
    /// result in the same status.
    Invalid = 2,
    /// The Neuron could not be created because it already existed
    /// within SNS Governance. Additional retries will result in
    /// the same status.
    AlreadyExists = 3,
    /// The Neuron could not be created because Governance has
    /// reached its configured memory limits. A retry is
    /// possible if more memory becomes available to the canister.
    MemoryExhausted = 4,
}
impl ClaimedSwapNeuronStatus {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            ClaimedSwapNeuronStatus::Unspecified => "CLAIMED_SWAP_NEURON_STATUS_UNSPECIFIED",
            ClaimedSwapNeuronStatus::Success => "CLAIMED_SWAP_NEURON_STATUS_SUCCESS",
            ClaimedSwapNeuronStatus::Invalid => "CLAIMED_SWAP_NEURON_STATUS_INVALID",
            ClaimedSwapNeuronStatus::AlreadyExists => "CLAIMED_SWAP_NEURON_STATUS_ALREADY_EXISTS",
            ClaimedSwapNeuronStatus::MemoryExhausted => {
                "CLAIMED_SWAP_NEURON_STATUS_MEMORY_EXHAUSTED"
            }
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "CLAIMED_SWAP_NEURON_STATUS_UNSPECIFIED" => Some(Self::Unspecified),
            "CLAIMED_SWAP_NEURON_STATUS_SUCCESS" => Some(Self::Success),
            "CLAIMED_SWAP_NEURON_STATUS_INVALID" => Some(Self::Invalid),
            "CLAIMED_SWAP_NEURON_STATUS_ALREADY_EXISTS" => Some(Self::AlreadyExists),
            "CLAIMED_SWAP_NEURON_STATUS_MEMORY_EXHAUSTED" => Some(Self::MemoryExhausted),
            _ => None,
        }
    }
}
/// An enum representing the errors that the `claim_swap_neurons` API may
/// return.
#[derive(
    candid::CandidType,
    candid::Deserialize,
    comparable::Comparable,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    ::prost::Enumeration,
)]
#[repr(i32)]
pub enum ClaimSwapNeuronsError {
    /// Unspecified represents the default value for unknown enum values when deserializing.
    /// This value is unused.
    Unspecified = 0,
    /// The caller of `claim_swap_neurons` was unauthorized. No
    /// requested neurons were claimed if this error is returned.
    Unauthorized = 1,
    /// The Governance canister encountered an internal error. No
    /// requested neurons were claimed if this error is returned.
    Internal = 2,
}
impl ClaimSwapNeuronsError {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            ClaimSwapNeuronsError::Unspecified => "CLAIM_SWAP_NEURONS_ERROR_UNSPECIFIED",
            ClaimSwapNeuronsError::Unauthorized => "CLAIM_SWAP_NEURONS_ERROR_UNAUTHORIZED",
            ClaimSwapNeuronsError::Internal => "CLAIM_SWAP_NEURONS_ERROR_INTERNAL",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "CLAIM_SWAP_NEURONS_ERROR_UNSPECIFIED" => Some(Self::Unspecified),
            "CLAIM_SWAP_NEURONS_ERROR_UNAUTHORIZED" => Some(Self::Unauthorized),
            "CLAIM_SWAP_NEURONS_ERROR_INTERNAL" => Some(Self::Internal),
            _ => None,
        }
    }
}
