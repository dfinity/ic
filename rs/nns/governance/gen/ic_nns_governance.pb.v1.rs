/// The entity that owns the nodes that run the network.
///
/// Note that this is different from a node operator, the entity that
/// operates the nodes. In terms of responsibilities, the node operator
/// is responsible for adding/removing and generally making sure that
/// the nodes are working, while the NodeProvider is the entity that
/// is compensated.
///
/// Note: The NodeOperatorRecord is defined in:
/// rs/protobuf/def/registry/node_operator/v1/node_operator.proto.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NodeProvider {
    /// The ID of the node provider.
    #[prost(message, optional, tag="1")]
    pub id: ::core::option::Option<::ic_base_types::PrincipalId>,
    /// The account where rewards earned from providing nodes will be sent.
    #[prost(message, optional, tag="2")]
    pub reward_account: ::core::option::Option<::ledger_canister::protobuf::AccountIdentifier>,
}
/// Used to update node provider records
///
/// There is no need to specify a node provider Principal ID here, as Governance
/// uses the Principal ID of the caller as the Node Provider Principal ID.
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UpdateNodeProvider {
    /// The account where rewards earned from providing nodes will be sent.
    #[prost(message, optional, tag="1")]
    pub reward_account: ::core::option::Option<::ledger_canister::protobuf::AccountIdentifier>,
}
/// How did a neuron vote in the recent past? This data is used by
/// other neurons to determine what neurons to follow.
#[derive(candid::CandidType, candid::Deserialize, Eq)] #[cfg_attr(feature = "test", derive(comparable::Comparable), compare_default)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BallotInfo {
    #[prost(message, optional, tag="1")]
    pub proposal_id: ::core::option::Option<::ic_nns_common::pb::v1::ProposalId>,
    #[prost(enumeration="Vote", tag="2")]
    pub vote: i32,
}
/// The result of querying for the state of a single neuron.
#[derive(candid::CandidType, candid::Deserialize, Eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NeuronInfo {
    /// The exact time at which this data was computed. This means, for
    /// example, that the exact time that this neuron will enter the
    /// dissolved state, assuming it is currently dissolving, is given
    /// by `retrieved_at_timestamp_seconds+dissolve_delay_seconds`.
    #[prost(uint64, tag="1")]
    pub retrieved_at_timestamp_seconds: u64,
    /// The current state of the neuron. See \[NeuronState\] for a
    /// description of the different states.
    #[prost(enumeration="NeuronState", tag="2")]
    pub state: i32,
    /// The current age of the neuron. See \[Neuron::age_seconds\]
    /// for details on how it is computed.
    #[prost(uint64, tag="3")]
    pub age_seconds: u64,
    /// The current dissolve delay of the neuron. See
    /// \[Neuron::dissolve_delay_seconds\] for details on how it is
    /// computed.
    #[prost(uint64, tag="4")]
    pub dissolve_delay_seconds: u64,
    /// See \[Neuron::recent_ballots\] for a description.
    #[prost(message, repeated, tag="5")]
    pub recent_ballots: ::prost::alloc::vec::Vec<BallotInfo>,
    /// Current voting power of the neuron.
    #[prost(uint64, tag="6")]
    pub voting_power: u64,
    /// When the Neuron was created. A neuron can only vote on proposals
    /// submitted after its creation date.
    #[prost(uint64, tag="7")]
    pub created_timestamp_seconds: u64,
    /// Current stake of the neuron, in e8s.
    #[prost(uint64, tag="8")]
    pub stake_e8s: u64,
    /// Timestamp when this neuron joined the community fund.
    #[prost(uint64, optional, tag="9")]
    pub joined_community_fund_timestamp_seconds: ::core::option::Option<u64>,
    /// If this neuron is a known neuron, this is data associated with it, including the neuron's name and (optionally) a description.
    #[prost(message, optional, tag="10")]
    pub known_neuron_data: ::core::option::Option<KnownNeuronData>,
}
/// A transfer performed from some account to stake a new neuron.
#[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NeuronStakeTransfer {
    /// When the transfer arrived at the governance canister.
    #[prost(uint64, tag="1")]
    pub transfer_timestamp: u64,
    /// The principal that made the transfer.
    #[prost(message, optional, tag="2")]
    pub from: ::core::option::Option<::ic_base_types::PrincipalId>,
    /// The (optional) subaccount from which the transfer was made.
    #[prost(bytes="vec", tag="3")]
    pub from_subaccount: ::prost::alloc::vec::Vec<u8>,
    /// The subaccount to which the transfer was made.
    #[prost(bytes="vec", tag="4")]
    pub to_subaccount: ::prost::alloc::vec::Vec<u8>,
    /// The amount of stake that was transfered.
    #[prost(uint64, tag="5")]
    pub neuron_stake_e8s: u64,
    /// The block height at which the transfer occurred.
    #[prost(uint64, tag="6")]
    pub block_height: u64,
    /// The memo sent with the transfer.
    #[prost(uint64, tag="7")]
    pub memo: u64,
}
/// This structure represents a neuron "at rest" in governance system of
/// the Internet Computer IC.
#[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable), compare_default)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Neuron {
    /// The id of the neuron.
    ///
    /// This is stored here temporarily, since its also stored on the map
    /// that contains neurons.
    ///
    /// Initialization uses ids for the following graph. We need neurons
    /// to come into existence at genesis with pre-chosen ids, so a
    /// neuron needs to have an id. We could alternatively choose a
    /// unique naming scheme instead and chose the ids on the
    /// initialization of the canister.
    #[prost(message, optional, tag="1")]
    pub id: ::core::option::Option<::ic_nns_common::pb::v1::NeuronId>,
    /// The principal of the ICP ledger account where the locked ICP
    /// balance resides. This principal is indistinguishable from one
    /// identifying a public key pair, such that those browsing the ICP
    /// ledger cannot tell which balances belong to neurons.
    #[prost(bytes="vec", tag="2")]
    pub account: ::prost::alloc::vec::Vec<u8>,
    /// The principal that actually controls the neuron. The principal
    /// must identify a public key pair, which acts as a “master key”,
    /// such that the corresponding secret key should be kept very
    /// secure. The principal may control many neurons.
    #[prost(message, optional, tag="3")]
    pub controller: ::core::option::Option<::ic_base_types::PrincipalId>,
    /// Keys that can be used to perform actions with limited privileges
    /// without exposing the secret key corresponding to the principal
    /// e.g. could be a WebAuthn key.
    #[prost(message, repeated, tag="4")]
    pub hot_keys: ::prost::alloc::vec::Vec<::ic_base_types::PrincipalId>,
    /// The amount of staked ICP tokens, measured in fractions of 10E-8
    /// of an ICP.
    ///
    /// Cached record of the locked ICP balance on the ICP ledger.
    ///
    /// For neuron creation: has to contain some minimum amount. A
    /// spawned neuron with less stake cannot increase its dissolve
    /// delay.
    #[prost(uint64, tag="5")]
    pub cached_neuron_stake_e8s: u64,
    /// The amount of ICP that this neuron has forfeited due to making
    /// proposals that were subsequently rejected or from using the
    /// 'manage neurons through proposals' functionality. Must be smaller
    /// than 'neuron_stake_e8s'. When a neuron is disbursed, these ICP
    /// will be burned.
    #[prost(uint64, tag="6")]
    pub neuron_fees_e8s: u64,
    /// When the Neuron was created. A neuron can only vote on proposals
    /// submitted after its creation date.
    #[prost(uint64, tag="7")]
    pub created_timestamp_seconds: u64,
    /// The timestamp, in seconds from the Unix epoch, corresponding to
    /// the time this neuron has started aging. This is either the
    /// creation time or the last time at which the neuron has stopped
    /// dissolving.
    ///
    /// This value is meaningless when the neuron is dissolving, since a
    /// dissolving neurons always has age zero. The canonical value of
    /// this field for a dissolving neuron is `u64::MAX`.
    #[prost(uint64, tag="8")]
    pub aging_since_timestamp_seconds: u64,
    /// Map `Topic` to followees. The key is represented by an integer as
    /// Protobuf does not support enum keys in maps.
    #[prost(map="int32, message", tag="11")]
    pub followees: ::std::collections::HashMap<i32, neuron::Followees>,
    /// Information about how this neuron voted in the recent past. It
    /// only contains proposals that the neuron voted yes or no on.
    #[prost(message, repeated, tag="12")]
    pub recent_ballots: ::prost::alloc::vec::Vec<BallotInfo>,
    /// `true` if this neuron has passed KYC, `false` otherwise
    #[prost(bool, tag="13")]
    pub kyc_verified: bool,
    /// The record of the transfer that was made to create this neuron.
    #[prost(message, optional, tag="14")]
    pub transfer: ::core::option::Option<NeuronStakeTransfer>,
    /// The accumulated maturity of the neuron, in "e8s equivalent".
    ///
    /// The unit is "e8s equivalent" to insist that, while this quantity is on
    /// the same scale as ICPs, maturity is not directly convertible to ICPs:
    /// conversion requires a minting event to spawn a new neuron.
    #[prost(uint64, tag="15")]
    pub maturity_e8s_equivalent: u64,
    /// Whether this neuron is "Not for profit", making it dissolvable
    /// by voting.
    #[prost(bool, tag="16")]
    pub not_for_profit: bool,
    /// If set, this neuron participates with all of its stake in the
    /// Internet Computer's community fund. Setting this value is an
    /// irreversible decision that can only be made by the neuron's
    /// controller.
    #[prost(uint64, optional, tag="17")]
    pub joined_community_fund_timestamp_seconds: ::core::option::Option<u64>,
    /// If set, the neuron belongs to the "known neurons". It has been given a name and maybe a description.
    #[prost(message, optional, tag="18")]
    pub known_neuron_data: ::core::option::Option<KnownNeuronData>,
    /// At any time, at most one of `when_dissolved` and
    /// `dissolve_delay` are specified.
    ///
    /// `NotDissolving`. This is represented by `dissolve_delay` being
    /// set to a non zero value.
    ///
    /// `Dissolving`. This is represented by `when_dissolved` being
    /// set, and this value is in the future.
    ///
    /// `Dissolved`. All other states represent the dissolved
    /// state. That is, (a) `when_dissolved` is set and in the past,
    /// (b) `dissolve_delay` is set to zero, (c) neither value is set.
    ///
    /// Cf. \[Neuron::stop_dissolving\] and \[Neuron::start_dissolving\].
    #[prost(oneof="neuron::DissolveState", tags="9, 10")]
    pub dissolve_state: ::core::option::Option<neuron::DissolveState>,
}
/// Nested message and enum types in `Neuron`.
pub mod neuron {
    /// Protobuf representing a list of followees of a neuron for a
    /// specific topic.
    #[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Followees {
        #[prost(message, repeated, tag="1")]
        pub followees: ::prost::alloc::vec::Vec<::ic_nns_common::pb::v1::NeuronId>,
    }
    /// At any time, at most one of `when_dissolved` and
    /// `dissolve_delay` are specified.
    ///
    /// `NotDissolving`. This is represented by `dissolve_delay` being
    /// set to a non zero value.
    ///
    /// `Dissolving`. This is represented by `when_dissolved` being
    /// set, and this value is in the future.
    ///
    /// `Dissolved`. All other states represent the dissolved
    /// state. That is, (a) `when_dissolved` is set and in the past,
    /// (b) `dissolve_delay` is set to zero, (c) neither value is set.
    ///
    /// Cf. \[Neuron::stop_dissolving\] and \[Neuron::start_dissolving\].
    #[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum DissolveState {
        /// When the dissolve timer is running, this stores the timestamp,
        /// in seconds from the Unix epoch, at which the neuron becomes
        /// dissolved.
        ///
        /// At any time while the neuron is dissolving, the neuron owner
        /// may pause dissolving, in which case `dissolve_delay_seconds`
        /// will get assigned to: `when_dissolved_timestamp_seconds -
        /// <timestamp when the action is taken>`.
        #[prost(uint64, tag="9")]
        WhenDissolvedTimestampSeconds(u64),
        /// When the dissolve timer is stopped, this stores how much time,
        /// in seconds, the dissolve timer will be started with. Can be at
        /// most 8 years.
        ///
        /// At any time while in this state, the neuron owner may (re)start
        /// dissolving, in which case `when_dissolved_timestamp_seconds`
        /// will get assigned to: `<timestamp when the action is taken> +
        /// dissolve_delay_seconds`.
        #[prost(uint64, tag="10")]
        DissolveDelaySeconds(u64),
    }
}
/// Payload of a proposal that calls a function on another NNS
/// canister. The canister and function to call is derived from the
/// `nns_function`.
#[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExecuteNnsFunction {
    /// This enum value determines what canister to call and what NNS
    /// function to call on that canister.
    #[prost(enumeration="NnsFunction", tag="1")]
    pub nns_function: i32,
    /// The payload of the NNS function.
    #[prost(bytes="vec", tag="2")]
    pub payload: ::prost::alloc::vec::Vec<u8>,
}
/// If adopted, a motion should guide the future strategy of the
/// Internet Computer ecosystem.
#[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable), self_describing)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Motion {
    /// The text of the motion. Maximum 100kib.
    #[prost(string, tag="1")]
    pub motion_text: ::prost::alloc::string::String,
}
/// For all Neurons controlled by the given principals, set their
/// KYC status to `kyc_verified=true`.
#[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ApproveGenesisKyc {
    #[prost(message, repeated, tag="1")]
    pub principals: ::prost::alloc::vec::Vec<::ic_base_types::PrincipalId>,
}
/// Adds and/or removes NodeProviders from the list of current
/// node providers.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]
#[cfg_attr(feature = "test", derive(comparable::Comparable))]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AddOrRemoveNodeProvider {
    #[prost(oneof="add_or_remove_node_provider::Change", tags="1, 2")]
    pub change: ::core::option::Option<add_or_remove_node_provider::Change>,
}
/// Nested message and enum types in `AddOrRemoveNodeProvider`.
pub mod add_or_remove_node_provider {
    #[derive(candid::CandidType, candid::Deserialize, serde::Serialize)]
#[cfg_attr(feature = "test", derive(comparable::Comparable))]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Change {
        #[prost(message, tag="1")]
        ToAdd(super::NodeProvider),
        #[prost(message, tag="2")]
        ToRemove(super::NodeProvider),
    }
}
/// This proposal payload is used to reward a node provider by minting
/// ICPs directly to the node provider's ledger account, or into a new
/// neuron created on behalf of the node provider.
#[derive(candid::CandidType, candid::Deserialize)]
#[cfg_attr(feature = "test", derive(comparable::Comparable))]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RewardNodeProvider {
    /// The NodeProvider to reward.
    #[prost(message, optional, tag="1")]
    pub node_provider: ::core::option::Option<NodeProvider>,
    /// The amount of e8s to mint to reward the node provider.
    #[prost(uint64, tag="2")]
    pub amount_e8s: u64,
    #[prost(oneof="reward_node_provider::RewardMode", tags="4, 5")]
    pub reward_mode: ::core::option::Option<reward_node_provider::RewardMode>,
}
/// Nested message and enum types in `RewardNodeProvider`.
pub mod reward_node_provider {
    /// This message specifies how to create a new neuron on behalf of
    /// the node provider.
    ///
    /// - The controller of the new neuron is the node provider's
    ///   principal.
    ///
    /// - The account is chosen at random.
    ///
    /// - The stake of the new neuron is `amount_e8s`.
    ///
    /// - `dissolve_delay_seconds` is as specified in the proto.
    ///
    /// - `kyc_verified` is set to true, as node providers are
    ///   (implicitly) KYC'ed.
    ///
    /// - `not_for_profit` is set to false.
    ///
    /// - All other values are set as for other neurons: timestamp is
    ///   now, following is set up per default, maturity is 0, neuron fee
    ///   is 0.
    #[derive(candid::CandidType, candid::Deserialize)]
#[cfg_attr(feature = "test", derive(comparable::Comparable))]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct RewardToNeuron {
        #[prost(uint64, tag="1")]
        pub dissolve_delay_seconds: u64,
    }
    #[derive(candid::CandidType, candid::Deserialize)]
#[cfg_attr(feature = "test", derive(comparable::Comparable))]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct RewardToAccount {
        #[prost(message, optional, tag="1")]
        pub to_account: ::core::option::Option<::ledger_canister::protobuf::AccountIdentifier>,
    }
    #[derive(candid::CandidType, candid::Deserialize)]
#[cfg_attr(feature = "test", derive(comparable::Comparable))]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum RewardMode {
        /// If this is specified, executing this proposal will create a
        /// neuron instead of directly minting ICP into the node provider's
        /// account.
        #[prost(message, tag="4")]
        RewardToNeuron(RewardToNeuron),
        /// If this is specificed, executing this proposal will mint to the
        /// specified account.
        #[prost(message, tag="5")]
        RewardToAccount(RewardToAccount),
    }
}
#[derive(candid::CandidType, candid::Deserialize)]
#[cfg_attr(feature = "test", derive(comparable::Comparable))]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RewardNodeProviders {
    #[prost(message, repeated, tag="1")]
    pub rewards: ::prost::alloc::vec::Vec<RewardNodeProvider>,
    /// If true, reward Node Providers with the rewards returned by the Registry's
    /// get_node_providers_monthly_xdr_rewards method
    #[prost(bool, optional, tag="2")]
    pub use_registry_derived_rewards: ::core::option::Option<bool>,
}
/// Changes the default followees to match the one provided.
/// This completely replaces the default followees so entries for all
/// Topics (except ManageNeuron) must be provided on each proposal.
#[derive(candid::CandidType, candid::Deserialize)]
#[cfg_attr(feature = "test", derive(comparable::Comparable))]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SetDefaultFollowees {
    #[prost(map="int32, message", tag="1")]
    pub default_followees: ::std::collections::HashMap<i32, neuron::Followees>,
}
/// A proposal is the immutable input of a proposal submission. This contains
/// all the information from the original proposal submission.
///
/// Making a proposal implicitly votes yes.
#[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable), compare_default)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Proposal {
    /// Must be present (enforced at the application layer, not by PB).
    /// A brief description of what the proposal does.
    /// Size in bytes must be in the interval [5, 256].
    #[prost(string, optional, tag="20")]
    pub title: ::core::option::Option<::prost::alloc::string::String>,
    /// Text providing a short description of the proposal, composed
    /// using a maximum of 15000 bytes of characters.
    #[prost(string, tag="1")]
    pub summary: ::prost::alloc::string::String,
    /// The Web address of additional content required to evaluate the
    /// proposal, specified using HTTPS. For example, the address might
    /// describe content supporting the assignment of a DCID (data center
    /// id) to a new data center. The URL string must not be longer than
    /// 2000 bytes.
    #[prost(string, tag="2")]
    pub url: ::prost::alloc::string::String,
    /// This section describes the action that the proposal proposes to
    /// take.
    #[prost(oneof="proposal::Action", tags="10, 12, 13, 14, 15, 16, 17, 18, 19, 21")]
    pub action: ::core::option::Option<proposal::Action>,
}
/// Nested message and enum types in `Proposal`.
pub mod proposal {
    /// This section describes the action that the proposal proposes to
    /// take.
    #[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Action {
        /// This type of proposal calls a major function on a specified
        /// target neuron. Only the followees of the target neuron (on the
        /// topic \[Topic::ManageNeuron\]) may vote on these proposals,
        /// which effectively provides the followees with control over the
        /// target neuron. This can provide a convenient and highly secure
        /// means for a team of individuals to manage an important
        /// neuron. For example, a neuron might hold a large balance, or
        /// belong to an organization of high repute, and be publicized so
        /// that many other neurons can follow its vote. In both cases,
        /// managing the private key of the principal securely could be
        /// problematic (either a single copy is held, which is very
        /// insecure and provides for a single party to take control, or a
        /// group of individuals must divide responsibility, for example
        /// using threshold cryptography, which is complex and time
        /// consuming). To address this, using this proposal type, the
        /// important neuron can be configured to follow the neurons
        /// controlled by individual members of a team. Now they can submit
        /// proposals to make the important neuron perform actions, which
        /// are adopted if and only if a majority of them vote to
        /// adopt. Nearly any command on the target neuron can be executed,
        /// including commands that change the follow rules, allowing the
        /// set of team members to be dynamic. Only the final step of
        /// dissolving the neuron once its dissolve delay reaches zero
        /// cannot be performed using this type of proposal (since this
        /// would allow control/“ownership” over the locked balances to be
        /// transferred). To prevent a neuron falling under the malign
        /// control of the principal’s private key by accident, the private
        /// key can be destroyed so that the neuron can only be controlled
        /// by its followees, although this makes it impossible to
        /// subsequently unlock the balance.
        #[prost(message, tag="10")]
        ManageNeuron(::prost::alloc::boxed::Box<super::ManageNeuron>),
        /// Propose a change to some network parameters of network
        /// economics.
        #[prost(message, tag="12")]
        ManageNetworkEconomics(super::NetworkEconomics),
        /// See \[Motion\]
        #[prost(message, tag="13")]
        Motion(super::Motion),
        /// A update affecting something outside of the Governance
        /// canister.
        #[prost(message, tag="14")]
        ExecuteNnsFunction(super::ExecuteNnsFunction),
        /// Approve Genesis KYC for a given list of principals.
        #[prost(message, tag="15")]
        ApproveGenesisKyc(super::ApproveGenesisKyc),
        /// Add/remove NodeProvider from the list of NodeProviders
        #[prost(message, tag="16")]
        AddOrRemoveNodeProvider(super::AddOrRemoveNodeProvider),
        /// Reward a NodeProvider
        #[prost(message, tag="17")]
        RewardNodeProvider(super::RewardNodeProvider),
        /// Set the default following
        #[prost(message, tag="18")]
        SetDefaultFollowees(super::SetDefaultFollowees),
        /// Reward multiple NodeProvider
        #[prost(message, tag="19")]
        RewardNodeProviders(super::RewardNodeProviders),
        /// Register Known Neuron
        #[prost(message, tag="21")]
        RegisterKnownNeuron(super::KnownNeuron),
    }
}
/// Empty message to use in oneof fields that represent empty
/// enums.
#[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Empty {
}
/// All operations that modify the state of an existing neuron are
/// represented by instances of `ManageNeuron`.
///
/// All commands are available to the `controller` of the neuron. In
/// addition, commands related to voting, i.g., \[manage_neuron::Follow\]
/// and \[manage_neuron::RegisterVote\], are also available to the
/// registered hot keys of the neuron.
#[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ManageNeuron {
    /// This is the legacy way to specify neuron IDs that is now discouraged.
    #[prost(message, optional, tag="1")]
    pub id: ::core::option::Option<::ic_nns_common::pb::v1::NeuronId>,
    /// The ID of the neuron to manage. This can either be a subaccount or a neuron ID.
    #[prost(oneof="manage_neuron::NeuronIdOrSubaccount", tags="11, 12")]
    pub neuron_id_or_subaccount: ::core::option::Option<manage_neuron::NeuronIdOrSubaccount>,
    #[prost(oneof="manage_neuron::Command", tags="2, 3, 4, 5, 6, 7, 8, 9, 10, 13, 14")]
    pub command: ::core::option::Option<manage_neuron::Command>,
}
/// Nested message and enum types in `ManageNeuron`.
pub mod manage_neuron {
    /// The dissolve delay of a neuron can be increased up to a maximum
    /// of 8 years.
    #[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct IncreaseDissolveDelay {
        #[prost(uint32, tag="1")]
        pub additional_dissolve_delay_seconds: u32,
    }
    #[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct StartDissolving {
    }
    #[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct StopDissolving {
    }
    /// Add a new hot key that can be used to manage the neuron. This
    /// provides an alternative to using the controller principal’s cold key to
    /// manage the neuron, which might be onerous and difficult to keep
    /// secure, especially if it is used regularly. A hot key might be a
    /// WebAuthn key that is maintained inside a user device, such as a
    /// smartphone.
    #[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct AddHotKey {
        #[prost(message, optional, tag="1")]
        pub new_hot_key: ::core::option::Option<::ic_base_types::PrincipalId>,
    }
    /// Remove a hot key that has been previously assigned to the neuron.
    #[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct RemoveHotKey {
        #[prost(message, optional, tag="1")]
        pub hot_key_to_remove: ::core::option::Option<::ic_base_types::PrincipalId>,
    }
    /// An (idempotent) alternative to IncreaseDissolveDelay where the dissolve delay
    /// is passed as an absolute timestamp in seconds since the unix epoch.
    #[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct SetDissolveTimestamp {
        #[prost(uint64, tag="1")]
        pub dissolve_timestamp_seconds: u64,
    }
    /// Join the Internet Computer's community fund with this neuron's
    /// entire stake. Caution: this operation is not reversible.
    #[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct JoinCommunityFund {
    }
    /// Commands that only configure a given neuron, but do not interact
    /// with the outside world. They all require the caller to be the
    /// controller of the neuron.
    #[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Configure {
        #[prost(oneof="configure::Operation", tags="1, 2, 3, 4, 5, 6, 7")]
        pub operation: ::core::option::Option<configure::Operation>,
    }
    /// Nested message and enum types in `Configure`.
    pub mod configure {
        #[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
        #[derive(Clone, PartialEq, ::prost::Oneof)]
        pub enum Operation {
            #[prost(message, tag="1")]
            IncreaseDissolveDelay(super::IncreaseDissolveDelay),
            #[prost(message, tag="2")]
            StartDissolving(super::StartDissolving),
            #[prost(message, tag="3")]
            StopDissolving(super::StopDissolving),
            #[prost(message, tag="4")]
            AddHotKey(super::AddHotKey),
            #[prost(message, tag="5")]
            RemoveHotKey(super::RemoveHotKey),
            #[prost(message, tag="6")]
            SetDissolveTimestamp(super::SetDissolveTimestamp),
            #[prost(message, tag="7")]
            JoinCommunityFund(super::JoinCommunityFund),
        }
    }
    /// Disburse this neuron's stake: transfer the staked ICP to the
    /// specified account.
    #[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Disburse {
        /// The (optional) amount to transfer. If not specified the cached
        /// stake is used.
        #[prost(message, optional, tag="1")]
        pub amount: ::core::option::Option<disburse::Amount>,
        /// The principal to which to transfer the stake.
        #[prost(message, optional, tag="2")]
        pub to_account: ::core::option::Option<::ledger_canister::protobuf::AccountIdentifier>,
    }
    /// Nested message and enum types in `Disburse`.
    pub mod disburse {
        #[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct Amount {
            #[prost(uint64, tag="1")]
            pub e8s: u64,
        }
    }
    /// Split this neuron into two neurons.
    ///
    /// The child neuron retains the parent neuron's properties.
    #[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Split {
        /// The amount to split to the child neuron.
        #[prost(uint64, tag="1")]
        pub amount_e8s: u64,
    }
    /// Merge another neuron into this neuron.
    #[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Merge {
        /// The neuron to merge stake and maturity from.
        #[prost(message, optional, tag="1")]
        pub source_neuron_id: ::core::option::Option<::ic_nns_common::pb::v1::NeuronId>,
    }
    /// When the maturity of a neuron has risen above a threshold, it can
    /// be instructed to spawn a new neuron. This creates a new neuron
    /// that locks a new balance of ICP on the ledger. The new neuron can
    /// remain controlled by the same principal as its parent, or be
    /// assigned to a new principal.
    #[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Spawn {
        /// If not set, the spawned neuron will have the same controller as
        /// this neuron.
        #[prost(message, optional, tag="1")]
        pub new_controller: ::core::option::Option<::ic_base_types::PrincipalId>,
        /// The nonce with which to create the subaccount.
        #[prost(uint64, optional, tag="2")]
        pub nonce: ::core::option::Option<u64>,
        /// The percentage to spawn, from 1 to 100 (inclusive).
        #[prost(uint32, optional, tag="3")]
        pub percentage_to_spawn: ::core::option::Option<u32>,
    }
    /// Merge the maturity of a neuron into the current stake.
    /// The caller can choose a percentage of the current maturity to merge into
    /// the existing stake. The resulting amount to merge must be greater than
    /// or equal to the transaction fee.
    #[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct MergeMaturity {
        /// The percentage to merge, from 1 to 100 (inclusive).
        #[prost(uint32, tag="1")]
        pub percentage_to_merge: u32,
    }
    /// Disburse a portion of this neuron's stake into another neuron.
    /// This allows to split a neuron but with a new dissolve delay
    /// and owned by someone else.
    #[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct DisburseToNeuron {
        /// The controller of the new neuron (must be set).
        #[prost(message, optional, tag="1")]
        pub new_controller: ::core::option::Option<::ic_base_types::PrincipalId>,
        /// The amount to disburse.
        #[prost(uint64, tag="2")]
        pub amount_e8s: u64,
        /// The dissolve delay of the new neuron.
        #[prost(uint64, tag="3")]
        pub dissolve_delay_seconds: u64,
        /// Whether the new neuron has been kyc verified.
        #[prost(bool, tag="4")]
        pub kyc_verified: bool,
        /// The nonce with which to create the subaccount.
        #[prost(uint64, tag="5")]
        pub nonce: u64,
    }
    /// Add a rule that enables the neuron to vote automatically on
    /// proposals that belong to a specific topic, by specifying a group
    /// of followee neurons whose majority vote is followed. The
    /// configuration of such follow rules can be used to a) distribute
    /// control over voting power amongst multiple entities, b) have a
    /// neuron vote automatically when its owner lacks time to evaluate
    /// newly submitted proposals, c) have a neuron vote automatically
    /// when its own lacks the expertise to evaluate newly submitted
    /// proposals, and d) for other purposes. A follow rule specifies a
    /// set of followees. Once a majority of the followees votes to adopt
    /// or reject a proposal belonging to the specified topic, the neuron
    /// votes the same way. If it becomes impossible for a majority of
    /// the followees to adopt (for example, because they are split 50-50
    /// between adopt and reject), then the neuron votes to reject. If a
    /// rule is specified where the proposal topic is UNSPECIFIED, then it
    /// becomes a catch-all follow rule, which will be used to vote
    /// automatically on proposals belonging to topics for which no
    /// specific rule has been specified.
    ///
    /// If the list 'followees' is empty, this removes following for a
    /// specific topic.
    #[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Follow {
        /// Topic UNSPECIFIED means add following for the 'catch all'.
        #[prost(enumeration="super::Topic", tag="1")]
        pub topic: i32,
        #[prost(message, repeated, tag="2")]
        pub followees: ::prost::alloc::vec::Vec<::ic_nns_common::pb::v1::NeuronId>,
    }
    /// Have the neuron vote to either adopt or reject a proposal with a specified
    /// id.
    #[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct RegisterVote {
        #[prost(message, optional, tag="1")]
        pub proposal: ::core::option::Option<::ic_nns_common::pb::v1::ProposalId>,
        #[prost(enumeration="super::Vote", tag="2")]
        pub vote: i32,
    }
    /// Claim a new neuron or refresh the stake of an existing neuron.
    #[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct ClaimOrRefresh {
        #[prost(oneof="claim_or_refresh::By", tags="1, 2, 3")]
        pub by: ::core::option::Option<claim_or_refresh::By>,
    }
    /// Nested message and enum types in `ClaimOrRefresh`.
    pub mod claim_or_refresh {
        #[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
        #[derive(Clone, PartialEq, ::prost::Message)]
        pub struct MemoAndController {
            #[prost(uint64, tag="1")]
            pub memo: u64,
            #[prost(message, optional, tag="2")]
            pub controller: ::core::option::Option<::ic_base_types::PrincipalId>,
        }
        #[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
        #[derive(Clone, PartialEq, ::prost::Oneof)]
        pub enum By {
            /// DEPRECATED: Use MemoAndController and omit the controller.
            #[prost(uint64, tag="1")]
            Memo(u64),
            /// Claim or refresh a neuron, by providing the memo used in the
            /// staking stransfer and 'controller' as the principal id used to
            /// calculate the subaccount to which the transfer was made. If
            /// 'controller' is omitted, the principal id of the caller is
            /// used.
            #[prost(message, tag="2")]
            MemoAndController(MemoAndController),
            /// This just serves as a tag to indicate that the neuron should be
            /// refreshed by it's id or subaccount. This does not work to claim
            /// new neurons.
            #[prost(message, tag="3")]
            NeuronIdOrSubaccount(super::super::Empty),
        }
    }
    /// The ID of the neuron to manage. This can either be a subaccount or a neuron ID.
    #[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum NeuronIdOrSubaccount {
        #[prost(bytes, tag="11")]
        Subaccount(::prost::alloc::vec::Vec<u8>),
        #[prost(message, tag="12")]
        NeuronId(::ic_nns_common::pb::v1::NeuronId),
    }
    #[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Command {
        #[prost(message, tag="2")]
        Configure(Configure),
        #[prost(message, tag="3")]
        Disburse(Disburse),
        #[prost(message, tag="4")]
        Spawn(Spawn),
        #[prost(message, tag="5")]
        Follow(Follow),
        #[prost(message, tag="6")]
        MakeProposal(::prost::alloc::boxed::Box<super::Proposal>),
        #[prost(message, tag="7")]
        RegisterVote(RegisterVote),
        #[prost(message, tag="8")]
        Split(Split),
        #[prost(message, tag="9")]
        DisburseToNeuron(DisburseToNeuron),
        #[prost(message, tag="10")]
        ClaimOrRefresh(ClaimOrRefresh),
        #[prost(message, tag="13")]
        MergeMaturity(MergeMaturity),
        #[prost(message, tag="14")]
        Merge(Merge),
    }
}
/// The response of the ManageNeuron command
///
/// There is a dedicated response type for each `ManageNeuron.command` field
#[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ManageNeuronResponse {
    #[prost(oneof="manage_neuron_response::Command", tags="1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12")]
    pub command: ::core::option::Option<manage_neuron_response::Command>,
}
/// Nested message and enum types in `ManageNeuronResponse`.
pub mod manage_neuron_response {
    #[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct ConfigureResponse {
    }
    #[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct DisburseResponse {
        /// The block height at which the disburse transfer happened
        #[prost(uint64, tag="1")]
        pub transfer_block_height: u64,
    }
    #[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct SpawnResponse {
        /// The ID of the Neuron created from spawning a Neuron
        #[prost(message, optional, tag="1")]
        pub created_neuron_id: ::core::option::Option<::ic_nns_common::pb::v1::NeuronId>,
    }
    #[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct MergeMaturityResponse {
        #[prost(uint64, tag="1")]
        pub merged_maturity_e8s: u64,
        #[prost(uint64, tag="2")]
        pub new_stake_e8s: u64,
    }
    #[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct FollowResponse {
    }
    #[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct MakeProposalResponse {
        /// The ID of the created proposal
        #[prost(message, optional, tag="1")]
        pub proposal_id: ::core::option::Option<::ic_nns_common::pb::v1::ProposalId>,
    }
    #[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct RegisterVoteResponse {
    }
    #[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct SplitResponse {
        /// The ID of the Neuron created from splitting another Neuron
        #[prost(message, optional, tag="1")]
        pub created_neuron_id: ::core::option::Option<::ic_nns_common::pb::v1::NeuronId>,
    }
    #[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct MergeResponse {
    }
    #[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct DisburseToNeuronResponse {
        /// The ID of the Neuron created from disbursing a Neuron
        #[prost(message, optional, tag="1")]
        pub created_neuron_id: ::core::option::Option<::ic_nns_common::pb::v1::NeuronId>,
    }
    #[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct ClaimOrRefreshResponse {
        #[prost(message, optional, tag="1")]
        pub refreshed_neuron_id: ::core::option::Option<::ic_nns_common::pb::v1::NeuronId>,
    }
    #[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Command {
        #[prost(message, tag="1")]
        Error(super::GovernanceError),
        #[prost(message, tag="2")]
        Configure(ConfigureResponse),
        #[prost(message, tag="3")]
        Disburse(DisburseResponse),
        #[prost(message, tag="4")]
        Spawn(SpawnResponse),
        #[prost(message, tag="5")]
        Follow(FollowResponse),
        #[prost(message, tag="6")]
        MakeProposal(MakeProposalResponse),
        #[prost(message, tag="7")]
        RegisterVote(RegisterVoteResponse),
        #[prost(message, tag="8")]
        Split(SplitResponse),
        #[prost(message, tag="9")]
        DisburseToNeuron(DisburseToNeuronResponse),
        #[prost(message, tag="10")]
        ClaimOrRefresh(ClaimOrRefreshResponse),
        #[prost(message, tag="11")]
        MergeMaturity(MergeMaturityResponse),
        #[prost(message, tag="12")]
        Merge(MergeResponse),
    }
}
#[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable), compare_default)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GovernanceError {
    #[prost(enumeration="governance_error::ErrorType", tag="1")]
    pub error_type: i32,
    #[prost(string, tag="2")]
    pub error_message: ::prost::alloc::string::String,
}
/// Nested message and enum types in `GovernanceError`.
pub mod governance_error {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum ErrorType {
        Unspecified = 0,
        /// The operation was successfully completed.
        Ok = 1,
        /// This operation is not available, e.g., not implemented.
        Unavailable = 2,
        /// The caller is not authorized to perform this operation.
        NotAuthorized = 3,
        /// Some entity required for the operation (for example, a neuron) was not found.
        NotFound = 4,
        /// The command was missing or invalid. This is a permanent error.
        InvalidCommand = 5,
        /// The neuron is dissolving or dissolved and the operation requires it to
        /// be not dissolving (that is, having a non-zero dissolve delay that is
        /// accumulating age).
        RequiresNotDissolving = 6,
        /// The neuron is not dissolving or dissolved and the operation requires
        /// it to be dissolving (that is, having a non-zero dissolve delay with
        /// zero age that is not accumulating).
        RequiresDissolving = 7,
        /// The neuron is not dissolving and not dissolved and the operation
        /// requires it to be dissolved (that is, having a dissolve delay of zero
        /// and an age of zero).
        RequiresDissolved = 8,
        /// When adding or removing a hot key: the key to add was already
        /// present or the key to remove was not present or the key to add
        /// was invalid or adding another hot key would bring the total
        /// number of the maximum number of allowed hot keys per neuron.
        HotKey = 9,
        /// Some canister side resource is exhausted, so this operation cannot be
        /// performed.
        ResourceExhausted = 10,
        /// Some precondition for executing this method was not met (e.g. the
        /// neuron's desolve time is too short). There could be a change in the
        /// state of the system such that the operation becomes allowed (e.g. the
        /// owner of the neuron increases its desolve delay).
        PreconditionFailed = 11,
        /// Executing this method failed for some reason external to the
        /// governance canister.
        External = 12,
        /// A neuron has an ongoing ledger update and thus can't be
        /// changed.
        LedgerUpdateOngoing = 13,
        /// There wasn't enough funds to perform the operation.
        InsufficientFunds = 14,
        /// The principal provided was invalid.
        InvalidPrincipal = 15,
        /// The proposal is defective in some way (e.g. title is too long). If the
        /// same proposal is submitted again without modification, it will be
        /// rejected regardless of changes in the system's state (e.g. increasing
        /// the neuron's desolve delay will not make the proposal acceptable).
        InvalidProposal = 16,
        /// The neuron attempted to join the community fund while already
        /// a member.
        AlreadyJoinedCommunityFund = 17,
    }
}
#[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable), self_describing)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Ballot {
    #[prost(enumeration="Vote", tag="1")]
    pub vote: i32,
    #[prost(uint64, tag="2")]
    pub voting_power: u64,
}
/// A tally of votes.
#[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable), self_describing)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Tally {
    /// When was this tally made
    #[prost(uint64, tag="1")]
    pub timestamp_seconds: u64,
    /// Yeses, in voting power unit.
    #[prost(uint64, tag="2")]
    pub yes: u64,
    /// Noes, in voting power unit.
    #[prost(uint64, tag="3")]
    pub no: u64,
    /// Total voting power unit of eligible neurons.
    /// Should always be greater than or equal to yes + no.
    #[prost(uint64, tag="4")]
    pub total: u64,
}
/// A ProposalData contains everything related to an open proposal:
/// the proposal itself (immutable), as well as mutable data such as
/// ballots.
#[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable), compare_default)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProposalData {
    /// This is stored here temporarily. It is also stored on the map
    /// that contains proposals.
    ///
    /// Immutable: The unique id for this proposal.
    #[prost(message, optional, tag="1")]
    pub id: ::core::option::Option<::ic_nns_common::pb::v1::ProposalId>,
    /// Immutable: The ID of the neuron that made this proposal.
    #[prost(message, optional, tag="2")]
    pub proposer: ::core::option::Option<::ic_nns_common::pb::v1::NeuronId>,
    /// Immutable: The amount of ICP in E8s to be charged to the proposer if the
    /// proposal is rejected.
    #[prost(uint64, tag="3")]
    pub reject_cost_e8s: u64,
    /// Immutable: The proposal originally submitted.
    #[prost(message, optional, tag="4")]
    pub proposal: ::core::option::Option<Proposal>,
    /// Immutable: The timestamp, in seconds from the Unix epoch, when this proposal
    /// was made.
    #[prost(uint64, tag="5")]
    pub proposal_timestamp_seconds: u64,
    /// Map neuron ID to to the neuron's vote and voting power. Only
    /// present for as long as the proposal is not yet settled with
    /// respect to rewards.
    #[prost(map="fixed64, message", tag="6")]
    pub ballots: ::std::collections::HashMap<u64, Ballot>,
    /// Latest tally. Recomputed for open proposals, when proposals are
    /// processed. If the proposal is decided (not open), then the tally
    /// will never change again. (But the ballots may still change as
    /// neurons may vote after the proposal has been decided.)
    #[prost(message, optional, tag="7")]
    pub latest_tally: ::core::option::Option<Tally>,
    /// If specified: the timestamp when this proposal was adopted or
    /// rejected. If not specified, this proposal is still 'open'.
    #[prost(uint64, tag="8")]
    pub decided_timestamp_seconds: u64,
    /// When an adopted proposal has been executed, this is set to
    /// current timestamp.
    #[prost(uint64, tag="12")]
    pub executed_timestamp_seconds: u64,
    /// When an adopted proposal has failed to be executed, this is set
    /// to the current timestamp.
    #[prost(uint64, tag="13")]
    pub failed_timestamp_seconds: u64,
    /// When an adopted proposal has failed to executed, this is set the
    /// reason for the failure.
    #[prost(message, optional, tag="15")]
    pub failure_reason: ::core::option::Option<GovernanceError>,
    /// The reward event round at which rewards for votes on this proposal
    /// was distributed.
    ///
    /// Rounds do not have to be consecutive.
    ///
    /// Rounds start at one: a value of zero indicates that
    /// no reward event taking this proposal into consideration happened yet.
    ///
    /// This field matches field day_after_genesis in RewardEvent.
    #[prost(uint64, tag="14")]
    pub reward_event_round: u64,
    /// Wait-for-quiet state that needs to be saved in stable memory.
    #[prost(message, optional, tag="16")]
    pub wait_for_quiet_state: ::core::option::Option<WaitForQuietState>,
}
/// Stores data relevant to the "wait for quiet" implementation.
#[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct WaitForQuietState {
    #[prost(uint64, tag="1")]
    pub current_deadline_timestamp_seconds: u64,
}
/// This is a view of the ProposalData returned by API queries and is NOT used
/// for storage. The ballots are restricted to those of the caller's neurons and
/// additionally it has the computed fields, topic, status, and reward_status.
#[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProposalInfo {
    /// The unique id for this proposal.
    #[prost(message, optional, tag="1")]
    pub id: ::core::option::Option<::ic_nns_common::pb::v1::ProposalId>,
    /// The ID of the neuron that made this proposal.
    #[prost(message, optional, tag="2")]
    pub proposer: ::core::option::Option<::ic_nns_common::pb::v1::NeuronId>,
    /// The amount of ICP in E8s to be charged to the proposer if the proposal is
    /// rejected.
    #[prost(uint64, tag="3")]
    pub reject_cost_e8s: u64,
    /// The proposal originally submitted.
    #[prost(message, optional, tag="4")]
    pub proposal: ::core::option::Option<Proposal>,
    /// The timestamp, in seconds from the Unix epoch, when this proposal was made.
    #[prost(uint64, tag="5")]
    pub proposal_timestamp_seconds: u64,
    /// See \[PropopsalData::ballots\].
    #[prost(map="fixed64, message", tag="6")]
    pub ballots: ::std::collections::HashMap<u64, Ballot>,
    /// See \[PropopsalData::latest_tally\].
    #[prost(message, optional, tag="7")]
    pub latest_tally: ::core::option::Option<Tally>,
    /// See \[PropopsalData::decided_timestamp_seconds\].
    #[prost(uint64, tag="8")]
    pub decided_timestamp_seconds: u64,
    /// See \[PropopsalData::executed_timestamp_seconds\].
    #[prost(uint64, tag="12")]
    pub executed_timestamp_seconds: u64,
    /// See \[PropopsalData::failed_timestamp_seconds\].
    #[prost(uint64, tag="13")]
    pub failed_timestamp_seconds: u64,
    /// See \[ProposalData::failure_reason\].
    #[prost(message, optional, tag="18")]
    pub failure_reason: ::core::option::Option<GovernanceError>,
    /// See \[PropopsalData::reward_event_round\].
    #[prost(uint64, tag="14")]
    pub reward_event_round: u64,
    /// Derived - see \[Topic\] for more information
    #[prost(enumeration="Topic", tag="15")]
    pub topic: i32,
    /// Derived - see \[ProposalStatus\] for more information
    #[prost(enumeration="ProposalStatus", tag="16")]
    pub status: i32,
    /// Derived - see \[ProposalRewardStatus\] for more information
    #[prost(enumeration="ProposalRewardStatus", tag="17")]
    pub reward_status: i32,
    #[prost(uint64, optional, tag="19")]
    pub deadline_timestamp_seconds: ::core::option::Option<u64>,
}
/// Network economics contains the parameters for several operations related
/// to the economy of the network. When submitting a NetworkEconomics proposal
/// default values (0) are considered unchanged, so a valid proposal only needs
/// to set the parameters that it wishes to change.
/// In other words, it's not possible to set any of the values of
/// NetworkEconomics to 0.
///
/// NOTE: If adding a value to this proto, make sure there is a corresponding
/// `if` in Governance::perform_action().
#[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable), self_describing)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NetworkEconomics {
    /// The number of E8s (10E-8 of an ICP token) that a rejected
    /// proposal will cost.
    ///
    /// This fee should be controlled by an #Economic proposal type.
    /// The fee does not apply for ManageNeuron proposals.
    #[prost(uint64, tag="1")]
    pub reject_cost_e8s: u64,
    /// The minimum number of E8s that can be staked in a neuron.
    #[prost(uint64, tag="2")]
    pub neuron_minimum_stake_e8s: u64,
    /// The number of E8s (10E-8 of an ICP token) that it costs to
    /// employ the 'manage neuron' functionality through proposals. The
    /// cost is incurred by the neuron that makes the 'manage neuron'
    /// proposal and is applied regardless of whether the proposal is
    /// adopted or rejected.
    #[prost(uint64, tag="4")]
    pub neuron_management_fee_per_proposal_e8s: u64,
    /// The minimum number that the ICP/XDR conversion rate can be set to.
    ///
    /// Measured in XDR (the currency code of IMF SDR) to two decimal
    /// places.
    ///
    /// See /rs/protobuf/def/registry/conversion_rate/v1/conversion_rate.proto
    /// for more information on the rate itself.
    #[prost(uint64, tag="5")]
    pub minimum_icp_xdr_rate: u64,
    /// The dissolve delay of a neuron spawned from the maturity of an
    /// existing neuron.
    #[prost(uint64, tag="6")]
    pub neuron_spawn_dissolve_delay_seconds: u64,
    /// The maximum rewards to be distributed to NodeProviders in a single
    /// distribution event, in e8s.
    #[prost(uint64, tag="8")]
    pub maximum_node_provider_rewards_e8s: u64,
    /// The transaction fee that must be paid for each ledger transaction.
    #[prost(uint64, tag="9")]
    pub transaction_fee_e8s: u64,
    /// The maximum number of proposals to keep, per topic. When the
    /// total number of proposals for a given topic is greater than this
    /// number, the oldest proposals that have reached a "final" state
    /// may be deleted.
    ///
    /// If unspecified or zero, all proposals are kept.
    #[prost(uint32, tag="10")]
    pub max_proposals_to_keep_per_topic: u32,
}
/// A reward event is an event at which neuron maturity is increased
#[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RewardEvent {
    /// This reward event correspond to a time interval that ends at the end of
    /// genesis + day_after_genesis days.
    ///
    /// For instance: when this is 0, this is for a period that ends at genesis -- there can
    /// never be a reward for this.
    ///
    /// When this is 1, this is for the first day after genesis.
    ///
    /// On rare occasions, the reward event may cover several days ending at genesis + day_after_genesis days,
    /// when it was not possible to proceed to a reward event for a while. This makes that day_after_genesis
    /// does not have to be consecutive.
    #[prost(uint64, tag="1")]
    pub day_after_genesis: u64,
    /// The timestamp at which this reward event took place, in seconds since the unix epoch.
    ///
    /// This does not match the date taken into account for reward computation, which
    /// should always be an integer number of days after genesis.
    #[prost(uint64, tag="2")]
    pub actual_timestamp_seconds: u64,
    /// The list of proposals that were taken into account during
    /// this reward event.
    #[prost(message, repeated, tag="3")]
    pub settled_proposals: ::prost::alloc::vec::Vec<::ic_nns_common::pb::v1::ProposalId>,
    /// The total amount of reward that was distributed during this reward event.
    ///
    /// The unit is "e8s equivalent" to insist that, while this quantity is on
    /// the same scale as ICPs, maturity is not directly convertible to ICPs:
    /// conversion requires a minting event to spawn a new neuron.
    #[prost(uint64, tag="4")]
    pub distributed_e8s_equivalent: u64,
}
#[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct KnownNeuron {
    #[prost(message, optional, tag="1")]
    pub id: ::core::option::Option<::ic_nns_common::pb::v1::NeuronId>,
    #[prost(message, optional, tag="2")]
    pub known_neuron_data: ::core::option::Option<KnownNeuronData>,
}
/// Known neurons have extra information (a name and optionally a description) that can be used to identify them.
#[derive(candid::CandidType, candid::Deserialize, Eq)] #[cfg_attr(feature = "test", derive(comparable::Comparable), compare_default)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct KnownNeuronData {
    #[prost(string, tag="1")]
    pub name: ::prost::alloc::string::String,
    #[prost(string, optional, tag="2")]
    pub description: ::core::option::Option<::prost::alloc::string::String>,
}
/// This represents the whole NNS governance system. It contains all
/// information about the NNS governance system that must be kept
/// across upgrades of the NNS governance system.
#[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable), compare_default)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Governance {
    /// Current set of neurons.
    #[prost(map="fixed64, message", tag="1")]
    pub neurons: ::std::collections::HashMap<u64, Neuron>,
    /// Proposals.
    #[prost(btree_map="uint64, message", tag="2")]
    pub proposals: ::prost::alloc::collections::BTreeMap<u64, ProposalData>,
    /// The transfers that have been made to stake new neurons, but
    /// haven't been claimed by the user, yet.
    #[prost(message, repeated, tag="3")]
    pub to_claim_transfers: ::prost::alloc::vec::Vec<NeuronStakeTransfer>,
    /// Also known as the 'normal voting period'. The maximum time a
    /// proposal (of a topic with "normal" voting period) is open for
    /// voting. If a proposal has not been decided (adopted or rejected)
    /// within this time since the proposal was made, the proposal is
    /// rejected.
    ///
    /// See also `short_voting_period_seconds`.
    #[prost(uint64, tag="5")]
    pub wait_for_quiet_threshold_seconds: u64,
    /// The network economics configuration parameters.
    #[prost(message, optional, tag="8")]
    pub economics: ::core::option::Option<NetworkEconomics>,
    /// The last reward event. Should never be missing.
    #[prost(message, optional, tag="9")]
    pub latest_reward_event: ::core::option::Option<RewardEvent>,
    /// Set of in-flight neuron ledger commands.
    ///
    /// Whenever we issue a ledger transfer (for disburse, split, spawn etc)
    /// we store it in this map, keyed by the id of the neuron being changed
    /// and remove the entry when it completes.
    ///
    /// An entry being present in this map acts like a "lock" on the neuron
    /// and thus prevents concurrent changes that might happen due to the
    /// interleaving of user requests and callback execution.
    ///
    /// If there are no ongoing requests, this map should be empty.
    ///
    /// If something goes fundamentally wrong (say we trap at some point
    /// after issueing a transfer call) the neuron(s) involved are left in a
    /// "locked" state, meaning new operations can't be applied without
    /// reconciling the state.
    ///
    /// Because we know exactly what was going on, we should have the
    /// information necessary to reconcile the state, using custom code
    /// added on upgrade, if necessary.
    #[prost(map="fixed64, message", tag="10")]
    pub in_flight_commands: ::std::collections::HashMap<u64, governance::NeuronInFlightCommand>,
    /// The timestamp, in seconds since the unix epoch, at which `canister_init` was run for
    /// the governance canister, considered
    /// the genesis of the IC for reward purposes.
    #[prost(uint64, tag="11")]
    pub genesis_timestamp_seconds: u64,
    /// The entities that own the nodes running the IC.
    #[prost(message, repeated, tag="12")]
    pub node_providers: ::prost::alloc::vec::Vec<NodeProvider>,
    /// Default followees
    ///
    /// A map of Topic (as i32) to Neuron id that is set as the default
    /// following for all neurons created post-genesis.
    ///
    /// On initialization it's required that the Neurons present in this
    /// map are present in the initial set of neurons.
    ///
    /// Default following can be changed via proposal.
    #[prost(map="int32, message", tag="13")]
    pub default_followees: ::std::collections::HashMap<i32, neuron::Followees>,
    /// The maximum time a proposal of a topic with *short voting period*
    /// is open for voting. If a proposal on a topic with short voting
    /// period has not been decided (adopted or rejected) within this
    /// time since the proposal was made, the proposal is rejected.
    #[prost(uint64, tag="14")]
    pub short_voting_period_seconds: u64,
    #[prost(message, optional, tag="15")]
    pub metrics: ::core::option::Option<governance::GovernanceCachedMetrics>,
}
/// Nested message and enum types in `Governance`.
pub mod governance {
    /// The possible commands that require interaction with the ledger.
    #[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct NeuronInFlightCommand {
        /// The timestamp at which the command was issued, for debugging
        /// purposes.
        #[prost(uint64, tag="1")]
        pub timestamp: u64,
        #[prost(oneof="neuron_in_flight_command::Command", tags="2, 3, 4, 5, 7, 8, 9, 10")]
        pub command: ::core::option::Option<neuron_in_flight_command::Command>,
    }
    /// Nested message and enum types in `NeuronInFlightCommand`.
    pub mod neuron_in_flight_command {
        #[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
        #[derive(Clone, PartialEq, ::prost::Oneof)]
        pub enum Command {
            #[prost(message, tag="2")]
            Disburse(super::super::manage_neuron::Disburse),
            #[prost(message, tag="3")]
            Split(super::super::manage_neuron::Split),
            #[prost(message, tag="4")]
            Spawn(super::super::manage_neuron::Spawn),
            #[prost(message, tag="5")]
            DisburseToNeuron(super::super::manage_neuron::DisburseToNeuron),
            #[prost(message, tag="7")]
            MergeMaturity(super::super::manage_neuron::MergeMaturity),
            #[prost(message, tag="8")]
            ClaimOrRefreshNeuron(super::super::manage_neuron::ClaimOrRefresh),
            #[prost(message, tag="9")]
            Configure(super::super::manage_neuron::Configure),
            #[prost(message, tag="10")]
            Merge(super::super::manage_neuron::Merge),
        }
    }
    /// Stores metrics that are too costly to compute each time metrics are
    /// requested
    #[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable), compare_default)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct GovernanceCachedMetrics {
        #[prost(uint64, tag="1")]
        pub timestamp_seconds: u64,
        #[prost(uint64, tag="2")]
        pub total_supply_icp: u64,
        #[prost(uint64, tag="3")]
        pub dissolving_neurons_count: u64,
        #[prost(map="uint64, double", tag="4")]
        pub dissolving_neurons_e8s_buckets: ::std::collections::HashMap<u64, f64>,
        #[prost(map="uint64, uint64", tag="5")]
        pub dissolving_neurons_count_buckets: ::std::collections::HashMap<u64, u64>,
        #[prost(uint64, tag="6")]
        pub not_dissolving_neurons_count: u64,
        #[prost(map="uint64, double", tag="7")]
        pub not_dissolving_neurons_e8s_buckets: ::std::collections::HashMap<u64, f64>,
        #[prost(map="uint64, uint64", tag="8")]
        pub not_dissolving_neurons_count_buckets: ::std::collections::HashMap<u64, u64>,
        #[prost(uint64, tag="9")]
        pub dissolved_neurons_count: u64,
        #[prost(uint64, tag="10")]
        pub dissolved_neurons_e8s: u64,
        #[prost(uint64, tag="11")]
        pub garbage_collectable_neurons_count: u64,
        #[prost(uint64, tag="12")]
        pub neurons_with_invalid_stake_count: u64,
        #[prost(uint64, tag="13")]
        pub total_staked_e8s: u64,
        #[prost(uint64, tag="14")]
        pub neurons_with_less_than_6_months_dissolve_delay_count: u64,
        #[prost(uint64, tag="15")]
        pub neurons_with_less_than_6_months_dissolve_delay_e8s: u64,
        #[prost(uint64, tag="16")]
        pub community_fund_total_staked_e8s: u64,
    }
}
/// Proposals with restricted voting are not included unless the caller
/// is allowed to vote on them.
///
/// The actual ballots of the proposal are restricted to ballots cast
/// by the caller.
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListProposalInfo {
    /// Limit on the number of \[ProposalInfo\] to return. If no value is
    /// specified, or if a value greater than 100 is specified, 100
    /// will be used.
    #[prost(uint32, tag="1")]
    pub limit: u32,
    /// If specified, only return proposals that are stricty earlier than
    /// the specified proposal according to the proposal ID. If not
    /// specified, start with the most recent proposal.
    #[prost(message, optional, tag="2")]
    pub before_proposal: ::core::option::Option<::ic_nns_common::pb::v1::ProposalId>,
    /// Exclude proposals with a topic in this list. This is particularly
    /// useful to exclude proposals on the topics TOPIC_EXCHANGE_RATE and
    /// TOPIC_KYC which most users are not likely to be interested in
    /// seeing.
    #[prost(enumeration="Topic", repeated, tag="3")]
    pub exclude_topic: ::prost::alloc::vec::Vec<i32>,
    /// Include proposals that have a reward status in this list (see
    /// \[ProposalRewardStatus\] for more information). If this list is
    /// empty, no restriction is applied. For example, many users listing
    /// proposals will only be interested in proposals for which they can
    /// receive voting rewards, i.e., with reward status
    /// PROPOSAL_REWARD_STATUS_ACCEPT_VOTES.
    #[prost(enumeration="ProposalRewardStatus", repeated, tag="4")]
    pub include_reward_status: ::prost::alloc::vec::Vec<i32>,
    /// Include proposals that have a status in this list (see
    /// \[ProposalStatus\] for more information). If this list is empty, no
    /// restriction is applied.
    #[prost(enumeration="ProposalStatus", repeated, tag="5")]
    pub include_status: ::prost::alloc::vec::Vec<i32>,
}
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListProposalInfoResponse {
    #[prost(message, repeated, tag="1")]
    pub proposal_info: ::prost::alloc::vec::Vec<ProposalInfo>,
}
/// A request to list neurons. The "requested list", i.e., the list of
/// neuron IDs to retrieve information about, is the union of the list
/// of neurons listed in `neuron_ids` and, if `caller_neurons` is true,
/// the list of neuron IDs of neurons for which the caller is the
/// controller or one of the hot keys.
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListNeurons {
    /// The neurons to get information about. The "requested list"
    /// contains all of these neuron IDs.
    #[prost(fixed64, repeated, packed="false", tag="1")]
    pub neuron_ids: ::prost::alloc::vec::Vec<u64>,
    /// If true, the "requested list" also contains the neuron ID of the
    /// neurons that the calling principal is authorized to read.
    #[prost(bool, tag="2")]
    pub include_neurons_readable_by_caller: bool,
}
/// A response to a `ListNeurons` request.
///
/// The "requested list" is described in `ListNeurons`.
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListNeuronsResponse {
    /// For each neuron ID in the "requested list", if this neuron exists,
    /// its `NeuronInfo` at the time of the call will be in this map.
    #[prost(map="fixed64, message", tag="1")]
    pub neuron_infos: ::std::collections::HashMap<u64, NeuronInfo>,
    /// For each neuron ID in the "requested list", if the neuron exists,
    /// and the caller is authorized to read the full neuron (controller,
    /// hot key, or controller or hot key of some followee on the
    /// `ManageNeuron` topic).
    #[prost(message, repeated, tag="2")]
    pub full_neurons: ::prost::alloc::vec::Vec<Neuron>,
}
/// A response to "ListKnownNeurons"
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListKnownNeuronsResponse {
    /// List of known neurons.
    #[prost(message, repeated, tag="1")]
    pub known_neurons: ::prost::alloc::vec::Vec<KnownNeuron>,
}
/// Response to list_node_providers
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListNodeProvidersResponse {
    /// List of all "NodeProviders"
    #[prost(message, repeated, tag="1")]
    pub node_providers: ::prost::alloc::vec::Vec<NodeProvider>,
}
/// The arguments to the method `claim_or_refresh_neuron_from_account`.
///
/// DEPRECATED: Use ManageNeuron::ClaimOrRefresh.
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ClaimOrRefreshNeuronFromAccount {
    /// The principal for which to refresh the account. If not specified,
    /// defaults to the caller.
    #[prost(message, optional, tag="1")]
    pub controller: ::core::option::Option<::ic_base_types::PrincipalId>,
    /// The memo of the staking transaction.
    #[prost(uint64, tag="2")]
    pub memo: u64,
}
/// Response to claim_or_refresh_neuron_from_account.
///
/// DEPRECATED: Use ManageNeuron::ClaimOrRefresh.
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ClaimOrRefreshNeuronFromAccountResponse {
    #[prost(oneof="claim_or_refresh_neuron_from_account_response::Result", tags="1, 2")]
    pub result: ::core::option::Option<claim_or_refresh_neuron_from_account_response::Result>,
}
/// Nested message and enum types in `ClaimOrRefreshNeuronFromAccountResponse`.
pub mod claim_or_refresh_neuron_from_account_response {
    #[derive(candid::CandidType, candid::Deserialize)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Result {
        /// Specified in case of error.
        #[prost(message, tag="1")]
        Error(super::GovernanceError),
        /// The ID of the neuron that was created or empty in the case of error.
        #[prost(message, tag="2")]
        NeuronId(::ic_nns_common::pb::v1::NeuronId),
    }
}
/// Proposal types are organized into topics. Neurons can automatically
/// vote based on following other neurons, and these follow
/// relationships are defined per topic.
#[derive(candid::CandidType, candid::Deserialize, strum_macros::EnumIter)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum Topic {
    /// The `Unspecified` topic is used as a fallback when
    /// following. That is, if no followees are specified for a given
    /// topic, the followees for this topic are used instead.
    Unspecified = 0,
    /// A special topic by means of which a neuron can be managed by the
    /// followees for this topic (in this case, there is no fallback to
    /// 'unspecified'). Votes on this topic are not included in the
    /// voting history of the neuron (cf., `recent_ballots` in `Neuron`).
    ///
    /// For proposals on this topic, only followees on the 'neuron
    /// management' topic of the neuron that the proposals pertains to
    /// are allowed to vote.
    ///
    /// As the set of eligible voters on this topic is restricted,
    /// proposals on this topic have a *short voting period*.
    NeuronManagement = 1,
    /// All proposals that provide “real time” information about the
    /// value of ICP, as measured by an IMF SDR, which allows the NNS to
    /// convert ICP to cycles (which power computation) at a rate which
    /// keeps their real world cost constant. Votes on this topic are not
    /// included in the voting history of the neuron (cf.,
    /// `recent_ballots` in `Neuron`).
    ///
    /// Proposals on this topic have a *short voting period* due to their
    /// frequency.
    ExchangeRate = 2,
    /// All proposals that administer network economics, for example,
    /// determining what rewards should be paid to node operators.
    NetworkEconomics = 3,
    /// All proposals that administer governance, for example to freeze
    /// malicious canisters that are harming the network.
    Governance = 4,
    /// All proposals that administer node machines, including, but not
    /// limited to, upgrading or configuring the OS, upgrading or
    /// configuring the virtual machine framework and upgrading or
    /// configuring the node replica software.
    NodeAdmin = 5,
    /// All proposals that administer network participants, for example,
    /// granting and revoking DCIDs (data center identities) or NOIDs
    /// (node operator identities).
    ParticipantManagement = 6,
    /// All proposals that administer network subnets, for example
    /// creating new subnets, adding and removing subnet nodes, and
    /// splitting subnets.
    SubnetManagement = 7,
    /// Installing and upgrading “system” canisters that belong to the network.
    /// For example, upgrading the NNS.
    NetworkCanisterManagement = 8,
    /// Proposals that update KYC information for regulatory purposes,
    /// for example during the initial Genesis distribution of ICP in the
    /// form of neurons.
    Kyc = 9,
    /// Topic for proposals to reward node providers.
    NodeProviderRewards = 10,
}
/// Every neuron is in one of three states.
///
/// Note that `Disbursed` is not a state of a neuron, as the neuron is
/// consumed throught the act disbursement (using the method
/// \[Governance::disburse\]).
///
/// See \[neuron::DissolveState\] for detail on how the different states
/// are represented.
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum NeuronState {
    /// Not a valid state. Required by Protobufs.
    Unspecified = 0,
    /// In this state, the neuron is not dissolving and has a specific
    /// `dissolve_delay`. It accrues `age` by the passge of time and it
    /// can vote if `dissolve_delay` is at least six months. The method
    /// \[Neuron::start_dissolving\] can be called to transfer the neuron
    /// to the `Dissolving` state. The method
    /// \[Neuron::increase_dissolve_delay\] can be used to increase the
    /// dissolve delay without affecting the state or the age of the
    /// neuron.
    NotDissolving = 1,
    /// In this state, the neuron's `dissolve_delay` decreases with the
    /// passage of time. While dissolving, the neuron's age is considered
    /// zero. Eventually it will reach the `Dissolved` state. The method
    /// \[Neuron::stop_dissolving\] can be called to transfer the neuron to
    /// the `NotDissolving` state, and the neuron will start aging again. The
    /// method \[Neuron::increase_dissolve_delay\] can be used to increase
    /// the dissolve delay, but this will not stop the timer or affect
    /// the age of the neuron.
    Dissolving = 2,
    /// In the dissolved state, the neuron's stake can be disbursed using
    /// the \[Governance::disburse\] method. It cannot vote as its
    /// `dissolve_delay` is considered to be zero.
    ///
    /// If the method \[Neuron::increase_dissolve_delay\] is called in this
    /// state, the neuron will no longer be dissolving, with the specified
    /// dissolve delay, and will start aging again.
    ///
    /// Neuron holders have an incentive not to keep neurons in the
    /// 'dissolved' state for a long time: if the holders wants to make
    /// their tokens liquid, they disburse the neuron's stake, and if
    /// they want to earn voting rewards, they increase the dissolve
    /// delay. If these incentives turn out to be insufficient, the NNS
    /// may decide to impose further restrictions on dissolved neurons.
    Dissolved = 3,
}
/// The types of votes the Neuron can issue.
#[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum Vote {
    /// This exists because proto3 defaults to the 0 value on enums.
    /// This is not a valid choice, i.e., a vote with this choice will
    /// not be counted.
    Unspecified = 0,
    /// Vote for the proposal to be adopted.
    Yes = 1,
    /// Vote for the proposal to be rejected.
    No = 2,
}
/// List of NNS functions that can be called by proposals.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum NnsFunction {
    /// This exists because proto3 defaults to the 0 value on enums.
    Unspecified = 0,
    /// Combine a specified set of nodes, typically drawn from data centers and
    /// operators in such a way as to guarantee their independence, into a new
    /// decentralized subnet.
    /// The execution of this NNS function first initiates a new instance of
    /// the distributed key generation protocol. The transcript of that protocol
    /// is written to a new subnet record in the registry, together with initial
    /// configuration information for the subnet, from where the nodes comprising
    /// the subnet pick it up.
    CreateSubnet = 1,
    /// Add a new node to a subnet. The node cannot be currently assigned to a
    /// subnet.
    /// The execution of this proposal changes an existing subnet record to add
    /// a node. From the perspective of the NNS, this update is a simple update
    /// of the subnet record in the registry.
    AddNodeToSubnet = 2,
    /// A proposal to add a new canister to be installed and executed in the
    /// NNS subnetwork.
    /// The root canister, which controls all canisters on the NNS except for
    /// itself, handles this proposal type. The call also expects the Wasm module
    /// that shall be installed.
    NnsCanisterInstall = 3,
    /// A proposal to upgrade an existing canister in the NNS subnetwork.
    /// This proposal type is executed by the root canister. Beyond upgrading
    /// the Wasm module of the target canister, the proposal can also set the
    /// authorization information and the allocations.
    NnsCanisterUpgrade = 4,
    /// A proposal to bless a new version to which the replicas can be
    /// upgraded.
    /// The proposal registers a replica version (identified by the hash of the
    /// installation image) in the registry. Besides creating a record for that
    /// version, the proposal also appends that version to the list of "blessed
    /// versions" that can be installed on a subnet. By itself, this proposal
    /// does not effect any upgrade.
    BlessReplicaVersion = 5,
    /// Update a subnet's recovery CUP (used to recover subnets that have stalled).
    /// Nodes that find a recovery CUP for their subnet will load that CUP from
    /// the registry and restart the replica from that CUP.
    RecoverSubnet = 6,
    /// Update a subnet's configuration.
    /// This proposal updates the subnet record in the registry, with the changes
    /// being picked up by the nodes on the subnet when they reference the
    /// respective registry version. Subnet configuration comprises protocol
    /// parameters that must be consistent across the subnet (e.g. message sizes).
    UpdateConfigOfSubnet = 7,
    /// Assign an identity to a node operator, such as a funding partner,
    /// associating key information regarding its ownership, the jurisdiction
    /// in which it is located, and other information.
    /// The node operator is stored as a record in the registry. It contains
    /// the remaining node allowance for that node operator, that is the number
    /// of nodes the node operator can still add to the IC. When an additional
    /// node is added by the node operator, the remaining allowance is decreased.
    AssignNoid = 8,
    /// A proposal to upgrade the root canister in the NNS subnetwork.
    /// The proposal is processed by the Lifeline canister, which controls the
    /// root canister. The proposal updates the Wasm module as well as the
    /// authorization settings.
    NnsRootUpgrade = 9,
    /// Update the ICP/XDR conversion rate.
    /// Changes the ICP-to-XDR conversion rate in the governance canister. This
    /// setting affects cycles pricing (as the value of cycles shall be constant
    /// with respect to IMF SDRs) as well as the rewards paid for nodes, which
    /// are expected to be specified in terms of IMF SDRs as well.
    IcpXdrConversionRate = 10,
    /// Update the replica version running on a given subnet.
    /// The proposal changes the replica version that is used on the specified
    /// subnet. The version must be contained in the list of blessed replica
    /// versions. The upgrade is performed when the subnet creates the next
    /// regular CUP.
    UpdateSubnetReplicaVersion = 11,
    //// Clear the provisional whitelist.
    //// The proposal changes the provisional whitelist to the empty list.
    ClearProvisionalWhitelist = 12,
    /// Removes a node from a subnet. The node must be currently assigned to a
    /// subnet.
    /// The execution of this proposal changes an existing subnet record to remove
    /// a node. From the perspective of the NNS, this update is a simple update
    /// of the subnet record in the registry.
    RemoveNodesFromSubnet = 13,
    /// Informs the cycles minting canister that a certain principal is
    /// authorized to use certain subnetworks (from a list). Can also be
    /// used to set the "default" list of subnetworks that principals
    /// without special authorization are allowed to use.
    SetAuthorizedSubnetworks = 14,
    /// Change the Firewall configuration in the registry. (TODO: Remove when IC-1026 is fully integrated)
    SetFirewallConfig = 15,
    /// Change a Node Operator's allowance in the registry.
    UpdateNodeOperatorConfig = 16,
    /// Stop or start an NNS canister.
    StopOrStartNnsCanister = 17,
    /// Remove unassigned nodes from the registry.
    RemoveNodes = 18,
    /// Uninstall code of a canister.
    UninstallCode = 19,
    /// Update the node rewards table.
    UpdateNodeRewardsTable = 20,
    /// Add or remove Data Center records.
    AddOrRemoveDataCenters = 21,
    /// Update the config for all unassigned nodes.
    UpdateUnassignedNodesConfig = 22,
    /// Remove Node Operator from the registry.
    RemoveNodeOperators = 23,
    /// Update the routing table in the registry.
    RerouteCanisterRanges = 24,
    /// Add firewall rules in the registry
    AddFirewallRules = 25,
    /// Remove firewall rules in the registry
    RemoveFirewallRules = 26,
    /// Update firewall rules in the registry
    UpdateFirewallRules = 27,
    /// Insert or update `canister_migrations` entries.
    PrepareCanisterMigration = 28,
    /// Remove `canister_migrations` entries.
    CompleteCanisterMigration = 29,
}
/// The proposal status, with respect to decision making and execution.
/// See also ProposalRewardStatus.
#[derive(candid::CandidType, candid::Deserialize)] #[cfg_attr(feature = "test", derive(comparable::Comparable))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ProposalStatus {
    Unspecified = 0,
    /// A decision (adopt/reject) has yet to be made.
    Open = 1,
    /// The proposal has been rejected.
    Rejected = 2,
    /// The proposal has been adopted (sometimes also called
    /// "accepted"). At this time, either execution as not yet started,
    /// or it has but the outcome is not yet known.
    Adopted = 3,
    /// The proposal was adopted and successfully executed.
    Executed = 4,
    /// The proposal was adopted, but execution failed.
    Failed = 5,
}
/// The proposal status, with respect to reward distribution.
/// See also ProposalStatus.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ProposalRewardStatus {
    Unspecified = 0,
    /// The proposal still accept votes, for the purpose of
    /// vote rewards. This implies nothing on the ProposalStatus.
    AcceptVotes = 1,
    /// The proposal no longer accepts votes. It is due to settle
    /// at the next reward event.
    ReadyToSettle = 2,
    /// The proposal has been taken into account in a reward event.
    Settled = 3,
    /// The proposal is not eligible to be taken into account in a reward event.
    Ineligible = 4,
}
