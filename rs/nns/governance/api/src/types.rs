#![allow(clippy::all)]
use candid::{Int, Nat};
use ic_base_types::PrincipalId;
use ic_nns_common::pb::v1::{NeuronId, ProposalId};
use icp_ledger::protobuf::AccountIdentifier;
use std::collections::{BTreeMap, HashMap};

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
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct NodeProvider {
    /// The ID of the node provider.
    pub id: Option<PrincipalId>,
    /// The account where rewards earned from providing nodes will be sent.
    pub reward_account: Option<AccountIdentifier>,
}
/// Used to update node provider records
///
/// There is no need to specify a node provider Principal ID here, as Governance
/// uses the Principal ID of the caller as the Node Provider Principal ID.
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct UpdateNodeProvider {
    /// The account where rewards earned from providing nodes will be sent.
    pub reward_account: Option<AccountIdentifier>,
}
/// How did a neuron vote in the recent past? This data is used by
/// other neurons to determine what neurons to follow.
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Eq, Clone, PartialEq, Debug, Default,
)]
pub struct BallotInfo {
    pub proposal_id: Option<::ic_nns_common::pb::v1::ProposalId>,
    pub vote: i32,
}
/// The result of querying for the state of a single neuron.
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Eq, Clone, PartialEq, Debug, Default,
)]
pub struct NeuronInfo {
    /// The unique identifier of the neuron.
    pub id: Option<NeuronId>,
    /// The exact time at which this data was computed. This means, for
    /// example, that the exact time that this neuron will enter the
    /// dissolved state, assuming it is currently dissolving, is given
    /// by `retrieved_at_timestamp_seconds+dissolve_delay_seconds`.
    pub retrieved_at_timestamp_seconds: u64,
    /// The current state of the neuron. See \[NeuronState\] for a
    /// description of the different states.
    pub state: i32,
    /// The current age of the neuron. See \[Neuron::age_seconds\]
    /// for details on how it is computed.
    pub age_seconds: u64,
    /// The current dissolve delay of the neuron. See
    /// \[Neuron::dissolve_delay_seconds\] for details on how it is
    /// computed.
    pub dissolve_delay_seconds: u64,
    /// See \[Neuron::recent_ballots\] for a description.
    pub recent_ballots: Vec<BallotInfo>,
    /// Current voting power of the neuron.
    pub voting_power: u64,
    /// When the Neuron was created. A neuron can only vote on proposals
    /// submitted after its creation date.
    pub created_timestamp_seconds: u64,
    /// Current stake of the neuron, in e8s.
    pub stake_e8s: u64,
    /// Timestamp when this neuron joined the community fund.
    pub joined_community_fund_timestamp_seconds: Option<u64>,
    /// If this neuron is a known neuron, this is data associated
    /// with it, including the neuron's name and (optionally) a description.
    pub known_neuron_data: Option<KnownNeuronData>,
    /// The type of the Neuron. See \[NeuronType\] for a description
    /// of the different states.
    pub neuron_type: Option<i32>,
    /// See the Visibility enum.
    pub visibility: Option<i32>,
    /// The last time that voting power was "refreshed". There are two ways to
    /// refresh the voting power of a neuron: set following, or vote directly. In
    /// the future, there will be a dedicated API for refreshing. Note that direct
    /// voting implies that refresh also occurs when a proposal is created, because
    /// direct voting is part of proposal creation.
    ///
    /// Effect: When this becomes > 6 months ago, the amount of voting power that
    /// this neuron can exercise decreases linearly down to 0 over the course of 1
    /// month. After that, following is cleared, except for ManageNeuron proposals.
    ///
    /// This will always be populated. If the underlying neuron was never
    /// refreshed, this will be set to 2024-11-05T00:00:01 UTC (1730764801 seconds
    /// after the UNIX epoch).
    pub voting_power_refreshed_timestamp_seconds: ::core::option::Option<u64>,
    /// See analogous field in Neuron.
    pub deciding_voting_power: Option<u64>,
    /// See analogous field in Neuron.
    pub potential_voting_power: Option<u64>,
}

impl NeuronInfo {
    pub fn is_seed_neuron(&self) -> bool {
        self.neuron_type == Some(NeuronType::Seed as i32)
    }

    pub fn is_ect_neuron(&self) -> bool {
        self.neuron_type == Some(NeuronType::Ect as i32)
    }
}

/// A transfer performed from some account to stake a new neuron.
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct NeuronStakeTransfer {
    /// When the transfer arrived at the governance canister.
    pub transfer_timestamp: u64,
    /// The principal that made the transfer.
    pub from: Option<PrincipalId>,
    /// The (optional) subaccount from which the transfer was made.
    #[serde(with = "serde_bytes")]
    pub from_subaccount: Vec<u8>,
    /// The subaccount to which the transfer was made.
    #[serde(with = "serde_bytes")]
    pub to_subaccount: Vec<u8>,
    /// The amount of stake that was transferred.
    pub neuron_stake_e8s: u64,
    /// The block height at which the transfer occurred.
    pub block_height: u64,
    /// The memo sent with the transfer.
    pub memo: u64,
}
/// This structure represents a neuron "at rest" in governance system of
/// the Internet Computer IC.
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
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
    pub id: Option<NeuronId>,
    /// The principal of the ICP ledger account where the locked ICP
    /// balance resides. This principal is indistinguishable from one
    /// identifying a public key pair, such that those browsing the ICP
    /// ledger cannot tell which balances belong to neurons.
    #[serde(with = "serde_bytes")]
    pub account: Vec<u8>,
    /// The principal that actually controls the neuron. The principal
    /// must identify a public key pair, which acts as a “master key”,
    /// such that the corresponding secret key should be kept very
    /// secure. The principal may control many neurons.
    pub controller: Option<PrincipalId>,
    /// Keys that can be used to perform actions with limited privileges
    /// without exposing the secret key corresponding to the principal
    /// e.g. could be a WebAuthn key.
    pub hot_keys: Vec<PrincipalId>,
    /// The amount of staked ICP tokens, measured in fractions of 10E-8
    /// of an ICP.
    ///
    /// Cached record of the locked ICP balance on the ICP ledger.
    ///
    /// For neuron creation: has to contain some minimum amount. A
    /// spawned neuron with less stake cannot increase its dissolve
    /// delay.
    pub cached_neuron_stake_e8s: u64,
    /// The amount of ICP that this neuron has forfeited due to making
    /// proposals that were subsequently rejected or from using the
    /// 'manage neurons through proposals' functionality. Must be smaller
    /// than 'neuron_stake_e8s'. When a neuron is disbursed, these ICP
    /// will be burned.
    pub neuron_fees_e8s: u64,
    /// When the Neuron was created. A neuron can only vote on proposals
    /// submitted after its creation date.
    pub created_timestamp_seconds: u64,
    /// The timestamp, in seconds from the Unix epoch, corresponding to
    /// the time this neuron has started aging. This is either the
    /// creation time or the last time at which the neuron has stopped
    /// dissolving.
    ///
    /// This value is meaningless when the neuron is dissolving, since a
    /// dissolving neurons always has age zero. The canonical value of
    /// this field for a dissolving neuron is `u64::MAX`.
    pub aging_since_timestamp_seconds: u64,
    /// The timestamp, in seconds from the Unix epoch, at which this
    /// neuron should be spawned and its maturity converted to ICP
    /// according to <https://wiki.internetcomputer.org/wiki/Maturity_modulation.>
    pub spawn_at_timestamp_seconds: Option<u64>,
    /// Map `Topic` to followees. The key is represented by an integer as
    /// Protobuf does not support enum keys in maps.
    pub followees: ::std::collections::HashMap<i32, neuron::Followees>,
    /// Information about how this neuron voted in the recent past. It
    /// only contains proposals that the neuron voted yes or no on.
    pub recent_ballots: Vec<BallotInfo>,
    /// `true` if this neuron has passed KYC, `false` otherwise
    pub kyc_verified: bool,
    /// The record of the transfer that was made to create this neuron.
    pub transfer: Option<NeuronStakeTransfer>,
    /// The accumulated unstaked maturity of the neuron, in "e8s equivalent".
    ///
    /// The unit is "e8s equivalent" to insist that, while this quantity is on
    /// the same scale as ICPs, maturity is not directly convertible to ICPs:
    /// conversion requires a minting event and the conversion rate is variable.
    pub maturity_e8s_equivalent: u64,
    /// The accumulated staked maturity of the neuron, in "e8s equivalent" (see
    /// "maturity_e8s_equivalent"). Staked maturity becomes regular maturity once
    /// the neuron is dissolved.
    ///
    /// Contrary to `maturity_e8s_equivalent` this maturity is staked and thus
    /// locked until the neuron is dissolved and contributes to voting power
    /// and rewards. Once the neuron is dissolved, this maturity will be "moved"
    /// to 'maturity_e8s_equivalent' and will be able to be spawned (with maturity
    /// modulation).
    pub staked_maturity_e8s_equivalent: Option<u64>,
    /// If set and true the maturity rewarded to this neuron for voting will be
    /// automatically staked and will contribute to the neuron's voting power.
    pub auto_stake_maturity: Option<bool>,
    /// Whether this neuron is "Not for profit", making it dissolvable
    /// by voting.
    pub not_for_profit: bool,
    /// If set, this neuron is a member of the Community Fund. This means that when
    /// a proposal to open an SNS token swap is executed, maturity from this neuron
    /// will be used to participate in the SNS token swap.
    pub joined_community_fund_timestamp_seconds: Option<u64>,
    /// If set, the neuron belongs to the "known neurons". It has been given a name and maybe a description.
    pub known_neuron_data: Option<KnownNeuronData>,
    /// The type of the Neuron. See \[NeuronType\] for a description
    /// of the different states.
    pub neuron_type: Option<i32>,
    /// See the Visibility enum.
    pub visibility: Option<i32>,
    /// The last time that voting power was "refreshed". There are two ways to
    /// refresh the voting power of a neuron: set following, or vote directly. In
    /// the future, there will be a dedicated API for refreshing. Note that direct
    /// voting implies that refresh also occurs when a proposal is created, because
    /// direct voting is part of proposal creation.
    ///
    /// Effect: When this becomes > 6 months ago, the amount of voting power that
    /// this neuron can exercise decreases linearly down to 0 over the course of 1
    /// month. After that, following is cleared, except for ManageNeuron proposals.
    ///
    /// This will always be populated. If the underlying neuron was never
    /// refreshed, this will be set to 2024-11-05T00:00:01 UTC (1730764801 seconds
    /// after the UNIX epoch).
    pub voting_power_refreshed_timestamp_seconds: ::core::option::Option<u64>,
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
    pub dissolve_state: Option<neuron::DissolveState>,
    /// The amount of "sway" this neuron has when voting on proposals.
    ///
    /// When a proposal is created, each eligible neuron gets a "blank" ballot. The
    /// amount of voting power in that ballot is set to the neuron's deciding
    /// voting power at the time of proposal creation. There are two ways that a
    /// proposal can become decided:
    ///
    ///   1. Early: Either more than half of the total voting power in the ballots
    ///   votes in favor (then the proposal is approved), or at least half of the
    ///   votal voting power in the ballots votes against (then, the proposal is
    ///   rejected).
    ///
    ///   2. The proposal's voting deadline is reached. At that point, if there is
    ///   more voting power in favor than against, and at least 3% of the total
    ///   voting power voted in favor, then the proposal is approved. Otherwise, it
    ///   is rejected.
    ///
    /// If a neuron regularly refreshes its voting power, this has the same value
    /// as potential_voting_power. Actions that cause a refresh are as follows:
    ///
    ///     1. voting directly (not via following)
    ///     2. set following
    ///     3. refresh voting power
    ///
    /// (All of these actions are performed via the manage_neuron method.)
    ///
    /// However, if a neuron has not refreshed in a "long" time, this will be less
    /// than potential voting power. See VotingPowerEconomics. As a further result
    /// of less deciding voting power, not only does it have less influence on the
    /// outcome of proposals, the neuron receives less voting rewards (when it
    /// votes indirectly via following).
    ///
    /// For details, see https://dashboard.internetcomputer.org/proposal/132411.
    ///
    /// Per NNS policy, this is opt. Nevertheless, it will never be null.
    pub deciding_voting_power: Option<u64>,
    /// The amount of "sway" this neuron can have if it refreshes its voting power
    /// frequently enough.
    ///
    /// Unlike deciding_voting_power, this does NOT take refreshing into account.
    /// Rather, this only takes three factors into account:
    ///
    ///     1. (Net) staked amount - This is the "base" of a neuron's voting power.
    ///        This primarily consists of the neuron's ICP balance.
    ///
    ///     2. Age - Neurons with more age have more voting power (all else being
    ///        equal).
    ///
    ///     3. Dissolve delay - Neurons with longer dissolve delay have more voting
    ///        power (all else being equal). Neurons with a dissolve delay of less
    ///        than six months are not eligible to vote. Therefore, such neurons
    ///        are considered to have 0 voting power.
    ///
    /// Per NNS policy, this is opt. Nevertheless, it will never be null.
    pub potential_voting_power: Option<u64>,

    /// The maturity disbursements in progress for this neuron.
    pub maturity_disbursements_in_progress: Option<Vec<MaturityDisbursement>>,
}
/// Nested message and enum types in `Neuron`.
pub mod neuron {
    use super::*;

    /// Protobuf representing a list of followees of a neuron for a
    /// specific topic.
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct Followees {
        pub followees: Vec<NeuronId>,
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
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug,
    )]
    pub enum DissolveState {
        /// When the dissolve timer is running, this stores the timestamp,
        /// in seconds from the Unix epoch, at which the neuron becomes
        /// dissolved.
        ///
        /// At any time while the neuron is dissolving, the neuron owner
        /// may pause dissolving, in which case `dissolve_delay_seconds`
        /// will get assigned to: `when_dissolved_timestamp_seconds -
        /// <timestamp when the action is taken>`.
        WhenDissolvedTimestampSeconds(u64),
        /// When the dissolve timer is stopped, this stores how much time,
        /// in seconds, the dissolve timer will be started with. Can be at
        /// most 8 years.
        ///
        /// At any time while in this state, the neuron owner may (re)start
        /// dissolving, in which case `when_dissolved_timestamp_seconds`
        /// will get assigned to: `<timestamp when the action is taken> +
        /// dissolve_delay_seconds`.
        DissolveDelaySeconds(u64),
    }
}

/// Payload of a proposal that calls a function on another NNS
/// canister. The canister and function to call is derived from the
/// `nns_function`.
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct ExecuteNnsFunction {
    /// This enum value determines what canister to call and what NNS
    /// function to call on that canister.
    pub nns_function: i32,
    /// The payload of the NNS function.
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>,
}
/// If adopted, a motion should guide the future strategy of the
/// Internet Computer ecosystem.
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct Motion {
    /// The text of the motion. Maximum 100kib.
    pub motion_text: String,
}
/// For all Neurons controlled by the given principals, set their
/// KYC status to `kyc_verified=true`.
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct ApproveGenesisKyc {
    pub principals: Vec<PrincipalId>,
}
/// Adds and/or removes NodeProviders from the list of current
/// node providers.
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct AddOrRemoveNodeProvider {
    pub change: Option<add_or_remove_node_provider::Change>,
}
/// Nested message and enum types in `AddOrRemoveNodeProvider`.
pub mod add_or_remove_node_provider {
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug,
    )]
    pub enum Change {
        ToAdd(super::NodeProvider),
        ToRemove(super::NodeProvider),
    }
}
/// This proposal payload is used to reward a node provider by minting
/// ICPs directly to the node provider's ledger account, or into a new
/// neuron created on behalf of the node provider.
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct RewardNodeProvider {
    /// The NodeProvider to reward.
    pub node_provider: Option<NodeProvider>,
    /// The amount of e8s to mint to reward the node provider.
    pub amount_e8s: u64,
    pub reward_mode: Option<reward_node_provider::RewardMode>,
}
/// Nested message and enum types in `RewardNodeProvider`.
pub mod reward_node_provider {
    use super::*;
    /// This message specifies how to create a new neuron on behalf of
    /// the node provider.
    ///
    /// - The controller of the new neuron is the node provider's
    ///    principal.
    ///
    /// - The account is chosen at random.
    ///
    /// - The stake of the new neuron is `amount_e8s`.
    ///
    /// - `dissolve_delay_seconds` is as specified in the proto.
    ///
    /// - `kyc_verified` is set to true, as node providers are
    ///    (implicitly) KYC'ed.
    ///
    /// - `not_for_profit` is set to false.
    ///
    /// - All other values are set as for other neurons: timestamp is
    ///    now, following is set up per default, maturity is 0, neuron fee
    ///    is 0.
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct RewardToNeuron {
        pub dissolve_delay_seconds: u64,
    }
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct RewardToAccount {
        pub to_account: Option<AccountIdentifier>,
    }
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug,
    )]
    pub enum RewardMode {
        /// If this is specified, executing this proposal will create a
        /// neuron instead of directly minting ICP into the node provider's
        /// account.
        RewardToNeuron(RewardToNeuron),
        /// If this is specified, executing this proposal will mint to the
        /// specified account.
        RewardToAccount(RewardToAccount),
    }
}
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct RewardNodeProviders {
    pub rewards: Vec<RewardNodeProvider>,
    /// If true, reward Node Providers with the rewards returned by the Registry's
    /// get_node_providers_monthly_xdr_rewards method
    pub use_registry_derived_rewards: Option<bool>,
}
/// Changes the default followees to match the one provided.
/// This completely replaces the default followees so entries for all
/// Topics (except ManageNeuron) must be provided on each proposal.
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct SetDefaultFollowees {
    pub default_followees: ::std::collections::HashMap<i32, neuron::Followees>,
}
/// Obsolete. Superseded by OpenSnsTokenSwap.
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct SetSnsTokenSwapOpenTimeWindow {
    /// The swap canister to send the request to.
    pub swap_canister_id: Option<PrincipalId>,
    /// Arguments that get sent to the swap canister when its set_open_time_window
    /// Candid method is called.
    pub request: Option<::ic_sns_swap::pb::v1::SetOpenTimeWindowRequest>,
}
/// A proposal is the immutable input of a proposal submission. This contains
/// all the information from the original proposal submission.
///
/// Making a proposal implicitly votes yes.
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct Proposal {
    /// Must be present (enforced at the application layer, not by PB).
    /// A brief description of what the proposal does.
    /// Size in bytes must be in the interval \[5, 256\].
    pub title: Option<String>,
    /// Text providing a short description of the proposal, composed
    /// using a maximum of 30000 bytes of characters.
    pub summary: String,
    /// The Web address of additional content required to evaluate the
    /// proposal, specified using HTTPS. For example, the address might
    /// describe content supporting the assignment of a DCID (data center
    /// id) to a new data center. The URL string must not be longer than
    /// 2000 bytes.
    pub url: String,
    /// This section describes the action that the proposal proposes to
    /// take.
    pub action: Option<proposal::Action>,
    /// A self-describing action that can be understood without the schema of a specific
    /// proposal type.
    pub self_describing_action: Option<SelfDescribingProposalAction>,
}
/// Nested message and enum types in `Proposal`.
pub mod proposal {
    /// This section describes the action that the proposal proposes to
    /// take.
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug,
    )]
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
        ManageNeuron(Box<super::ManageNeuronProposal>),
        /// Propose a change to some network parameters of network
        /// economics.
        ManageNetworkEconomics(super::NetworkEconomics),
        /// See \[Motion\]
        Motion(super::Motion),
        /// A update affecting something outside of the Governance
        /// canister.
        ExecuteNnsFunction(super::ExecuteNnsFunction),
        /// Approve Genesis KYC for a given list of principals.
        ApproveGenesisKyc(super::ApproveGenesisKyc),
        /// Add/remove NodeProvider from the list of NodeProviders
        AddOrRemoveNodeProvider(super::AddOrRemoveNodeProvider),
        /// Reward a NodeProvider
        RewardNodeProvider(super::RewardNodeProvider),
        /// Set the default following
        SetDefaultFollowees(super::SetDefaultFollowees),
        /// Reward multiple NodeProvider
        RewardNodeProviders(super::RewardNodeProviders),
        /// Register Known Neuron
        RegisterKnownNeuron(super::KnownNeuron),
        /// Deregister Known Neuron
        DeregisterKnownNeuron(super::DeregisterKnownNeuron),
        /// Obsolete. Superseded by CreateServiceNervousSystem. Kept for Candid compatibility.
        SetSnsTokenSwapOpenTimeWindow(super::SetSnsTokenSwapOpenTimeWindow),
        /// Call the open method on an SNS swap canister.
        ///
        /// This is still supported but will soon be superseded by
        /// CreateServiceNervousSystem.
        OpenSnsTokenSwap(super::OpenSnsTokenSwap),
        /// Create a new SNS.
        CreateServiceNervousSystem(super::CreateServiceNervousSystem),
        /// Install, reinstall or upgrade the code of a canister that is controlled by the NNS.
        InstallCode(super::InstallCode),
        /// Stop or start a canister that is controlled by the NNS.
        StopOrStartCanister(super::StopOrStartCanister),
        /// Update the settings of a canister that is controlled by the NNS.
        UpdateCanisterSettings(super::UpdateCanisterSettings),
        /// The main thing this does is create a subnet where the "user" of the
        /// rental request has exclusive authorization to create canisters. The
        /// other special property of this subnet is that canisters are not
        /// charged for the use of computational resources (mainly, executing
        /// instructions, storing data, network, etc.)
        FulfillSubnetRentalRequest(super::FulfillSubnetRentalRequest),
        /// The main use case for this is when the virtual machine (VM) where
        /// replica runs is totally hosed such that it cannot be upgraded (and
        /// therefore fixed) using the usual mechanisms. When the VM is started
        /// with this alternative software, a signed copy of the ProposalInfo is
        /// passed to the VM, and read at boot time to prove that NNS has
        /// approved this alternative set of software. One of the main goals of
        /// this alternative software would generally be to bring the system
        /// back to a healthy state, to recover from some kind of disaster, like
        /// a boot loop, or something like that.
        BlessAlternativeGuestOsVersion(super::BlessAlternativeGuestOsVersion),
    }
}
/// Empty message to use in oneof fields that represent empty
/// enums.
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct Empty {}

/// All operations that modify the state of an existing neuron are
/// represented by instances of `ManageNeuron`.
///
/// All commands are available to the `controller` of the neuron. In
/// addition, commands related to voting, i.g., \[manage_neuron::Follow\]
/// and \[manage_neuron::RegisterVote\], are also available to the
/// registered hot keys of the neuron.
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct ManageNeuronProposal {
    /// This is the legacy way to specify neuron IDs that is now discouraged.
    pub id: Option<NeuronId>,
    /// The ID of the neuron to manage. This can either be a subaccount or a neuron ID.
    pub neuron_id_or_subaccount: Option<manage_neuron::NeuronIdOrSubaccount>,
    pub command: Option<manage_neuron::ManageNeuronProposalCommand>,
}
/// Nested message and enum types in `ManageNeuron`.
pub mod manage_neuron {
    use super::*;

    /// The dissolve delay of a neuron can be increased up to a maximum
    /// of 8 years.
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct IncreaseDissolveDelay {
        pub additional_dissolve_delay_seconds: u32,
    }
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct StartDissolving {}
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct StopDissolving {}
    /// Add a new hot key that can be used to manage the neuron. This
    /// provides an alternative to using the controller principal’s cold key to
    /// manage the neuron, which might be onerous and difficult to keep
    /// secure, especially if it is used regularly. A hot key might be a
    /// WebAuthn key that is maintained inside a user device, such as a
    /// smartphone.
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct AddHotKey {
        pub new_hot_key: Option<PrincipalId>,
    }
    /// Remove a hot key that has been previously assigned to the neuron.
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct RemoveHotKey {
        pub hot_key_to_remove: Option<PrincipalId>,
    }
    /// An (idempotent) alternative to IncreaseDissolveDelay where the dissolve delay
    /// is passed as an absolute timestamp in seconds since the unix epoch.
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct SetDissolveTimestamp {
        pub dissolve_timestamp_seconds: u64,
    }
    /// Join the Internet Computer's community fund with this neuron's present and future maturity.
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct JoinCommunityFund {}
    /// Leave the Internet Computer's community fund.
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct LeaveCommunityFund {}
    /// Changes auto-stake maturity for this Neuron. While on, auto-stake
    /// maturity will cause all the maturity generated by voting rewards
    /// to this neuron to be automatically staked and contribute to the
    /// voting power of the neuron.
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct ChangeAutoStakeMaturity {
        pub requested_setting_for_auto_stake_maturity: bool,
    }
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct SetVisibility {
        pub visibility: Option<i32>,
    }
    /// Commands that only configure a given neuron, but do not interact
    /// with the outside world. They all require the caller to be the
    /// controller of the neuron.
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct Configure {
        pub operation: Option<configure::Operation>,
    }
    /// Nested message and enum types in `Configure`.
    pub mod configure {
        #[derive(
            candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug,
        )]
        pub enum Operation {
            IncreaseDissolveDelay(super::IncreaseDissolveDelay),
            StartDissolving(super::StartDissolving),
            StopDissolving(super::StopDissolving),
            AddHotKey(super::AddHotKey),
            RemoveHotKey(super::RemoveHotKey),
            SetDissolveTimestamp(super::SetDissolveTimestamp),
            JoinCommunityFund(super::JoinCommunityFund),
            LeaveCommunityFund(super::LeaveCommunityFund),
            ChangeAutoStakeMaturity(super::ChangeAutoStakeMaturity),
            SetVisibility(super::SetVisibility),
        }
    }
    /// Disburse this neuron's stake: transfer the staked ICP to the
    /// specified account.
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct Disburse {
        /// The (optional) amount to transfer. If not specified the cached
        /// stake is used.
        pub amount: Option<disburse::Amount>,
        /// The principal to which to transfer the stake.
        pub to_account: Option<AccountIdentifier>,
    }
    /// Nested message and enum types in `Disburse`.
    pub mod disburse {
        #[derive(
            candid::CandidType,
            candid::Deserialize,
            serde::Serialize,
            Clone,
            PartialEq,
            Debug,
            Default,
        )]
        pub struct Amount {
            pub e8s: u64,
        }
    }
    /// Split this neuron into two neurons.
    ///
    /// The child neuron retains the parent neuron's properties.
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct Split {
        /// The amount to split to the child neuron.
        pub amount_e8s: u64,
        /// The memo to use for the child neuron.
        pub memo: Option<u64>,
    }
    /// Merge another neuron into this neuron.
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct Merge {
        /// The neuron to merge stake and maturity from.
        pub source_neuron_id: Option<NeuronId>,
    }
    /// When the maturity of a neuron has risen above a threshold, it can
    /// be instructed to spawn a new neuron. This creates a new neuron
    /// that locks a new balance of ICP on the ledger. The new neuron can
    /// remain controlled by the same principal as its parent, or be
    /// assigned to a new principal.
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct Spawn {
        /// If not set, the spawned neuron will have the same controller as
        /// this neuron.
        pub new_controller: Option<PrincipalId>,
        /// The nonce with which to create the subaccount.
        pub nonce: Option<u64>,
        /// The percentage to spawn, from 1 to 100 (inclusive).
        pub percentage_to_spawn: Option<u32>,
    }
    /// Merge the maturity of a neuron into the current stake.
    /// The caller can choose a percentage of the current maturity to merge into
    /// the existing stake. The resulting amount to merge must be greater than
    /// or equal to the transaction fee.
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct MergeMaturity {
        /// The percentage to merge, from 1 to 100 (inclusive).
        pub percentage_to_merge: u32,
    }
    /// Stake the maturity of a neuron.
    /// The caller can choose a percentage of of the current maturity to stake.
    /// If 'percentage_to_stake' is not provided, all of the neuron's current
    /// maturity will be staked.
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct StakeMaturity {
        /// The percentage of maturity to stake, from 1 to 100 (inclusive).
        pub percentage_to_stake: Option<u32>,
    }
    /// Disburse a portion of this neuron's stake into another neuron.
    /// This allows to split a neuron but with a new dissolve delay
    /// and owned by someone else.
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct DisburseToNeuron {
        /// The controller of the new neuron (must be set).
        pub new_controller: Option<PrincipalId>,
        /// The amount to disburse.
        pub amount_e8s: u64,
        /// The dissolve delay of the new neuron.
        pub dissolve_delay_seconds: u64,
        /// Whether the new neuron has been kyc verified.
        pub kyc_verified: bool,
        /// The nonce with which to create the subaccount.
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
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct Follow {
        /// Topic UNSPECIFIED means add following for the 'catch all'.
        pub topic: i32,
        pub followees: Vec<NeuronId>,
    }
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct SetFollowing {
        pub topic_following: Option<Vec<set_following::FolloweesForTopic>>,
    }
    pub mod set_following {
        use super::*;

        #[derive(
            candid::CandidType,
            candid::Deserialize,
            serde::Serialize,
            Clone,
            PartialEq,
            Debug,
            Default,
        )]
        pub struct FolloweesForTopic {
            pub followees: Option<Vec<NeuronId>>,
            pub topic: Option<i32>,
        }
    }
    /// Have the neuron vote to either adopt or reject a proposal with a specified
    /// id.
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct RegisterVote {
        pub proposal: Option<::ic_nns_common::pb::v1::ProposalId>,
        pub vote: i32,
    }
    /// Claim a new neuron or refresh the stake of an existing neuron.
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct ClaimOrRefresh {
        pub by: Option<claim_or_refresh::By>,
    }
    /// Nested message and enum types in `ClaimOrRefresh`.
    pub mod claim_or_refresh {
        use super::*;

        #[derive(
            candid::CandidType,
            candid::Deserialize,
            serde::Serialize,
            Clone,
            PartialEq,
            Debug,
            Default,
        )]
        pub struct MemoAndController {
            pub memo: u64,
            pub controller: Option<PrincipalId>,
        }
        #[derive(
            candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug,
        )]
        pub enum By {
            /// DEPRECATED: Use MemoAndController and omit the controller.
            Memo(u64),
            /// Claim or refresh a neuron, by providing the memo used in the
            /// staking transfer and 'controller' as the principal id used to
            /// calculate the subaccount to which the transfer was made. If
            /// 'controller' is omitted, the principal id of the caller is
            /// used.
            MemoAndController(MemoAndController),
            /// This just serves as a tag to indicate that the neuron should be
            /// refreshed by it's id or subaccount. This does not work to claim
            /// new neurons.
            NeuronIdOrSubaccount(super::super::Empty),
        }
    }

    /// This is one way for a neuron to make sure that its deciding_voting_power is
    /// not less than its potential_voting_power. See the description of those
    /// fields in Neuron.
    #[derive(
        candid::CandidType,
        candid::Deserialize,
        serde::Serialize,
        Clone,
        Copy,
        PartialEq,
        Debug,
        Default,
    )]
    pub struct RefreshVotingPower {}

    /// Disburse the maturity of a neuron to any ledger account. If an account
    /// is not specified, the caller's account will be used. The caller can choose
    /// a percentage of the current maturity to disburse to the ledger account. The
    /// resulting amount to disburse must be greater than or equal to the
    /// transaction fee.
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct DisburseMaturity {
        /// The percentage to disburse, from 1 to 100
        pub percentage_to_disburse: u32,
        /// The (optional) principal to which to transfer the stake. It should not be set if
        /// `to_account_identifier` is set.
        pub to_account: ::core::option::Option<super::Account>,
        /// The (optional) account identifier to which to transfer the stake. It should not be set if
        /// `to_account` is set.
        pub to_account_identifier: ::core::option::Option<super::AccountIdentifier>,
    }

    /// The ID of the neuron to manage. This can either be a subaccount or a neuron ID.
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug,
    )]
    pub enum NeuronIdOrSubaccount {
        #[serde(with = "serde_bytes")]
        Subaccount(Vec<u8>),
        NeuronId(NeuronId),
    }

    // KEEP THIS IN SYNC WITH ManageNeuronCommandRequest!
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug,
    )]
    pub enum ManageNeuronProposalCommand {
        Configure(Configure),
        Disburse(Disburse),
        Spawn(Spawn),
        Follow(Follow),
        MakeProposal(Box<super::Proposal>),
        RegisterVote(RegisterVote),
        Split(Split),
        DisburseToNeuron(DisburseToNeuron),
        ClaimOrRefresh(ClaimOrRefresh),
        MergeMaturity(MergeMaturity),
        Merge(Merge),
        StakeMaturity(StakeMaturity),
        RefreshVotingPower(RefreshVotingPower),
        DisburseMaturity(DisburseMaturity),
        SetFollowing(SetFollowing),
        // KEEP THIS IN SYNC WITH ManageNeuronCommandRequest!
    }
}
/// The response of the ManageNeuron command
///
/// There is a dedicated response type for each `ManageNeuron.command` field
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct ManageNeuronResponse {
    pub command: Option<manage_neuron_response::Command>,
}
/// Nested message and enum types in `ManageNeuronResponse`.
pub mod manage_neuron_response {
    use super::*;

    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct ConfigureResponse {}
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct DisburseResponse {
        /// The block height at which the disburse transfer happened
        pub transfer_block_height: u64,
    }
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct SpawnResponse {
        /// The ID of the Neuron created from spawning a Neuron
        pub created_neuron_id: Option<NeuronId>,
    }
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct MergeMaturityResponse {
        pub merged_maturity_e8s: u64,
        pub new_stake_e8s: u64,
    }
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct StakeMaturityResponse {
        pub maturity_e8s: u64,
        pub staked_maturity_e8s: u64,
    }
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct FollowResponse {}
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct MakeProposalResponse {
        /// The ID of the created proposal
        pub proposal_id: Option<::ic_nns_common::pb::v1::ProposalId>,
        pub message: Option<String>,
    }
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct RegisterVoteResponse {}
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct SplitResponse {
        /// The ID of the Neuron created from splitting another Neuron
        pub created_neuron_id: Option<NeuronId>,
    }
    /// A response for merging or simulating merge neurons
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct MergeResponse {
        /// The resulting state of the source neuron
        pub source_neuron: Option<super::Neuron>,
        /// The resulting state of the target neuron
        pub target_neuron: Option<super::Neuron>,
        /// The NeuronInfo of the source neuron
        pub source_neuron_info: Option<super::NeuronInfo>,
        /// The NeuronInfo of the target neuron
        pub target_neuron_info: Option<super::NeuronInfo>,
    }
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct DisburseToNeuronResponse {
        /// The ID of the Neuron created from disbursing a Neuron
        pub created_neuron_id: Option<NeuronId>,
    }
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct ClaimOrRefreshResponse {
        pub refreshed_neuron_id: Option<NeuronId>,
    }

    #[derive(
        candid::CandidType,
        candid::Deserialize,
        serde::Serialize,
        Clone,
        Copy,
        PartialEq,
        Debug,
        Default,
    )]
    pub struct RefreshVotingPowerResponse {}

    #[derive(
        candid::CandidType,
        candid::Deserialize,
        serde::Serialize,
        Clone,
        Copy,
        PartialEq,
        Debug,
        Default,
    )]
    pub struct DisburseMaturityResponse {
        pub amount_disbursed_e8s: Option<u64>,
    }

    #[derive(
        candid::CandidType,
        candid::Deserialize,
        serde::Serialize,
        Clone,
        Copy,
        PartialEq,
        Debug,
        Default,
    )]
    pub struct SetFollowingResponse {}

    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug,
    )]
    pub enum Command {
        Error(super::GovernanceError),
        Configure(ConfigureResponse),
        Disburse(DisburseResponse),
        Spawn(SpawnResponse),
        Follow(FollowResponse),
        MakeProposal(MakeProposalResponse),
        RegisterVote(RegisterVoteResponse),
        Split(SplitResponse),
        DisburseToNeuron(DisburseToNeuronResponse),
        ClaimOrRefresh(ClaimOrRefreshResponse),
        MergeMaturity(MergeMaturityResponse),
        Merge(MergeResponse),
        StakeMaturity(StakeMaturityResponse),
        RefreshVotingPower(RefreshVotingPowerResponse),
        DisburseMaturity(DisburseMaturityResponse),
        SetFollowing(SetFollowingResponse),
    }

    // Below, we should remove `manage_neuron_response::`, but that should be
    // done later, so that the original PR that transplanted this code does not
    // have "extra" refactoring in it.
    impl ManageNeuronResponse {
        pub fn is_err(&self) -> bool {
            matches!(
                &self.command,
                Some(manage_neuron_response::Command::Error(_))
            )
        }

        pub fn err_ref(&self) -> Option<&GovernanceError> {
            match &self.command {
                Some(manage_neuron_response::Command::Error(err)) => Some(err),
                _ => None,
            }
        }

        pub fn err(self) -> Option<GovernanceError> {
            match self.command {
                Some(manage_neuron_response::Command::Error(err)) => Some(err),
                _ => None,
            }
        }

        pub fn is_ok(&self) -> bool {
            !self.is_err()
        }

        pub fn panic_if_error(self, msg: &str) -> Self {
            if let Some(manage_neuron_response::Command::Error(err)) = &self.command {
                panic!("{}: {}", msg, err);
            }
            self
        }

        // This is generic so that callers can pass either GovernanceError from
        // the ic_nns_governance crate (notice the lack of "_api" at the end of
        // the name!), in addition to GovernanceError from this crate.
        pub fn error<E>(err: E) -> Self
        where
            GovernanceError: From<E>,
        {
            ManageNeuronResponse {
                command: Some(Command::Error(GovernanceError::from(err))),
            }
        }

        pub fn configure_response() -> Self {
            ManageNeuronResponse {
                command: Some(manage_neuron_response::Command::Configure(
                    manage_neuron_response::ConfigureResponse {},
                )),
            }
        }

        pub fn disburse_response(transfer_block_height: u64) -> Self {
            ManageNeuronResponse {
                command: Some(manage_neuron_response::Command::Disburse(
                    manage_neuron_response::DisburseResponse {
                        transfer_block_height,
                    },
                )),
            }
        }

        pub fn spawn_response(created_neuron_id: NeuronId) -> Self {
            let created_neuron_id = Some(created_neuron_id);
            ManageNeuronResponse {
                command: Some(manage_neuron_response::Command::Spawn(
                    manage_neuron_response::SpawnResponse { created_neuron_id },
                )),
            }
        }

        pub fn stake_maturity_response(response: StakeMaturityResponse) -> Self {
            ManageNeuronResponse {
                command: Some(manage_neuron_response::Command::StakeMaturity(response)),
            }
        }

        pub fn follow_response() -> Self {
            ManageNeuronResponse {
                command: Some(manage_neuron_response::Command::Follow(
                    manage_neuron_response::FollowResponse {},
                )),
            }
        }

        pub fn make_proposal_response(proposal_id: ProposalId, message: String) -> Self {
            let proposal_id = Some(proposal_id);
            let message = Some(message);
            ManageNeuronResponse {
                command: Some(manage_neuron_response::Command::MakeProposal(
                    manage_neuron_response::MakeProposalResponse {
                        proposal_id,
                        message,
                    },
                )),
            }
        }

        pub fn register_vote_response() -> Self {
            ManageNeuronResponse {
                command: Some(manage_neuron_response::Command::RegisterVote(
                    manage_neuron_response::RegisterVoteResponse {},
                )),
            }
        }

        pub fn split_response(created_neuron_id: NeuronId) -> Self {
            let created_neuron_id = Some(created_neuron_id);
            ManageNeuronResponse {
                command: Some(manage_neuron_response::Command::Split(
                    manage_neuron_response::SplitResponse { created_neuron_id },
                )),
            }
        }

        pub fn merge_response(merge_response: manage_neuron_response::MergeResponse) -> Self {
            ManageNeuronResponse {
                command: Some(manage_neuron_response::Command::Merge(merge_response)),
            }
        }

        pub fn disburse_to_neuron_response(created_neuron_id: NeuronId) -> Self {
            let created_neuron_id = Some(created_neuron_id);
            ManageNeuronResponse {
                command: Some(manage_neuron_response::Command::DisburseToNeuron(
                    manage_neuron_response::DisburseToNeuronResponse { created_neuron_id },
                )),
            }
        }

        pub fn claim_or_refresh_neuron_response(refreshed_neuron_id: NeuronId) -> Self {
            let refreshed_neuron_id = Some(refreshed_neuron_id);
            ManageNeuronResponse {
                command: Some(manage_neuron_response::Command::ClaimOrRefresh(
                    manage_neuron_response::ClaimOrRefreshResponse {
                        refreshed_neuron_id,
                    },
                )),
            }
        }

        pub fn refresh_voting_power_response(_: ()) -> Self {
            ManageNeuronResponse {
                command: Some(manage_neuron_response::Command::RefreshVotingPower(
                    manage_neuron_response::RefreshVotingPowerResponse {},
                )),
            }
        }

        pub fn disburse_maturity_response(amount_disbursed_e8s: u64) -> Self {
            ManageNeuronResponse {
                command: Some(manage_neuron_response::Command::DisburseMaturity(
                    manage_neuron_response::DisburseMaturityResponse {
                        amount_disbursed_e8s: Some(amount_disbursed_e8s),
                    },
                )),
            }
        }

        pub fn set_following_response(_: ()) -> Self {
            ManageNeuronResponse {
                command: Some(manage_neuron_response::Command::SetFollowing(
                    manage_neuron_response::SetFollowingResponse {},
                )),
            }
        }
    }
}

#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct MakeProposalRequest {
    pub title: ::core::option::Option<String>,
    pub summary: String,
    pub url: String,
    pub action: ::core::option::Option<ProposalActionRequest>,
}

#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug)]
pub enum ProposalActionRequest {
    ManageNeuron(Box<ManageNeuronRequest>),
    ManageNetworkEconomics(NetworkEconomics),
    Motion(Motion),
    ExecuteNnsFunction(ExecuteNnsFunction),
    ApproveGenesisKyc(ApproveGenesisKyc),
    AddOrRemoveNodeProvider(AddOrRemoveNodeProvider),
    RewardNodeProvider(RewardNodeProvider),
    RewardNodeProviders(RewardNodeProviders),
    RegisterKnownNeuron(KnownNeuron),
    DeregisterKnownNeuron(DeregisterKnownNeuron),
    CreateServiceNervousSystem(CreateServiceNervousSystem),
    InstallCode(InstallCodeRequest),
    StopOrStartCanister(StopOrStartCanister),
    UpdateCanisterSettings(UpdateCanisterSettings),
    FulfillSubnetRentalRequest(FulfillSubnetRentalRequest),
    BlessAlternativeGuestOsVersion(BlessAlternativeGuestOsVersion),
}

#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct ManageNeuronRequest {
    pub id: ::core::option::Option<::ic_nns_common::pb::v1::NeuronId>,
    pub neuron_id_or_subaccount: ::core::option::Option<manage_neuron::NeuronIdOrSubaccount>,
    pub command: ::core::option::Option<ManageNeuronCommandRequest>,
}

// KEEP THIS IN SYNC WITH manage_neuron::Command!
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug)]
pub enum ManageNeuronCommandRequest {
    Configure(manage_neuron::Configure),
    Disburse(manage_neuron::Disburse),
    Spawn(manage_neuron::Spawn),
    Follow(manage_neuron::Follow),
    MakeProposal(Box<MakeProposalRequest>),
    RegisterVote(manage_neuron::RegisterVote),
    Split(manage_neuron::Split),
    DisburseToNeuron(manage_neuron::DisburseToNeuron),
    ClaimOrRefresh(manage_neuron::ClaimOrRefresh),
    MergeMaturity(manage_neuron::MergeMaturity),
    Merge(manage_neuron::Merge),
    StakeMaturity(manage_neuron::StakeMaturity),
    RefreshVotingPower(manage_neuron::RefreshVotingPower),
    DisburseMaturity(manage_neuron::DisburseMaturity),
    SetFollowing(manage_neuron::SetFollowing),
    // KEEP THIS IN SYNC WITH manage_neuron::Command!
}

#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct GovernanceError {
    pub error_type: i32,
    pub error_message: String,
}
/// Nested message and enum types in `GovernanceError`.
pub mod governance_error {
    #[derive(
        candid::CandidType,
        candid::Deserialize,
        serde::Serialize,
        Clone,
        Copy,
        Debug,
        PartialEq,
        Eq,
        Hash,
        PartialOrd,
        Ord,
        strum_macros::FromRepr,
    )]
    #[repr(i32)]
    pub enum ErrorType {
        Unspecified = 0,
        /// The operation was successfully completed.
        Ok = 1,
        /// There have been too many instances of this operation recently. In
        /// practice, this usually just means that another instance of this operation
        /// is currently in flight, but another reason this might come up is rate
        /// limiting.
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
        /// neuron's dissolve time is too short). There could be a change in the
        /// state of the system such that the operation becomes allowed (e.g. the
        /// owner of the neuron increases its dissolve delay).
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
        /// the neuron's dissolve delay will not make the proposal acceptable).
        InvalidProposal = 16,
        /// The neuron attempted to join the community fund while already
        /// a member.
        AlreadyJoinedCommunityFund = 17,
        /// The neuron attempted to leave the community fund but is not a member.
        NotInTheCommunityFund = 18,
        /// The neuron attempted to vote on a proposal that it has already voted on before.
        NeuronAlreadyVoted = 19,
    }
    impl ErrorType {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                ErrorType::Unspecified => "ERROR_TYPE_UNSPECIFIED",
                ErrorType::Ok => "ERROR_TYPE_OK",
                ErrorType::Unavailable => "ERROR_TYPE_UNAVAILABLE",
                ErrorType::NotAuthorized => "ERROR_TYPE_NOT_AUTHORIZED",
                ErrorType::NotFound => "ERROR_TYPE_NOT_FOUND",
                ErrorType::InvalidCommand => "ERROR_TYPE_INVALID_COMMAND",
                ErrorType::RequiresNotDissolving => "ERROR_TYPE_REQUIRES_NOT_DISSOLVING",
                ErrorType::RequiresDissolving => "ERROR_TYPE_REQUIRES_DISSOLVING",
                ErrorType::RequiresDissolved => "ERROR_TYPE_REQUIRES_DISSOLVED",
                ErrorType::HotKey => "ERROR_TYPE_HOT_KEY",
                ErrorType::ResourceExhausted => "ERROR_TYPE_RESOURCE_EXHAUSTED",
                ErrorType::PreconditionFailed => "ERROR_TYPE_PRECONDITION_FAILED",
                ErrorType::External => "ERROR_TYPE_EXTERNAL",
                ErrorType::LedgerUpdateOngoing => "ERROR_TYPE_LEDGER_UPDATE_ONGOING",
                ErrorType::InsufficientFunds => "ERROR_TYPE_INSUFFICIENT_FUNDS",
                ErrorType::InvalidPrincipal => "ERROR_TYPE_INVALID_PRINCIPAL",
                ErrorType::InvalidProposal => "ERROR_TYPE_INVALID_PROPOSAL",
                ErrorType::AlreadyJoinedCommunityFund => "ERROR_TYPE_ALREADY_JOINED_COMMUNITY_FUND",
                ErrorType::NotInTheCommunityFund => "ERROR_TYPE_NOT_IN_THE_COMMUNITY_FUND",
                ErrorType::NeuronAlreadyVoted => "ERROR_TYPE_NEURON_ALREADY_VOTED",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> Option<Self> {
            match value {
                "ERROR_TYPE_UNSPECIFIED" => Some(Self::Unspecified),
                "ERROR_TYPE_OK" => Some(Self::Ok),
                "ERROR_TYPE_UNAVAILABLE" => Some(Self::Unavailable),
                "ERROR_TYPE_NOT_AUTHORIZED" => Some(Self::NotAuthorized),
                "ERROR_TYPE_NOT_FOUND" => Some(Self::NotFound),
                "ERROR_TYPE_INVALID_COMMAND" => Some(Self::InvalidCommand),
                "ERROR_TYPE_REQUIRES_NOT_DISSOLVING" => Some(Self::RequiresNotDissolving),
                "ERROR_TYPE_REQUIRES_DISSOLVING" => Some(Self::RequiresDissolving),
                "ERROR_TYPE_REQUIRES_DISSOLVED" => Some(Self::RequiresDissolved),
                "ERROR_TYPE_HOT_KEY" => Some(Self::HotKey),
                "ERROR_TYPE_RESOURCE_EXHAUSTED" => Some(Self::ResourceExhausted),
                "ERROR_TYPE_PRECONDITION_FAILED" => Some(Self::PreconditionFailed),
                "ERROR_TYPE_EXTERNAL" => Some(Self::External),
                "ERROR_TYPE_LEDGER_UPDATE_ONGOING" => Some(Self::LedgerUpdateOngoing),
                "ERROR_TYPE_INSUFFICIENT_FUNDS" => Some(Self::InsufficientFunds),
                "ERROR_TYPE_INVALID_PRINCIPAL" => Some(Self::InvalidPrincipal),
                "ERROR_TYPE_INVALID_PROPOSAL" => Some(Self::InvalidProposal),
                "ERROR_TYPE_ALREADY_JOINED_COMMUNITY_FUND" => {
                    Some(Self::AlreadyJoinedCommunityFund)
                }
                "ERROR_TYPE_NOT_IN_THE_COMMUNITY_FUND" => Some(Self::NotInTheCommunityFund),
                "ERROR_TYPE_NEURON_ALREADY_VOTED" => Some(Self::NeuronAlreadyVoted),
                _ => None,
            }
        }
    }
}
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct Ballot {
    pub vote: i32,
    pub voting_power: u64,
}
/// A tally of votes.
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct Tally {
    /// When was this tally made
    pub timestamp_seconds: u64,
    /// Yeses, in voting power unit.
    pub yes: u64,
    /// Noes, in voting power unit.
    pub no: u64,
    /// Total voting power unit of eligible neurons.
    /// Should always be greater than or equal to yes + no.
    pub total: u64,
}
/// A ProposalData contains everything related to an open proposal:
/// the proposal itself (immutable), as well as mutable data such as
/// ballots.
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct ProposalData {
    /// This is stored here temporarily. It is also stored on the map
    /// that contains proposals.
    ///
    /// Immutable: The unique id for this proposal.
    pub id: Option<::ic_nns_common::pb::v1::ProposalId>,
    /// Immutable: The ID of the neuron that made this proposal.
    pub proposer: Option<NeuronId>,
    /// Immutable: The amount of ICP in E8s to be charged to the proposer if the
    /// proposal is rejected.
    pub reject_cost_e8s: u64,
    /// Immutable: The proposal originally submitted.
    pub proposal: Option<Proposal>,
    /// Immutable: The timestamp, in seconds from the Unix epoch, when this proposal
    /// was made.
    pub proposal_timestamp_seconds: u64,
    /// Map neuron ID to to the neuron's vote and voting power. Only
    /// present for as long as the proposal is not yet settled with
    /// respect to rewards.
    pub ballots: ::std::collections::HashMap<u64, Ballot>,
    /// Latest tally. Recomputed for every vote. Even after the proposal has been
    /// decided, the latest_tally will still be updated based on the recent vote,
    /// until the voting deadline.
    pub latest_tally: Option<Tally>,
    /// If specified: the timestamp when this proposal was adopted or
    /// rejected. If not specified, this proposal is still 'open'.
    pub decided_timestamp_seconds: u64,
    /// When an adopted proposal has been executed, this is set to
    /// current timestamp.
    pub executed_timestamp_seconds: u64,
    /// When an adopted proposal has failed to be executed, this is set
    /// to the current timestamp.
    pub failed_timestamp_seconds: u64,
    /// When an adopted proposal has failed to executed, this is set the
    /// reason for the failure.
    pub failure_reason: Option<GovernanceError>,
    /// The reward event round at which rewards for votes on this proposal
    /// was distributed.
    ///
    /// Rounds do not have to be consecutive.
    ///
    /// Rounds start at one: a value of zero indicates that
    /// no reward event taking this proposal into consideration happened yet.
    ///
    /// This field matches field day_after_genesis in RewardEvent.
    pub reward_event_round: u64,
    /// Wait-for-quiet state that needs to be saved in stable memory.
    pub wait_for_quiet_state: Option<WaitForQuietState>,
    /// This is populated when an OpenSnsTokenSwap proposal is first made.
    pub original_total_community_fund_maturity_e8s_equivalent: Option<u64>,
    /// This gets set to one of the terminal values (i.e. Committed or Aborted)
    /// when the swap canister calls our conclude_community_fund_participation
    /// Candid method. Initially, it is set to Open, because swap is supposed to
    /// enter that state when we call its open Candid method, which is the main
    /// operation in the execution of an OpenSnsTokenSwap proposal.
    pub sns_token_swap_lifecycle: Option<i32>,
    pub derived_proposal_information: Option<DerivedProposalInformation>,
    /// This structure contains data for settling the Neurons' Fund participation at the end of a swap.
    ///
    /// TODO\[NNS1-2566\]: deprecate `original_total_community_fund_maturity_e8s_equivalent` and
    /// `cf_participants` and use only this field for managing the Neurons' Fund swap participation.
    pub neurons_fund_data: Option<NeuronsFundData>,
    /// This is the amount of voting power that would be available if all neurons
    /// kept themselves "refreshed". This is used as the baseline for voting
    /// rewards. That is, the amount of maturity that a neuron receives is the
    /// amount of voting power that it exercised (so called "deciding" voting
    /// power) in proportion to this.
    pub total_potential_voting_power: ::core::option::Option<u64>,
    /// The topic of the proposal.
    pub topic: ::core::option::Option<i32>,
}
/// This structure contains data for settling the Neurons' Fund participation in an SNS token swap.
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct NeuronsFundData {
    /// Initial Neurons' Fund reserves computed at the time of execution of the proposal through which
    /// the SNS swap is created.
    pub initial_neurons_fund_participation: Option<NeuronsFundParticipation>,
    /// Final Neurons' Fund participation computed at the time of swap finalization. This field should
    /// remain unspecified until either (1) the `settle_neurons_fund_participation` function is called
    /// or (2) the NNS handles an error at the SNS deployment stage.
    ///
    /// If specified, this must be a subset of `initial_neurons_fund_participation`.
    pub final_neurons_fund_participation: Option<NeuronsFundParticipation>,
    /// Refunds for any leftover Neurons' Fund maturity that could not be used to participate in
    /// the swap. This field should remain unspecified `settle_neurons_fund_participation` is called.
    ///
    /// If specified, this must be equal to the following set-difference:
    /// `initial_neurons_fund_participation.neurons_fund_reserves`
    /// set-minus `final_neurons_fund_participation.neurons_fund_reserves`.
    pub neurons_fund_refunds: Option<NeuronsFundSnapshot>,
}
/// This is a view of the NeuronsFundData returned by API queries and is NOT used for storage.
/// Currently, the structure is identical to NeuronsFundData, but this may change over time.
/// Some of the fields, e.g., actual IDs of neurons, are anonymized.
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct NeuronsFundAuditInfo {
    /// See documentation for NeuronsFundData.neurons_fund_participation
    pub initial_neurons_fund_participation: Option<NeuronsFundParticipation>,
    /// See documentation for NeuronsFundData.final_neurons_fund_participation
    pub final_neurons_fund_participation: Option<NeuronsFundParticipation>,
    /// See documentation for NeuronsFundData.neurons_fund_refunds
    pub neurons_fund_refunds: Option<NeuronsFundSnapshot>,
}
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct GetNeuronsFundAuditInfoRequest {
    /// ID of the NNS proposal that resulted in the creation of the corresponding Swap.
    pub nns_proposal_id: Option<::ic_nns_common::pb::v1::ProposalId>,
}
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct GetNeuronsFundAuditInfoResponse {
    pub result: Option<get_neurons_fund_audit_info_response::Result>,
}
/// Nested message and enum types in `GetNeuronsFundAuditInfoResponse`.
pub mod get_neurons_fund_audit_info_response {
    /// Request was completed successfully.
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct Ok {
        /// Represents public information suitable for auditing Neurons' Fund participation in an SNS swap.
        pub neurons_fund_audit_info: Option<super::NeuronsFundAuditInfo>,
    }
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug,
    )]
    pub enum Result {
        Err(super::GovernanceError),
        Ok(Ok),
    }
}
/// Information for deciding how the Neurons' Fund should participate in an SNS Swap.
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct NeuronsFundParticipation {
    /// The function used in the implementation of Matched Funding.
    ///
    /// If an NNS Governance upgrade takes place *during* a swap, the original "ideal" matched
    /// participation function needs to be recovered at the end of the swap, ensuring e.g., that
    /// the amount of maturity stored in `neurons_fund_snapshot` will not not be exceeded for due to
    /// a change in this function.
    pub ideal_matched_participation_function: Option<IdealMatchedParticipationFunction>,
    /// The snapshot of the Neurons' Fund allocation of its maximum swap participation amount among
    /// its neurons. This snapshot is computed at the execution time of the NNS proposal leading
    /// to the swap opening.
    pub neurons_fund_reserves: Option<NeuronsFundSnapshot>,
    /// Absolute constraints for direct participants of this swap needed in Matched Funding
    /// computations.
    pub swap_participation_limits: Option<SwapParticipationLimits>,
    /// Neurons' Fund participation is computed for this amount of direct participation.
    pub direct_participation_icp_e8s: Option<u64>,
    /// Total amount of maturity in the Neurons' Fund at the time when the Neurons' Fund participation
    /// was created.
    pub total_maturity_equivalent_icp_e8s: Option<u64>,
    /// Maximum amount that the Neurons' Fund will participate with in this SNS swap, regardless of how
    /// large the value of `direct_participation_icp_e8s` is.
    pub max_neurons_fund_swap_participation_icp_e8s: Option<u64>,
    /// How much the Neurons' Fund would ideally like to participate with in this SNS swap, given
    /// the direct participation amount (`direct_participation_icp_e8s`) and matching function
    /// (`ideal_matched_participation_function`).
    pub intended_neurons_fund_participation_icp_e8s: Option<u64>,
    /// How much from `intended_neurons_fund_participation_icp_e8s` was the Neurons' Fund actually able
    /// to allocate, given the specific composition of neurons at the time of execution of the proposal
    /// through which this SNS was created and the participation limits of this SNS.
    pub allocated_neurons_fund_participation_icp_e8s: Option<u64>,
}
/// This function is called "ideal" because it serves as the guideline that the Neurons' Fund will
/// try to follow, but may deviate from in order to satisfy SNS-specific participation constraints
/// while allocating its overall participation amount among its neurons' maturity. In contrast,
/// The "effective" matched participation function `crate::neurons_fund::MatchedParticipationFunction`
/// is computed *based* on this one.
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct IdealMatchedParticipationFunction {
    /// The encoding of the "ideal" matched participation function is defined in `crate::neurons_fund`.
    /// In the future, we could change this message to represent full abstract syntactic trees
    /// comprised of elementary mathematical operators, with literals and variables as tree leaves.
    pub serialized_representation: Option<String>,
}
/// The snapshot of the Neurons' Fund allocation of its maximum swap participation amount among
/// its neurons. This snapshot is computed at the execution time of the NNS proposal leading
/// to the swap opening; it is then used at the end of a swap to compute the refund amounts
/// per Neuron' Fund neuron.
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct NeuronsFundSnapshot {
    pub neurons_fund_neuron_portions: Vec<neurons_fund_snapshot::NeuronsFundNeuronPortion>,
}
/// Nested message and enum types in `NeuronsFundSnapshot`.
pub mod neurons_fund_snapshot {
    use super::*;

    /// Represents one NNS neuron from the Neurons' Fund participating in this swap.
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct NeuronsFundNeuronPortion {
        /// The NNS neuron ID of the participating neuron.
        pub nns_neuron_id: Option<NeuronId>,
        /// Portion of maturity taken from this neuron. Must be less than or equal to
        /// `maturity_equivalent_icp_e8s`.
        pub amount_icp_e8s: Option<u64>,
        /// Overall amount of maturity of the neuron from which this portion is taken.
        pub maturity_equivalent_icp_e8s: Option<u64>,
        /// Whether the portion specified by `amount_icp_e8s` is limited due to SNS-specific
        /// participation constraints.
        pub is_capped: Option<bool>,
        /// The principal that can manage the NNS neuron that participated in the Neurons' Fund.
        pub controller: Option<PrincipalId>,
        /// The principals that can vote, propose, and follow on behalf of this neuron.
        pub hotkeys: Vec<PrincipalId>,
    }
}
/// Absolute constraints of this swap needed that the Neurons' Fund need to be aware of.
/// The fields correspond to those in Swap's `Init` message.
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct SwapParticipationLimits {
    pub min_direct_participation_icp_e8s: Option<u64>,
    pub max_direct_participation_icp_e8s: Option<u64>,
    pub min_participant_icp_e8s: Option<u64>,
    pub max_participant_icp_e8s: Option<u64>,
}
/// This message has a couple of unusual features.
///
/// 1. There is (currently) only one field. We expect that more fields will be
///     (and possibly other clients) to be able to handle this information in a
///     generic way, i.e. without having to change their code.
///
/// 2. Fields that might be added later will probably be mutually exclusive with
///     existing fields. Normally, this would be handled by putting all such
///     fields into a oneof. However, Candid has a bug where variant is not
///     handled correctly. Therefore, we refrain from using oneof until we believe
///     that the fix is very imminent.
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct DerivedProposalInformation {
    pub swap_background_information: Option<SwapBackgroundInformation>,
}
/// Additional information about the SNS that's being "swapped".
///
/// This data is fetched from other canisters. Currently, the swap canister
/// itself, and the root canister are queried, but additional canisters could be
/// queried later. In particular, the ID of the root canister is discovered via
/// the swap canister.
///
/// (See Governance::fetch_swap_background_information for how this is compiled.)
///
/// Obsolete. Superseded by newer fields.
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct SwapBackgroundInformation {
    pub fallback_controller_principal_ids: Vec<PrincipalId>,
    pub root_canister_summary: Option<swap_background_information::CanisterSummary>,
    pub governance_canister_summary: Option<swap_background_information::CanisterSummary>,
    pub ledger_canister_summary: Option<swap_background_information::CanisterSummary>,
    pub swap_canister_summary: Option<swap_background_information::CanisterSummary>,
    pub ledger_archive_canister_summaries: Vec<swap_background_information::CanisterSummary>,
    pub ledger_index_canister_summary: Option<swap_background_information::CanisterSummary>,
    pub dapp_canister_summaries: Vec<swap_background_information::CanisterSummary>,
}
/// Nested message and enum types in `SwapBackgroundInformation`.
pub mod swap_background_information {
    use super::*;

    /// Transcribed from sns/root.
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct CanisterSummary {
        pub canister_id: Option<PrincipalId>,
        pub status: Option<CanisterStatusResultV2>,
    }
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct CanisterStatusResultV2 {
        pub status: Option<i32>,
        #[serde(with = "serde_bytes")]
        pub module_hash: Vec<u8>,
        pub controllers: Vec<PrincipalId>,
        pub memory_size: Option<u64>,
        pub cycles: Option<u64>,
        pub freezing_threshold: Option<u64>,
        pub idle_cycles_burned_per_day: Option<u64>,
    }
    /// A canister can be stopped by calling stop_canister. The effect of
    /// stop_canister can be undone by calling start_canister. Stopping is an
    /// intermediate state where new method calls are rejected, but in-flight
    /// method calls are allowed to be fully serviced.
    #[derive(
        candid::CandidType,
        candid::Deserialize,
        serde::Serialize,
        Clone,
        Copy,
        Debug,
        PartialEq,
        Eq,
        Hash,
        PartialOrd,
        Ord,
    )]
    #[repr(i32)]
    pub enum CanisterStatusType {
        Unspecified = 0,
        Running = 1,
        Stopping = 2,
        Stopped = 3,
    }
    impl CanisterStatusType {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                CanisterStatusType::Unspecified => "CANISTER_STATUS_TYPE_UNSPECIFIED",
                CanisterStatusType::Running => "CANISTER_STATUS_TYPE_RUNNING",
                CanisterStatusType::Stopping => "CANISTER_STATUS_TYPE_STOPPING",
                CanisterStatusType::Stopped => "CANISTER_STATUS_TYPE_STOPPED",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> Option<Self> {
            match value {
                "CANISTER_STATUS_TYPE_UNSPECIFIED" => Some(Self::Unspecified),
                "CANISTER_STATUS_TYPE_RUNNING" => Some(Self::Running),
                "CANISTER_STATUS_TYPE_STOPPING" => Some(Self::Stopping),
                "CANISTER_STATUS_TYPE_STOPPED" => Some(Self::Stopped),
                _ => None,
            }
        }
    }
}
/// Stores data relevant to the "wait for quiet" implementation.
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct WaitForQuietState {
    pub current_deadline_timestamp_seconds: u64,
}
/// This is a view of the ProposalData returned by API queries and is NOT used
/// for storage. The ballots are restricted to those of the caller's neurons and
/// additionally it has the computed fields, topic, status, and reward_status.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, Clone, Debug, PartialEq)]
pub struct ProposalInfo {
    /// The unique id for this proposal.
    pub id: Option<::ic_nns_common::pb::v1::ProposalId>,
    /// The ID of the neuron that made this proposal.
    pub proposer: Option<NeuronId>,
    /// The amount of ICP in E8s to be charged to the proposer if the proposal is
    /// rejected.
    pub reject_cost_e8s: u64,
    /// The proposal originally submitted.
    pub proposal: Option<Proposal>,
    /// The timestamp, in seconds from the Unix epoch, when this proposal was made.
    pub proposal_timestamp_seconds: u64,
    /// See \[ProposalData::ballots\].
    pub ballots: ::std::collections::HashMap<u64, Ballot>,
    /// See \[ProposalData::latest_tally\].
    pub latest_tally: Option<Tally>,
    /// See \[ProposalData::decided_timestamp_seconds\].
    pub decided_timestamp_seconds: u64,
    /// See \[ProposalData::executed_timestamp_seconds\].
    pub executed_timestamp_seconds: u64,
    /// See \[ProposalData::failed_timestamp_seconds\].
    pub failed_timestamp_seconds: u64,
    /// See \[ProposalData::failure_reason\].
    pub failure_reason: Option<GovernanceError>,
    /// See \[ProposalData::reward_event_round\].
    pub reward_event_round: u64,
    /// Derived - see \[Topic\] for more information
    pub topic: i32,
    /// Derived - see \[ProposalStatus\] for more information
    pub status: i32,
    /// Derived - see \[ProposalRewardStatus\] for more information
    pub reward_status: i32,
    pub deadline_timestamp_seconds: Option<u64>,
    pub derived_proposal_information: Option<DerivedProposalInformation>,
    pub total_potential_voting_power: ::core::option::Option<u64>,
}

/// Network economics contains the parameters for several operations related
/// to the economy of the network. When submitting a NetworkEconomics proposal
/// default values (0) are considered unchanged, so a valid proposal only needs
/// to set the parameters that it wishes to change.
/// In other words, it's not possible to set any of the values of
/// NetworkEconomics to 0.
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct NetworkEconomics {
    /// The number of E8s (10E-8 of an ICP token) that a rejected
    /// proposal will cost.
    ///
    /// This fee should be controlled by an #Economic proposal type.
    /// The fee does not apply for ManageNeuron proposals.
    pub reject_cost_e8s: u64,
    /// The minimum number of E8s that can be staked in a neuron.
    pub neuron_minimum_stake_e8s: u64,
    /// The number of E8s (10E-8 of an ICP token) that it costs to
    /// employ the 'manage neuron' functionality through proposals. The
    /// cost is incurred by the neuron that makes the 'manage neuron'
    /// proposal and is applied regardless of whether the proposal is
    /// adopted or rejected.
    pub neuron_management_fee_per_proposal_e8s: u64,
    /// The minimum number that the ICP/XDR conversion rate can be set to.
    ///
    /// Measured in XDR (the currency code of IMF SDR) to two decimal
    /// places.
    ///
    /// See /rs/protobuf/def/registry/conversion_rate/v1/conversion_rate.proto
    /// for more information on the rate itself.
    pub minimum_icp_xdr_rate: u64,
    /// The dissolve delay of a neuron spawned from the maturity of an
    /// existing neuron.
    pub neuron_spawn_dissolve_delay_seconds: u64,
    /// The maximum rewards to be distributed to NodeProviders in a single
    /// distribution event, in e8s.
    pub maximum_node_provider_rewards_e8s: u64,
    /// The transaction fee that must be paid for each ledger transaction.
    pub transaction_fee_e8s: u64,
    /// The maximum number of proposals to keep, per topic for eligible topics.
    /// When the total number of proposals for a given topic is greater than this
    /// number, the oldest proposals that have reached a "final" state
    /// may be deleted.
    ///
    /// If unspecified or zero, all proposals are kept.
    pub max_proposals_to_keep_per_topic: u32,
    /// Global Neurons' Fund participation thresholds.
    pub neurons_fund_economics: Option<NeuronsFundEconomics>,

    /// Parameters that affect the voting power of neurons.
    pub voting_power_economics: ::core::option::Option<VotingPowerEconomics>,
}

/// Parameters that affect the voting power of neurons.
#[derive(
    candid::CandidType,
    candid::Deserialize,
    serde::Serialize,
    Clone,
    Copy,
    PartialEq,
    Debug,
    Default,
)]
pub struct VotingPowerEconomics {
    /// If a neuron has not "refreshed" its voting power after this amount of time,
    /// its deciding voting power starts decreasing linearly. See also
    /// clear_following_after_seconds.
    ///
    /// For explanation of what "refresh" means in this context, see
    /// <https://dashboard.internetcomputer.org/proposal/132411>
    ///
    /// Initially, set to 0.5 years. (The nominal length of a year is 365.25 days).
    pub start_reducing_voting_power_after_seconds: ::core::option::Option<u64>,

    /// After a neuron has experienced voting power reduction for this amount of
    /// time, a couple of things happen:
    ///
    ///      1. Deciding voting power reaches 0.
    ///
    ///      2. Its following on topics other than NeuronManagement are cleared.
    ///
    /// Initially, set to 1/12 years.
    pub clear_following_after_seconds: ::core::option::Option<u64>,

    /// The minimum dissolve delay a neuron must have in order to be eligible to vote or
    /// make proposals.
    ///
    /// Neurons with a dissolve delay lower than this threshold will not have
    /// voting power, even if they are otherwise active.
    ///
    /// This value is an essential part of the staking mechanism, promoting
    /// long-term alignment with the network's governance.
    pub neuron_minimum_dissolve_delay_to_vote_seconds: ::core::option::Option<u64>,
}

/// The thresholds specify the shape of the ideal matching function used by the Neurons' Fund to
/// determine how much to contribute for a given direct participation amount. Note that the actual
/// swap participation is in ICP, whereas these thresholds are specifid in XDR; the conversion rate
/// is determined at the time of execution of the CreateServiceNervousSystem proposal.
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct NeuronsFundMatchedFundingCurveCoefficients {
    /// Up to this amount of direct participation, the Neurons' Fund does not contribute to this SNS.
    pub contribution_threshold_xdr: Option<::ic_nervous_system_proto::pb::v1::Decimal>,
    /// Say the direct participation amount is `x_icp`. When `x_icp` equals the equavalent of
    /// `one_third_participation_milestone_xdr` in ICP (we use ICP/XDR conversion data from the CMC),
    /// the Neurons' Fund contributes 50% on top of that amount, so the overall contributions would
    /// be `1.5 * x_icp` of which 1/3 comes from the Neurons' Fund.
    pub one_third_participation_milestone_xdr: Option<::ic_nervous_system_proto::pb::v1::Decimal>,
    /// Say the direct participation amount is `x_icp`. When `x_icp` equals the equavalent of
    /// `full_participation_milestone_xdr` in ICP (we use ICP/XDR conversion data from the CMC),
    /// the Neurons' Fund contributes 100% on top of that amount, so the overall contributions would
    /// be `2.0 * x_icp` of which a half comes from the Neurons' Fund.
    pub full_participation_milestone_xdr: Option<::ic_nervous_system_proto::pb::v1::Decimal>,
}
/// When the Neurons' Fund decides to participates in an SNS swap, the amount of participation is
/// determined according to the rules of Matched Funding. The amount of ICP tokens contributed by
/// the Neurons' Fund depends on four factors:
/// (1) Direct participation amount at the time of the swap's successful finalization.
/// (2) Amount of maturity held by all eligible neurons that were members of the Neurons' Fund
///      at the time of the CreateServiceNervousSystem proposal execution.
/// (3) Global Neurons' Fund participation thresholds, held in this structure (defined in XDR).
/// (4) ICP/XDR conversion rate at the time of the CreateServiceNervousSystem proposal execution.
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct NeuronsFundEconomics {
    /// This is a theoretical limit which should be smaller than any realistic amount of maturity
    /// that practically needs to be reserved from the Neurons' Fund for a given SNS swap.
    pub max_theoretical_neurons_fund_participation_amount_xdr:
        Option<::ic_nervous_system_proto::pb::v1::Decimal>,
    /// Thresholds specifying the shape of the matching function used by the Neurons' Fund to
    /// determine how much to contribute for a given direct participation amount.
    pub neurons_fund_matched_funding_curve_coefficients:
        Option<NeuronsFundMatchedFundingCurveCoefficients>,
    /// The minimum value of the ICP/XDR conversion rate used by the Neurons' Fund for converting
    /// XDR values into ICP.
    pub minimum_icp_xdr_rate: Option<::ic_nervous_system_proto::pb::v1::Percentage>,
    /// The maximum value of the ICP/XDR conversion rate used by the Neurons' Fund for converting
    /// XDR values into ICP.
    pub maximum_icp_xdr_rate: Option<::ic_nervous_system_proto::pb::v1::Percentage>,
}
/// A reward event is an event at which neuron maturity is increased
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
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
    pub day_after_genesis: u64,
    /// The timestamp at which this reward event took place, in seconds since the unix epoch.
    ///
    /// This does not match the date taken into account for reward computation, which
    /// should always be an integer number of days after genesis.
    pub actual_timestamp_seconds: u64,
    /// The list of proposals that were taken into account during
    /// this reward event.
    pub settled_proposals: Vec<::ic_nns_common::pb::v1::ProposalId>,
    /// The total amount of reward that was distributed during this reward event.
    ///
    /// The unit is "e8s equivalent" to insist that, while this quantity is on
    /// the same scale as ICPs, maturity is not directly convertible to ICPs:
    /// conversion requires a minting event to spawn a new neuron.
    pub distributed_e8s_equivalent: u64,
    /// The total amount of rewards that was available during the reward event.
    pub total_available_e8s_equivalent: u64,
    /// The amount of rewards that was available during the last round included in
    /// this event. This will only be different from `total_available_e8s_equivalent`
    /// if there were "rollover rounds" included in this event.
    pub latest_round_available_e8s_equivalent: Option<u64>,
    /// In some cases, the rewards that would have been distributed in one round are
    /// "rolled over" into the next reward event. This field keeps track of how many
    /// rounds have passed since the last time rewards were distributed (rather
    /// than being rolled over).
    ///
    /// For the genesis reward event, this field will be zero.
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
    pub rounds_since_last_distribution: Option<u64>,
}
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct KnownNeuron {
    pub id: Option<NeuronId>,
    pub known_neuron_data: Option<KnownNeuronData>,
}
/// Topic variants that can be followed by known neurons.
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Eq, Clone, PartialEq, Debug,
)]
pub enum TopicToFollow {
    CatchAll,
    NeuronManagement,
    ExchangeRate,
    NetworkEconomics,
    Governance,
    NodeAdmin,
    ParticipantManagement,
    SubnetManagement,
    Kyc,
    NodeProviderRewards,
    IcOsVersionDeployment,
    IcOsVersionElection,
    SnsAndCommunityFund,
    ApiBoundaryNodeManagement,
    SubnetRental,
    ApplicationCanisterManagement,
    ProtocolCanisterManagement,
    ServiceNervousSystemManagement,
}

/// Known neurons have extra information (a name and optionally a description) that can be used to identify them.
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Eq, Clone, PartialEq, Debug, Default,
)]
pub struct KnownNeuronData {
    pub name: String,
    pub description: Option<String>,
    pub committed_topics: Option<Vec<Option<TopicToFollow>>>,
    pub links: Option<Vec<String>>,
}
/// Proposal action to deregister a known neuron by removing its name and description.
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct DeregisterKnownNeuron {
    pub id: Option<NeuronId>,
}
/// Proposal action to call the "open" method of an SNS token swap canister.
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct OpenSnsTokenSwap {
    /// The ID of the canister where the command will be sent (assuming that the
    /// proposal is adopted, of course).
    pub target_swap_canister_id: Option<PrincipalId>,
    /// Various limits on the swap.
    pub params: Option<::ic_sns_swap::pb::v1::Params>,
    /// The amount that the community fund will collectively spend in maturity on
    /// the swap.
    pub community_fund_investment_e8s: Option<u64>,
}
/// Mainly, calls the deploy_new_sns Candid method on the SNS-WASMs canister.
/// Therefore, most of the fields here have equivalents in SnsInitPayload.
/// Please, consult the comments therein.
///
/// Metadata
/// --------
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct CreateServiceNervousSystem {
    pub name: Option<String>,
    pub description: Option<String>,
    pub url: Option<String>,
    pub logo: Option<::ic_nervous_system_proto::pb::v1::Image>,
    pub fallback_controller_principal_ids: Vec<PrincipalId>,
    pub dapp_canisters: Vec<::ic_nervous_system_proto::pb::v1::Canister>,
    pub initial_token_distribution: Option<create_service_nervous_system::InitialTokenDistribution>,
    pub swap_parameters: Option<create_service_nervous_system::SwapParameters>,
    pub ledger_parameters: Option<create_service_nervous_system::LedgerParameters>,
    pub governance_parameters: Option<create_service_nervous_system::GovernanceParameters>,
}
/// Nested message and enum types in `CreateServiceNervousSystem`.
pub mod create_service_nervous_system {
    use super::*;

    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct InitialTokenDistribution {
        pub developer_distribution: Option<initial_token_distribution::DeveloperDistribution>,
        pub treasury_distribution: Option<initial_token_distribution::TreasuryDistribution>,
        pub swap_distribution: Option<initial_token_distribution::SwapDistribution>,
    }
    /// Nested message and enum types in `InitialTokenDistribution`.
    pub mod initial_token_distribution {
        use super::*;

        #[derive(
            candid::CandidType,
            candid::Deserialize,
            serde::Serialize,
            Clone,
            PartialEq,
            Debug,
            Default,
        )]
        pub struct DeveloperDistribution {
            pub developer_neurons: Vec<developer_distribution::NeuronDistribution>,
        }
        /// Nested message and enum types in `DeveloperDistribution`.
        pub mod developer_distribution {
            use super::*;

            #[derive(
                candid::CandidType,
                candid::Deserialize,
                serde::Serialize,
                Clone,
                PartialEq,
                Debug,
                Default,
            )]
            pub struct NeuronDistribution {
                pub controller: Option<PrincipalId>,
                pub dissolve_delay: Option<::ic_nervous_system_proto::pb::v1::Duration>,
                pub memo: Option<u64>,
                pub stake: Option<::ic_nervous_system_proto::pb::v1::Tokens>,
                pub vesting_period: Option<::ic_nervous_system_proto::pb::v1::Duration>,
            }
        }
        #[derive(
            candid::CandidType,
            candid::Deserialize,
            serde::Serialize,
            Clone,
            PartialEq,
            Debug,
            Default,
        )]
        pub struct TreasuryDistribution {
            pub total: Option<::ic_nervous_system_proto::pb::v1::Tokens>,
        }
        #[derive(
            candid::CandidType,
            candid::Deserialize,
            serde::Serialize,
            Clone,
            PartialEq,
            Debug,
            Default,
        )]
        pub struct SwapDistribution {
            pub total: Option<::ic_nervous_system_proto::pb::v1::Tokens>,
        }
    }
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct SwapParameters {
        pub minimum_participants: Option<u64>,
        pub minimum_icp: Option<::ic_nervous_system_proto::pb::v1::Tokens>,
        pub maximum_icp: Option<::ic_nervous_system_proto::pb::v1::Tokens>,
        pub minimum_direct_participation_icp: Option<::ic_nervous_system_proto::pb::v1::Tokens>,
        pub maximum_direct_participation_icp: Option<::ic_nervous_system_proto::pb::v1::Tokens>,
        pub minimum_participant_icp: Option<::ic_nervous_system_proto::pb::v1::Tokens>,
        pub maximum_participant_icp: Option<::ic_nervous_system_proto::pb::v1::Tokens>,
        pub neuron_basket_construction_parameters:
            Option<swap_parameters::NeuronBasketConstructionParameters>,
        pub confirmation_text: Option<String>,
        pub restricted_countries: Option<::ic_nervous_system_proto::pb::v1::Countries>,
        /// The swap occurs at a specific time of day, in UTC.
        /// It will happen the first time start_time occurs that's at least 24h after
        /// the proposal is adopted.
        pub start_time: Option<::ic_nervous_system_proto::pb::v1::GlobalTimeOfDay>,
        pub duration: Option<::ic_nervous_system_proto::pb::v1::Duration>,
        /// The amount that the Neuron's Fund will collectively spend in maturity on
        /// the swap.
        pub neurons_fund_investment_icp: Option<::ic_nervous_system_proto::pb::v1::Tokens>,
        /// Whether Neurons' Fund participation is requested.
        /// Cannot be set to true until Matched Funding is released
        pub neurons_fund_participation: Option<bool>,
    }
    /// Nested message and enum types in `SwapParameters`.
    pub mod swap_parameters {
        #[derive(
            candid::CandidType,
            candid::Deserialize,
            serde::Serialize,
            Clone,
            PartialEq,
            Debug,
            Default,
        )]
        pub struct NeuronBasketConstructionParameters {
            pub count: Option<u64>,
            pub dissolve_delay_interval: Option<::ic_nervous_system_proto::pb::v1::Duration>,
        }
    }
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct LedgerParameters {
        pub transaction_fee: Option<::ic_nervous_system_proto::pb::v1::Tokens>,
        pub token_name: Option<String>,
        pub token_symbol: Option<String>,
        pub token_logo: Option<::ic_nervous_system_proto::pb::v1::Image>,
    }
    /// Proposal Parameters
    /// -------------------
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct GovernanceParameters {
        pub proposal_rejection_fee: Option<::ic_nervous_system_proto::pb::v1::Tokens>,
        pub proposal_initial_voting_period: Option<::ic_nervous_system_proto::pb::v1::Duration>,
        pub proposal_wait_for_quiet_deadline_increase:
            Option<::ic_nervous_system_proto::pb::v1::Duration>,
        pub neuron_minimum_stake: Option<::ic_nervous_system_proto::pb::v1::Tokens>,
        pub neuron_minimum_dissolve_delay_to_vote:
            Option<::ic_nervous_system_proto::pb::v1::Duration>,
        pub neuron_maximum_dissolve_delay: Option<::ic_nervous_system_proto::pb::v1::Duration>,
        pub neuron_maximum_dissolve_delay_bonus:
            Option<::ic_nervous_system_proto::pb::v1::Percentage>,
        pub neuron_maximum_age_for_age_bonus: Option<::ic_nervous_system_proto::pb::v1::Duration>,
        pub neuron_maximum_age_bonus: Option<::ic_nervous_system_proto::pb::v1::Percentage>,
        pub voting_reward_parameters: Option<governance_parameters::VotingRewardParameters>,
    }
    /// Nested message and enum types in `GovernanceParameters`.
    pub mod governance_parameters {
        #[derive(
            candid::CandidType,
            candid::Deserialize,
            serde::Serialize,
            Clone,
            PartialEq,
            Debug,
            Default,
        )]
        pub struct VotingRewardParameters {
            pub initial_reward_rate: Option<::ic_nervous_system_proto::pb::v1::Percentage>,
            pub final_reward_rate: Option<::ic_nervous_system_proto::pb::v1::Percentage>,
            pub reward_rate_transition_duration:
                Option<::ic_nervous_system_proto::pb::v1::Duration>,
        }
    }
}
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct InstallCode {
    /// The target canister ID to call install_code on. Required.
    pub canister_id: Option<PrincipalId>,
    /// The install mode. Either install, reinstall, or upgrade. Required.
    pub install_mode: Option<i32>,

    /// Whether to skip stopping the canister before installing. Optional. Default is false.
    pub skip_stopping_before_installing: Option<bool>,

    #[serde(deserialize_with = "ic_utils::deserialize::deserialize_option_blob")]
    pub wasm_module_hash: Option<Vec<u8>>,

    #[serde(deserialize_with = "ic_utils::deserialize::deserialize_option_blob")]
    pub arg_hash: Option<Vec<u8>>,
}
/// Nested message and enum types in `InstallCode`.
pub mod install_code {
    #[derive(
        candid::CandidType,
        candid::Deserialize,
        serde::Serialize,
        Clone,
        Copy,
        Debug,
        PartialEq,
        Eq,
        Hash,
        PartialOrd,
        Ord,
    )]
    #[repr(i32)]
    pub enum CanisterInstallMode {
        Unspecified = 0,
        Install = 1,
        Reinstall = 2,
        Upgrade = 3,
    }
    impl CanisterInstallMode {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                CanisterInstallMode::Unspecified => "CANISTER_INSTALL_MODE_UNSPECIFIED",
                CanisterInstallMode::Install => "CANISTER_INSTALL_MODE_INSTALL",
                CanisterInstallMode::Reinstall => "CANISTER_INSTALL_MODE_REINSTALL",
                CanisterInstallMode::Upgrade => "CANISTER_INSTALL_MODE_UPGRADE",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> Option<Self> {
            match value {
                "CANISTER_INSTALL_MODE_UNSPECIFIED" => Some(Self::Unspecified),
                "CANISTER_INSTALL_MODE_INSTALL" => Some(Self::Install),
                "CANISTER_INSTALL_MODE_REINSTALL" => Some(Self::Reinstall),
                "CANISTER_INSTALL_MODE_UPGRADE" => Some(Self::Upgrade),
                _ => None,
            }
        }
    }
}

#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Default)]
pub struct InstallCodeRequest {
    pub canister_id: ::core::option::Option<PrincipalId>,
    pub install_mode: ::core::option::Option<i32>,
    #[serde(deserialize_with = "ic_utils::deserialize::deserialize_option_blob")]
    pub wasm_module: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    #[serde(deserialize_with = "ic_utils::deserialize::deserialize_option_blob")]
    pub arg: ::core::option::Option<::prost::alloc::vec::Vec<u8>>,
    pub skip_stopping_before_installing: ::core::option::Option<bool>,
}

#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct StopOrStartCanister {
    /// The target canister ID to call stop_canister or start_canister on. The canister must be
    /// controlled by NNS Root, and it cannot be NNS Governance or Lifeline. Required.
    pub canister_id: Option<PrincipalId>,
    pub action: Option<i32>,
}
/// Nested message and enum types in `StopOrStartCanister`.
pub mod stop_or_start_canister {
    /// The action to take on the canister. Required.
    #[derive(
        candid::CandidType,
        candid::Deserialize,
        serde::Serialize,
        Clone,
        Copy,
        Debug,
        PartialEq,
        Eq,
        Hash,
        PartialOrd,
        Ord,
    )]
    #[repr(i32)]
    pub enum CanisterAction {
        Unspecified = 0,
        Stop = 1,
        Start = 2,
    }
    impl CanisterAction {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                CanisterAction::Unspecified => "CANISTER_ACTION_UNSPECIFIED",
                CanisterAction::Stop => "CANISTER_ACTION_STOP",
                CanisterAction::Start => "CANISTER_ACTION_START",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> Option<Self> {
            match value {
                "CANISTER_ACTION_UNSPECIFIED" => Some(Self::Unspecified),
                "CANISTER_ACTION_STOP" => Some(Self::Stop),
                "CANISTER_ACTION_START" => Some(Self::Start),
                _ => None,
            }
        }
    }
}
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct UpdateCanisterSettings {
    /// The target canister ID to call update_settings on. Required.
    pub canister_id: Option<PrincipalId>,
    /// The settings to update. Required.
    pub settings: Option<update_canister_settings::CanisterSettings>,
}
/// Nested message and enum types in `UpdateCanisterSettings`.
pub mod update_canister_settings {
    use super::*;

    /// The controllers of the canister. We use a message to wrap the repeated field because prost does
    /// not generate `Option<Vec<T>>` for repeated fields.
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct Controllers {
        /// The controllers of the canister.
        pub controllers: Vec<PrincipalId>,
    }
    /// The CanisterSettings struct as defined in the ic-interface-spec
    /// <https://internetcomputer.org/docs/current/references/ic-interface-spec/#ic-candid.>
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct CanisterSettings {
        pub controllers: Option<Controllers>,
        pub compute_allocation: Option<u64>,
        pub memory_allocation: Option<u64>,
        pub freezing_threshold: Option<u64>,
        pub log_visibility: Option<i32>,
        pub wasm_memory_limit: Option<u64>,
        pub wasm_memory_threshold: Option<u64>,
    }
    /// Log visibility of a canister.
    #[derive(
        candid::CandidType,
        candid::Deserialize,
        serde::Serialize,
        Clone,
        Copy,
        Debug,
        PartialEq,
        Eq,
        Hash,
        PartialOrd,
        Ord,
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
        pub fn from_str_name(value: &str) -> Option<Self> {
            match value {
                "LOG_VISIBILITY_UNSPECIFIED" => Some(Self::Unspecified),
                "LOG_VISIBILITY_CONTROLLERS" => Some(Self::Controllers),
                "LOG_VISIBILITY_PUBLIC" => Some(Self::Public),
                _ => None,
            }
        }
    }
}
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct FulfillSubnetRentalRequest {
    pub user: Option<PrincipalId>,
    pub node_ids: Option<Vec<PrincipalId>>,
    pub replica_version_id: Option<String>,
}

#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Eq, Debug, Default,
)]
pub struct BlessAlternativeGuestOsVersion {
    pub chip_ids: Option<Vec<Vec<u8>>>,
    pub rootfs_hash: Option<String>,
    pub base_guest_launch_measurements: Option<GuestLaunchMeasurements>,
}

/// See also the definition of GuestLaunchMeasurements (plural!) in
/// rs/protobuf/def/registry/replica_version/v1/replica_version.proto
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Eq, Debug, Default,
)]
pub struct GuestLaunchMeasurements {
    pub guest_launch_measurements: Option<Vec<GuestLaunchMeasurement>>,
}

/// See also the definition of GuestLaunchMeasurement in
/// rs/protobuf/def/registry/replica_version/v1/replica_version.proto
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Eq, Debug, Default,
)]
pub struct GuestLaunchMeasurement {
    pub encoded_measurement: Option<String>,
    pub metadata: Option<GuestLaunchMeasurementMetadata>,
}

/// See also the definition of GuestLaunchMeasurementMetadata in
/// rs/protobuf/def/registry/replica_version/v1/replica_version.proto
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Eq, Debug, Default,
)]
pub struct GuestLaunchMeasurementMetadata {
    pub kernel_cmdline: Option<String>,
}

/// This represents the whole NNS governance system. It contains all
/// information about the NNS governance system that must be kept
/// across upgrades of the NNS governance system.
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Default, Debug,
)]
pub struct Governance {
    /// Current set of neurons.
    pub neurons: BTreeMap<u64, Neuron>,
    /// Proposals.
    pub proposals: BTreeMap<u64, ProposalData>,
    /// The transfers that have been made to stake new neurons, but
    /// haven't been claimed by the user, yet.
    pub to_claim_transfers: Vec<NeuronStakeTransfer>,
    /// Also known as the 'normal voting period'. The maximum time a
    /// proposal (of a topic with "normal" voting period) is open for
    /// voting. If a proposal has not been decided (adopted or rejected)
    /// within this time since the proposal was made, the proposal is
    /// rejected.
    ///
    /// See also `short_voting_period_seconds`.
    pub wait_for_quiet_threshold_seconds: u64,
    /// The network economics configuration parameters.
    pub economics: Option<NetworkEconomics>,
    /// The last reward event. Should never be missing.
    pub latest_reward_event: Option<RewardEvent>,
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
    /// after issuing a transfer call) the neuron(s) involved are left in a
    /// "locked" state, meaning new operations can't be applied without
    /// reconciling the state.
    ///
    /// Because we know exactly what was going on, we should have the
    /// information necessary to reconcile the state, using custom code
    /// added on upgrade, if necessary.
    pub in_flight_commands: ::std::collections::HashMap<u64, governance::NeuronInFlightCommand>,
    /// The timestamp, in seconds since the unix epoch, at which `canister_init` was run for
    /// the governance canister, considered
    /// the genesis of the IC for reward purposes.
    pub genesis_timestamp_seconds: u64,
    /// The entities that own the nodes running the IC.
    pub node_providers: Vec<NodeProvider>,
    /// Default followees
    ///
    /// A map of Topic (as i32) to Neuron id that is set as the default
    /// following for all neurons created post-genesis.
    ///
    /// On initialization it's required that the Neurons present in this
    /// map are present in the initial set of neurons.
    ///
    /// Default following can be changed via proposal.
    pub default_followees: ::std::collections::HashMap<i32, neuron::Followees>,
    /// The maximum time a proposal of a topic with *short voting period*
    /// is open for voting. If a proposal on a topic with short voting
    /// period has not been decided (adopted or rejected) within this
    /// time since the proposal was made, the proposal is rejected.
    /// The short voting period is used for proposals that don't make sense to vote
    /// on if the proposal is "old". For example, proposals to set the exchange
    /// rate should not be voted on if they're days old because exchange rates
    /// fluctuate regularly. Currently, only proposals to set the exchange rate
    /// use the short voting period, and such proposals are deprecated.
    pub short_voting_period_seconds: u64,
    /// The maximum time a proposal of a topic with *private voting period*
    /// is open for voting. If a proposal on a topic with short voting
    /// period has not been decided (adopted or rejected) within this
    /// time since the proposal was made, the proposal is rejected.
    /// This is useful for proposals that are for "private matters" like
    /// NeuronManagement proposals. These proposals are not meant to be voted on
    /// by the general public and have limited impact, so a different voting period
    /// is appropriate.
    pub neuron_management_voting_period_seconds: Option<u64>,
    pub metrics: Option<governance::GovernanceCachedMetrics>,
    pub most_recent_monthly_node_provider_rewards: Option<MonthlyNodeProviderRewards>,
    /// Cached value for the maturity modulation as calculated each day.
    pub cached_daily_maturity_modulation_basis_points: Option<i32>,
    /// The last time that the maturity modulation value was updated.
    pub maturity_modulation_last_updated_at_timestamp_seconds: Option<u64>,
    /// Whether the heartbeat function is currently spawning neurons, meaning
    /// that it should finish before being called again.
    pub spawning_neurons: Option<bool>,
    /// Local cache for XDR-related conversion rates (the source of truth is in the CMC canister).
    pub xdr_conversion_rate: Option<XdrConversionRate>,
    /// The summary of restore aging event.
    pub restore_aging_summary: Option<RestoreAgingSummary>,
}
/// Nested message and enum types in `Governance`.
pub mod governance {
    use super::*;

    /// The possible commands that require interaction with the ledger.
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct NeuronInFlightCommand {
        /// The timestamp at which the command was issued, for debugging
        /// purposes.
        pub timestamp: u64,
        pub command: Option<neuron_in_flight_command::Command>,
    }
    /// Nested message and enum types in `NeuronInFlightCommand`.
    pub mod neuron_in_flight_command {
        use super::*;

        /// A general place holder for sync commands. The neuron lock is
        /// never left holding a sync command (as it either succeeds to
        /// acquire the lock and releases it in the same call, or never
        /// acquires it in the first place), but it still must be acquired
        /// to prevent interleaving with another async command. Thus there's
        /// no value in actually storing the command itself, and this placeholder
        /// can generally be used in all sync cases.
        #[derive(
            candid::CandidType,
            candid::Deserialize,
            serde::Serialize,
            Clone,
            PartialEq,
            Debug,
            Default,
        )]
        pub struct SyncCommand {}
        #[derive(
            candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug,
        )]
        pub enum Command {
            Disburse(super::super::manage_neuron::Disburse),
            Split(super::super::manage_neuron::Split),
            DisburseToNeuron(super::super::manage_neuron::DisburseToNeuron),
            MergeMaturity(super::super::manage_neuron::MergeMaturity),
            ClaimOrRefreshNeuron(super::super::manage_neuron::ClaimOrRefresh),
            Configure(super::super::manage_neuron::Configure),
            Merge(super::super::manage_neuron::Merge),
            Spawn(NeuronId),
            SyncCommand(SyncCommand),
        }
    }
    /// Stores metrics that are too costly to compute each time metrics are
    /// requested. For bucketed metrics, keys are bucket IDs, i.e., number of full
    /// half-year dissolve delay intervals of neurons counted towards this bucket.
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct GovernanceCachedMetrics {
        pub timestamp_seconds: u64,
        pub total_supply_icp: u64,
        pub dissolving_neurons_count: u64,
        pub dissolving_neurons_e8s_buckets: ::std::collections::HashMap<u64, f64>,
        pub dissolving_neurons_count_buckets: ::std::collections::HashMap<u64, u64>,
        pub not_dissolving_neurons_count: u64,
        pub not_dissolving_neurons_e8s_buckets: ::std::collections::HashMap<u64, f64>,
        pub not_dissolving_neurons_count_buckets: ::std::collections::HashMap<u64, u64>,
        pub dissolved_neurons_count: u64,
        pub dissolved_neurons_e8s: u64,
        pub garbage_collectable_neurons_count: u64,
        pub neurons_with_invalid_stake_count: u64,
        pub total_staked_e8s: u64,
        pub neurons_with_less_than_6_months_dissolve_delay_count: u64,
        pub neurons_with_less_than_6_months_dissolve_delay_e8s: u64,
        pub community_fund_total_staked_e8s: u64,
        pub community_fund_total_maturity_e8s_equivalent: u64,
        pub neurons_fund_total_active_neurons: u64,
        pub total_locked_e8s: u64,
        pub total_maturity_e8s_equivalent: u64,
        pub total_staked_maturity_e8s_equivalent: u64,
        pub dissolving_neurons_staked_maturity_e8s_equivalent_buckets:
            ::std::collections::HashMap<u64, f64>,
        pub dissolving_neurons_staked_maturity_e8s_equivalent_sum: u64,
        pub not_dissolving_neurons_staked_maturity_e8s_equivalent_buckets:
            ::std::collections::HashMap<u64, f64>,
        pub not_dissolving_neurons_staked_maturity_e8s_equivalent_sum: u64,
        pub seed_neuron_count: u64,
        pub ect_neuron_count: u64,
        pub total_staked_e8s_seed: u64,
        pub total_staked_e8s_ect: u64,
        pub total_staked_maturity_e8s_equivalent_seed: u64,
        pub total_staked_maturity_e8s_equivalent_ect: u64,
        pub dissolving_neurons_e8s_buckets_seed: ::std::collections::HashMap<u64, f64>,
        pub dissolving_neurons_e8s_buckets_ect: ::std::collections::HashMap<u64, f64>,
        pub not_dissolving_neurons_e8s_buckets_seed: ::std::collections::HashMap<u64, f64>,
        pub not_dissolving_neurons_e8s_buckets_ect: ::std::collections::HashMap<u64, f64>,
        pub spawning_neurons_count: u64,
        /// Deprecated. Use non_self_authenticating_controller_neuron_subset_metrics instead.
        pub total_voting_power_non_self_authenticating_controller: Option<u64>,
        pub total_staked_e8s_non_self_authenticating_controller: Option<u64>,
        pub non_self_authenticating_controller_neuron_subset_metrics:
            Option<governance_cached_metrics::NeuronSubsetMetrics>,
        pub public_neuron_subset_metrics: Option<governance_cached_metrics::NeuronSubsetMetrics>,
        pub declining_voting_power_neuron_subset_metrics:
            ::core::option::Option<governance_cached_metrics::NeuronSubsetMetrics>,
        pub fully_lost_voting_power_neuron_subset_metrics:
            ::core::option::Option<governance_cached_metrics::NeuronSubsetMetrics>,
    }
    /// Nested message and enum types in `GovernanceCachedMetrics`.
    pub mod governance_cached_metrics {
        /// Statistics about some subset (not necessarily a proper subset) of
        /// neurons. So far, these are mostly totals.
        #[derive(
            candid::CandidType,
            candid::Deserialize,
            serde::Serialize,
            Clone,
            PartialEq,
            Debug,
            Default,
        )]
        pub struct NeuronSubsetMetrics {
            /// The values in these fields can be derived from the value in the
            /// analogous fields (declared a little lower in this message). For
            /// example, count = count_buckets.values().sum().
            pub count: Option<u64>,

            pub total_staked_e8s: Option<u64>,
            pub total_staked_maturity_e8s_equivalent: Option<u64>,
            pub total_maturity_e8s_equivalent: Option<u64>,

            /// Deprecated. Use one of the following instead.
            pub total_voting_power: Option<u64>,
            /// Used to decide proposals. If all neurons refresh their voting
            /// power/following frequently enough, this will be equal to potential
            /// voting power. If not, this will be less.
            pub total_deciding_voting_power: ::core::option::Option<u64>,
            /// Used for voting rewards.
            pub total_potential_voting_power: ::core::option::Option<u64>,

            /// These fields are keyed by floor(dissolve delay / 0.5 years). These are
            /// analogous to the (singular) fields above. Here, the usual definition of
            /// year for the IC is used: exactly 365.25 days.
            pub count_buckets: ::std::collections::HashMap<u64, u64>,

            pub staked_e8s_buckets: ::std::collections::HashMap<u64, u64>,
            pub staked_maturity_e8s_equivalent_buckets: ::std::collections::HashMap<u64, u64>,
            pub maturity_e8s_equivalent_buckets: ::std::collections::HashMap<u64, u64>,

            /// Deprecated. Use one of the following instead.
            pub voting_power_buckets: ::std::collections::HashMap<u64, u64>,
            pub deciding_voting_power_buckets: ::std::collections::HashMap<u64, u64>,
            pub potential_voting_power_buckets: ::std::collections::HashMap<u64, u64>,
        }
    }
}
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct XdrConversionRate {
    /// / Time at which this rate has been fetched.
    pub timestamp_seconds: Option<u64>,
    /// / One ICP is worth this number of 1/10,000ths parts of an XDR.
    pub xdr_permyriad_per_icp: Option<u64>,
}
/// Proposals with restricted voting are not included unless the caller
/// is allowed to vote on them.
///
/// The actual ballots of the proposal are restricted to ballots cast
/// by the caller.
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct ListProposalInfoRequest {
    /// Limit on the number of \[ProposalInfo\] to return. If no value is
    /// specified, or if a value greater than 100 is specified, 100
    /// will be used.
    pub limit: u32,
    /// If specified, only return proposals that are strictly earlier than
    /// the specified proposal according to the proposal ID. If not
    /// specified, start with the most recent proposal.
    pub before_proposal: Option<::ic_nns_common::pb::v1::ProposalId>,
    /// Exclude proposals with a topic in this list. This is particularly
    /// useful to exclude proposals on the topics TOPIC_EXCHANGE_RATE and
    /// TOPIC_KYC which most users are not likely to be interested in
    /// seeing.
    pub exclude_topic: Vec<i32>,
    /// Include proposals that have a reward status in this list (see
    /// \[ProposalRewardStatus\] for more information). If this list is
    /// empty, no restriction is applied. For example, many users listing
    /// proposals will only be interested in proposals for which they can
    /// receive voting rewards, i.e., with reward status
    /// PROPOSAL_REWARD_STATUS_ACCEPT_VOTES.
    pub include_reward_status: Vec<i32>,
    /// Include proposals that have a status in this list (see
    /// \[ProposalStatus\] for more information). If this list is empty, no
    /// restriction is applied.
    pub include_status: Vec<i32>,
    /// Include all ManageNeuron proposals regardless of the visibility of the
    /// proposal to the caller principal. Note that exclude_topic is still
    /// respected even when this option is set to true.
    pub include_all_manage_neuron_proposals: Option<bool>,
    /// Omits "large fields" from the response. Currently only omits the
    /// `logo` and `token_logo` field of CreateServiceNervousSystem proposals. This
    /// is useful to improve download times and to ensure that the response to the
    /// request doesn't exceed the message size limit.
    pub omit_large_fields: Option<bool>,
    /// Whether to include self-describing proposal actions in the response.
    pub return_self_describing_action: Option<bool>,
}
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, Clone, Debug, PartialEq)]
pub struct ListProposalInfoResponse {
    pub proposal_info: Vec<ProposalInfo>,
}

/// A request to list neurons. The "requested list", i.e., the list of
/// neuron IDs to retrieve information about, is the union of the list
/// of neurons listed in `neuron_ids` and, if `caller_neurons` is true,
/// the list of neuron IDs of neurons for which the caller is the
/// controller or one of the hot keys.
///
/// Paging is available if the result set is larger than `MAX_LIST_NEURONS_RESULTS`,
/// which is currently 500 neurons.  If you are unsure of the number of results in a set,
/// you can use the `total_pages_available` field in the response to determine how many
/// additional pages need to be queried.  It will be based on your `page_size` parameter.  
/// When paging through results, it is good to keep in mind that newly inserted neurons
/// could be missed if they are inserted between calls to pages, and this could result in missing
/// a neuron in the combined responses.
///
/// If a user provides neuron_ids that do not exist in the request, there is no guarantee that
/// each page will contain the exactly the page size, even if it is not the final request.  This is
/// because neurons are retrieved by their neuron_id, and no additional checks are made on the
/// validity of the neuron_ids provided by the user before deciding which sets of neuron_ids
/// will be returned in the current page.
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, Debug, Default, PartialEq,
)]
pub struct ListNeurons {
    /// The neurons to get information about. The "requested list"
    /// contains all of these neuron IDs.
    pub neuron_ids: Vec<u64>,
    /// If true, the "requested list" also contains the neuron ID of the
    /// neurons that the calling principal is authorized to read.
    pub include_neurons_readable_by_caller: bool,
    /// Whether to also include empty neurons readable by the caller. This field only has an effect
    /// when `include_neurons_readable_by_caller` is true. If a neuron's id already exists in the
    /// `neuron_ids` field, then the neuron will be included in the response regardless of the value
    /// of this field. The default value is false (i.e. `None` is treated as `Some(false)`). Here,
    /// being "empty" means 0 stake, 0 maturity and 0 staked maturity.
    pub include_empty_neurons_readable_by_caller: Option<bool>,
    /// If this is set to true, and a neuron in the "requested list" has its
    /// visibility set to public, then, it will (also) be included in the
    /// full_neurons field in the response (which is of type ListNeuronsResponse).
    /// Note that this has no effect on which neurons are in the "requested list".
    /// In particular, this does not cause all public neurons to become part of the
    /// requested list. In general, you probably want to set this to true, but
    /// since this feature was added later, it is opt in to avoid confusing
    /// existing (unmigrated) callers.
    pub include_public_neurons_in_full_neurons: Option<bool>,
    /// If this is set, we return the batch of neurons at a given page, using the `page_size` to
    /// determine how many neurons are returned in each page.
    pub page_number: Option<u64>,
    /// If this is set, we use the page limit provided to determine how large pages will be.
    /// This cannot be greater than MAX_LIST_NEURONS_RESULTS, which is set to 500.
    /// If not set, this defaults to MAX_LIST_NEURONS_RESULTS.
    pub page_size: Option<u64>,
    /// A list of neurons by subaccounts to return in the response.  If the neurons are not
    /// found by subaccount, no error is returned, but the page will still be returned.
    pub neuron_subaccounts: Option<Vec<list_neurons::NeuronSubaccount>>,
}

pub mod list_neurons {
    /// A type for the request to list neurons.
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, Debug, PartialEq,
    )]
    pub struct NeuronSubaccount {
        #[serde(with = "serde_bytes")]
        pub subaccount: Vec<u8>,
    }
}

/// A response to a `ListNeurons` request.
///
/// The "requested list" is described in `ListNeurons`.
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct ListNeuronsResponse {
    /// For each neuron ID in the "requested list", if this neuron exists,
    /// its `NeuronInfo` at the time of the call will be in this map.
    pub neuron_infos: ::std::collections::HashMap<u64, NeuronInfo>,
    /// For each neuron ID in the "requested list", if the neuron exists,
    /// and the caller is authorized to read the full neuron (controller,
    /// hot key, or controller or hot key of some followee on the
    /// `ManageNeuron` topic).
    pub full_neurons: Vec<Neuron>,
    /// This is returned to tell the caller how many pages of results are available to query.
    /// If there are fewer than the page_size neurons, this will equal 1.
    pub total_pages_available: Option<u64>,
}
/// A response to "ListKnownNeurons"
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct ListKnownNeuronsResponse {
    /// List of known neurons.
    pub known_neurons: Vec<KnownNeuron>,
}
/// Response to list_node_providers
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct ListNodeProvidersResponse {
    /// List of all "NodeProviders"
    pub node_providers: Vec<NodeProvider>,
}
/// The arguments to the method `claim_or_refresh_neuron_from_account`.
///
/// DEPRECATED: Use ManageNeuron::ClaimOrRefresh.
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct ClaimOrRefreshNeuronFromAccount {
    /// The principal for which to refresh the account. If not specified,
    /// defaults to the caller.
    pub controller: Option<PrincipalId>,
    /// The memo of the staking transaction.
    pub memo: u64,
}
/// Response to claim_or_refresh_neuron_from_account.
///
/// DEPRECATED: Use ManageNeuron::ClaimOrRefresh.
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct ClaimOrRefreshNeuronFromAccountResponse {
    pub result: Option<claim_or_refresh_neuron_from_account_response::Result>,
}
/// Nested message and enum types in `ClaimOrRefreshNeuronFromAccountResponse`.
pub mod claim_or_refresh_neuron_from_account_response {
    use super::*;

    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug,
    )]
    pub enum Result {
        /// Specified in case of error.
        Error(super::GovernanceError),
        /// The ID of the neuron that was created or empty in the case of error.
        NeuronId(NeuronId),
    }
}
/// Date UTC used in NodeProviderRewards to define their validity boundaries
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct DateUtc {
    pub year: u32,
    pub month: u32,
    pub day: u32,
}
/// The monthly Node Provider rewards, representing the distribution of rewards for a specific time period.
///
/// Prior to the introduction of the performance-based reward algorithm, rewards were computed from a
/// single registry snapshot (identified by `registry_version`). After performance-based rewards were enabled,
/// rewards depend on node metrics collected over a date range, making `start_date` and `end_date` essential
/// for defining the covered period. In this case, `registry_version` is no longer set.
///
/// Summary of field usage:
/// - Before performance-based rewards: `registry_version` is Some; `start_date` and `end_date` are None.
/// - After performance-based rewards: `start_date` and `end_date` are Some; `registry_version` is None.
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct MonthlyNodeProviderRewards {
    /// The time when the rewards were calculated.
    pub timestamp: u64,
    /// The start date (included) that these rewards cover.
    pub start_date: Option<DateUtc>,
    /// The end date (included) that these rewards cover.
    pub end_date: Option<DateUtc>,
    /// The Rewards calculated and rewarded.
    pub rewards: Vec<RewardNodeProvider>,
    /// The XdrConversionRate used to calculate the rewards.  This comes from the CMC canister.
    /// This field snapshots the actual rate used by governance when the rewards were calculated.
    pub xdr_conversion_rate: Option<XdrConversionRate>,
    /// The minimum xdr permyriad per icp at the time when the rewards were calculated.  This is useful for understanding
    /// why the rewards were what they were if the xdr_conversion_rate falls below this threshold.
    pub minimum_xdr_permyriad_per_icp: Option<u64>,
    /// The maximum amount of ICP e8s that can be awarded to a single node provider in one event.  This is snapshotted
    /// from the value in network economics.
    pub maximum_node_provider_rewards_e8s: Option<u64>,
    /// The registry version used to calculate these rewards at the time the rewards were calculated.
    pub registry_version: Option<u64>,
    /// Rewards calculation algorithm version used to calculate rewards.
    /// See RewardsCalculationAlgorithmVersion for the allowed values.
    pub algorithm_version: Option<u32>,
    /// The list of node_provieders at the time when the rewards were calculated.
    pub node_providers: Vec<NodeProvider>,
}
/// TODO(NNS1-1589): Until the Jira ticket gets solved, changes here need to be
/// manually propagated to (sns) swap.proto.
/// This message is obsolete; please use SettleNeuronsFundParticipation instead.
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct SettleCommunityFundParticipation {
    /// The caller's principal ID must match the value in the
    /// target_swap_canister_id field in the proposal (more precisely, in the
    /// OpenSnsTokenSwap).
    pub open_sns_token_swap_proposal_id: Option<u64>,
    /// Each of the possibilities here corresponds to one of two ways that a swap
    /// can terminate. See also sns_swap_pb::Lifecycle::is_terminal.
    pub result: Option<settle_community_fund_participation::Result>,
}
/// Nested message and enum types in `SettleCommunityFundParticipation`.
pub mod settle_community_fund_participation {
    use super::*;

    /// When this happens, ICP needs to be minted, and sent to the SNS governance
    /// canister's main account on the ICP Ledger. As with Aborted, the amount of
    /// ICP that needs to be minted can be deduced from the ProposalData's
    /// cf_participants field.
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct Committed {
        /// This is where the minted ICP will be sent. In principal, this could be
        /// fetched using the swap canister's get_state method.
        pub sns_governance_canister_id: Option<PrincipalId>,
        /// Total contribution amount from direct swap participants.
        pub total_direct_contribution_icp_e8s: Option<u64>,
        /// Total contribution amount from the Neuron's Fund.
        /// TODO\[NNS1-2570\]: Ensure this field is set.
        pub total_neurons_fund_contribution_icp_e8s: Option<u64>,
    }
    /// When this happens, maturity needs to be restored to CF neurons. The amounts
    /// to be refunded can be found in the ProposalData's cf_participants field.
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct Aborted {}
    /// Each of the possibilities here corresponds to one of two ways that a swap
    /// can terminate. See also sns_swap_pb::Lifecycle::is_terminal.
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug,
    )]
    pub enum Result {
        Committed(Committed),
        Aborted(Aborted),
    }
}
/// Request to settle the Neurons' Fund participation in this SNS Swap.
///
/// When a swap ends, the Swap canister notifies the Neurons' Fund of the swap's ultimate result,
/// which can be either `Committed` or `Aborted`. Note that currently, the Neurons' Fund is managed
/// by the NNS Governance canister.
/// * If the result is `Committed`:
///    - Neurons' Fund computes the "effective" participation amount for each of its neurons (as per
///      the Matched Funding rules). This computation is based on the total direct participation
///      amount, which is thus a field of `Committed`.
///    - Neurons' Fund converts the "effective" amount of maturity into ICP by:
///      - Requesting the ICP Ledger to mint an appropriate amount of ICP tokens and sending them
///        to the SNS treasury.
///      - Refunding whatever maturity is left over (the maximum possible maturity is reserved by
///        the Neurons' Fund before the swap begins).
///    - Neurons' Fund returns the Neurons' Fund participants back to the Swap canister
///      (see SettleNeuronsFundParticipationResponse).
///    - The Swap canister then creates SNS neurons for the Neurons' Fund participants.
/// * If the result is Aborted, the Neurons' Fund is refunded for all maturity reserved for this SNS.
///
/// This design assumes trust between the Neurons' Fund and the SNS Swap canisters. In the one hand,
/// the Swap trusts that the Neurons' Fund sends the correct amount of ICP to the SNS treasury,
/// and that the Neurons' Fund allocates its participants following the Matched Funding rules. On the
/// other hand, the Neurons' Fund trusts that the Swap will indeed create appropriate SNS neurons
/// for the Neurons' Fund participants.
///
/// The justification for this trust assumption is as follows. The Neurons' Fund can be trusted as
/// it is controlled by the NNS. The SNS Swap can be trusted as it is (1) deployed by SNS-W, which is
/// also part of the NNS and (2) upgraded via an NNS proposal (unlike all other SNS canisters).
///
/// This request may be submitted only by the Swap canister of an SNS instance created by
/// a CreateServiceNervousSystem proposal.
///
/// TODO(NNS1-1589): Until the Jira ticket gets solved, changes here need to be
/// manually propagated to (sns) swap.proto.
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct SettleNeuronsFundParticipationRequest {
    /// Proposal ID of the CreateServiceNervousSystem proposal that created this SNS instance.
    pub nns_proposal_id: Option<u64>,
    /// Each of the possibilities here corresponds to one of two ways that a swap can terminate.
    /// See also sns_swap_pb::Lifecycle::is_terminal.
    pub result: Option<settle_neurons_fund_participation_request::Result>,
}
/// Nested message and enum types in `SettleNeuronsFundParticipationRequest`.
pub mod settle_neurons_fund_participation_request {
    use super::*;

    /// When this happens, the NNS Governance needs to do several things:
    /// (1) Compute the effective amount of ICP per neuron of the Neurons' Fund as a function of
    ///      `total_direct_participation_icp_e8s`. The overall Neurons' Fund participation should
    ///      equal `total_neurons_fund_contribution_icp_e8s`.
    /// (2) Mint (via the ICP Ledger) and sent to the SNS governance the amount of
    ///      `total_neurons_fund_contribution_icp_e8s`.
    /// (3) Respond to this request with `SettleNeuronsFundParticipationResponse`, providing
    ///      the set of `NeuronsFundParticipant`s with the effective amount of ICP per neuron,
    ///      as computed in step (1).
    /// (4) Refund each neuron of the Neurons' Fund with (reserved - effective) amount of ICP.
    /// Effective amounts depend on `total_direct_participation_icp_e8s` and the participation limits
    /// of a particular SNS instance, namely, each participation must be between
    /// `min_participant_icp_e8s` and `max_participant_icp_e8s`.
    /// - If a neuron of the Neurons' Fund has less than `min_participant_icp_e8s` worth of maturity,
    ///    then it is ineligible to participate.
    /// - If a neuron of the Neurons' Fund has more than `max_participant_icp_e8s` worth of maturity,
    ///    then its participation amount is limited to `max_participant_icp_e8s`.
    /// Reserved amounts are computed as the minimal upper bound on the effective amounts, i.e., when
    /// the value `total_direct_participation_icp_e8s` reaches its theoretical maximum.
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct Committed {
        /// This is where the minted ICP will be sent.
        pub sns_governance_canister_id: Option<PrincipalId>,
        /// Total amount of participation from direct swap participants.
        pub total_direct_participation_icp_e8s: Option<u64>,
        /// Total amount of participation from the Neurons' Fund.
        /// TODO\[NNS1-2570\]: Ensure this field is set.
        pub total_neurons_fund_participation_icp_e8s: Option<u64>,
    }
    /// When this happens, all priorly reserved maturity for this SNS instance needs to be restored to
    /// the Neurons' Fund neurons.
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct Aborted {}
    /// Each of the possibilities here corresponds to one of two ways that a swap can terminate.
    /// See also sns_swap_pb::Lifecycle::is_terminal.
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug,
    )]
    pub enum Result {
        Committed(Committed),
        Aborted(Aborted),
    }
}
/// Handling the Neurons' Fund and transferring some of its maturity to an SNS treasury is
/// thus the responsibility of the NNS Governance. When a swap succeeds, a Swap canister should send
/// a `settle_neurons_fund_participation` request to the NNS Governance, specifying its `result`
/// field as `committed`. The NNS Governance then computes the ultimate distribution of maturity in
/// the Neurons' Fund. However, this distribution also needs to be made available to the SNS Swap
/// that will use this information to create SNS neurons of an appropriate size for each
/// Neurons' Fund (as well as direct) participant. That is why in the `committed` case,
/// the NNS Governance should populate the `neurons_fund_participants` field, while in the `aborted`
/// case it should be empty.
///
/// TODO(NNS1-1589): Until the Jira ticket gets solved, changes here need to be
/// manually propagated to (sns) swap.proto.
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct SettleNeuronsFundParticipationResponse {
    pub result: Option<settle_neurons_fund_participation_response::Result>,
}
/// Nested message and enum types in `SettleNeuronsFundParticipationResponse`.
pub mod settle_neurons_fund_participation_response {
    use super::*;

    /// Represents one NNS neuron from the Neurons' Fund participating in this swap.
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct NeuronsFundNeuron {
        /// The NNS neuron ID of the participating neuron.
        pub nns_neuron_id: Option<u64>,
        /// The amount of Neurons' Fund participation associated with this neuron.
        pub amount_icp_e8s: Option<u64>,
        /// The principal that can manage the NNS neuron that participated in the Neurons' Fund.
        pub controller: Option<PrincipalId>,
        /// The principals that can vote, propose, and follow on behalf of this neuron.
        pub hotkeys: Option<::ic_nervous_system_proto::pb::v1::Principals>,
        /// Whether the amount maturity amount of Neurons' Fund participation associated with this neuron
        /// has been capped to reflect the maximum participation amount for this SNS swap.
        pub is_capped: ::core::option::Option<bool>,
    }
    /// Request was completed successfully.
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct Ok {
        pub neurons_fund_neuron_portions: Vec<NeuronsFundNeuron>,
    }
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug,
    )]
    pub enum Result {
        Err(super::GovernanceError),
        Ok(Ok),
    }
}
/// Audit events in order to leave an audit trail for certain operations.
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct AuditEvent {
    /// The timestamp of the event.
    pub timestamp_seconds: u64,
    pub payload: Option<audit_event::Payload>,
}
/// Nested message and enum types in `AuditEvent`.
pub mod audit_event {
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct ResetAging {
        /// The neuron id whose aging was reset.
        pub neuron_id: u64,
        /// The aging_since_timestamp_seconds before reset.
        pub previous_aging_since_timestamp_seconds: u64,
        /// The aging_since_timestamp_seconds after reset.
        pub new_aging_since_timestamp_seconds: u64,
        /// Neuron's stake at the time of reset.
        pub neuron_stake_e8s: u64,
        /// Neuron's dissolve state at the time of reset.
        pub neuron_dissolve_state: Option<reset_aging::NeuronDissolveState>,
    }
    /// Nested message and enum types in `ResetAging`.
    pub mod reset_aging {
        /// Neuron's dissolve state at the time of reset.
        #[derive(
            candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug,
        )]
        pub enum NeuronDissolveState {
            WhenDissolvedTimestampSeconds(u64),
            DissolveDelaySeconds(u64),
        }
    }
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct RestoreAging {
        /// The neuron id whose aging was restored.
        pub neuron_id: Option<u64>,
        /// The aging_since_timestamp_seconds before restore.
        pub previous_aging_since_timestamp_seconds: Option<u64>,
        /// The aging_since_timestamp_seconds after restore.
        pub new_aging_since_timestamp_seconds: Option<u64>,
        /// Neuron's stake at the time of restore.
        pub neuron_stake_e8s: Option<u64>,
        /// Neuron's dissolve state at the time of restore.
        pub neuron_dissolve_state: Option<restore_aging::NeuronDissolveState>,
    }
    /// Nested message and enum types in `RestoreAging`.
    pub mod restore_aging {
        /// Neuron's dissolve state at the time of restore.
        #[derive(
            candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug,
        )]
        pub enum NeuronDissolveState {
            WhenDissolvedTimestampSeconds(u64),
            DissolveDelaySeconds(u64),
        }
    }
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct NormalizeDissolveStateAndAge {
        /// The neuron id whose dissolve state and age were normalized.
        pub neuron_id: Option<u64>,
        /// Which legacy case the neuron falls into.
        pub neuron_legacy_case: i32,
        /// Previous when_dissolved_timestamp_seconds if the neuron was dissolving or dissolved.
        pub previous_when_dissolved_timestamp_seconds: Option<u64>,
        /// Previous aging_since_timestamp_seconds.
        pub previous_aging_since_timestamp_seconds: Option<u64>,
    }
    #[derive(
        candid::CandidType,
        candid::Deserialize,
        serde::Serialize,
        Clone,
        Copy,
        Debug,
        PartialEq,
        Eq,
        Hash,
        PartialOrd,
        Ord,
    )]
    #[repr(i32)]
    pub enum NeuronLegacyCase {
        Unspecified = 0,
        /// Neuron is dissolving or dissolved but with a non-zero age.
        DissolvingOrDissolved = 1,
        /// Neuron is dissolved with DissolveDelaySeconds(0).
        Dissolved = 2,
        /// Neuron has a None dissolve state.
        NoneDissolveState = 3,
    }
    impl NeuronLegacyCase {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                NeuronLegacyCase::Unspecified => "NEURON_LEGACY_CASE_UNSPECIFIED",
                NeuronLegacyCase::DissolvingOrDissolved => {
                    "NEURON_LEGACY_CASE_DISSOLVING_OR_DISSOLVED"
                }
                NeuronLegacyCase::Dissolved => "NEURON_LEGACY_CASE_DISSOLVED",
                NeuronLegacyCase::NoneDissolveState => "NEURON_LEGACY_CASE_NONE_DISSOLVE_STATE",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> Option<Self> {
            match value {
                "NEURON_LEGACY_CASE_UNSPECIFIED" => Some(Self::Unspecified),
                "NEURON_LEGACY_CASE_DISSOLVING_OR_DISSOLVED" => Some(Self::DissolvingOrDissolved),
                "NEURON_LEGACY_CASE_DISSOLVED" => Some(Self::Dissolved),
                "NEURON_LEGACY_CASE_NONE_DISSOLVE_STATE" => Some(Self::NoneDissolveState),
                _ => None,
            }
        }
    }
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug,
    )]
    pub enum Payload {
        /// Reset aging timestamps (<https://forum.dfinity.org/t/icp-neuron-age-is-52-years/21261/26>).
        ResetAging(ResetAging),
        /// Restore aging timestamp that were incorrectly reset (<https://forum.dfinity.org/t/restore-neuron-age-in-proposal-129394/29840>).
        RestoreAging(RestoreAging),
        /// Normalize neuron dissolve state and age (<https://forum.dfinity.org/t/simplify-neuron-state-age/30527>)
        NormalizeDissolveStateAndAge(NormalizeDissolveStateAndAge),
    }
}
/// The summary of the restore aging event.
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct RestoreAgingSummary {
    /// The timestamp of the restore aging event.
    pub timestamp_seconds: Option<u64>,
    /// Groups of neurons that were considered for restoring their aging.
    pub groups: Vec<restore_aging_summary::RestoreAgingNeuronGroup>,
}
/// Nested message and enum types in `RestoreAgingSummary`.
pub mod restore_aging_summary {
    #[derive(
        candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
    )]
    pub struct RestoreAgingNeuronGroup {
        pub group_type: i32,
        /// The number of neurons in this group.
        pub count: Option<u64>,
        /// The previous total stake of neurons in this group when the aging was reset.
        pub previous_total_stake_e8s: Option<u64>,
        /// The current total stake of neurons in this group when considering to restore aging.
        pub current_total_stake_e8s: Option<u64>,
    }
    #[derive(
        candid::CandidType,
        candid::Deserialize,
        serde::Serialize,
        Clone,
        Copy,
        Debug,
        PartialEq,
        Eq,
        Hash,
        PartialOrd,
        Ord,
    )]
    #[repr(i32)]
    pub enum NeuronGroupType {
        Unspecified = 0,
        /// The neurons in this group were not pre-aging. We don't restore their aging.
        NotPreAging = 1,
        /// The neurons in this group are dissolving or dissolved. We don't restore their aging because
        /// it's invalid for a dissolving/dissolved neuron to have age.
        DissolvingOrDissolved = 2,
        /// The neurons in this group have their stake changed. We restore them to be pre-aged.
        StakeChanged = 3,
        /// The neurons in this group have their stake remain the same and aging changed. We restore them
        /// to be pre-aged.
        StakeSameAgingChanged = 4,
        /// The neurons in this group have their stake remain the same and aging remain the same. We
        /// restore them to be pre-aged.
        StakeSameAgingSame = 5,
    }
    impl NeuronGroupType {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                NeuronGroupType::Unspecified => "NEURON_GROUP_TYPE_UNSPECIFIED",
                NeuronGroupType::NotPreAging => "NEURON_GROUP_TYPE_NOT_PRE_AGING",
                NeuronGroupType::DissolvingOrDissolved => {
                    "NEURON_GROUP_TYPE_DISSOLVING_OR_DISSOLVED"
                }
                NeuronGroupType::StakeChanged => "NEURON_GROUP_TYPE_STAKE_CHANGED",
                NeuronGroupType::StakeSameAgingChanged => {
                    "NEURON_GROUP_TYPE_STAKE_SAME_AGING_CHANGED"
                }
                NeuronGroupType::StakeSameAgingSame => "NEURON_GROUP_TYPE_STAKE_SAME_AGING_SAME",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> Option<Self> {
            match value {
                "NEURON_GROUP_TYPE_UNSPECIFIED" => Some(Self::Unspecified),
                "NEURON_GROUP_TYPE_NOT_PRE_AGING" => Some(Self::NotPreAging),
                "NEURON_GROUP_TYPE_DISSOLVING_OR_DISSOLVED" => Some(Self::DissolvingOrDissolved),
                "NEURON_GROUP_TYPE_STAKE_CHANGED" => Some(Self::StakeChanged),
                "NEURON_GROUP_TYPE_STAKE_SAME_AGING_CHANGED" => Some(Self::StakeSameAgingChanged),
                "NEURON_GROUP_TYPE_STAKE_SAME_AGING_SAME" => Some(Self::StakeSameAgingSame),
                _ => None,
            }
        }
    }
}

/// A Ledger account identified by the owner of the account `of` and
/// the `subaccount`. If the `subaccount` is not specified then the default
/// one is used.
#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Clone, PartialEq, Debug, Default,
)]
pub struct Account {
    /// The owner of the account.
    pub owner: ::core::option::Option<::ic_base_types::PrincipalId>,
    /// The subaccount of the account. If not set then the default
    /// subaccount (all bytes set to 0) is used.
    #[serde(deserialize_with = "ic_utils::deserialize::deserialize_option_blob")]
    pub subaccount: ::core::option::Option<Vec<u8>>,
}

/// Proposal types are organized into topics. Neurons can automatically
/// vote based on following other neurons, and these follow
/// relationships are defined per topic.
#[derive(
    candid::CandidType,
    candid::Deserialize,
    serde::Serialize,
    strum_macros::EnumIter,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    strum_macros::FromRepr,
)]
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
    /// All proposals to manage NNS-controlled canisters not covered by other topics (Protocol
    /// Canister Management or Service Nervous System Management).
    ApplicationCanisterManagement = 8,
    /// Proposals that update KYC information for regulatory purposes,
    /// for example during the initial Genesis distribution of ICP in the
    /// form of neurons.
    Kyc = 9,
    /// Topic for proposals to reward node providers.
    NodeProviderRewards = 10,
    /// IC OS upgrade proposals
    /// -----------------------
    /// ICP runs on a distributed network of nodes grouped into subnets. Each node runs a stack of
    /// operating systems, including HostOS (runs on bare metal) and GuestOS (runs inside HostOS;
    /// contains, e.g., the ICP replica process). HostOS and GuestOS are distributed via separate disk
    /// images. The umbrella term IC OS refers to the whole stack.
    ///
    /// The IC OS upgrade process involves two phases, where the first phase is the election of a new
    /// IC OS version and the second phase is the deployment of a previously elected IC OS version on
    /// all nodes of a subnet or on some number of nodes (including nodes comprising subnets and
    /// unassigned nodes).
    ///
    /// A special case is for API boundary nodes, special nodes that route API requests to a replica
    /// of the right subnet. API boundary nodes run a different process than the replica, but their
    /// executable is distributed via the same disk image as GuestOS. Therefore, electing a new GuestOS
    /// version also results in a new version of boundary node software being elected.
    ///
    /// Proposals handling the deployment of IC OS to some nodes. It is possible to deploy only
    /// the versions of IC OS that are in the set of elected IC OS versions.
    IcOsVersionDeployment = 12,
    /// Proposals for changing the set of elected IC OS versions.
    IcOsVersionElection = 13,
    /// Proposals related to SNS and Community Fund.
    SnsAndCommunityFund = 14,
    /// Proposals related to the management of API Boundary Nodes
    ApiBoundaryNodeManagement = 15,
    /// Proposals related to subnet rental.
    SubnetRental = 16,
    /// All proposals to manage protocol canisters, which are considered part of the ICP protocol
    /// and are essential for its proper functioning.
    ProtocolCanisterManagement = 17,
    /// All proposals to manage the canisters of service nervous systems (SNS), including upgrading
    /// relevant canisters and managing SNS framework canister WASMs through SNS-W.
    ServiceNervousSystemManagement = 18,
}

/// Every neuron is in one of three states.
///
/// Note that `Disbursed` is not a state of a neuron, as the neuron is
/// consumed through the act of disbursement (using the method
/// \[Governance::disburse\]).
///
/// See \[neuron::DissolveState\] for detail on how the different states
/// are represented.
#[derive(
    candid::CandidType,
    candid::Deserialize,
    serde::Serialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    strum_macros::FromRepr,
)]
#[repr(i32)]
pub enum NeuronState {
    /// Not a valid state. Required by Protobufs.
    Unspecified = 0,
    /// In this state, the neuron is not dissolving and has a specific
    /// `dissolve_delay`. It accrues `age` by the passage of time and it
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
    /// The neuron is in spawning state, meaning it's maturity will be
    /// converted to ICP according to <https://wiki.internetcomputer.org/wiki/Maturity_modulation.>
    Spawning = 4,
}
impl NeuronState {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            NeuronState::Unspecified => "NEURON_STATE_UNSPECIFIED",
            NeuronState::NotDissolving => "NEURON_STATE_NOT_DISSOLVING",
            NeuronState::Dissolving => "NEURON_STATE_DISSOLVING",
            NeuronState::Dissolved => "NEURON_STATE_DISSOLVED",
            NeuronState::Spawning => "NEURON_STATE_SPAWNING",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> Option<Self> {
        match value {
            "NEURON_STATE_UNSPECIFIED" => Some(Self::Unspecified),
            "NEURON_STATE_NOT_DISSOLVING" => Some(Self::NotDissolving),
            "NEURON_STATE_DISSOLVING" => Some(Self::Dissolving),
            "NEURON_STATE_DISSOLVED" => Some(Self::Dissolved),
            "NEURON_STATE_SPAWNING" => Some(Self::Spawning),
            _ => None,
        }
    }
}
/// Controls how much information non-controller and non-hot-key principals can
/// see about this neuron. Currently, if a neuron is private, recent_ballots and
/// joined_community_fund_timestamp_seconds are redacted when being read by an
/// unprivileged principal.
///
/// <https://forum.dfinity.org/t/request-for-comments-api-changes-for-public-private-neurons/33360>
///
/// As of Jul 19, this is not yet enforced, but will be once the plan described
/// above is fully executed.
#[derive(
    candid::CandidType,
    candid::Deserialize,
    serde::Serialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
)]
#[repr(i32)]
pub enum Visibility {
    Unspecified = 0,
    Private = 1,
    Public = 2,
}
impl Visibility {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Visibility::Unspecified => "VISIBILITY_UNSPECIFIED",
            Visibility::Private => "VISIBILITY_PRIVATE",
            Visibility::Public => "VISIBILITY_PUBLIC",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> Option<Self> {
        match value {
            "VISIBILITY_UNSPECIFIED" => Some(Self::Unspecified),
            "VISIBILITY_PRIVATE" => Some(Self::Private),
            "VISIBILITY_PUBLIC" => Some(Self::Public),
            _ => None,
        }
    }
}
/// Types of a Neuron.
#[derive(
    candid::CandidType,
    candid::Deserialize,
    serde::Serialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
)]
#[repr(i32)]
pub enum NeuronType {
    /// Placeholder value due to the proto3 requirement for a zero default.
    /// This is an invalid type; neurons should not be assigned this value.
    Unspecified = 0,
    /// Represents neurons initially created for Seed accounts in the
    /// Genesis Token Canister, or those descended from such neurons.
    Seed = 1,
    /// Represents neurons initially created for Early Contributor Token (ECT)
    /// accounts in the Genesis Token Canister, or those descended from such neurons.
    Ect = 2,
}
impl NeuronType {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            NeuronType::Unspecified => "NEURON_TYPE_UNSPECIFIED",
            NeuronType::Seed => "NEURON_TYPE_SEED",
            NeuronType::Ect => "NEURON_TYPE_ECT",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> Option<Self> {
        match value {
            "NEURON_TYPE_UNSPECIFIED" => Some(Self::Unspecified),
            "NEURON_TYPE_SEED" => Some(Self::Seed),
            "NEURON_TYPE_ECT" => Some(Self::Ect),
            _ => None,
        }
    }
}
/// The types of votes the Neuron can issue.
#[derive(
    candid::CandidType,
    candid::Deserialize,
    serde::Serialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    strum_macros::FromRepr,
)]
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
    pub fn from_str_name(value: &str) -> Option<Self> {
        match value {
            "VOTE_UNSPECIFIED" => Some(Self::Unspecified),
            "VOTE_YES" => Some(Self::Yes),
            "VOTE_NO" => Some(Self::No),
            _ => None,
        }
    }
}
/// List of NNS functions that can be called by proposals.
#[derive(
    candid::CandidType,
    candid::Deserialize,
    serde::Serialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
)]
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
    /// Deploy a GuestOS version to a given subnet. The proposal changes the GuestOS version that is
    /// used on the specified subnet. The version must be contained in the list of elected GuestOS
    /// versions. The upgrade is completed when the subnet creates the next regular CUP.
    DeployGuestosToAllSubnetNodes = 11,
    /// Clear the provisional whitelist.
    /// The proposal changes the provisional whitelist to the empty list.
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
    /// (obsolete) Update the config for all unassigned nodes.
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
    /// Add a new SNS canister WASM
    AddSnsWasm = 30,
    /// Change the subnet node membership. In a way, this function combines the separate
    /// functions for adding and removing nodes from the subnet record, but adds the property
    /// of atomic node replacement (node swap) on top.
    ///
    /// The nodes that are being added to the subnet must be currently unassigned.
    /// The nodes that are being removed from the subnet must be currently assigned to the subnet.
    ChangeSubnetMembership = 31,
    /// Updates the available subnet types in the cycles minting canister.
    UpdateSubnetType = 32,
    /// Changes the assignment of subnets to subnet types in the cycles minting
    /// canister.
    ChangeSubnetTypeAssignment = 33,
    /// Update the list of SNS subnet IDs that SNS WASM will deploy SNS instances to.
    UpdateSnsWasmSnsSubnetIds = 34,
    /// Update the SNS-wasm canister's list of allowed principals. This list guards which principals can deploy an SNS.
    UpdateAllowedPrincipals = 35,
    /// A proposal to retire previously elected and unused replica versions.
    /// The specified versions are removed from the registry and the "blessed versions" record.
    /// This ensures that the replica cannot upgrade to these versions anymore.
    RetireReplicaVersion = 36,
    /// Insert custom upgrade path entries into SNS-W for all SNSes, or for an SNS specified by its governance canister ID.
    InsertSnsWasmUpgradePathEntries = 37,
    /// A proposal to change the set of elected GuestOS versions. The version to elect (identified by
    /// the hash of the installation image) is added to the registry. Besides creating a record for
    /// that version, the proposal also appends that version to the list of elected versions that can
    /// be installed on nodes of a subnet. Only elected GuestOS versions can be deployed.
    ReviseElectedGuestosVersions = 38,
    BitcoinSetConfig = 39,
    /// OBSOLETE: use NNS_FUNCTION_REVISE_ELECTED_HOSTOS_VERSIONS instead
    UpdateElectedHostosVersions = 40,
    /// OBSOLETE: use NNS_FUNCTION_UPGRADE_HOSTOS_FOR_SOME_NODES instead
    UpdateNodesHostosVersion = 41,
    /// Uninstall and Install Root with the WASM provided in the function.  If InitArgs are provided
    /// They will be passed to the canister_init function of the WASM provided.
    /// This function is meant as a Break Glass mechanism for when an open call context in
    /// the Root canister is preventing root or another canister from upgrading (in the case of proxied calls).
    HardResetNnsRootToVersion = 42,
    /// A proposal to add a set of new API Boundary Nodes using unassigned nodes
    AddApiBoundaryNodes = 43,
    /// A proposal to remove a set of API Boundary Nodes, which will designate them as unassigned nodes
    RemoveApiBoundaryNodes = 44,
    /// (obsolete) A proposal to update the version of a set of API Boundary Nodes
    UpdateApiBoundaryNodesVersion = 46,
    /// A proposal to update the version of a set of API Boundary Nodes
    DeployGuestosToSomeApiBoundaryNodes = 47,
    /// A proposal to update the version of all unassigned nodes
    DeployGuestosToAllUnassignedNodes = 48,
    /// A proposal to update SSH readonly access for all unassigned nodes
    UpdateSshReadonlyAccessForAllUnassignedNodes = 49,
    /// A proposal to change the set of currently elected HostOS versions, by electing a new version,
    /// and/or unelecting some priorly elected versions. HostOS versions are identified by the hash
    /// of the installation image. The version to elect is added to the Registry, and the versions
    /// to unelect are removed from the Registry, ensuring that HostOS cannot upgrade to these versions
    /// anymore. This proposal does not actually perform the upgrade; for deployment of an elected
    /// version, please refer to `NNS_FUNCTION_DEPLOY_HOSTOS_TO_SOME_NODES`.
    ReviseElectedHostosVersions = 50,
    /// Deploy a HostOS version to a given set of nodes. The proposal changes the HostOS version that
    /// is used on the specified nodes.
    DeployHostosToSomeNodes = 51,
    /// The proposal requests a subnet rental.
    SubnetRentalRequest = 52,
    /// Instruct the migration canister to not accept any more migration requests.
    PauseCanisterMigrations = 53,
    /// Instruct the migration canister to accept migration requests again.
    UnpauseCanisterMigrations = 54,
    /// For taking a subnet offline for repairs, as well as back online. These
    /// are the first and last steps in subnet recovery.
    ///
    /// The primary thing this does is set the `halted` field in `SubnetRecord`.
    /// However, there are a couple of secondary changes that this also does:
    ///
    ///     1. Set the `ssh_read_only_access` field in `SubnetRecord`.
    ///     2. Set the `ssh_node_state_write_access` field in `NodeRecord`.
    ///
    /// When there is a DFINITY node where SEV is not enabled in the subnet,
    /// UpdateConfigOfSubnet can be used instead. But otherwise, this is the
    /// state of the art (as of Oct 2025) way of doing subnet recovery.
    SetSubnetOperationalLevel = 55,
}
impl NnsFunction {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            NnsFunction::Unspecified => "NNS_FUNCTION_UNSPECIFIED",
            NnsFunction::CreateSubnet => "NNS_FUNCTION_CREATE_SUBNET",
            NnsFunction::AddNodeToSubnet => "NNS_FUNCTION_ADD_NODE_TO_SUBNET",
            NnsFunction::NnsCanisterInstall => "NNS_FUNCTION_NNS_CANISTER_INSTALL",
            NnsFunction::NnsCanisterUpgrade => "NNS_FUNCTION_NNS_CANISTER_UPGRADE",
            NnsFunction::BlessReplicaVersion => "NNS_FUNCTION_BLESS_REPLICA_VERSION",
            NnsFunction::RecoverSubnet => "NNS_FUNCTION_RECOVER_SUBNET",
            NnsFunction::UpdateConfigOfSubnet => "NNS_FUNCTION_UPDATE_CONFIG_OF_SUBNET",
            NnsFunction::AssignNoid => "NNS_FUNCTION_ASSIGN_NOID",
            NnsFunction::NnsRootUpgrade => "NNS_FUNCTION_NNS_ROOT_UPGRADE",
            NnsFunction::IcpXdrConversionRate => "NNS_FUNCTION_ICP_XDR_CONVERSION_RATE",
            NnsFunction::DeployGuestosToAllSubnetNodes => {
                "NNS_FUNCTION_DEPLOY_GUESTOS_TO_ALL_SUBNET_NODES"
            }
            NnsFunction::ClearProvisionalWhitelist => "NNS_FUNCTION_CLEAR_PROVISIONAL_WHITELIST",
            NnsFunction::RemoveNodesFromSubnet => "NNS_FUNCTION_REMOVE_NODES_FROM_SUBNET",
            NnsFunction::SetAuthorizedSubnetworks => "NNS_FUNCTION_SET_AUTHORIZED_SUBNETWORKS",
            NnsFunction::SetFirewallConfig => "NNS_FUNCTION_SET_FIREWALL_CONFIG",
            NnsFunction::UpdateNodeOperatorConfig => "NNS_FUNCTION_UPDATE_NODE_OPERATOR_CONFIG",
            NnsFunction::StopOrStartNnsCanister => "NNS_FUNCTION_STOP_OR_START_NNS_CANISTER",
            NnsFunction::RemoveNodes => "NNS_FUNCTION_REMOVE_NODES",
            NnsFunction::UninstallCode => "NNS_FUNCTION_UNINSTALL_CODE",
            NnsFunction::UpdateNodeRewardsTable => "NNS_FUNCTION_UPDATE_NODE_REWARDS_TABLE",
            NnsFunction::AddOrRemoveDataCenters => "NNS_FUNCTION_ADD_OR_REMOVE_DATA_CENTERS",
            NnsFunction::UpdateUnassignedNodesConfig => {
                "NNS_FUNCTION_UPDATE_UNASSIGNED_NODES_CONFIG"
            }
            NnsFunction::RemoveNodeOperators => "NNS_FUNCTION_REMOVE_NODE_OPERATORS",
            NnsFunction::RerouteCanisterRanges => "NNS_FUNCTION_REROUTE_CANISTER_RANGES",
            NnsFunction::AddFirewallRules => "NNS_FUNCTION_ADD_FIREWALL_RULES",
            NnsFunction::RemoveFirewallRules => "NNS_FUNCTION_REMOVE_FIREWALL_RULES",
            NnsFunction::UpdateFirewallRules => "NNS_FUNCTION_UPDATE_FIREWALL_RULES",
            NnsFunction::PrepareCanisterMigration => "NNS_FUNCTION_PREPARE_CANISTER_MIGRATION",
            NnsFunction::CompleteCanisterMigration => "NNS_FUNCTION_COMPLETE_CANISTER_MIGRATION",
            NnsFunction::AddSnsWasm => "NNS_FUNCTION_ADD_SNS_WASM",
            NnsFunction::ChangeSubnetMembership => "NNS_FUNCTION_CHANGE_SUBNET_MEMBERSHIP",
            NnsFunction::UpdateSubnetType => "NNS_FUNCTION_UPDATE_SUBNET_TYPE",
            NnsFunction::ChangeSubnetTypeAssignment => "NNS_FUNCTION_CHANGE_SUBNET_TYPE_ASSIGNMENT",
            NnsFunction::UpdateSnsWasmSnsSubnetIds => "NNS_FUNCTION_UPDATE_SNS_WASM_SNS_SUBNET_IDS",
            NnsFunction::UpdateAllowedPrincipals => "NNS_FUNCTION_UPDATE_ALLOWED_PRINCIPALS",
            NnsFunction::RetireReplicaVersion => "NNS_FUNCTION_RETIRE_REPLICA_VERSION",
            NnsFunction::InsertSnsWasmUpgradePathEntries => {
                "NNS_FUNCTION_INSERT_SNS_WASM_UPGRADE_PATH_ENTRIES"
            }
            NnsFunction::ReviseElectedGuestosVersions => {
                "NNS_FUNCTION_REVISE_ELECTED_GUESTOS_VERSIONS"
            }
            NnsFunction::BitcoinSetConfig => "NNS_FUNCTION_BITCOIN_SET_CONFIG",
            NnsFunction::UpdateElectedHostosVersions => {
                "NNS_FUNCTION_UPDATE_ELECTED_HOSTOS_VERSIONS"
            }
            NnsFunction::UpdateNodesHostosVersion => "NNS_FUNCTION_UPDATE_NODES_HOSTOS_VERSION",
            NnsFunction::HardResetNnsRootToVersion => "NNS_FUNCTION_HARD_RESET_NNS_ROOT_TO_VERSION",
            NnsFunction::AddApiBoundaryNodes => "NNS_FUNCTION_ADD_API_BOUNDARY_NODES",
            NnsFunction::RemoveApiBoundaryNodes => "NNS_FUNCTION_REMOVE_API_BOUNDARY_NODES",
            NnsFunction::UpdateApiBoundaryNodesVersion => {
                "NNS_FUNCTION_UPDATE_API_BOUNDARY_NODES_VERSION"
            }
            NnsFunction::DeployGuestosToSomeApiBoundaryNodes => {
                "NNS_FUNCTION_DEPLOY_GUESTOS_TO_SOME_API_BOUNDARY_NODES"
            }
            NnsFunction::DeployGuestosToAllUnassignedNodes => {
                "NNS_FUNCTION_DEPLOY_GUESTOS_TO_ALL_UNASSIGNED_NODES"
            }
            NnsFunction::UpdateSshReadonlyAccessForAllUnassignedNodes => {
                "NNS_FUNCTION_UPDATE_SSH_READONLY_ACCESS_FOR_ALL_UNASSIGNED_NODES"
            }
            NnsFunction::ReviseElectedHostosVersions => {
                "NNS_FUNCTION_REVISE_ELECTED_HOSTOS_VERSIONS"
            }
            NnsFunction::DeployHostosToSomeNodes => "NNS_FUNCTION_DEPLOY_HOSTOS_TO_SOME_NODES",
            NnsFunction::SubnetRentalRequest => "NNS_FUNCTION_SUBNET_RENTAL_REQUEST",
            NnsFunction::PauseCanisterMigrations => "NNS_FUNCTION_PAUSE_CANISTER_MIGRATIONS",
            NnsFunction::UnpauseCanisterMigrations => "NNS_FUNCTION_UNPAUSE_CANISTER_MIGRATIONS",
            NnsFunction::SetSubnetOperationalLevel => "NNS_FUNCTION_SET_SUBNET_OPERATIONAL_LEVEL",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> Option<Self> {
        match value {
            "NNS_FUNCTION_UNSPECIFIED" => Some(Self::Unspecified),
            "NNS_FUNCTION_CREATE_SUBNET" => Some(Self::CreateSubnet),
            "NNS_FUNCTION_ADD_NODE_TO_SUBNET" => Some(Self::AddNodeToSubnet),
            "NNS_FUNCTION_NNS_CANISTER_INSTALL" => Some(Self::NnsCanisterInstall),
            "NNS_FUNCTION_NNS_CANISTER_UPGRADE" => Some(Self::NnsCanisterUpgrade),
            "NNS_FUNCTION_BLESS_REPLICA_VERSION" => Some(Self::BlessReplicaVersion),
            "NNS_FUNCTION_RECOVER_SUBNET" => Some(Self::RecoverSubnet),
            "NNS_FUNCTION_UPDATE_CONFIG_OF_SUBNET" => Some(Self::UpdateConfigOfSubnet),
            "NNS_FUNCTION_ASSIGN_NOID" => Some(Self::AssignNoid),
            "NNS_FUNCTION_NNS_ROOT_UPGRADE" => Some(Self::NnsRootUpgrade),
            "NNS_FUNCTION_ICP_XDR_CONVERSION_RATE" => Some(Self::IcpXdrConversionRate),
            "NNS_FUNCTION_DEPLOY_GUESTOS_TO_ALL_SUBNET_NODES" => {
                Some(Self::DeployGuestosToAllSubnetNodes)
            }
            "NNS_FUNCTION_CLEAR_PROVISIONAL_WHITELIST" => Some(Self::ClearProvisionalWhitelist),
            "NNS_FUNCTION_REMOVE_NODES_FROM_SUBNET" => Some(Self::RemoveNodesFromSubnet),
            "NNS_FUNCTION_SET_AUTHORIZED_SUBNETWORKS" => Some(Self::SetAuthorizedSubnetworks),
            "NNS_FUNCTION_SET_FIREWALL_CONFIG" => Some(Self::SetFirewallConfig),
            "NNS_FUNCTION_UPDATE_NODE_OPERATOR_CONFIG" => Some(Self::UpdateNodeOperatorConfig),
            "NNS_FUNCTION_STOP_OR_START_NNS_CANISTER" => Some(Self::StopOrStartNnsCanister),
            "NNS_FUNCTION_REMOVE_NODES" => Some(Self::RemoveNodes),
            "NNS_FUNCTION_UNINSTALL_CODE" => Some(Self::UninstallCode),
            "NNS_FUNCTION_UPDATE_NODE_REWARDS_TABLE" => Some(Self::UpdateNodeRewardsTable),
            "NNS_FUNCTION_ADD_OR_REMOVE_DATA_CENTERS" => Some(Self::AddOrRemoveDataCenters),
            "NNS_FUNCTION_UPDATE_UNASSIGNED_NODES_CONFIG" => {
                Some(Self::UpdateUnassignedNodesConfig)
            }
            "NNS_FUNCTION_REMOVE_NODE_OPERATORS" => Some(Self::RemoveNodeOperators),
            "NNS_FUNCTION_REROUTE_CANISTER_RANGES" => Some(Self::RerouteCanisterRanges),
            "NNS_FUNCTION_ADD_FIREWALL_RULES" => Some(Self::AddFirewallRules),
            "NNS_FUNCTION_REMOVE_FIREWALL_RULES" => Some(Self::RemoveFirewallRules),
            "NNS_FUNCTION_UPDATE_FIREWALL_RULES" => Some(Self::UpdateFirewallRules),
            "NNS_FUNCTION_PREPARE_CANISTER_MIGRATION" => Some(Self::PrepareCanisterMigration),
            "NNS_FUNCTION_COMPLETE_CANISTER_MIGRATION" => Some(Self::CompleteCanisterMigration),
            "NNS_FUNCTION_ADD_SNS_WASM" => Some(Self::AddSnsWasm),
            "NNS_FUNCTION_CHANGE_SUBNET_MEMBERSHIP" => Some(Self::ChangeSubnetMembership),
            "NNS_FUNCTION_UPDATE_SUBNET_TYPE" => Some(Self::UpdateSubnetType),
            "NNS_FUNCTION_CHANGE_SUBNET_TYPE_ASSIGNMENT" => Some(Self::ChangeSubnetTypeAssignment),
            "NNS_FUNCTION_UPDATE_SNS_WASM_SNS_SUBNET_IDS" => Some(Self::UpdateSnsWasmSnsSubnetIds),
            "NNS_FUNCTION_UPDATE_ALLOWED_PRINCIPALS" => Some(Self::UpdateAllowedPrincipals),
            "NNS_FUNCTION_RETIRE_REPLICA_VERSION" => Some(Self::RetireReplicaVersion),
            "NNS_FUNCTION_INSERT_SNS_WASM_UPGRADE_PATH_ENTRIES" => {
                Some(Self::InsertSnsWasmUpgradePathEntries)
            }
            "NNS_FUNCTION_REVISE_ELECTED_GUESTOS_VERSIONS" => {
                Some(Self::ReviseElectedGuestosVersions)
            }
            "NNS_FUNCTION_BITCOIN_SET_CONFIG" => Some(Self::BitcoinSetConfig),
            "NNS_FUNCTION_UPDATE_ELECTED_HOSTOS_VERSIONS" => {
                Some(Self::UpdateElectedHostosVersions)
            }
            "NNS_FUNCTION_UPDATE_NODES_HOSTOS_VERSION" => Some(Self::UpdateNodesHostosVersion),
            "NNS_FUNCTION_HARD_RESET_NNS_ROOT_TO_VERSION" => Some(Self::HardResetNnsRootToVersion),
            "NNS_FUNCTION_ADD_API_BOUNDARY_NODES" => Some(Self::AddApiBoundaryNodes),
            "NNS_FUNCTION_REMOVE_API_BOUNDARY_NODES" => Some(Self::RemoveApiBoundaryNodes),
            "NNS_FUNCTION_UPDATE_API_BOUNDARY_NODES_VERSION" => {
                Some(Self::UpdateApiBoundaryNodesVersion)
            }
            "NNS_FUNCTION_DEPLOY_GUESTOS_TO_SOME_API_BOUNDARY_NODES" => {
                Some(Self::DeployGuestosToSomeApiBoundaryNodes)
            }
            "NNS_FUNCTION_DEPLOY_GUESTOS_TO_ALL_UNASSIGNED_NODES" => {
                Some(Self::DeployGuestosToAllUnassignedNodes)
            }
            "NNS_FUNCTION_UPDATE_SSH_READONLY_ACCESS_FOR_ALL_UNASSIGNED_NODES" => {
                Some(Self::UpdateSshReadonlyAccessForAllUnassignedNodes)
            }
            "NNS_FUNCTION_REVISE_ELECTED_HOSTOS_VERSIONS" => {
                Some(Self::ReviseElectedHostosVersions)
            }
            "NNS_FUNCTION_DEPLOY_HOSTOS_TO_SOME_NODES" => Some(Self::DeployHostosToSomeNodes),
            "NNS_FUNCTION_SUBNET_RENTAL_REQUEST" => Some(Self::SubnetRentalRequest),
            "NNS_FUNCTION_PAUSE_CANISTER_MIGRATIONS" => Some(Self::PauseCanisterMigrations),
            "NNS_FUNCTION_UNPAUSE_CANISTER_MIGRATIONS" => Some(Self::UnpauseCanisterMigrations),
            "NNS_FUNCTION_SET_SUBNET_OPERATIONAL_LEVEL" => Some(Self::SetSubnetOperationalLevel),
            _ => None,
        }
    }
}
/// The proposal status, with respect to decision making and execution.
/// See also ProposalRewardStatus.
#[derive(
    candid::CandidType,
    candid::Deserialize,
    serde::Serialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    strum_macros::FromRepr,
)]
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
impl ProposalStatus {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            ProposalStatus::Unspecified => "PROPOSAL_STATUS_UNSPECIFIED",
            ProposalStatus::Open => "PROPOSAL_STATUS_OPEN",
            ProposalStatus::Rejected => "PROPOSAL_STATUS_REJECTED",
            ProposalStatus::Adopted => "PROPOSAL_STATUS_ADOPTED",
            ProposalStatus::Executed => "PROPOSAL_STATUS_EXECUTED",
            ProposalStatus::Failed => "PROPOSAL_STATUS_FAILED",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> Option<Self> {
        match value {
            "PROPOSAL_STATUS_UNSPECIFIED" => Some(Self::Unspecified),
            "PROPOSAL_STATUS_OPEN" => Some(Self::Open),
            "PROPOSAL_STATUS_REJECTED" => Some(Self::Rejected),
            "PROPOSAL_STATUS_ADOPTED" => Some(Self::Adopted),
            "PROPOSAL_STATUS_EXECUTED" => Some(Self::Executed),
            "PROPOSAL_STATUS_FAILED" => Some(Self::Failed),
            _ => None,
        }
    }
}
/// The proposal status, with respect to reward distribution.
/// See also ProposalStatus.
#[derive(
    candid::CandidType,
    candid::Deserialize,
    serde::Serialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
)]
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
            ProposalRewardStatus::Ineligible => "PROPOSAL_REWARD_STATUS_INELIGIBLE",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> Option<Self> {
        match value {
            "PROPOSAL_REWARD_STATUS_UNSPECIFIED" => Some(Self::Unspecified),
            "PROPOSAL_REWARD_STATUS_ACCEPT_VOTES" => Some(Self::AcceptVotes),
            "PROPOSAL_REWARD_STATUS_READY_TO_SETTLE" => Some(Self::ReadyToSettle),
            "PROPOSAL_REWARD_STATUS_SETTLED" => Some(Self::Settled),
            "PROPOSAL_REWARD_STATUS_INELIGIBLE" => Some(Self::Ineligible),
            _ => None,
        }
    }
}

/// A closed range of dates (i.e. includes both start and end dates)
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, Debug, Clone, PartialEq)]
pub struct DateRangeFilter {
    /// The start date of the range as seconds since epoch.  When not provided,
    /// no start date is assumed.
    pub start_timestamp_seconds: Option<u64>,
    /// The end date of the range as seconds since epoch.  When not provided, no end date is assumed.
    pub end_timestamp_seconds: Option<u64>,
}

/// A Request to list minted node provider rewards.  Rewards are listed in descending order of date
/// minted, meaning that the latest rewards are always returned first.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, Debug, Clone, PartialEq)]
pub struct ListNodeProviderRewardsRequest {
    /// Filter for the dates of the rewards
    pub date_filter: Option<DateRangeFilter>,
}

/// A Response to list minted node provider rewards.
/// Includes optional paging information to get next set of results.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, Debug, Clone, PartialEq)]
pub struct ListNodeProviderRewardsResponse {
    /// The list of minted node provider rewards
    pub rewards: Vec<MonthlyNodeProviderRewards>,
}

#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Debug, Default, Clone, PartialEq,
)]
pub struct MaturityDisbursement {
    /// The amount of maturity being disbursed in e8s.
    pub amount_e8s: Option<u64>,
    /// The timestamp at which the maturity was disbursed.
    pub timestamp_of_disbursement_seconds: Option<u64>,
    /// The timestamp at which the maturity disbursement should be finalized.
    pub finalize_disbursement_timestamp_seconds: Option<u64>,
    /// The account to disburse the maturity to.
    pub account_to_disburse_to: Option<Account>,
    /// The account identifier to disburse the maturity to.
    pub account_identifier_to_disburse_to: Option<AccountIdentifier>,
}

#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Debug, Default, Clone, PartialEq,
)]
pub struct GetNeuronIndexRequest {
    pub exclusive_start_neuron_id: Option<NeuronId>,
    pub page_size: Option<u32>,
}

#[derive(
    candid::CandidType, candid::Deserialize, serde::Serialize, Debug, Default, Clone, PartialEq,
)]
pub struct NeuronIndexData {
    pub neurons: Vec<NeuronInfo>,
}

#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, Debug, Clone, PartialEq)]
pub struct ListNeuronVotesRequest {
    pub neuron_id: Option<NeuronId>,
    pub before_proposal: Option<ProposalId>,
    pub limit: Option<u64>,
}

pub type ListNeuronVotesResponse = Result<NeuronVotes, GovernanceError>;

#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, Debug, Clone, PartialEq)]
pub struct NeuronVotes {
    pub votes: Option<Vec<NeuronVote>>,
    pub all_finalized_before_proposal: Option<ProposalId>,
}

#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, Debug, Clone, PartialEq)]
pub struct NeuronVote {
    pub proposal_id: Option<ProposalId>,
    pub vote: Option<Vote>,
}

#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, Debug, Clone, PartialEq)]
pub enum SelfDescribingValue {
    Blob(Vec<u8>),
    Text(String),
    Nat(Nat),
    Int(Int),
    Array(Vec<SelfDescribingValue>),
    Map(HashMap<String, SelfDescribingValue>),
}

#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, Debug, Clone, PartialEq)]
pub struct SelfDescribingProposalAction {
    pub type_name: Option<String>,
    pub type_description: Option<String>,
    pub value: Option<SelfDescribingValue>,
}

#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, Debug, Clone, PartialEq)]
pub struct GetPendingProposalsRequest {
    pub return_self_describing_action: Option<bool>,
}
