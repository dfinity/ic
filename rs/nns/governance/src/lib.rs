//! The purpose of the Network Nervous System (NNS) is to allow the
//! Internet Computer (IC) network to be governed in an open,
//! decentralized and secure manner. It has complete control over all
//! aspects of the IC network. For example, it can upgrade the protocol
//! and software used by the node machines that host the network, it
//! can induct new node operators and machines into the network, it
//! can create new subnets (special blockchains) to increase network
//! capacity, it can split subnets to divide their load, it can
//! configure economic parameters that control how much must be paid
//! by users for compute capacity, and in extremis it can freeze
//! malicious canister software (smart contracts) in order to protect
//! the network, and many other things. The NNS works by accepting
//! proposals, and deciding to adopt or reject them based on voting
//! activity by “neurons” that network participants have created.
//!
//! Neurons are also used by participants to submit new
//! proposals. After submission, proposals are either adopted or
//! rejected, which can happen almost immediately, or after some
//! delay, depending upon how the totality of neurons vote. Each
//! proposal is an instance of a specific “proposal type”, which
//! determines what information it contains. For each type of
//! proposal, the NNS maintains a corresponding system function, which
//! it invokes whenever an instance of the type is adopted. When a
//! proposal is adopted by the NNS, it invokes the corresponding
//! system function by drawing information from the proposal’s content
//! to fill the parameters. Each type of proposal belongs to a
//! specific “proposal topic”, such as “#NodeAdmin” or
//! “#NetworkEconomics”, which determines details about how it will be
//! processed. To prevent users spamming the NNS, a fee is levied on
//! the neuron that submitted a proposal if it is rejected.
//!
//! The NNS decides whether to adopt or reject proposals by watching
//! how neurons emit votes. Anyone can create a neuron by locking
//! balances of “ICP governance tokens”, a special native utility
//! token that is hosted on a ledger inside the NNS. When a user
//! creates a neuron, the locked balance of ICP can only be unlocked
//! by fully dissolving (“destroying”) the neuron. Users are
//! incentivized to create neurons because they earn rewards when they
//! vote on proposals. Rewards take the form of newly minted ICP that
//! are created by the NNS. The quantity of ICP rewards disbursed to a
//! neuron derive from such factors as the size of the locked balance,
//! the minimum lockup period remaining (the “dissolve delay”), the
//! neuron’s “age”, the proportion of possible votes it has correctly
//! participated in, and the sum of voting activity across all
//! neurons, since the overall total rewards disbursed is capped and
//! must be divided.
//!
//! Each neuron has a currently configured “dissolve delay”. At any
//! moment, this determines how long it will take to dissolve if it is
//! placed into “dissolve mode”. Once a neuron has been placed into
//! “dissolve mode”, its dissolve delay falls over the passage of
//! time, rather like a kitchen timer, until it reaches zero,
//! whereupon its owner can perform a final action to make it dissolve
//! completely, and unlock the balance of ICP. The dissolve delay
//! creates an economic incentive for neuron owners to vote with a
//! view to maximizing the value of their locked ICP balances at a
//! future date. Since the price of ICP is a proxy for the success of
//! the network over the long term, sans short-term volatility, this
//! creates an economic incentive to vote in the best interests of the
//! network. Neuron owners can freely configure higher dissolve
//! delays, up to a maximum delay of 8 years, but cannot configure
//! lower dissolve delays. The NNS pays higher voting rewards the
//! higher the dissolve delay, encouraging users to enter a game in
//! which an economic incentive is created to vote according to a very
//! long term vision.
//!
//! Neuron owners may find it hard to manually direct voting on every
//! proposal submitted to the NNS. Firstly, large volumes of proposals
//! may be submitted to the NNS, often at awkward times, and owners
//! may not be available or have the time necessary to evaluate each
//! one. Secondly, neuron owners may lack the necessary expertise to
//! evaluate proposals themselves. The NNS uses a form of liquid
//! democracy to address these challenges. For any proposal topic, a
//! neuron can be configured to vote automatically by following the
//! votes of a group of neurons, voting to adopt proposals whenever a
//! majority of the followees vote to adopt, and voting to reject
//! whenever that becomes impossible. A catch-all follow rule may also
//! be defined to make a neuron vote automatically on proposals with
//! topics for which no follow rule has been defined. It is assumed
//! that neuron owners will manage how their neurons follow other
//! neurons in the best interests of the network, which is also in
//! their own economic interests, owing to their locked ICP balances.
//!
//! It is expected that a large proportion of the overall supply of
//! ICP will be locked in order to earn rewards. This secures the
//! Internet Computer network’s governance, by making it both
//! difficult and exorbitantly expensive for an attacker to acquire a
//! sufficiently large stake to gain significant influence. Since
//! neuron owners will wish to maximize their rewards by voting on all
//! proposals, most neurons will either be actively managed, or
//! configured to follow other neurons so they can vote
//! automatically. In practice, once trusted neurons have voted on
//! proposals, a majority of the other neurons will also vote as the
//! result of cascading follow relationships. This means the NNS can
//! usually quickly determine whether a majority of the overall voting
//! power represented by all neurons wishes to adopt or reject a
//! proposal, and decide on the proposal accordingly. However, the NNS
//! cannot rely upon obtaining such a majority, since in principle,
//! neuron owners may not define follow rules, or simply choose not to
//! vote.
//!
//! When the treatment of a newly submitted proposal is not quickly
//! decided by a majority of the overall voting power, the NNS must
//! use a technique once described as “Wait For Quiet”. This involves
//! deriving a measure of “voting noise” from the volume of ongoing
//! voting on a proposal, and waiting for it to fall below some
//! threshold (which value is a tuning parameter that the NNS can
//! modify in production according to experience), and then proceeding
//! to tally the votes received that far to decide. Different
//! algorithms can be applied, but most simply, the NNS can use a
//! running average of the votes received every time interval as the
//! measure of “voting noise”. If the threshold is too low, an
//! attacker can delay the NNS from deciding on proposals by voting
//! just as the “noise level” is about to fall beneath the threshold,
//! and it cannot be made too high, or else an attacker might try to
//! DoS the NNS so that it decides on proposals using only a small
//! proportion of the voting power that wanted to participate (since
//! it equates their not being able to vote, with their not wanting to
//! vote). Using Wait For Quiet, the NNS can decide on proposals
//! without need for a quorum of voting power to participate, and it
//! can also always decide upon proposals in a timely manner.

/// The 'governance' module contains the canister (smart contract)
/// that manages neurons, proposals, voting, voter following, voting
/// rewards, and the code necessary to execute accepted proposals.
///
/// The governance canister interfaces with the 'ledger' canister to
/// deal with the transfer of ICP (Internet Computer Protocol) tokens
/// between ledger accounts, and with the 'registry' canister to
/// distribute configuration information to all nodes of all
/// subnetworks that participate in the Internet Computer (IC).
pub mod governance;
pub mod handler_utils;
pub mod init;
pub mod pb;
pub mod proposal_submission;
mod reward;
pub mod stable_mem_utils;
