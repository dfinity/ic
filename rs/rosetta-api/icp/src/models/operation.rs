use strum_macros::Display;
use strum_macros::EnumIter;
use strum_macros::{EnumString, VariantNames};

#[derive(Clone, Eq, PartialEq, Debug, Display, EnumIter, EnumString, VariantNames)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum OperationType {
    Transaction,
    Mint,
    Burn,
    Approve,
    Fee,
    Stake,
    StartDissolving,
    StopDissolving,
    SetDissolveTimestamp,
    ChangeAutoStakeMaturity,
    Disburse,
    AddHotkey,
    RemoveHotkey,
    Spawn,
    RegisterVote,
    StakeMaturity,
    NeuronInfo,
    ListNeurons,
    Follow,
    RefreshVotingPower,
    DisburseMaturity,
}
