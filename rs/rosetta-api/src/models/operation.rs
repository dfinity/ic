use strum_macros::Display;
use strum_macros::EnumIter;
use strum_macros::{EnumString, EnumVariantNames};

#[derive(Display, Debug, Clone, PartialEq, Eq, EnumIter, EnumString, EnumVariantNames)]
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
    MergeMaturity,
    RegisterVote,
    StakeMaturity,
    NeuronInfo,
    Follow,
}
