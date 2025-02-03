use ic_base_types::{NodeId, PrincipalId};

pub enum NnsHealthStatus {
    Healthy,
    Unhealthy,
}

pub enum Ballot {
    Yes,
    No,
    Undecided,
}

pub struct NodeOperatorBallot {
    pub principal: PrincipalId,
    pub node_tied_to_ballot: NodeId,
    pub ballot: Ballot,
    pub signature: Vec<u8>,
}

pub struct RecoveryProposalDetails {
    /// Should be equal to recovery proposal
    pub payload: String,

    /// The principal id of the proposer (must be one of the node
    /// operators of the NNS subnet according to the registry at
    /// time of submission).
    pub proposer: PrincipalId,

    /// The timestamp, in seconds, at which the proposal was submitted.
    pub submission_timestamp_seconds: u64,

    /// List containing the
    pub node_operator_ballots: Vec<NodeOperatorBallot>,
}

pub struct UpdateNnsHealthStatus {
    pub status: NnsHealthStatus,
    pub recovery_proposal: Option<RecoveryProposalDetails>,
}
