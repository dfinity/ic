#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MaliciousBehaviourLogEntry {
    #[prost(enumeration="MaliciousBehaviour", tag="1")]
    pub malicious_behaviour: i32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum MaliciousBehaviour {
    Unspecified = 0,
    GossipDropRequests = 1,
    GossipArtifactNotFound = 2,
    GossipSendManyArtifacts = 3,
    GossipSendInvalidArtifacts = 4,
    GossipSendLateArtifacts = 5,
    ProposeEquivocatingBlocks = 6,
    ProposeEmptyBlocks = 7,
    FinalizeAll = 8,
    NotarizeAll = 9,
    TweakDkg = 10,
    CertifyInvalidHash = 11,
    MalfunctioningXnetEndpoint = 12,
    DisableExecution = 13,
    CorruptOwnStateAtHeights = 14,
}
