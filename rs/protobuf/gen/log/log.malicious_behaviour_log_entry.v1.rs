#[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq, ::prost::Message)]
pub struct MaliciousBehaviourLogEntry {
    #[prost(enumeration = "MaliciousBehaviour", tag = "1")]
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
impl MaliciousBehaviour {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            MaliciousBehaviour::Unspecified => "MALICIOUS_BEHAVIOUR_UNSPECIFIED",
            MaliciousBehaviour::GossipDropRequests => "MALICIOUS_BEHAVIOUR_GOSSIP_DROP_REQUESTS",
            MaliciousBehaviour::GossipArtifactNotFound => {
                "MALICIOUS_BEHAVIOUR_GOSSIP_ARTIFACT_NOT_FOUND"
            }
            MaliciousBehaviour::GossipSendManyArtifacts => {
                "MALICIOUS_BEHAVIOUR_GOSSIP_SEND_MANY_ARTIFACTS"
            }
            MaliciousBehaviour::GossipSendInvalidArtifacts => {
                "MALICIOUS_BEHAVIOUR_GOSSIP_SEND_INVALID_ARTIFACTS"
            }
            MaliciousBehaviour::GossipSendLateArtifacts => {
                "MALICIOUS_BEHAVIOUR_GOSSIP_SEND_LATE_ARTIFACTS"
            }
            MaliciousBehaviour::ProposeEquivocatingBlocks => {
                "MALICIOUS_BEHAVIOUR_PROPOSE_EQUIVOCATING_BLOCKS"
            }
            MaliciousBehaviour::ProposeEmptyBlocks => "MALICIOUS_BEHAVIOUR_PROPOSE_EMPTY_BLOCKS",
            MaliciousBehaviour::FinalizeAll => "MALICIOUS_BEHAVIOUR_FINALIZE_ALL",
            MaliciousBehaviour::NotarizeAll => "MALICIOUS_BEHAVIOUR_NOTARIZE_ALL",
            MaliciousBehaviour::TweakDkg => "MALICIOUS_BEHAVIOUR_TWEAK_DKG",
            MaliciousBehaviour::CertifyInvalidHash => "MALICIOUS_BEHAVIOUR_CERTIFY_INVALID_HASH",
            MaliciousBehaviour::MalfunctioningXnetEndpoint => {
                "MALICIOUS_BEHAVIOUR_MALFUNCTIONING_XNET_ENDPOINT"
            }
            MaliciousBehaviour::DisableExecution => "MALICIOUS_BEHAVIOUR_DISABLE_EXECUTION",
            MaliciousBehaviour::CorruptOwnStateAtHeights => {
                "MALICIOUS_BEHAVIOUR_CORRUPT_OWN_STATE_AT_HEIGHTS"
            }
        }
    }
}
