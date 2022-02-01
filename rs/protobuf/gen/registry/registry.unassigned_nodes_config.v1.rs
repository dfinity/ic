/// Config applied to the set of all unassigned nodes.
#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UnassignedNodesConfigRecord {
    /// The list of public keys whose owners have "readonly" SSH access to all unassigned replicas,
    /// in case it is necessary to perform disaster recovery.
    #[prost(string, repeated, tag="1")]
    pub ssh_readonly_access: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    /// The list of public keys whose owners have "backup" SSH access to unassigned nodes
    /// to make sure they can be backed up.
    #[prost(string, tag="2")]
    pub replica_version: ::prost::alloc::string::String,
}
