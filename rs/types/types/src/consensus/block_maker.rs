use ic_protobuf::registry::subnet::v1::SubnetRecord;

/// A collection of subnet records, that are relevant for constructing a block
pub struct SubnetRecords {
    /// The membership [`SubnetRecord`], that is available to this node
    pub membership_version: SubnetRecord,

    /// The stable [`SubnetRecord`], that might be older than latest
    /// but is very likely available to all nodes on the subnet.
    ///
    /// This is the [`SubnetRecord`] that corresponds to the
    /// [`ic_types::batch::ValidationContext`].
    pub context_version: SubnetRecord,
}
