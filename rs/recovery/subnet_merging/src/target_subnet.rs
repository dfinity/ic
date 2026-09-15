/// The three states a subnet merge works with: the two states that are
/// downloaded and the merged one that is assembled from them.
#[derive(Copy, Clone, PartialEq, Debug)]
pub(crate) enum TargetSubnet {
    /// The subnet that is cooling down, whose canisters are merged away and
    /// which is deleted afterwards.
    Source,
    /// The subnet that hosts the canisters of the source subnet after the merge
    /// and that is recovered at the merged state.
    Destination,
    /// Not a subnet of its own: the state assembled from the states of the two
    /// subnets above, which the destination subnet is recovered at.
    Merged,
}

impl std::fmt::Display for TargetSubnet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            TargetSubnet::Source => "source",
            TargetSubnet::Destination => "destination",
            TargetSubnet::Merged => "merged",
        };
        write!(f, "{name}")
    }
}
