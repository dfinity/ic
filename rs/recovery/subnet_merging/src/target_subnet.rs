/// The two subnets a subnet merge works with.
#[derive(Copy, Clone, PartialEq, Debug)]
pub(crate) enum TargetSubnet {
    /// The subnet that is cooling down, whose canisters are merged away and
    /// which is deleted afterwards.
    Source,
    /// The subnet that hosts the canisters of the source subnet after the merge
    /// and that is recovered at the merged state.
    Destination,
}
