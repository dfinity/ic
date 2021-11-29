use canister_test::Runtime;
use ic_types::{NodeId, PrincipalId, SubnetId};

/// Shim for `IcHandle` implementations.
pub trait Ic {
    /// Iterator over subnet ids.
    fn subnet_ids(&self) -> Vec<SubnetId>;

    /// Retrieves a handle to the subnet with the given ID.
    fn subnet(&self, id: SubnetId) -> Box<dyn Subnet>;

    /// Returns the subnet hosting the given `PrincipalId`, if any.
    fn route(&self, principal_id: PrincipalId) -> Option<SubnetId>;

    /// Returns the principal ID that is used to interact with this Ic instance,
    /// or `None` if there is no explicit identity
    fn get_principal(&self) -> Option<PrincipalId>;
}

/// Shim for `SubnetHandle` implementations.
pub trait Subnet {
    /// Retrieves a handle to the node with the given index on this subnet.
    fn node_by_idx(&self, idx: usize) -> Box<dyn Node>;

    /// Retrieves a handle to the node with the given ID on this subnet.
    fn node(&self, id: NodeId) -> Box<dyn Node>;
}

/// Shim for `NodeHandle` implementations.
pub trait Node {
    /// An agent that targets this node.
    fn api(&self) -> Runtime;
}
