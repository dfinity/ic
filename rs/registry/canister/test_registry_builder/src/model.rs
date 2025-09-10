use ic_protobuf::registry::crypto::v1::PublicKey;
use ic_types::{NodeId, PrincipalId, SubnetId};

#[derive(Debug, Clone)]
pub struct TestNode {
    pub id: NodeId,
    pub operator: PrincipalId,
    pub subnet: Option<SubnetId>,
    pub public_key: PublicKey,
}

#[derive(Debug, Clone)]
pub struct TestNodeOperator {
    pub id: PrincipalId,
    pub provider: PrincipalId,
    pub dc_id: String,
}

impl TestNodeOperator {
    pub fn new(id: PrincipalId, provider: PrincipalId, dc_id: String) -> Self {
        Self {
            id,
            provider,
            dc_id,
        }
    }
}
