use ic_types::{
    messages::{CallContextId, MessageId, EXPECTED_MESSAGE_ID_LENGTH},
    CanisterId, NodeId, PrincipalId, SubnetId, UserId,
};

pub const NODE_1: NodeId = NodeId::new(PrincipalId::new(
    10,
    [
        1, 0, 0, 0, 0, 0, 0, 0, 0xfd, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ],
));

pub const NODE_2: NodeId = NodeId::new(PrincipalId::new(
    10,
    [
        2, 0, 0, 0, 0, 0, 0, 0, 0xfd, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ],
));

pub const NODE_3: NodeId = NodeId::new(PrincipalId::new(
    10,
    [
        3, 0, 0, 0, 0, 0, 0, 0, 0xfd, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ],
));

pub const NODE_4: NodeId = NodeId::new(PrincipalId::new(
    10,
    [
        4, 0, 0, 0, 0, 0, 0, 0, 0xfd, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ],
));

pub const NODE_5: NodeId = NodeId::new(PrincipalId::new(
    10,
    [
        5, 0, 0, 0, 0, 0, 0, 0, 0xfd, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ],
));

pub const NODE_6: NodeId = NodeId::new(PrincipalId::new(
    10,
    [
        6, 0, 0, 0, 0, 0, 0, 0, 0xfd, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ],
));

pub const NODE_7: NodeId = NodeId::new(PrincipalId::new(
    10,
    [
        7, 0, 0, 0, 0, 0, 0, 0, 0xfd, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ],
));

pub const NODE_42: NodeId = NodeId::new(PrincipalId::new(
    10,
    [
        42, 0, 0, 0, 0, 0, 0, 0, 0xfd, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ],
));

pub const SUBNET_0: SubnetId = SubnetId::new(PrincipalId::new(
    10,
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0xfc, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ],
));

pub const SUBNET_1: SubnetId = SubnetId::new(PrincipalId::new(
    10,
    [
        1, 0, 0, 0, 0, 0, 0, 0, 0xfc, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ],
));

pub const SUBNET_2: SubnetId = SubnetId::new(PrincipalId::new(
    10,
    [
        2, 0, 0, 0, 0, 0, 0, 0, 0xfc, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ],
));

pub const SUBNET_3: SubnetId = SubnetId::new(PrincipalId::new(
    10,
    [
        3, 0, 0, 0, 0, 0, 0, 0, 0xfc, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ],
));

pub const SUBNET_4: SubnetId = SubnetId::new(PrincipalId::new(
    10,
    [
        4, 0, 0, 0, 0, 0, 0, 0, 0xfc, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ],
));

pub const SUBNET_5: SubnetId = SubnetId::new(PrincipalId::new(
    10,
    [
        5, 0, 0, 0, 0, 0, 0, 0, 0xfc, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ],
));

pub const SUBNET_6: SubnetId = SubnetId::new(PrincipalId::new(
    10,
    [
        6, 0, 0, 0, 0, 0, 0, 0, 0xfc, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ],
));

pub const SUBNET_7: SubnetId = SubnetId::new(PrincipalId::new(
    10,
    [
        7, 0, 0, 0, 0, 0, 0, 0, 0xfc, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ],
));

pub const SUBNET_12: SubnetId = SubnetId::new(PrincipalId::new(
    10,
    [
        12, 0, 0, 0, 0, 0, 0, 0, 0xfc, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ],
));

pub const SUBNET_23: SubnetId = SubnetId::new(PrincipalId::new(
    10,
    [
        23, 0, 0, 0, 0, 0, 0, 0, 0xfc, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ],
));

pub const SUBNET_27: SubnetId = SubnetId::new(PrincipalId::new(
    10,
    [
        27, 0, 0, 0, 0, 0, 0, 0, 0xfc, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ],
));

pub const SUBNET_42: SubnetId = SubnetId::new(PrincipalId::new(
    10,
    [
        42, 0, 0, 0, 0, 0, 0, 0, 0xfc, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ],
));

/// Returns a [`CanisterId`] that can be used in tests.
///
/// Cannot be CanisterId::new_test(), because CanisterId is a type alias.
pub fn canister_test_id(i: u64) -> CanisterId {
    CanisterId::from(i)
}

/// Returns a [`NodeId`] that can be used in tests.
pub fn node_test_id(i: u64) -> NodeId {
    NodeId::from(PrincipalId::new_node_test_id(i))
}

/// Converts a [`NodeId`] to a [`u64`].
///
/// This is meant to be used in tests only.
pub fn node_id_to_u64(node_id: NodeId) -> u64 {
    let id_vec = node_id.get().into_vec();
    let mut id_arr: [u8; 8] = [0; 8];
    id_arr.copy_from_slice(&id_vec[..8]);
    u64::from_le_bytes(id_arr)
}

/// Returns a [`SubnetId`] that can be used in tests.
pub fn subnet_test_id(i: u64) -> SubnetId {
    SubnetId::from(PrincipalId::new_subnet_test_id(i))
}

/// Returns a [`UserId`] that can be used in tests.
pub fn user_test_id(i: u64) -> UserId {
    UserId::from(PrincipalId::new_user_test_id(i))
}

/// Returns the user id of the anonymous user.
pub fn user_anonymous_id() -> UserId {
    UserId::from(PrincipalId::new_anonymous())
}

/// Returns a [`CallContextId`] that can be used in tests.
pub fn call_context_test_id(i: u64) -> CallContextId {
    CallContextId::from(i)
}

/// Returns a [`MessageId`] that can be used in tests.
pub fn message_test_id(num: u64) -> MessageId {
    let mut bytes = num.to_le_bytes().to_vec();
    bytes.extend_from_slice(&[0; 24]);
    let mut array = [0; EXPECTED_MESSAGE_ID_LENGTH];
    array.copy_from_slice(&bytes);
    MessageId::from(array)
}
