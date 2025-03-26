use super::*;
use assert_matches::assert_matches;

#[test]
fn should_fail_convert_pubkey_nodeid_bad_bytes() {
    let bad_bytes = vec![3, 1, 4];
    let bad_proto_key = PublicKeyProto {
        version: 1,
        algorithm: 0,
        key_value: bad_bytes,
        proof_data: None,
        timestamp: None,
    };

    let result = derive_node_id(&bad_proto_key);

    assert_matches!(
        result.expect_err("Unexpected success."),
        InvalidNodePublicKey::MalformedRawBytes { internal_error: _ }
    );
}

#[test]
fn should_convert_pubkey_nodeid_known_result() {
    use std::str::FromStr;

    let key_value = hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        .expect("Invalid hex");

    let proto_key = PublicKeyProto {
        version: 1,
        algorithm: 0,
        key_value,
        proof_data: None,
        timestamp: None,
    };

    let nodeid = derive_node_id(&proto_key).expect("derive_node_id failed");

    let expected_nodeid = NodeId::from(
        PrincipalId::from_str("e73il-iz5tp-nkgt7-idxyw-ngkah-47bpv-qdase-pzde6-g6vwc-a3eql-jae")
            .expect("we know this converts OK"),
    );

    assert_eq!(nodeid, expected_nodeid);
}

// TODO(CRP-695): add more tests
