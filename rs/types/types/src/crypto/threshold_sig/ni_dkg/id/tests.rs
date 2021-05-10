use super::*;

#[test]
fn should_convert_ni_dkg_id_to_proto() {
    let principal_id = PrincipalId::new_subnet_test_id(42);
    let target_id = [42; NiDkgTargetId::SIZE];
    let height = 7;
    let id = NiDkgId {
        start_block_height: Height::new(7),
        dealer_subnet: SubnetId::from(principal_id),
        dkg_tag: NiDkgTag::HighThreshold,
        target_subnet: NiDkgTargetSubnet::Remote(NiDkgTargetId::new(target_id)),
    };

    let proto = NiDkgIdProto::from(id);

    assert_eq!(
        proto,
        NiDkgIdProto {
            start_block_height: height,
            dealer_subnet: principal_id.into_vec(),
            remote_target_id: Some(target_id.to_vec()),
            dkg_tag: 2,
        }
    )
}

#[test]
fn should_parse_valid_proto_as_ni_dkg_id() {
    let principal_id_blob = vec![42; PrincipalId::MAX_LENGTH_IN_BYTES];
    let target_id = [42; NiDkgTargetId::SIZE];
    let height = 7;

    for val in vec![None, Some(target_id.to_vec())].iter() {
        let proto = NiDkgIdProto {
            start_block_height: height,
            dealer_subnet: principal_id_blob.clone(),
            remote_target_id: val.clone(),
            dkg_tag: 2,
        };

        let id = NiDkgId::try_from(proto).unwrap();

        assert_eq!(
            id,
            NiDkgId {
                start_block_height: Height::new(height),
                dealer_subnet: SubnetId::from(
                    PrincipalId::try_from(principal_id_blob.as_slice()).unwrap()
                ),
                dkg_tag: NiDkgTag::HighThreshold,
                target_subnet: match val {
                    None => NiDkgTargetSubnet::Local,
                    Some(_) => NiDkgTargetSubnet::Remote(NiDkgTargetId::new(target_id)),
                },
            }
        );
    }
}

#[test]
fn should_return_error_if_remote_target_id_invalid_when_parsing_proto() {
    let target_id_size = NiDkgTargetId::SIZE - 2;
    let proto = NiDkgIdProto {
        start_block_height: 7,
        dealer_subnet: vec![42; PrincipalId::MAX_LENGTH_IN_BYTES],
        remote_target_id: Some(vec![42; target_id_size]),
        dkg_tag: 1,
    };

    let result = NiDkgId::try_from(proto);

    assert_matches::assert_matches!(
        result.unwrap_err(),
        NiDkgIdFromProtoError::InvalidRemoteTargetIdSize(_)
    );
}

#[test]
fn should_return_error_if_ni_dkg_tag_invalid_when_parsing_proto() {
    let invalid_dkg_tag = 3;
    let proto = NiDkgIdProto {
        start_block_height: 7,
        dealer_subnet: vec![42; PrincipalId::MAX_LENGTH_IN_BYTES],
        remote_target_id: Some(vec![42; NiDkgTargetId::SIZE]),
        dkg_tag: invalid_dkg_tag,
    };

    let result = NiDkgId::try_from(proto);

    assert_eq!(result.unwrap_err(), NiDkgIdFromProtoError::InvalidDkgTag);
}

#[test]
fn should_return_error_if_dealer_subnet_id_invalid_when_parsing_proto() {
    let invalid_principal_length = PrincipalId::MAX_LENGTH_IN_BYTES + 1;
    let proto = NiDkgIdProto {
        start_block_height: 7,
        dealer_subnet: vec![42; invalid_principal_length],
        remote_target_id: Some(vec![42; NiDkgTargetId::SIZE]),
        dkg_tag: 2,
    };

    let result = NiDkgId::try_from(proto);

    assert_eq!(
        result.unwrap_err(),
        NiDkgIdFromProtoError::InvalidPrincipalId(PrincipalIdBlobParseError::TooLong(
            invalid_principal_length
        ))
    );
}
