use assert_matches::assert_matches;
use ic_management_canister_types_private::{EcdsaCurve, EcdsaKeyId, VetKdCurve};

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
            key_id: None,
        }
    )
}

#[test]
fn should_convert_ni_dkg_id_with_key_id_to_proto() {
    let principal_id = PrincipalId::new_subnet_test_id(42);
    let target_id = [42; NiDkgTargetId::SIZE];
    let height = 7;
    let master_public_key_id = NiDkgMasterPublicKeyId::VetKd(VetKdKeyId {
        curve: VetKdCurve::Bls12_381_G2,
        name: "key".to_string(),
    });
    let id = NiDkgId {
        start_block_height: Height::new(7),
        dealer_subnet: SubnetId::from(principal_id),
        dkg_tag: NiDkgTag::HighThresholdForKey(master_public_key_id.clone()),
        target_subnet: NiDkgTargetSubnet::Remote(NiDkgTargetId::new(target_id)),
    };

    let proto = NiDkgIdProto::from(id);

    assert_eq!(
        proto,
        NiDkgIdProto {
            start_block_height: height,
            dealer_subnet: principal_id.into_vec(),
            remote_target_id: Some(target_id.to_vec()),
            dkg_tag: pb::NiDkgTag::HighThresholdForKey as i32,
            key_id: Some(pb::MasterPublicKeyId::from(&master_public_key_id)),
        }
    )
}

#[test]
fn should_parse_valid_proto_as_ni_dkg_id() {
    let principal_id_blob = vec![42; PrincipalId::MAX_LENGTH_IN_BYTES];
    let target_id = [42; NiDkgTargetId::SIZE];
    let height = 7;

    for val in [None, Some(target_id.to_vec())].iter() {
        let proto = NiDkgIdProto {
            start_block_height: height,
            dealer_subnet: principal_id_blob.clone(),
            remote_target_id: val.clone(),
            dkg_tag: 2,
            key_id: None,
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
fn should_parse_valid_proto_as_ni_dkg_id_with_key_id() {
    let principal_id_blob = vec![42; PrincipalId::MAX_LENGTH_IN_BYTES];
    let target_id = [42; NiDkgTargetId::SIZE];
    let height = 7;
    let ni_dkg_master_public_key_id = NiDkgMasterPublicKeyId::VetKd(VetKdKeyId {
        curve: VetKdCurve::Bls12_381_G2,
        name: "key".to_string(),
    });

    for val in [None, Some(target_id.to_vec())].iter() {
        let proto = NiDkgIdProto {
            start_block_height: height,
            dealer_subnet: principal_id_blob.clone(),
            remote_target_id: val.clone(),
            dkg_tag: pb::NiDkgTag::HighThresholdForKey as i32,
            key_id: Some(pb::MasterPublicKeyId::from(&ni_dkg_master_public_key_id)),
        };

        let id = NiDkgId::try_from(proto).unwrap();

        assert_eq!(
            id,
            NiDkgId {
                start_block_height: Height::new(height),
                dealer_subnet: SubnetId::from(
                    PrincipalId::try_from(principal_id_blob.as_slice()).unwrap()
                ),
                dkg_tag: NiDkgTag::HighThresholdForKey(ni_dkg_master_public_key_id.clone()),
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
        key_id: None,
    };

    let result = NiDkgId::try_from(proto);

    assert_matches::assert_matches!(
        result.unwrap_err(),
        NiDkgIdFromProtoError::InvalidRemoteTargetIdSize(_)
    );
}

#[test]
fn should_return_error_if_ni_dkg_tag_invalid_with_missing_keyid_when_parsing_proto() {
    let dkg_tag_requiring_some_key_id = 3;
    let proto = NiDkgIdProto {
        start_block_height: 7,
        dealer_subnet: vec![42; PrincipalId::MAX_LENGTH_IN_BYTES],
        remote_target_id: Some(vec![42; NiDkgTargetId::SIZE]),
        dkg_tag: dkg_tag_requiring_some_key_id,
        key_id: None,
    };

    let result = NiDkgId::try_from(proto);

    assert_eq!(
        result.unwrap_err(),
        NiDkgIdFromProtoError::InvalidDkgTagMissingKeyId
    );
}

#[test]
fn should_return_error_if_ni_dkg_tag_invalid_with_invalid_vetkd_master_public_key_when_parsing_proto()
 {
    let proto = NiDkgIdProto {
        start_block_height: 7,
        dealer_subnet: vec![42; PrincipalId::MAX_LENGTH_IN_BYTES],
        remote_target_id: Some(vec![42; NiDkgTargetId::SIZE]),
        dkg_tag: pb::NiDkgTag::HighThresholdForKey as i32,
        key_id: Some(pb::MasterPublicKeyId {
            key_id: Some(pb::master_public_key_id::KeyId::Vetkd(pb::VetKdKeyId {
                curve: 99,
                name: "invalid_curve".to_string(),
            })),
        }),
    };

    let result = NiDkgId::try_from(proto);

    assert_matches!(
        result.unwrap_err(),
        NiDkgIdFromProtoError::InvalidMasterPublicKeyId(_)
    );
}

#[test]
fn should_return_error_if_ni_dkg_tag_invalid_with_non_vetkd_master_public_key_when_parsing_proto() {
    let proto = NiDkgIdProto {
        start_block_height: 7,
        dealer_subnet: vec![42; PrincipalId::MAX_LENGTH_IN_BYTES],
        remote_target_id: Some(vec![42; NiDkgTargetId::SIZE]),
        dkg_tag: pb::NiDkgTag::HighThresholdForKey as i32,
        key_id: Some(pb::MasterPublicKeyId {
            key_id: Some(pb::master_public_key_id::KeyId::Ecdsa(pb::EcdsaKeyId {
                curve: 1,
                name: "name".to_string(),
            })),
        }),
    };

    let result = NiDkgId::try_from(proto);

    assert_matches!(
        result.unwrap_err(),
        NiDkgIdFromProtoError::InvalidMasterPublicKeyId(_)
    );
}

#[test]
fn should_return_error_if_ni_dkg_tag_invalid_with_nonempty_keyid_for_low_thres_tag_when_parsing_proto()
 {
    let master_public_key_id = MasterPublicKeyId::Ecdsa(EcdsaKeyId {
        curve: EcdsaCurve::Secp256k1,
        name: "key".to_string(),
    });
    let proto = NiDkgIdProto {
        start_block_height: 7,
        dealer_subnet: vec![42; PrincipalId::MAX_LENGTH_IN_BYTES],
        remote_target_id: Some(vec![42; NiDkgTargetId::SIZE]),
        dkg_tag: pb::NiDkgTag::LowThreshold as i32,
        key_id: Some(pb::MasterPublicKeyId::from(&master_public_key_id)),
    };

    let result = NiDkgId::try_from(proto);

    assert_matches!(
        result.unwrap_err(),
        NiDkgIdFromProtoError::InvalidDkgTagNonEmptyMasterPublicKeyId
    );
}

#[test]
fn should_return_error_if_ni_dkg_tag_invalid_with_nonempty_keyid_for_high_thres_tag_when_parsing_proto()
 {
    let master_public_key_id = MasterPublicKeyId::Ecdsa(EcdsaKeyId {
        curve: EcdsaCurve::Secp256k1,
        name: "key".to_string(),
    });
    let proto = NiDkgIdProto {
        start_block_height: 7,
        dealer_subnet: vec![42; PrincipalId::MAX_LENGTH_IN_BYTES],
        remote_target_id: Some(vec![42; NiDkgTargetId::SIZE]),
        dkg_tag: pb::NiDkgTag::HighThreshold as i32,
        key_id: Some(pb::MasterPublicKeyId::from(&master_public_key_id)),
    };

    let result = NiDkgId::try_from(proto);

    assert_matches!(
        result.unwrap_err(),
        NiDkgIdFromProtoError::InvalidDkgTagNonEmptyMasterPublicKeyId
    );
}

#[test]
fn should_return_error_if_ni_dkg_tag_invalid_when_parsing_proto() {
    let invalid_dkg_tag = 4;
    let proto = NiDkgIdProto {
        start_block_height: 7,
        dealer_subnet: vec![42; PrincipalId::MAX_LENGTH_IN_BYTES],
        remote_target_id: Some(vec![42; NiDkgTargetId::SIZE]),
        dkg_tag: invalid_dkg_tag,
        key_id: None,
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
        key_id: None,
    };

    let result = NiDkgId::try_from(proto);

    assert_eq!(
        result.unwrap_err(),
        NiDkgIdFromProtoError::InvalidPrincipalId(PrincipalIdBlobParseError::TooLong(
            invalid_principal_length
        ))
    );
}
