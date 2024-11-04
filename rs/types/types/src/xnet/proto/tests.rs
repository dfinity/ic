use crate::{
    consensus::certification::{Certification, CertificationContent},
    crypto::{
        threshold_sig::ni_dkg::{NiDkgId, NiDkgTag, NiDkgTargetSubnet},
        CombinedThresholdSig, CombinedThresholdSigOf, CryptoHash, Signed,
    },
    signature::ThresholdSignature,
    xnet::CertifiedStreamSlice,
    CryptoHashOfPartialState, Height, PrincipalId, PrincipalIdBlobParseError, SubnetId,
};
use assert_matches::assert_matches;
use ic_protobuf::messaging::xnet::v1;
use ic_protobuf::proxy::{ProtoProxy, ProxyDecodeError};
use ic_protobuf::types::v1 as pb_types;

const SUBNET_1: SubnetId = SubnetId::new(PrincipalId::new(
    10,
    [
        1, 0, 0, 0, 0, 0, 0, 0, 0xfc, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ],
));

#[test]
fn idkg_id_roundtrip() {
    let idkg_id = dkg_id_for_test();
    assert_eq!(
        idkg_id.clone(),
        pb_types::NiDkgId::proxy_decode(&pb_types::NiDkgId::proxy_encode(idkg_id)).unwrap()
    );
}

#[test]
fn threshold_signature_roundtrip() {
    let sig = threshold_signature_for_test();
    assert_eq!(
        sig.clone(),
        pb_types::ThresholdSignature::proxy_decode(&pb_types::ThresholdSignature::proxy_encode(
            sig
        ))
        .unwrap()
    );
}

#[test]
fn certification_content_roundtrip() {
    let content = certification_content_for_test();
    assert_eq!(
        content.clone(),
        v1::CertificationContent::proxy_decode(&v1::CertificationContent::proxy_encode(content))
            .unwrap()
    );
}

#[test]
fn certification_roundtrip() {
    let certification = certification_for_test();
    assert_eq!(
        certification.clone(),
        v1::Certification::proxy_decode(&v1::Certification::proxy_encode(certification)).unwrap()
    );
}

#[test]
fn certified_stream_slice_roundtrip() {
    let certified_stream_slice = certified_stream_slice_for_test();
    assert_eq!(
        certified_stream_slice.clone(),
        v1::CertifiedStreamSlice::proxy_decode(&v1::CertifiedStreamSlice::proxy_encode(
            certified_stream_slice
        ))
        .unwrap()
    );
}

#[test]
fn error_decode_error() {
    match <pb_types::NiDkgId as ProtoProxy<NiDkgId>>::proxy_decode(&b"garbage"[..]) {
        Err(ProxyDecodeError::DecodeError(_)) => {}
        other => panic!("Expected Err(DecodeError(_)), got {:?}", other),
    }
}

#[test]
fn error_invalid_principal_id() {
    let idkg_id = dkg_id_for_test();
    let mut idkg_id_proto: pb_types::NiDkgId = idkg_id.into();
    // A PrincipalId that's much too long.
    idkg_id_proto.dealer_subnet = vec![13; 169];
    let idkg_id_vec = pb_types::NiDkgId::proxy_encode(idkg_id_proto);

    assert_matches!(
        <pb_types::NiDkgId as ProtoProxy<NiDkgId>>::proxy_decode(&idkg_id_vec),
        Err(ProxyDecodeError::InvalidPrincipalId(err))
            if err.downcast_ref() == Some(&PrincipalIdBlobParseError::TooLong(169)));
}

#[test]
fn error_missing_field() {
    let sig = threshold_signature_for_test();
    let mut sig_proto: pb_types::ThresholdSignature = sig.into();
    // Clear the signer field.
    sig_proto.signer = None;
    let sig_vec = pb_types::ThresholdSignature::proxy_encode(sig_proto);

    assert_matches!(
        <pb_types::ThresholdSignature as ProtoProxy<ThresholdSignature<CertificationContent>>>::proxy_decode(&sig_vec),
        Err(ProxyDecodeError::MissingField("ThresholdSignature::signer"))
    );
}

fn certified_stream_slice_for_test() -> CertifiedStreamSlice {
    CertifiedStreamSlice {
        certification: certification_for_test(),
        merkle_proof: vec![7, 8, 9],
        payload: vec![4, 6, 8],
    }
}

fn certification_for_test() -> Certification {
    Certification {
        height: Height::new(14),
        signed: Signed {
            content: certification_content_for_test(),
            signature: threshold_signature_for_test(),
        },
    }
}

fn certification_content_for_test() -> CertificationContent {
    CertificationContent::new(CryptoHashOfPartialState::new(CryptoHash(vec![1, 2, 3])))
}

fn threshold_signature_for_test() -> ThresholdSignature<CertificationContent> {
    ThresholdSignature {
        signature: CombinedThresholdSigOf::new(CombinedThresholdSig(vec![4, 5, 6])),
        signer: dkg_id_for_test(),
    }
}

fn dkg_id_for_test() -> NiDkgId {
    NiDkgId {
        start_block_height: Height::from(1),
        dealer_subnet: SUBNET_1,
        dkg_tag: NiDkgTag::HighThreshold,
        target_subnet: NiDkgTargetSubnet::Local,
    }
}
