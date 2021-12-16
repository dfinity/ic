use ic_types::*;
use rand::Rng;
use std::collections::BTreeMap;
use tecdsa::*;

mod test_utils;

use crate::test_utils::ProtocolRound;
use crate::test_utils::*;

fn insufficient_dealings(r: Result<ProtocolRound, ThresholdEcdsaError>) {
    match r {
        Err(ThresholdEcdsaError::InsufficientDealings) => {}
        Err(e) => panic!("Unexpected error {:?}", e),
        Ok(r) => panic!("Unexpected success {:?}", r),
    }
}

#[test]
fn should_reshare_transcripts_correctly() -> Result<(), ThresholdEcdsaError> {
    let setup = ProtocolSetup::new(EccCurveType::K256, 4, 2)?;

    // First create a transcript of random dealings
    let random = ProtocolRound::random(&setup, 4)?;

    // Now reshare the random value twice

    // 1 dealing is not sufficient
    insufficient_dealings(ProtocolRound::reshare_of_masked(&setup, &random, 1));

    // 2, 3, or 4 works:
    let reshared2 = ProtocolRound::reshare_of_masked(&setup, &random, 2)?;
    let reshared3 = ProtocolRound::reshare_of_masked(&setup, &random, 3)?;
    let reshared4 = ProtocolRound::reshare_of_masked(&setup, &random, 4)?;

    // The same value is committed in the resharings despite different dealing cnt
    assert_eq!(reshared2.constant_term(), reshared3.constant_term());
    assert_eq!(reshared2.constant_term(), reshared4.constant_term());

    // Now reshare the now-unmasked value
    insufficient_dealings(ProtocolRound::reshare_of_unmasked(&setup, &reshared2, 1));
    let unmasked = ProtocolRound::reshare_of_unmasked(&setup, &reshared2, 2)?;
    assert_eq!(reshared2.constant_term(), unmasked.constant_term());

    // Now multiply the masked and umasked values
    // We need 3 dealings to multiply
    insufficient_dealings(ProtocolRound::multiply(&setup, &random, &unmasked, 1));
    insufficient_dealings(ProtocolRound::multiply(&setup, &random, &unmasked, 2));
    let _product = ProtocolRound::multiply(&setup, &random, &unmasked, 3)?;

    Ok(())
}

#[test]
fn should_multiply_transcripts_correctly() -> Result<(), ThresholdEcdsaError> {
    let setup = ProtocolSetup::new(EccCurveType::K256, 4, 2)?;

    let dealers = 4;

    // First create two random transcripts
    let random_a = ProtocolRound::random(&setup, dealers)?;
    let random_b = ProtocolRound::random(&setup, dealers)?;

    // Now reshare them both
    let random_c = ProtocolRound::reshare_of_masked(&setup, &random_a, dealers)?;
    let random_d = ProtocolRound::reshare_of_masked(&setup, &random_b, dealers)?;

    // Now multiply A*D and B*C (which will be the same numbers)
    let product_ad = ProtocolRound::multiply(&setup, &random_a, &random_d, dealers)?;
    let product_bc = ProtocolRound::multiply(&setup, &random_b, &random_c, dealers)?;

    // Now reshare AD and BC
    let reshare_ad = ProtocolRound::reshare_of_masked(&setup, &product_ad, dealers)?;
    let reshare_bc = ProtocolRound::reshare_of_masked(&setup, &product_bc, dealers)?;

    // The committed values of AD and BC should be the same:
    assert_eq!(reshare_ad.constant_term(), reshare_bc.constant_term());

    Ok(())
}

#[test]
fn should_reshare_transcripts_with_dynamic_threshold() -> Result<(), ThresholdEcdsaError> {
    let mut setup = ProtocolSetup::new(EccCurveType::K256, 5, 2)?;

    let random_a = ProtocolRound::random(&setup, 5)?;

    insufficient_dealings(ProtocolRound::reshare_of_masked(&setup, &random_a, 1));
    let reshared_b = ProtocolRound::reshare_of_masked(&setup, &random_a, 2)?;

    setup.modify_threshold(1);
    setup.remove_nodes(2);
    insufficient_dealings(ProtocolRound::reshare_of_unmasked(&setup, &reshared_b, 1));

    let reshared_c = ProtocolRound::reshare_of_unmasked(&setup, &reshared_b, 2)?;
    let reshared_d = ProtocolRound::reshare_of_unmasked(&setup, &reshared_b, 3)?;

    // b, c, and d all have the same value
    assert_eq!(reshared_b.constant_term(), reshared_c.constant_term());
    assert_eq!(reshared_b.constant_term(), reshared_d.constant_term());

    Ok(())
}

#[test]
fn should_multiply_transcripts_with_dynamic_threshold() -> Result<(), ThresholdEcdsaError> {
    let mut setup = ProtocolSetup::new(EccCurveType::K256, 5, 2)?;

    let random_a = ProtocolRound::random(&setup, 5)?;
    let random_b = ProtocolRound::random(&setup, 5)?;

    let reshared_c = ProtocolRound::reshare_of_masked(&setup, &random_a, 3)?;

    setup.modify_threshold(1);
    setup.remove_nodes(2);
    insufficient_dealings(ProtocolRound::multiply(&setup, &random_b, &reshared_c, 1));
    insufficient_dealings(ProtocolRound::multiply(&setup, &random_b, &reshared_c, 2));

    let _product = ProtocolRound::multiply(&setup, &random_b, &reshared_c, 3)?;

    Ok(())
}
fn random_subset(
    shares: &BTreeMap<NodeIndex, ThresholdEcdsaSigShareInternal>,
    include: usize,
) -> BTreeMap<NodeIndex, ThresholdEcdsaSigShareInternal> {
    assert!(include <= shares.len());

    let mut rng = rand::thread_rng();
    let mut result = BTreeMap::new();

    let keys = shares.keys().collect::<Vec<_>>();

    while result.len() != include {
        let key_to_add = keys[rng.gen::<usize>() % keys.len()];

        if !result.contains_key(key_to_add) {
            result.insert(*key_to_add, shares[key_to_add].clone());
        }
    }

    result
}

#[test]
fn should_basic_signing_protocol_work() -> Result<(), ThresholdEcdsaError> {
    let nodes = 5;
    let threshold = 2;
    let setup = SignatureProtocolSetup::new(EccCurveType::K256, nodes, threshold)?;

    let mut rng = rand::thread_rng();
    let signed_message = rng.gen::<[u8; 32]>().to_vec();
    let random_beacon = Randomness::from(rng.gen::<[u8; 32]>());

    let derivation_path = DerivationPath::new_bip32(&[1, 2, 3]);
    let proto = SignatureProtocolExecution::new(
        setup.clone(),
        signed_message.clone(),
        random_beacon,
        derivation_path.clone(),
    );

    let shares = proto.generate_shares()?;

    for i in 0..=nodes {
        let shares = random_subset(&shares, i);

        if shares.len() < threshold {
            assert!(proto.generate_signature(&shares).is_err());
        } else {
            let sig = proto.generate_signature(&shares).unwrap();
            assert!(proto.verify_signature(&sig).is_ok());
        }
    }

    // Test that another run of the protocol generates signatures
    // which are not verifiable in the earlier one (due to different rho)
    let random_beacon2 = Randomness::from(rng.gen::<[u8; 32]>());
    let proto2 =
        SignatureProtocolExecution::new(setup, signed_message, random_beacon2, derivation_path);

    let shares = proto2.generate_shares()?;
    let sig = proto2.generate_signature(&shares).unwrap();

    assert!(proto.verify_signature(&sig).is_err());
    assert!(proto2.verify_signature(&sig).is_ok());

    Ok(())
}
