use assert_matches::assert_matches;
use ic_canister_sig_creation::CanisterSigPublicKey;
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381;
use ic_crypto_test_utils_canister_sigs::new_valid_sig_and_crypto_component;
use ic_crypto_test_utils_reproducible_rng::ReproducibleRng;
use ic_principal::Principal;
use ic_types::crypto::Signable;
use ic_types::crypto::threshold_sig::{IcRootOfTrust, ThresholdSigPublicKey};

fn get_root_pk_raw(root_of_trust: &IcRootOfTrust) -> Vec<u8> {
    let pk_raw: bls12_381::PublicKeyBytes =
        (*<IcRootOfTrust as AsRef<ThresholdSigPublicKey>>::as_ref(root_of_trust)).into();
    pk_raw.as_bytes().to_vec()
}

fn get_canister_sig_pk_der(pk_raw: &[u8]) -> Vec<u8> {
    CanisterSigPublicKey::try_from_raw(pk_raw)
        .expect("wrong raw canister sig pk")
        .to_der()
}

#[test]
fn should_verify_canister_sig() {
    let rng = &mut ReproducibleRng::new();
    for with_delegation in [false, true] {
        let sig_data = new_valid_sig_and_crypto_component(rng, with_delegation);
        let result = ic_signature_verification::verify_canister_sig(
            &sig_data.msg.as_signed_bytes(),
            &sig_data.canister_sig.get_ref().0,
            &get_canister_sig_pk_der(&sig_data.canister_pk.key),
            &get_root_pk_raw(&sig_data.root_of_trust),
        );
        assert_eq!(result, Ok(()));
    }
}

#[test]
fn should_fail_verify_canister_sig_on_wrong_msg() {
    let rng = &mut ReproducibleRng::new();
    for with_delegation in [false, true] {
        let sig_data = new_valid_sig_and_crypto_component(rng, with_delegation);
        let wrong_msg = [1u8, 2, 3, 4];

        let result = ic_signature_verification::verify_canister_sig(
            &wrong_msg,
            &sig_data.canister_sig.get_ref().0,
            &get_canister_sig_pk_der(&sig_data.canister_pk.key),
            &get_root_pk_raw(&sig_data.root_of_trust),
        );
        assert_matches!(result, Err(e) if e.contains("signature entry not found"));
    }
}

#[test]
fn should_fail_verify_canister_sig_on_invalid_sig() {
    let rng = &mut ReproducibleRng::new();
    for with_delegation in [false, true] {
        let sig_data = new_valid_sig_and_crypto_component(rng, with_delegation);
        let invalid_sig = {
            let mut sig_with_bit_flipped = sig_data.canister_sig.get_ref().0.clone();
            let len = sig_with_bit_flipped.len();
            sig_with_bit_flipped.as_mut_slice()[len - 5] ^= 0x01; // to be valid CBOR
            sig_with_bit_flipped
        };

        let result = ic_signature_verification::verify_canister_sig(
            &sig_data.msg.as_signed_bytes(),
            &invalid_sig,
            &get_canister_sig_pk_der(&sig_data.canister_pk.key),
            &get_root_pk_raw(&sig_data.root_of_trust),
        );
        assert_matches!(result, Err(e) if e.contains("doesn't match sig tree digest"));
    }
}

#[test]
fn should_fail_verify_canister_sig_on_sig_with_malformed_cbor_tag() {
    let rng = &mut ReproducibleRng::new();
    for with_delegation in [false, true] {
        let sig_data = new_valid_sig_and_crypto_component(rng, with_delegation);
        let sig_with_malformed_cbor_tag = {
            let mut corrupted_sig = sig_data.canister_sig.get_ref().0.clone();
            // position 1 in the sig corrupts the CBOR tag:
            corrupted_sig[1] ^= 0xFF;
            corrupted_sig
        };

        let result = ic_signature_verification::verify_canister_sig(
            &sig_data.msg.as_signed_bytes(),
            &sig_with_malformed_cbor_tag,
            &get_canister_sig_pk_der(&sig_data.canister_pk.key),
            &get_root_pk_raw(&sig_data.root_of_trust),
        );
        assert_matches!(result, Err(e) if e.contains("CBOR doesn't have a self-describing tag"));
    }
}

#[test]
fn should_fail_verify_canister_sig_on_sig_with_malformed_cert() {
    let rng = &mut ReproducibleRng::new();
    for with_delegation in [false, true] {
        let sig_data = new_valid_sig_and_crypto_component(rng, with_delegation);
        let sig_with_malformed_cert = {
            let mut corrupted_sig_bytes = sig_data.canister_sig.get_ref().0.clone();
            // position 30 in the sig corrupts the certificate:
            corrupted_sig_bytes[30] ^= 0xFF;
            corrupted_sig_bytes
        };

        let result = ic_signature_verification::verify_canister_sig(
            &sig_data.msg.as_signed_bytes(),
            &sig_with_malformed_cert,
            &get_canister_sig_pk_der(&sig_data.canister_pk.key),
            &get_root_pk_raw(&sig_data.root_of_trust),
        );
        assert_matches!(result, Err(e) if e.contains("failed to parse certificate"));
    }
}

#[test]
fn should_fail_verify_canister_sig_on_wrong_root_pk() {
    let rng = &mut ReproducibleRng::new();
    for with_delegation in [false, true] {
        let sig_data = new_valid_sig_and_crypto_component(rng, with_delegation);
        let result = ic_signature_verification::verify_canister_sig(
            &sig_data.msg.as_signed_bytes(),
            &sig_data.canister_sig.get_ref().0,
            &get_canister_sig_pk_der(&sig_data.canister_pk.key),
            &[42; 96],
        );
        assert_matches!(result, Err(e) if e.contains("invalid BLS signature"));
    }
}

#[test]
fn should_fail_verify_canister_sig_on_invalid_root_pk() {
    let rng = &mut ReproducibleRng::new();
    for with_delegation in [false, true] {
        let sig_data = new_valid_sig_and_crypto_component(rng, with_delegation);
        let result = ic_signature_verification::verify_canister_sig(
            &sig_data.msg.as_signed_bytes(),
            &sig_data.canister_sig.get_ref().0,
            &get_canister_sig_pk_der(&sig_data.canister_pk.key),
            &[42; 99], // invalid length
        );
        assert_matches!(result, Err(e) if e.contains("invalid BLS signature"));
    }
}

#[test]
fn should_fail_verify_canister_sig_on_invalid_canister_sig_pk() {
    let rng = &mut ReproducibleRng::new();
    for with_delegation in [false, true] {
        let sig_data = new_valid_sig_and_crypto_component(rng, with_delegation);
        let invalid_canister_sig_pk =
            CanisterSigPublicKey::new(Principal::from_slice(&[1, 2, 3, 4]), [7; 11].to_vec());
        let result = ic_signature_verification::verify_canister_sig(
            &sig_data.msg.as_signed_bytes(),
            &sig_data.canister_sig.get_ref().0,
            &invalid_canister_sig_pk.to_der(),
            &get_root_pk_raw(&sig_data.root_of_trust),
        );
        assert_matches!(result, Err(e) if e.contains("certified_data entry not found"));
    }
}

#[test]
fn should_fail_verify_canister_sig_on_wrong_canister_sig_pk() {
    let rng = &mut ReproducibleRng::new();
    // A 2nd rng/sig_data to generate a different (yet well-formed) canister sig pk
    let rng_2 = &mut ReproducibleRng::new();
    let sig_data_2 = new_valid_sig_and_crypto_component(rng_2, false);

    for with_delegation in [false, true] {
        let sig_data = new_valid_sig_and_crypto_component(rng, with_delegation);

        let result = ic_signature_verification::verify_canister_sig(
            &sig_data.msg.as_signed_bytes(),
            &sig_data.canister_sig.get_ref().0,
            &get_canister_sig_pk_der(&sig_data_2.canister_pk.key), // use pk from 2nd sig
            &get_root_pk_raw(&sig_data.root_of_trust),
        );
        assert_matches!(result, Err(e) if e.contains("signature entry not found"));
    }
}

#[test]
fn should_accept_canister_sig_with_new_cert_format() {
    let sig_bytes = hex::decode("d9d9f7a26b6365727469666963617465590538d9d9f7a3647472656583018301830182045820267d108b825149c889227f220ca201138ce621c31c7c3cf174117e7015110bb783024863616e69737465728301820458207d77e250763245cc7e570839a03aeb87760da9a11636760fb0e057972136a9b9830182045820f7714b7ec20be0922386a55486483e91320f6ba792c3a630ece1072a91b1fe6e830182045820fe1819fadf00e62a3c69fe2442719dafef686b462c0bc645ae7d300eb99056a583024affffffffff90000701018301830183024e6365727469666965645f64617461820358209e694056379342a949c81a8b95d8b584f41f3bc2470e00202a8e9be6e98dc8628204582079eae22959b3c735f09ddf3823a645a89217acba18ca5fdd188671e1b71ef6c1820458202fe4081e422ffd32cd7ad47de77792b0a9bdac036ebbb3a6d901cfdd96ed2cb782045820b9fd74d4149a2706d66f58cad634b9c3ecc4cd980cdf565f707fbc2a90d84a488301820458207bf65240f865b6c6211156b0a764c297f8470172f8a5c7dd31326f8e4741032983018204582061796dd7b084c9b89f2fc75c966704a588a7a378d9ad81c182c5bb92e248724583024474696d65820349d0afe588eccedbcd18697369676e61747572655830a257ec4179f73b7408825f29f60b474ea36fcad745c15ad34594598a0dbc66a36c4147f1113ce7b6d87d260051ffa72c6a64656c65676174696f6ea2697375626e65745f6964581d65d265c4f1d36f04f205451f3d3a56e044f25af78aa7c3a191284beb026b63657274696669636174655902f7d9d9f7a264747265658301830182045820fa9d7edb7933e037d87555d74f66ef26bd05596da78b4d3a13d6555cf50393b5830183024f63616e69737465725f72616e6765738301830183018204582021427310e06557712f92337f15d6e49b094215e938b17af5cb7cd2d8b0621a818302581d65d265c4f1d36f04f205451f3d3a56e044f25af78aa7c3a191284beb0283024affffffffff90000001018203581bd9d9f781824affffffffff90000001014affffffffff9fffff010182045820b8ab276766031da6330f4450151b4dd2ea9f3c8791cfae2e00e186bd05f84bd88204582019954d2987fde6c55a169a04504ff5e90c7128748e3dd34c9c633e2983ae6c2c82045820471ba007a6f04530b4aaf3f16a4ade5c08133f75f2af42788b61e9303c5882ae830182045820807e21d961b17be8f9242657fd43206ab9c171e6aa370b2adb4eef7627bcff5483018302467375626e657483018301830182045820507e6babf2ca44a866823d39c14d3888e049382808972022d99d0aec7b61a57b8302581d65d265c4f1d36f04f205451f3d3a56e044f25af78aa7c3a191284beb02830182045820fe34325823e5c896def552a11dc9594c751026f2130ad022a6731501c169f13883024a7075626c69635f6b657982035885308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c0503020103610089e5956c545ab586d033101a0cdc9eb1526b27802a5609b8e9e82b81899c0d928d3562441c98d7a111a0b8ad6af39d5308682e875aac1f4b246272b93d3575e50562336b611dcbb73b2631b74d7aebb3afbb5820e97991268fb7c8f7041d8a9982045820f218b46c05fcb91a74a550a8ce424fab833d9f018ed20b9a31a91c0582daf18d82045820b0d97909549239b4e1fa8acd36f3c2eaf6c0c870892ead654ec4fb1d906cd59783024474696d65820349d0afe588eccedbcd18697369676e617475726558308f38d31c6b0110835abcb3134afacd327d1e3094f72cb55cee44f30473fb0ec65b0f2c866cca842d44c6561b116cea0464747265658302437369678302582004cd1048a11d72deeaa7e93c8b3a7c406b0d8ee6b33d16552c83f3f067f10245830258208b045d64915603c1cded87c23dfeac173b28f71b74df726f86b29e8b04ecf7e9820340").expect("Invalid hex");

    let pk_bytes =
        hex::decode("3024300c060a2b0601040183b84301020314000affffffffff90000701018c8b3e8478c1969b")
            .expect("Invalid hex");

    let signed_message = hex::decode("1062632d757365722d6964656e7469747922c562b4d9625329c039488f3a28aa2e090163d2ad994aec3bbe053002").expect("Invalid hex");

    let root_key = hex::decode("8b52b4994f94c7ce4be1c1542d7c81dc79fea17d49efe8fa42e8566373581d4b969c4a59e96a0ef51b711fe5027ec01601182519d0a788f4bfe388e593b97cd1d7e44904de79422430bca686ac8c21305b3397b5ba4d7037d17877312fb7ee34").expect("Invalid hex");

    let result = ic_signature_verification::verify_canister_sig(
        &signed_message,
        &sig_bytes,
        &pk_bytes,
        &root_key,
    );

    assert_matches!(result, Ok(()));
}
