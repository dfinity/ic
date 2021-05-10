#![allow(clippy::unwrap_used)]

use super::*;
use crate::common::test_utils::mockall_csp::MockAllCryptoServiceProvider;

use crate::sign::threshold_sig::dkg::dealings_to_csp_dealings::{
    CspDealings, DealingsToCspDealingsError,
};
use crate::sign::threshold_sig::dkg::test_utils::{csp_pk_pop_dealing, MockDealingsToCspDealings};
use crate::sign::threshold_sig::tests::I_DKG_ID;
use ic_crypto_internal_threshold_sig_bls12381::dkg::secp256k1::types::CLibResponseBytes;
use ic_test_utilities::types::ids::{NODE_1, NODE_2, NODE_3, NODE_4};

// We use threshold 1 in these tests to get a valid DkgConfig in a simple way.
// Threshold 1 not a common value used in practice, but in these this is not
// relevant as we only need some valid config.
const IDKM_THRESHOLD: usize = 1;

mod create_response {
    use super::*;
    use crate::sign::threshold_sig::dkg::test_utils::{
        any_dealings_to_pass_to_mapper_mock, dealings_with, keys_with,
    };
    use ic_crypto_internal_csp::types::CspDealing;
    use ic_crypto_internal_threshold_sig_bls12381::api::dkg_errors::{
        DkgCreateResponseError, MalformedDataError,
    };
    use ic_types::crypto::AlgorithmId;

    #[test]
    fn should_forward_keys_and_dealings_to_dealings_mapper() {
        let dkg_config = dkg_config_with_receivers(I_DKG_ID, vec![NODE_1, NODE_2, NODE_3, NODE_4]);
        let (csp_pk, csp_pop, csp_dealing) = csp_pk_pop_dealing();
        let csp = csp_with_create_response_returning(Ok(csp_response()));
        let verified_keys = keys_with(NODE_3, csp_pk, csp_pop);
        let verified_dealings = dealings_with(NODE_3, Dealing::from(&csp_dealing));

        let dealings_mapper =
            dealings_mapper_expecting(verified_keys.clone(), verified_dealings.clone());

        let _ = create_response(
            &csp,
            dealings_mapper,
            &dkg_config,
            &verified_keys,
            &verified_dealings,
            NODE_3,
        );
    }

    #[test]
    fn should_call_csp_correctly() {
        let dkg_config = dkg_config_with_receivers(I_DKG_ID, vec![NODE_1, NODE_2, NODE_3, NODE_4]);
        let (csp_pk, csp_pop, csp_dealing) = csp_pk_pop_dealing();
        let verified_keys = keys_with(NODE_3, csp_pk, csp_pop);
        let verified_csp_dealings = vec![((csp_pk, csp_pop), csp_dealing)];
        let dealings_mapper = dealings_mapper_returning(Ok(verified_csp_dealings.clone()));

        let csp = csp_with_create_response_expecting(I_DKG_ID, 2, verified_csp_dealings);

        let _ = create_response(
            &csp,
            dealings_mapper,
            &dkg_config,
            &verified_keys,
            &any_dealings_to_pass_to_mapper_mock(),
            NODE_3,
        );
    }

    #[test]
    fn should_return_response_from_csp() {
        let dkg_config = dkg_config_with_receivers(I_DKG_ID, vec![NODE_1, NODE_2, NODE_3, NODE_4]);
        let (csp_pk, csp_pop, csp_dealing) = csp_pk_pop_dealing();
        let verified_keys = keys_with(NODE_3, csp_pk, csp_pop);
        let dealings_mapper = dealings_mapper_returning(Ok(vec![((csp_pk, csp_pop), csp_dealing)]));

        let csp_response = csp_response();
        let csp = csp_with_create_response_returning(Ok(csp_response.clone()));

        let response = create_response(
            &csp,
            dealings_mapper,
            &dkg_config,
            &verified_keys,
            &any_dealings_to_pass_to_mapper_mock(),
            NODE_3,
        )
        .unwrap();

        assert_eq!(response, Response::from(&csp_response));
    }

    #[test]
    // TODO (CRP-327): Map the CSP errors to IDKM errors.
    fn should_return_invalid_argument_if_csp_returns_error() {
        let dkg_config = dkg_config_with_receivers(I_DKG_ID, vec![NODE_1, NODE_2, NODE_3, NODE_4]);
        let (csp_pk, csp_pop, csp_dealing) = csp_pk_pop_dealing();
        let verified_keys = keys_with(NODE_3, csp_pk, csp_pop);
        let dealings_mapper = dealings_mapper_returning(Ok(vec![((csp_pk, csp_pop), csp_dealing)]));

        let csp = csp_with_create_response_returning(Err(
            DkgCreateResponseError::MalformedDealingError(MalformedDataError {
                algorithm: AlgorithmId::Secp256k1,
                internal_error: "".to_string(),
                data: None,
            }),
        ));

        let result = create_response(
            &csp,
            dealings_mapper,
            &dkg_config,
            &verified_keys,
            &any_dealings_to_pass_to_mapper_mock(),
            NODE_3,
        );

        assert_eq!(
            result.unwrap_err(),
            invalid_arg("CSP error: MalformedDataError { algorithm: Secp256k1, internal_error: \"\", data: None }")
        );
    }

    #[test]
    fn should_return_error_if_responder_is_not_a_receiver() {
        const RESPONDER: NodeId = NODE_3;
        let dkg_config = dkg_config_with_receivers(I_DKG_ID, vec![NODE_1, NODE_2, NODE_4]);
        let csp = MockAllCryptoServiceProvider::new();
        let (csp_pk, csp_pop, csp_dealing) = csp_pk_pop_dealing();
        let verified_keys = keys_with(RESPONDER, csp_pk, csp_pop);
        let dealings_mapper = dealings_mapper_returning(Ok(vec![((csp_pk, csp_pop), csp_dealing)]));

        let result = create_response(
            &csp,
            dealings_mapper,
            &dkg_config,
            &verified_keys,
            &any_dealings_to_pass_to_mapper_mock(),
            RESPONDER,
        );

        assert_eq!(
            result.unwrap_err(),
            invalid_arg(
                "The provided node id \"32uhy-eydaa-aaaaa-aaaap-2ai\" is not a receiver. Only receivers are allowed for this \
                operation."
            )
        );
    }

    #[test]
    fn should_return_error_if_responder_has_no_key() {
        const RESPONDER: NodeId = NODE_3;
        let dkg_config =
            dkg_config_with_receivers(I_DKG_ID, vec![NODE_1, NODE_2, RESPONDER, NODE_4]);
        let csp = MockAllCryptoServiceProvider::new();
        let (csp_pk, csp_pop, _) = csp_pk_pop_dealing();
        let verified_keys_without_responder_key = keys_with(NODE_4, csp_pk, csp_pop);

        let result = create_response(
            &csp,
            MockDealingsToCspDealings::new(),
            &dkg_config,
            &verified_keys_without_responder_key,
            &any_dealings_to_pass_to_mapper_mock(),
            RESPONDER,
        );

        assert_eq!(
            result.unwrap_err(),
            invalid_arg("Missing key for node ID \"32uhy-eydaa-aaaaa-aaaap-2ai\".")
        );
    }

    fn csp_with_create_response_expecting(
        expected_dkg_id: IDkgId,
        expected_receiver_index: NodeIndex,
        expected_dealings: Vec<((CspEncryptionPublicKey, CspPop), CspDealing)>,
    ) -> impl CryptoServiceProvider {
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_dkg_create_response()
            .withf(move |dkg_id, verified_csp_dealings, my_index| {
                *dkg_id == expected_dkg_id
                    && verified_csp_dealings == &expected_dealings[..]
                    && *my_index == expected_receiver_index
            })
            .times(1)
            .return_const(Ok(csp_response()));
        csp
    }

    fn csp_with_create_response_returning(
        result: Result<CspResponse, DkgCreateResponseError>,
    ) -> impl CryptoServiceProvider {
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_dkg_create_response()
            .times(1)
            .return_const(result);
        csp
    }
}

mod verify_response {
    use super::*;
    use crate::sign::threshold_sig::dkg::test_utils::{dealings_with, keys_with};
    use ic_crypto_internal_threshold_sig_bls12381::api::dkg_errors::{
        DkgVerifyResponseError, InvalidArgumentError,
    };

    #[test]
    fn should_forward_keys_and_dealings_to_dealings_mapper() {
        let (csp_pk, csp_pop, csp_dealing) = csp_pk_pop_dealing();
        let csp = csp_with_verify_response_returning(Ok(()));
        let verified_keys = keys_with(NODE_3, csp_pk, csp_pop);
        let verified_dealings = dealings_with(NODE_3, Dealing::from(&csp_dealing));
        let dkg_config = dkg_config_with_receivers(I_DKG_ID, vec![NODE_1, NODE_2, NODE_3, NODE_4]);

        let dealings_mapper =
            dealings_mapper_expecting(verified_keys.clone(), verified_dealings.clone());

        let _ = verify_response(
            &csp,
            dealings_mapper,
            &dkg_config,
            &verified_keys,
            &verified_dealings,
            NODE_3,
            &Response::from(&csp_response()),
        );
    }

    #[test]
    fn should_call_csp_with_correct_parameters() {
        const RESPONDER: NodeId = NODE_2;
        let (csp_pk, csp_pop, csp_dealing) = csp_pk_pop_dealing();
        let csp_response = csp_response();
        let verified_csp_dealings = vec![((csp_pk, csp_pop), csp_dealing)];
        let dealings_mapper = dealings_mapper_returning(Ok(verified_csp_dealings.clone()));
        let verified_keys = keys_with(RESPONDER, csp_pk, csp_pop);
        let dkg_config =
            dkg_config_with_receivers(I_DKG_ID, vec![NODE_1, RESPONDER, NODE_3, NODE_4]);

        let mut csp = MockAllCryptoServiceProvider::new();
        let expected_dealings = verified_csp_dealings;
        let expected_receiver_key = (csp_pk, csp_pop);
        let expected_response = csp_response.clone();
        csp.expect_dkg_verify_response()
            .withf(
                move |dkg_id, verified_csp_dealings, receiver_index, receiver_key, response| {
                    *dkg_id == I_DKG_ID
                    && verified_csp_dealings == &expected_dealings[..]
                    && *receiver_index == 1 // the RECEIVER position in the receivers vector
                    && receiver_key == &expected_receiver_key
                    && response == &expected_response
                },
            )
            .times(1)
            .return_const(Ok(()));

        let _ = verify_response(
            &csp,
            dealings_mapper,
            &dkg_config,
            &verified_keys,
            &any_dealings_to_pass_to_mapper_mock(),
            RESPONDER,
            &Response::from(&csp_response),
        );
    }

    #[test]
    fn should_return_response_from_csp() {
        const RESPONDER: NodeId = NODE_2;
        let (csp_pk, csp_pop, csp_dealing) = csp_pk_pop_dealing();
        let dealings_mapper = dealings_mapper_returning(Ok(vec![((csp_pk, csp_pop), csp_dealing)]));
        let csp = csp_with_verify_response_returning(Ok(()));

        let result = verify_response(
            &csp,
            dealings_mapper,
            &dkg_config_with_receivers(I_DKG_ID, vec![NODE_1, RESPONDER, NODE_3, NODE_4]),
            &keys_with(RESPONDER, csp_pk, csp_pop),
            &any_dealings_to_pass_to_mapper_mock(),
            RESPONDER,
            &Response::from(&csp_response()),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn should_return_error_if_mapper_returns_error() {
        const RESPONDER: NodeId = NODE_2;
        let (csp_pk, csp_pop, _) = csp_pk_pop_dealing();
        let dealings_mapper =
            dealings_mapper_returning(Err(DealingsToCspDealingsError::KeysEmpty {}));
        let csp = MockAllCryptoServiceProvider::new();

        let result = verify_response(
            &csp,
            dealings_mapper,
            &dkg_config_with_receivers(I_DKG_ID, vec![NODE_1, RESPONDER, NODE_3, NODE_4]),
            &keys_with(RESPONDER, csp_pk, csp_pop),
            &any_dealings_to_pass_to_mapper_mock(),
            RESPONDER,
            &Response::from(&csp_response()),
        );

        assert_invalid_arg_error(
            result,
            "Error while mapping the dealings: The keys must not be empty.",
        );
    }

    #[test]
    fn should_return_error_if_responder_has_no_key() {
        const RESPONDER: NodeId = NODE_2;
        let (csp_pk, csp_pop, _) = csp_pk_pop_dealing();
        let dealings_mapper = MockDealingsToCspDealings::new();
        let keys_without_responder_key = keys_with(NODE_4, csp_pk, csp_pop);
        let csp = MockAllCryptoServiceProvider::new();

        let result = verify_response(
            &csp,
            dealings_mapper,
            &dkg_config_with_receivers(I_DKG_ID, vec![NODE_1, RESPONDER, NODE_3, NODE_4]),
            &keys_without_responder_key,
            &any_dealings_to_pass_to_mapper_mock(),
            RESPONDER,
            &Response::from(&csp_response()),
        );

        assert_invalid_arg_error(
            result,
            "Missing key for node ID \"gfvbo-licaa-aaaaa-aaaap-2ai\".",
        );
    }

    #[test]
    fn should_return_invalid_argument_if_csp_returns_error() {
        const RESPONDER: NodeId = NODE_2;
        let (csp_pk, csp_pop, csp_dealing) = csp_pk_pop_dealing();
        let dealings_mapper = dealings_mapper_returning(Ok(vec![((csp_pk, csp_pop), csp_dealing)]));
        let csp = csp_with_verify_response_returning(Err(
            DkgVerifyResponseError::InvalidResponseError(InvalidArgumentError {
                message: "message".to_string(),
            }),
        ));

        let result = verify_response(
            &csp,
            dealings_mapper,
            &dkg_config_with_receivers(I_DKG_ID, vec![NODE_1, RESPONDER, NODE_3, NODE_4]),
            &keys_with(RESPONDER, csp_pk, csp_pop),
            &any_dealings_to_pass_to_mapper_mock(),
            RESPONDER,
            &Response::from(&csp_response()),
        );

        assert_invalid_arg_error(
            result,
            "CSP error: InvalidArgumentError { message: \"message\" }",
        );
    }

    #[test]
    fn should_return_error_if_responder_is_not_a_receiver() {
        const RESPONDER: NodeId = NODE_2;
        let (csp_pk, csp_pop, _) = csp_pk_pop_dealing();
        let dealings_mapper = MockDealingsToCspDealings::new();
        let csp = MockAllCryptoServiceProvider::new();
        let receivers_with_responder_missing = vec![NODE_1, NODE_3, NODE_4];

        let result = verify_response(
            &csp,
            dealings_mapper,
            &dkg_config_with_receivers(I_DKG_ID, receivers_with_responder_missing),
            &keys_with(RESPONDER, csp_pk, csp_pop),
            &any_dealings_to_pass_to_mapper_mock(),
            RESPONDER,
            &Response::from(&csp_response()),
        );

        assert_invalid_arg_error(
            result,
            "The provided node id \"gfvbo-licaa-aaaaa-aaaap-2ai\" is not a receiver. Only receivers are allowed \
            for this operation.",
        );
    }

    fn csp_with_verify_response_returning(
        result: Result<(), DkgVerifyResponseError>,
    ) -> impl CryptoServiceProvider {
        let mut csp = MockAllCryptoServiceProvider::new();
        csp.expect_dkg_verify_response()
            .times(1)
            .return_const(result);
        csp
    }

    fn assert_invalid_arg_error(result: Result<(), CryptoError>, msg: &str) {
        assert_eq!(result.unwrap_err(), invalid_arg(msg));
    }

    fn any_dealings_to_pass_to_mapper_mock() -> BTreeMap<NodeId, Dealing> {
        BTreeMap::new()
    }
}

fn dealings_mapper_expecting(
    expected_keys: BTreeMap<NodeId, EncryptionPublicKeyWithPop>,
    expected_dealings: BTreeMap<NodeId, Dealing>,
) -> impl DealingsToCspDealings {
    let mut dealings_mapper = MockDealingsToCspDealings::new();
    dealings_mapper
        .expect_convert()
        .withf(move |verified_keys, verified_dealings| {
            verified_keys == &expected_keys && verified_dealings == &expected_dealings
        })
        .times(1)
        .return_const(Ok(vec![]));
    dealings_mapper
}

fn dealings_mapper_returning(
    result: Result<CspDealings, DealingsToCspDealingsError>,
) -> impl DealingsToCspDealings {
    let mut dealings_mapper = MockDealingsToCspDealings::new();
    dealings_mapper
        .expect_convert()
        .times(1)
        .return_const(result);
    dealings_mapper
}

fn dkg_config_with_receivers(dkg_id: IDkgId, receivers: Vec<NodeId>) -> DkgConfig {
    create_config(DkgConfigData {
        dkg_id,
        dealers: vec![NODE_1],
        receivers,
        threshold: IDKM_THRESHOLD,
        resharing_transcript: None,
    })
}

fn create_config(config_data: DkgConfigData) -> DkgConfig {
    DkgConfig::new(config_data).expect("unable to create dkg config")
}

fn invalid_arg(message: &str) -> CryptoError {
    CryptoError::InvalidArgument {
        message: message.to_string(),
    }
}

fn csp_response() -> CspResponse {
    CspResponse::Secp256k1(CLibResponseBytes {
        complaints: BTreeMap::new(),
    })
}
