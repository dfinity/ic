use super::*;
use ic_base_types::PrincipalId;

#[test]
fn test_validate_fulfill_subnet_rental_request() {
    // Step 1: Prepare the world.

    // Step 2: Call the code under test.

    let mut next_subnet_id = 123_000;
    let mut new_subnet_id = move || {
        let result = PrincipalId::new_user_test_id(next_subnet_id);
        next_subnet_id += 1;
        result
    };

    let ok = FulfillSubnetRentalRequest {
        user: Some(PrincipalId::new_user_test_id(42)),
        node_ids: (0_u64..13) // Because 13 is a typical number of nodes in a subnet.
            .map(|_| new_subnet_id())
            .collect(),
        replica_version_id: "60fb469c46e44e6071193a3314cc442044fcf17a".to_string(),
    };

    // Sad cases.

    let no_user = FulfillSubnetRentalRequest {
        user: None,
        ..ok.clone()
    }
    .validate()
    .unwrap_err();

    let no_node_ids = FulfillSubnetRentalRequest {
        node_ids: vec![],
        ..ok.clone()
    }
    .validate()
    .unwrap_err();

    let absurdly_many_node_ids = FulfillSubnetRentalRequest {
        node_ids: (0_u64..5000).map(|_| new_subnet_id()).collect(),
        ..ok.clone()
    }
    .validate()
    .unwrap_err();

    let garbage_replica_version_id = FulfillSubnetRentalRequest {
        replica_version_id: "Trust me, bro. This replica_version_id is legit.".to_string(),
        ..ok.clone()
    }
    .validate()
    .unwrap_err();

    // Step 3: Verify results.

    assert_eq!(ok.validate(), Ok(()));

    #[track_caller]
    fn assert_invalid(err: GovernanceError, key_words: &[&str]) {
        let GovernanceError {
            error_type,
            error_message,
        } = &err;

        let error_type = ErrorType::try_from(*error_type);
        assert_eq!(error_type, Ok(ErrorType::InvalidProposal), "{err:?}");

        for key_word in key_words {
            let ok = error_message
                .to_lowercase()
                .contains(&key_word.to_lowercase());

            assert!(ok, "{key_word:?} not in error message ({error_message:?})",);
        }
    }

    assert_invalid(no_user, &["user", "null"]);
    assert_invalid(no_node_ids, &["node_ids", "empty"]);
    assert_invalid(absurdly_many_node_ids, &["node_ids", "many"]);
    assert_invalid(
        garbage_replica_version_id,
        &["replica_version_id", "40", "hexidecimal"],
    );
}
