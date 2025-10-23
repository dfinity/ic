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

    let no_user_error = ValidFulfillSubnetRentalRequest::try_from(FulfillSubnetRentalRequest {
        user: None,
        ..ok.clone()
    })
    .unwrap_err();

    let no_node_ids_error = ValidFulfillSubnetRentalRequest::try_from(FulfillSubnetRentalRequest {
        node_ids: vec![],
        ..ok.clone()
    })
    .unwrap_err();

    let absurdly_many_node_ids_error =
        ValidFulfillSubnetRentalRequest::try_from(FulfillSubnetRentalRequest {
            node_ids: (0_u64..5000).map(|_| new_subnet_id()).collect(),
            ..ok.clone()
        })
        .unwrap_err();

    let garbage_replica_version_id_error =
        ValidFulfillSubnetRentalRequest::try_from(FulfillSubnetRentalRequest {
            replica_version_id: "Trust me, bro. This replica_version_id is legit.".to_string(),
            ..ok.clone()
        })
        .unwrap_err();

    // Step 3: Verify results.

    let valid = ValidFulfillSubnetRentalRequest::try_from(ok).unwrap();
    assert_eq!(valid.validate(), Ok(()));

    #[track_caller]
    fn assert_invalid(err: String, key_words: &[&str]) {
        for key_word in key_words {
            let ok = err.to_lowercase().contains(&key_word.to_lowercase());

            assert!(ok, "{key_word:?} not in error message ({err:?})",);
        }
    }

    assert_invalid(no_user_error, &["user", "null"]);
    assert_invalid(no_node_ids_error, &["node_ids", "empty"]);
    assert_invalid(absurdly_many_node_ids_error, &["node_ids", "many"]);
    assert_invalid(
        garbage_replica_version_id_error,
        &["replica_version_id", "40", "hexidecimal"],
    );
}
