use super::*;
use crate::icrc21::requests::ConsentMessageSpec;
use candid::Encode;

/// LEB128 encoding of `u32::MAX`.
const U32_MAX_LEB128: [u8; 5] = [0xff, 0xff, 0xff, 0xff, 0x0f];

fn new_account(id: u8) -> Account {
    Account {
        owner: Principal::from_slice(&[id; 29]),
        subaccount: None,
    }
}

fn new_consent_message_request(method: &str, arg: Vec<u8>) -> ConsentMessageRequest {
    ConsentMessageRequest {
        method: method.to_string(),
        arg,
        user_preferences: ConsentMessageSpec {
            metadata: ConsentMessageMetadata {
                language: "en".to_string(),
                utc_offset_minutes: None,
            },
            device_spec: None,
        },
    }
}

fn build_consent_info(method: &str, arg: Vec<u8>) -> Result<ConsentInfo, Icrc21Error> {
    build_icrc21_consent_info_for_icrc1_and_icrc2_endpoints(
        new_consent_message_request(method, arg),
        new_account(1).owner,  // caller
        Nat::from(10_000_u64), // ledger fee
        "TOK".to_string(),
        "Token".to_string(),
        8, // decimals
    )
}

/// Returns the encoding of `valid_arg` followed by a second argument, a vector of `u32::MAX`
/// `null` values. The vector takes only a few bytes, because `null` values take no bytes.
fn append_large_vec_of_nulls<T: CandidType>(valid_arg: &T) -> Vec<u8> {
    let mut arg = Encode!(valid_arg, &Vec::<()>::new()).unwrap();
    // The encoding ends with the length of the empty vector (0). Replace it with u32::MAX.
    assert_eq!(arg.pop(), Some(0));
    arg.extend_from_slice(&U32_MAX_LEB128);
    arg
}

/// Each case is (method name, valid encoded arg, encoded arg with a large trailing vec of nulls,
/// result of decoding the latter as the method's argument type).
fn new_cases() -> Vec<(&'static str, Vec<u8>, Vec<u8>, Result<(), candid::Error>)> {
    let transfer_arg = TransferArg {
        from_subaccount: None,
        to: new_account(2),
        fee: None,
        created_at_time: None,
        memo: None,
        amount: Nat::from(1_000_u64),
    };
    let transfer_from_args = TransferFromArgs {
        spender_subaccount: None,
        from: new_account(2),
        to: new_account(3),
        amount: Nat::from(1_000_u64),
        fee: None,
        memo: None,
        created_at_time: None,
    };
    let approve_args = ApproveArgs {
        from_subaccount: None,
        spender: new_account(2),
        amount: Nat::from(1_000_u64),
        expected_allowance: None,
        expires_at: None,
        fee: None,
        memo: None,
        created_at_time: None,
    };

    let transfer_large = append_large_vec_of_nulls(&transfer_arg);
    let transfer_from_large = append_large_vec_of_nulls(&transfer_from_args);
    let approve_large = append_large_vec_of_nulls(&approve_args);

    vec![
        (
            "icrc1_transfer",
            Encode!(&transfer_arg).unwrap(),
            transfer_large.clone(),
            decode_consent_message_arg::<TransferArg>(&transfer_large).map(|_| ()),
        ),
        (
            "icrc2_transfer_from",
            Encode!(&transfer_from_args).unwrap(),
            transfer_from_large.clone(),
            decode_consent_message_arg::<TransferFromArgs>(&transfer_from_large).map(|_| ()),
        ),
        (
            "icrc2_approve",
            Encode!(&approve_args).unwrap(),
            approve_large.clone(),
            decode_consent_message_arg::<ApproveArgs>(&approve_large).map(|_| ()),
        ),
    ]
}

#[test]
fn test_build_icrc21_consent_info_rejects_arg_exceeding_skipping_quota() {
    for (method, valid_arg, large_arg, decode_result) in new_cases() {
        // Step 1: Prepare the world. The large arg must fit within the size limit, so that only
        // the skipping quota can stop it.
        assert!(
            large_arg.len() <= MAX_CONSENT_MESSAGE_ARG_SIZE_BYTES as usize,
            "{method}: {} bytes",
            large_arg.len()
        );

        // Step 2: Run the code under test.
        let large_result = build_consent_info(method, large_arg);
        let valid_result = build_consent_info(method, valid_arg);

        // Step 3: Verify result(s).

        // Step 3.1: The root cause is the skipping quota, not some other limit. (The error
        // description only shows the outermost context of the decoding error.)
        let decode_error = decode_result.expect_err(method);
        assert!(
            format!("{decode_error:?}").contains("Skipping cost exceeds the limit"),
            "{method}: {decode_error:?}"
        );

        // Step 3.2: The large arg is rejected.
        match large_result {
            Err(Icrc21Error::UnsupportedCanisterCall(ErrorInfo { description })) => {
                assert!(
                    description.contains("Failed to decode"),
                    "{method}: {description}"
                );
            }
            other => panic!("{method}: expected UnsupportedCanisterCall, got {other:?}"),
        }

        // Step 3.3: The valid arg still produces a consent message.
        assert!(valid_result.is_ok(), "{method}: {valid_result:?}");
    }
}

#[test]
fn test_validate_consent_message_arg_size() {
    let max_len = MAX_CONSENT_MESSAGE_ARG_SIZE_BYTES as usize;

    assert_eq!(validate_consent_message_arg_size(&vec![0; max_len]), Ok(()));

    match validate_consent_message_arg_size(&vec![0; max_len + 1]) {
        Err(Icrc21Error::UnsupportedCanisterCall(ErrorInfo { description })) => {
            assert!(description.contains("too large"), "{description}");
        }
        other => panic!("expected UnsupportedCanisterCall, got {other:?}"),
    }
}
