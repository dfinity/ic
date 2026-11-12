use super::*;
use crate::icrc21::requests::ConsentMessageSpec;
use candid::Encode;

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
        new_account(1).owner,
        Nat::from(10_000_u64),
        "TOK".to_string(),
        "Token".to_string(),
        8,
    )
}

fn append_large_vec_of_nulls<T: CandidType>(valid_arg: &T) -> Vec<u8> {
    let mut arg = Encode!(valid_arg, &Vec::<()>::new()).unwrap();
    assert_eq!(arg.pop(), Some(0));
    arg.extend_from_slice(&U32_MAX_LEB128);
    arg
}

struct Case {
    method: &'static str,
    valid_arg: Vec<u8>,
    large_arg: Vec<u8>,
    large_arg_decode_result: Result<(), candid::Error>,
}

fn new_cases() -> Vec<Case> {
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
        Case {
            method: "icrc1_transfer",
            valid_arg: Encode!(&transfer_arg).unwrap(),
            large_arg: transfer_large.clone(),
            large_arg_decode_result: decode_consent_message_arg::<TransferArg>(&transfer_large)
                .map(|_| ()),
        },
        Case {
            method: "icrc2_transfer_from",
            valid_arg: Encode!(&transfer_from_args).unwrap(),
            large_arg: transfer_from_large.clone(),
            large_arg_decode_result: decode_consent_message_arg::<TransferFromArgs>(
                &transfer_from_large,
            )
            .map(|_| ()),
        },
        Case {
            method: "icrc2_approve",
            valid_arg: Encode!(&approve_args).unwrap(),
            large_arg: approve_large.clone(),
            large_arg_decode_result: decode_consent_message_arg::<ApproveArgs>(&approve_large)
                .map(|_| ()),
        },
    ]
}

#[test]
fn test_build_icrc21_consent_info_rejects_arg_exceeding_skipping_quota() {
    for case in new_cases() {
        let Case {
            method,
            valid_arg,
            large_arg,
            large_arg_decode_result,
        } = case;

        assert!(
            large_arg.len() <= MAX_CONSENT_MESSAGE_ARG_SIZE_BYTES as usize,
            "{method}: {} bytes",
            large_arg.len()
        );

        let large_result = build_consent_info(method, large_arg);
        let valid_result = build_consent_info(method, valid_arg);

        let decode_error = large_arg_decode_result.expect_err(method);
        assert!(
            format!("{decode_error:?}").contains("Skipping cost exceeds the limit"),
            "{method}: {decode_error:?}"
        );

        match large_result {
            Err(Icrc21Error::UnsupportedCanisterCall(ErrorInfo { description })) => {
                assert!(
                    description.contains("Failed to decode"),
                    "{method}: {description}"
                );
            }
            other => panic!("{method}: expected UnsupportedCanisterCall, got {other:?}"),
        }

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
