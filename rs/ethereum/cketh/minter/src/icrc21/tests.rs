use crate::blocklist::SAMPLE_BLOCKED_ADDRESS;
use crate::endpoints::WithdrawalArg;
use crate::endpoints::ckerc20::WithdrawErc20Arg;
use crate::erc20::CkErc20Token;
use crate::icrc21::{
    ConsentMessageConfig, TokenSymbols, build_consent_info, format_amount, token_amount,
};
use crate::lifecycle::EthereumNetwork;
use crate::numeric::Wei;
use candid::{Encode, Nat, Principal};
use icrc_ledger_types::icrc21::errors::{ErrorInfo, Icrc21Error};
use icrc_ledger_types::icrc21::lib::MAX_CONSENT_MESSAGE_ARG_SIZE_BYTES;
use icrc_ledger_types::icrc21::requests::{
    ConsentMessageMetadata, ConsentMessageRequest, ConsentMessageSpec, DisplayMessageType,
};
use icrc_ledger_types::icrc21::responses::{ConsentInfo, ConsentMessage, FieldsDisplay, Value};
use num_bigint::BigUint;

const DESTINATION: &str = "0x221E931fbFcb9bd54DdD26cE6f5e29E98AdD01C0";
const USDC_DECIMALS: u8 = 6;
const MINIMUM_WITHDRAWAL_AMOUNT: u64 = 30_000_000_000_000_000;

fn ckusdc() -> CkErc20Token {
    CkErc20Token {
        erc20_ethereum_network: EthereumNetwork::Mainnet,
        erc20_contract_address: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
            .parse()
            .unwrap(),
        ckerc20_token_symbol: "ckUSDC".parse().unwrap(),
        ckerc20_ledger_id: "xevnm-gaaaa-aaaar-qafnq-cai".parse().unwrap(),
    }
}

fn cksepolia_usdc() -> CkErc20Token {
    CkErc20Token {
        erc20_ethereum_network: EthereumNetwork::Sepolia,
        erc20_contract_address: "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238"
            .parse()
            .unwrap(),
        ckerc20_token_symbol: "ckSepoliaUSDC".parse().unwrap(),
        ckerc20_ledger_id: "yfumr-cyaaa-aaaar-qaela-cai".parse().unwrap(),
    }
}

fn mainnet_config() -> ConsentMessageConfig {
    ConsentMessageConfig {
        ethereum_network: EthereumNetwork::Mainnet,
        cketh_minimum_withdrawal_amount: Wei::from(MINIMUM_WITHDRAWAL_AMOUNT),
        ckerc20_tokens: vec![ckusdc()],
    }
}

fn sepolia_config() -> ConsentMessageConfig {
    ConsentMessageConfig {
        ethereum_network: EthereumNetwork::Sepolia,
        cketh_minimum_withdrawal_amount: Wei::from(MINIMUM_WITHDRAWAL_AMOUNT),
        ckerc20_tokens: vec![cksepolia_usdc()],
    }
}

fn make_request(
    method: &str,
    arg: Vec<u8>,
    device_spec: Option<DisplayMessageType>,
) -> ConsentMessageRequest {
    ConsentMessageRequest {
        method: method.to_string(),
        arg,
        user_preferences: ConsentMessageSpec {
            metadata: ConsentMessageMetadata {
                language: "en".to_string(),
                utc_offset_minutes: None,
            },
            device_spec,
        },
    }
}

fn withdraw_eth_arg(amount: u64) -> WithdrawalArg {
    WithdrawalArg {
        amount: Nat::from(amount),
        recipient: DESTINATION.to_string(),
        from_subaccount: None,
    }
}

fn withdraw_erc20_arg(amount: u64) -> WithdrawErc20Arg {
    WithdrawErc20Arg {
        amount: Nat::from(amount),
        ckerc20_ledger_id: ckusdc().ckerc20_ledger_id,
        recipient: DESTINATION.to_string(),
        from_cketh_subaccount: None,
        from_ckerc20_subaccount: None,
    }
}

/// Builds the consent message, answering requests for the decimals of a ckERC20 token with
/// the number of decimals of USDC.
async fn consent_info(
    request: ConsentMessageRequest,
    config: &ConsentMessageConfig,
) -> Result<ConsentInfo, Icrc21Error> {
    build_consent_info(request, config, async |_ledger_id| Ok(USDC_DECIMALS)).await
}

/// Builds the consent message, panicking if the decimals of a ckERC20 token are requested.
async fn consent_info_without_ledger_call(
    request: ConsentMessageRequest,
    config: &ConsentMessageConfig,
) -> Result<ConsentInfo, Icrc21Error> {
    build_consent_info(request, config, async |ledger_id| {
        panic!("BUG: unexpected call to the ckERC20 ledger {ledger_id}")
    })
    .await
}

fn expect_generic_display(info: ConsentInfo) -> String {
    match info.consent_message {
        ConsentMessage::GenericDisplayMessage(m) => m,
        other => panic!("expected GenericDisplayMessage, got {other:?}"),
    }
}

fn expect_fields_display(info: ConsentInfo) -> FieldsDisplay {
    match info.consent_message {
        ConsentMessage::FieldsDisplayMessage(f) => f,
        other => panic!("expected FieldsDisplayMessage, got {other:?}"),
    }
}

fn expect_unsupported_canister_call(result: Result<ConsentInfo, Icrc21Error>) -> String {
    match result {
        Err(Icrc21Error::UnsupportedCanisterCall(ErrorInfo { description })) => description,
        other => panic!("expected UnsupportedCanisterCall, got {other:?}"),
    }
}

#[test]
fn test_format_amount() {
    assert_eq!(format_amount(&Nat::from(0_u8), 18), "0");
    assert_eq!(format_amount(&Nat::from(1_u8), 18), "0.000000000000000001");
    assert_eq!(
        format_amount(&Nat::from(1_000_000_000_000_000_000_u64), 18),
        "1"
    );
    assert_eq!(
        format_amount(&Nat::from(1_500_000_000_000_000_000_u64), 18),
        "1.5"
    );
    assert_eq!(format_amount(&Nat::from(1_234_567_u64), 6), "1.234567");
    assert_eq!(format_amount(&Nat::from(42_u8), 0), "42");
    // Amounts that do not fit in a u64.
    assert_eq!(
        format_amount(&Nat::from(123_456_000_000_000_000_000_000_u128), 18),
        "123456"
    );
    let u256_max = Nat::from(BigUint::from(2_u8).pow(256) - 1_u8);
    assert_eq!(
        format_amount(&u256_max, 18),
        "115792089237316195423570985008687907853269984665640564039457.584007913129639935"
    );
}

#[test]
fn test_token_amount_falls_back_to_text_when_amount_does_not_fit_in_u64() {
    assert_eq!(
        token_amount(&Nat::from(u64::MAX), 18, "ckETH"),
        Value::TokenAmount {
            decimals: 18,
            amount: u64::MAX,
            symbol: "ckETH".to_string(),
        }
    );
    assert_eq!(
        token_amount(&Nat::from(u64::MAX as u128 + 1), 18, "ckETH"),
        Value::Text {
            content: "18.446744073709551616 ckETH".to_string()
        }
    );
}

#[test]
fn test_token_symbols_for_network() {
    assert_eq!(
        TokenSymbols::for_network(EthereumNetwork::Mainnet),
        TokenSymbols {
            cketh: "ckETH",
            eth: "ETH"
        }
    );
    assert_eq!(
        TokenSymbols::for_network(EthereumNetwork::Sepolia),
        TokenSymbols {
            cketh: "ckSepoliaETH",
            eth: "SepoliaETH"
        }
    );
}

#[tokio::test]
async fn test_unsupported_method() {
    // Only the endpoints that burn the caller's tokens are supported. The other update
    // endpoints do not move funds.
    for method in [
        "deposit_eth",
        "deposit_erc20",
        "retrieve_eth_status",
        "minter_address",
        "add_ckerc20_token",
        "get_canister_status",
        "",
    ] {
        let req = make_request(method, vec![], None);
        let description =
            expect_unsupported_canister_call(consent_info(req, &mainnet_config()).await);
        assert!(
            description.contains("is not supported"),
            "unexpected error description for method {method:?}: {description}"
        );
    }
}

#[tokio::test]
async fn test_argument_too_large() {
    for method in ["withdraw_eth", "withdraw_erc20"] {
        let req = make_request(
            method,
            vec![0; MAX_CONSENT_MESSAGE_ARG_SIZE_BYTES as usize + 1],
            None,
        );
        let description = expect_unsupported_canister_call(
            consent_info_without_ledger_call(req, &mainnet_config()).await,
        );
        assert!(description.contains("argument size is too large"));
    }
}

#[tokio::test]
async fn test_invalid_args() {
    for (method, arg) in [
        ("withdraw_eth", vec![1, 2, 3]),
        ("withdraw_erc20", vec![1, 2, 3]),
        // Valid Candid, but missing the `ckerc20_ledger_id` field.
        ("withdraw_erc20", Encode!(&withdraw_eth_arg(1)).unwrap()),
    ] {
        let req = make_request(method, arg, None);
        let description = expect_unsupported_canister_call(
            consent_info_without_ledger_call(req, &mainnet_config()).await,
        );
        assert!(
            description.contains("Failed to decode"),
            "unexpected error description for method {method}: {description}"
        );
    }
}

#[tokio::test]
async fn test_withdraw_eth_generic_display() {
    let req = make_request(
        "withdraw_eth",
        Encode!(&withdraw_eth_arg(150_000_000_000_000_000)).unwrap(),
        Some(DisplayMessageType::GenericDisplay),
    );
    let info = consent_info_without_ledger_call(req, &mainnet_config())
        .await
        .unwrap();
    assert_eq!(info.metadata.language, "en");
    assert_eq!(
        expect_generic_display(info),
        "# Convert ckETH to ETH\n\n\
         Authorize the ckETH minter to burn ckETH from your account and send the equivalent \
         amount in ETH, minus the Ethereum transaction fee, to the Ethereum address below. The \
         fee is estimated by the minter when it processes the withdrawal. Any unused part of \
         the fee is not refunded.\n\n\
         **Amount to convert:** `0.15 ckETH`\n\n\
         **Ethereum destination address:**\n`0x221E931fbFcb9bd54DdD26cE6f5e29E98AdD01C0`"
    );
}

#[tokio::test]
async fn test_withdraw_eth_generic_display_with_subaccount() {
    let mut subaccount = [0_u8; 32];
    subaccount[31] = 0x42;
    let args = WithdrawalArg {
        from_subaccount: Some(subaccount),
        ..withdraw_eth_arg(1_000_000_000_000_000_000)
    };
    // No device spec defaults to GenericDisplay.
    let req = make_request("withdraw_eth", Encode!(&args).unwrap(), None);
    let message = expect_generic_display(
        consent_info_without_ledger_call(req, &mainnet_config())
            .await
            .unwrap(),
    );
    assert!(message.contains("**Amount to convert:** `1 ckETH`"));
    assert!(message.ends_with(&format!(
        "\n\n**ckETH source subaccount:**\n`{}`",
        hex::encode(subaccount)
    )));
}

#[tokio::test]
async fn test_withdraw_eth_displays_eip_55_address() {
    let args = WithdrawalArg {
        recipient: DESTINATION.to_lowercase(),
        ..withdraw_eth_arg(1_000_000_000_000_000_000)
    };
    let req = make_request(
        "withdraw_eth",
        Encode!(&args).unwrap(),
        Some(DisplayMessageType::GenericDisplay),
    );
    let message = expect_generic_display(
        consent_info_without_ledger_call(req, &mainnet_config())
            .await
            .unwrap(),
    );
    assert!(message.contains(DESTINATION));
    assert!(!message.contains(&DESTINATION.to_lowercase()));
}

#[tokio::test]
async fn test_withdraw_eth_fields_display() {
    let mut subaccount = [0_u8; 32];
    subaccount[0] = 0xab;
    subaccount[31] = 0xcd;
    let args = WithdrawalArg {
        from_subaccount: Some(subaccount),
        ..withdraw_eth_arg(150_000_000_000_000_000)
    };
    let req = make_request(
        "withdraw_eth",
        Encode!(&args).unwrap(),
        Some(DisplayMessageType::FieldsDisplay),
    );
    let fields_display = expect_fields_display(
        consent_info_without_ledger_call(req, &mainnet_config())
            .await
            .unwrap(),
    );
    assert_eq!(
        fields_display,
        FieldsDisplay {
            intent: "ckETH to ETH".to_string(),
            fields: vec![
                (
                    "Amount".to_string(),
                    Value::TokenAmount {
                        decimals: 18,
                        amount: 150_000_000_000_000_000,
                        symbol: "ckETH".to_string(),
                    }
                ),
                (
                    "Ethereum address".to_string(),
                    Value::Text {
                        content: DESTINATION.to_string()
                    }
                ),
                (
                    "Transaction fee".to_string(),
                    Value::Text {
                        content: "Deducted from the amount as estimated by the minter; any \
                                  unused part is not refunded"
                            .to_string()
                    }
                ),
                (
                    "From subaccount".to_string(),
                    Value::Text {
                        content: hex::encode(subaccount)
                    }
                ),
            ]
        }
    );
}

#[tokio::test]
async fn test_withdraw_eth_fields_display_with_amount_larger_than_u64() {
    let args = WithdrawalArg {
        amount: Nat::from(100_000_000_000_000_000_000_u128),
        ..withdraw_eth_arg(0)
    };
    let req = make_request(
        "withdraw_eth",
        Encode!(&args).unwrap(),
        Some(DisplayMessageType::FieldsDisplay),
    );
    let fields_display = expect_fields_display(
        consent_info_without_ledger_call(req, &mainnet_config())
            .await
            .unwrap(),
    );
    assert_eq!(
        fields_display.fields,
        vec![
            (
                "Amount".to_string(),
                Value::Text {
                    content: "100 ckETH".to_string()
                }
            ),
            (
                "Ethereum address".to_string(),
                Value::Text {
                    content: DESTINATION.to_string()
                }
            ),
            (
                "Transaction fee".to_string(),
                Value::Text {
                    content: "Deducted from the amount as estimated by the minter; any unused \
                              part is not refunded"
                        .to_string()
                }
            ),
        ]
    );
}

#[tokio::test]
async fn test_withdraw_eth_uses_sepolia_symbols() {
    let args = withdraw_eth_arg(1_000_000_000_000_000_000);
    let message = expect_generic_display(
        consent_info_without_ledger_call(
            make_request(
                "withdraw_eth",
                Encode!(&args).unwrap(),
                Some(DisplayMessageType::GenericDisplay),
            ),
            &sepolia_config(),
        )
        .await
        .unwrap(),
    );
    assert!(message.starts_with("# Convert ckSepoliaETH to SepoliaETH"));
    assert!(message.contains("ckSepoliaETH minter"));
    assert!(message.contains("equivalent amount in SepoliaETH"));
    assert!(message.contains("`1 ckSepoliaETH`"));

    let fields_display = expect_fields_display(
        consent_info_without_ledger_call(
            make_request(
                "withdraw_eth",
                Encode!(&args).unwrap(),
                Some(DisplayMessageType::FieldsDisplay),
            ),
            &sepolia_config(),
        )
        .await
        .unwrap(),
    );
    assert_eq!(fields_display.intent, "ckSepoliaETH to SepoliaETH");
    match &fields_display.fields[0].1 {
        Value::TokenAmount { symbol, .. } => assert_eq!(symbol, "ckSepoliaETH"),
        other => panic!("expected TokenAmount, got {other:?}"),
    }
}

#[tokio::test]
async fn test_withdraw_erc20_generic_display() {
    let req = make_request(
        "withdraw_erc20",
        Encode!(&withdraw_erc20_arg(1_500_000)).unwrap(),
        Some(DisplayMessageType::GenericDisplay),
    );
    let info = build_consent_info(req, &mainnet_config(), async |ledger_id| {
        assert_eq!(ledger_id, ckusdc().ckerc20_ledger_id);
        Ok(USDC_DECIMALS)
    })
    .await
    .unwrap();
    assert_eq!(
        expect_generic_display(info),
        "# Convert ckUSDC to USDC\n\n\
         Authorize the ckETH minter to burn ckUSDC from your account and send the same amount \
         in USDC to the Ethereum address below.\n\n\
         The minter also burns ckETH from your account to pay for the Ethereum transaction \
         fee. The fee is estimated by the minter when it processes the withdrawal and is \
         limited by the ckETH allowance you granted to the minter. Any unused part of the fee \
         is not refunded.\n\n\
         **Amount to convert:** `1.5 ckUSDC`\n\n\
         **Ethereum destination address:**\n`0x221E931fbFcb9bd54DdD26cE6f5e29E98AdD01C0`"
    );
}

#[tokio::test]
async fn test_withdraw_erc20_generic_display_with_subaccounts() {
    let ckerc20_subaccount = [1_u8; 32];
    let cketh_subaccount = [2_u8; 32];
    let args = WithdrawErc20Arg {
        from_ckerc20_subaccount: Some(ckerc20_subaccount),
        from_cketh_subaccount: Some(cketh_subaccount),
        ..withdraw_erc20_arg(1_000_000)
    };
    let req = make_request("withdraw_erc20", Encode!(&args).unwrap(), None);
    let message = expect_generic_display(consent_info(req, &mainnet_config()).await.unwrap());
    assert!(message.contains("**Amount to convert:** `1 ckUSDC`"));
    assert!(message.ends_with(&format!(
        "\n\n**ckUSDC source subaccount:**\n`{}`\n\n\
         **ckETH source subaccount (transaction fee):**\n`{}`",
        hex::encode(ckerc20_subaccount),
        hex::encode(cketh_subaccount)
    )));
}

#[tokio::test]
async fn test_withdraw_erc20_fields_display() {
    let ckerc20_subaccount = [1_u8; 32];
    let cketh_subaccount = [2_u8; 32];
    let args = WithdrawErc20Arg {
        from_ckerc20_subaccount: Some(ckerc20_subaccount),
        from_cketh_subaccount: Some(cketh_subaccount),
        ..withdraw_erc20_arg(1_500_000)
    };
    let req = make_request(
        "withdraw_erc20",
        Encode!(&args).unwrap(),
        Some(DisplayMessageType::FieldsDisplay),
    );
    let fields_display = expect_fields_display(consent_info(req, &mainnet_config()).await.unwrap());
    assert_eq!(
        fields_display,
        FieldsDisplay {
            intent: "ckUSDC to USDC".to_string(),
            fields: vec![
                (
                    "Amount".to_string(),
                    Value::TokenAmount {
                        decimals: USDC_DECIMALS,
                        amount: 1_500_000,
                        symbol: "ckUSDC".to_string(),
                    }
                ),
                (
                    "Ethereum address".to_string(),
                    Value::Text {
                        content: DESTINATION.to_string()
                    }
                ),
                (
                    "Transaction fee".to_string(),
                    Value::Text {
                        content: "Paid in ckETH as estimated by the minter; any unused part is \
                                  not refunded"
                            .to_string()
                    }
                ),
                (
                    "From subaccount".to_string(),
                    Value::Text {
                        content: hex::encode(ckerc20_subaccount)
                    }
                ),
                (
                    "Fee subaccount".to_string(),
                    Value::Text {
                        content: hex::encode(cketh_subaccount)
                    }
                ),
            ]
        }
    );
}

#[tokio::test]
async fn test_withdraw_erc20_uses_sepolia_symbols() {
    let args = WithdrawErc20Arg {
        ckerc20_ledger_id: cksepolia_usdc().ckerc20_ledger_id,
        ..withdraw_erc20_arg(2_000_000)
    };
    let message = expect_generic_display(
        consent_info(
            make_request(
                "withdraw_erc20",
                Encode!(&args).unwrap(),
                Some(DisplayMessageType::GenericDisplay),
            ),
            &sepolia_config(),
        )
        .await
        .unwrap(),
    );
    assert!(message.starts_with("# Convert ckSepoliaUSDC to SepoliaUSDC"));
    assert!(message.contains("ckSepoliaETH minter"));
    assert!(message.contains("burns ckSepoliaETH from your account"));
    assert!(message.contains("`2 ckSepoliaUSDC`"));

    let fields_display = expect_fields_display(
        consent_info(
            make_request(
                "withdraw_erc20",
                Encode!(&args).unwrap(),
                Some(DisplayMessageType::FieldsDisplay),
            ),
            &sepolia_config(),
        )
        .await
        .unwrap(),
    );
    assert_eq!(fields_display.intent, "ckSepoliaUSDC to SepoliaUSDC");
    assert_eq!(
        fields_display.fields[2].1,
        Value::Text {
            content: "Paid in ckSepoliaETH as estimated by the minter; any unused part is not \
                      refunded"
                .to_string()
        }
    );
}

#[tokio::test]
async fn test_withdraw_erc20_rejects_unsupported_ckerc20_ledger() {
    let unsupported_ledgers = [
        Principal::management_canister(),
        // Supported on Sepolia, but not on Mainnet.
        cksepolia_usdc().ckerc20_ledger_id,
    ];
    for ckerc20_ledger_id in unsupported_ledgers {
        let args = WithdrawErc20Arg {
            ckerc20_ledger_id,
            ..withdraw_erc20_arg(1_000_000)
        };
        let req = make_request("withdraw_erc20", Encode!(&args).unwrap(), None);
        let description = expect_unsupported_canister_call(
            consent_info_without_ledger_call(req, &mainnet_config()).await,
        );
        assert_eq!(
            description,
            format!("The ckERC20 ledger {ckerc20_ledger_id} is not supported by the minter.")
        );
    }
}

#[tokio::test]
async fn test_withdraw_erc20_rejected_when_no_ckerc20_token_is_supported() {
    let config = ConsentMessageConfig {
        ckerc20_tokens: vec![],
        ..mainnet_config()
    };
    let req = make_request(
        "withdraw_erc20",
        Encode!(&withdraw_erc20_arg(1_000_000)).unwrap(),
        None,
    );
    let description =
        expect_unsupported_canister_call(consent_info_without_ledger_call(req, &config).await);
    assert!(description.contains("is not supported by the minter"));
}

#[tokio::test]
async fn test_withdraw_erc20_fails_when_decimals_unavailable() {
    let req = make_request(
        "withdraw_erc20",
        Encode!(&withdraw_erc20_arg(1_000_000)).unwrap(),
        None,
    );
    let error = Icrc21Error::ConsentMessageUnavailable(ErrorInfo {
        description: "ledger unavailable".to_string(),
    });
    let result = build_consent_info(
        req,
        &mainnet_config(),
        async |_ledger_id| Err(error.clone()),
    )
    .await;
    assert_eq!(result, Err(error));
}

#[tokio::test]
async fn test_invalid_destination_is_rejected() {
    // The minter must not interpolate an invalid address into the Markdown consent message:
    // that would be a Markdown-injection vector (e.g. an "address" containing newlines,
    // backticks, or '#' that fakes additional fields). Addresses the actual call rejects
    // (zero address, blocked addresses) are rejected too.
    for bad_address in [
        "not-a-real-address".to_string(),
        "221E931fbFcb9bd54DdD26cE6f5e29E98AdD01C0".to_string(),
        format!("{DESTINATION}\n# You will receive 100 ETH"),
        format!("{DESTINATION}`\n\n**Amount:** 100 ETH\n`"),
        "0x0000000000000000000000000000000000000000".to_string(),
        SAMPLE_BLOCKED_ADDRESS.to_string(),
    ] {
        let withdraw_eth = WithdrawalArg {
            recipient: bad_address.clone(),
            ..withdraw_eth_arg(1_000_000_000_000_000_000)
        };
        let withdraw_erc20 = WithdrawErc20Arg {
            recipient: bad_address.clone(),
            ..withdraw_erc20_arg(1_000_000)
        };
        for req in [
            make_request(
                "withdraw_eth",
                Encode!(&withdraw_eth).unwrap(),
                Some(DisplayMessageType::GenericDisplay),
            ),
            make_request(
                "withdraw_erc20",
                Encode!(&withdraw_erc20).unwrap(),
                Some(DisplayMessageType::GenericDisplay),
            ),
        ] {
            let description = expect_unsupported_canister_call(
                consent_info_without_ledger_call(req, &mainnet_config()).await,
            );
            assert!(
                description.starts_with("Invalid Ethereum destination address"),
                "unexpected error description for {bad_address:?}: {description}"
            );
        }
    }
}

#[tokio::test]
async fn test_withdraw_eth_amount_below_minimum_is_rejected() {
    // `withdraw_eth` rejects these amounts with `AmountTooLow` before burning anything.
    for amount in [0, MINIMUM_WITHDRAWAL_AMOUNT - 1] {
        let req = make_request(
            "withdraw_eth",
            Encode!(&withdraw_eth_arg(amount)).unwrap(),
            None,
        );
        let description = expect_unsupported_canister_call(
            consent_info_without_ledger_call(req, &mainnet_config()).await,
        );
        assert_eq!(
            description,
            "The amount is below the minimum withdrawal amount of 0.03 ckETH."
        );
    }

    let req = make_request(
        "withdraw_eth",
        Encode!(&withdraw_eth_arg(MINIMUM_WITHDRAWAL_AMOUNT)).unwrap(),
        None,
    );
    let message = expect_generic_display(
        consent_info_without_ledger_call(req, &mainnet_config())
            .await
            .unwrap(),
    );
    assert!(message.contains("**Amount to convert:** `0.03 ckETH`"));
}

#[tokio::test]
async fn test_amount_larger_than_u256_is_rejected() {
    let too_large = Nat(BigUint::from(2_u8).pow(256));
    let withdraw_eth = WithdrawalArg {
        amount: too_large.clone(),
        ..withdraw_eth_arg(0)
    };
    let withdraw_erc20 = WithdrawErc20Arg {
        amount: too_large,
        ..withdraw_erc20_arg(0)
    };
    for req in [
        make_request("withdraw_eth", Encode!(&withdraw_eth).unwrap(), None),
        make_request("withdraw_erc20", Encode!(&withdraw_erc20).unwrap(), None),
    ] {
        let description = expect_unsupported_canister_call(
            consent_info_without_ledger_call(req, &mainnet_config()).await,
        );
        assert!(
            description.contains("Invalid amount"),
            "unexpected error description: {description}"
        );
    }
}

#[tokio::test]
async fn test_metadata_echoes_utc_offset() {
    let mut req = make_request(
        "withdraw_eth",
        Encode!(&withdraw_eth_arg(1_000_000_000_000_000_000)).unwrap(),
        None,
    );
    req.user_preferences.metadata = ConsentMessageMetadata {
        language: "fr".to_string(),
        utc_offset_minutes: Some(120),
    };
    let info = consent_info_without_ledger_call(req, &mainnet_config())
        .await
        .unwrap();
    assert_eq!(
        info.metadata,
        ConsentMessageMetadata {
            language: "en".to_string(),
            utc_offset_minutes: Some(120),
        }
    );
}
