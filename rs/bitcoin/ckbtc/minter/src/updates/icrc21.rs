//! Implementation of the [ICRC-21](https://github.com/dfinity/ICRC/blob/main/ICRCs/ICRC-21/ICRC-21.md)
//! Canister Call Consent Message standard for the ckBTC minter.

use crate::Network;
use crate::address::BitcoinAddress;
use crate::state::read_state;
use crate::updates::retrieve_btc::{RetrieveBtcArgs, RetrieveBtcWithApprovalArgs};
use candid::{CandidType, Decode, Deserialize};
use icrc_ledger_types::icrc21::errors::{ErrorInfo, Icrc21Error};
use icrc_ledger_types::icrc21::lib::MAX_CONSENT_MESSAGE_ARG_SIZE_BYTES;
use icrc_ledger_types::icrc21::requests::{
    ConsentMessageMetadata, ConsentMessageRequest, DisplayMessageType,
};
use icrc_ledger_types::icrc21::responses::{ConsentInfo, ConsentMessage, FieldsDisplay, Value};

/// The number of decimals used to display token amounts.
/// Both ckBTC and BTC use 8 decimals (1 BTC = 10^8 satoshis).
const DECIMALS: u8 = 8;

/// Token symbols used in consent messages. They depend on the configured
/// Bitcoin network so that test deployments use the test-token names.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct TokenSymbols {
    /// The ledger token, e.g. "ckBTC" on mainnet, "ckTESTBTC" otherwise.
    ckbtc: &'static str,
    /// The native Bitcoin token, e.g. "BTC" on mainnet, "TESTBTC" otherwise.
    btc: &'static str,
}

impl TokenSymbols {
    fn for_network(network: Network) -> Self {
        match network {
            Network::Mainnet => Self {
                ckbtc: "ckBTC",
                btc: "BTC",
            },
            Network::Testnet | Network::Regtest => Self {
                ckbtc: "ckTESTBTC",
                btc: "TESTBTC",
            },
        }
    }
}

/// An entry of the ICRC-10 supported standards list.
#[derive(Clone, Debug, CandidType, Deserialize, Eq, PartialEq)]
pub struct StandardRecord {
    pub name: String,
    pub url: String,
}

pub fn icrc10_supported_standards() -> Vec<StandardRecord> {
    vec![
        StandardRecord {
            name: "ICRC-10".to_string(),
            url: "https://github.com/dfinity/ICRC/blob/main/ICRCs/ICRC-10/ICRC-10.md".to_string(),
        },
        StandardRecord {
            name: "ICRC-21".to_string(),
            url: "https://github.com/dfinity/ICRC/blob/main/ICRCs/ICRC-21/ICRC-21.md".to_string(),
        },
    ]
}

pub fn icrc21_canister_call_consent_message(
    consent_msg_request: ConsentMessageRequest,
) -> Result<ConsentInfo, Icrc21Error> {
    let network = read_state(|s| s.btc_network);
    build_consent_info(consent_msg_request, network)
}

fn build_consent_info(
    consent_msg_request: ConsentMessageRequest,
    network: Network,
) -> Result<ConsentInfo, Icrc21Error> {
    if consent_msg_request.arg.len() > MAX_CONSENT_MESSAGE_ARG_SIZE_BYTES as usize {
        return Err(Icrc21Error::UnsupportedCanisterCall(ErrorInfo {
            description: format!(
                "The argument size is too large. The maximum allowed size is \
                 {MAX_CONSENT_MESSAGE_ARG_SIZE_BYTES} bytes."
            ),
        }));
    }

    let display_type = consent_msg_request
        .user_preferences
        .device_spec
        .clone()
        .unwrap_or(DisplayMessageType::GenericDisplay);

    let symbols = TokenSymbols::for_network(network);

    let consent_message = match consent_msg_request.method.as_str() {
        "retrieve_btc_with_approval" => {
            let args = Decode!(
                consent_msg_request.arg.as_slice(),
                RetrieveBtcWithApprovalArgs
            )
            .map_err(|e| {
                Icrc21Error::UnsupportedCanisterCall(ErrorInfo {
                    description: format!("Failed to decode RetrieveBtcWithApprovalArgs: {e}"),
                })
            })?;
            validate_address(&args.address, network)?;
            build_retrieve_btc_with_approval_message(&args, &display_type, symbols)
        }
        "retrieve_btc" => {
            let args =
                Decode!(consent_msg_request.arg.as_slice(), RetrieveBtcArgs).map_err(|e| {
                    Icrc21Error::UnsupportedCanisterCall(ErrorInfo {
                        description: format!("Failed to decode RetrieveBtcArgs: {e}"),
                    })
                })?;
            validate_address(&args.address, network)?;
            build_retrieve_btc_message(&args, &display_type, symbols)
        }
        method => {
            return Err(Icrc21Error::UnsupportedCanisterCall(ErrorInfo {
                description: format!(
                    "The method '{method}' is not supported by the ckBTC minter ICRC-21 endpoint."
                ),
            }));
        }
    };

    // Respond in English regardless of what the client requested for now.
    let metadata = ConsentMessageMetadata {
        language: "en".to_string(),
        utc_offset_minutes: consent_msg_request
            .user_preferences
            .metadata
            .utc_offset_minutes,
    };

    Ok(ConsentInfo {
        metadata,
        consent_message,
    })
}

fn build_retrieve_btc_with_approval_message(
    args: &RetrieveBtcWithApprovalArgs,
    display_type: &DisplayMessageType,
    symbols: TokenSymbols,
) -> ConsentMessage {
    let TokenSymbols { ckbtc, btc } = symbols;
    let amount = format_amount(args.amount, DECIMALS);
    match display_type {
        DisplayMessageType::GenericDisplay => {
            let mut message = format!(
                "# Convert {ckbtc} to {btc}\n\n\
                 Authorize the {ckbtc} minter to burn {ckbtc} from your account and \
                 send the equivalent amount in {btc} (minus network and minter fees) to \
                 the Bitcoin address below.\n\n\
                 **Amount to convert:** `{amount} {ckbtc}`\n\n\
                 **Bitcoin destination address:**\n`{address}`",
                address = args.address,
            );
            if let Some(subaccount) = args.from_subaccount {
                message.push_str(&format!(
                    "\n\n**{ckbtc} source subaccount:**\n`{}`",
                    hex::encode(subaccount)
                ));
            }
            ConsentMessage::GenericDisplayMessage(message)
        }
        DisplayMessageType::FieldsDisplay => {
            // Long values (Bitcoin addresses, subaccount hex) are sent as a
            // single `Value::Text` per the ICRC-21 spec — wallets are
            // responsible for paginating them across screens. See e.g. the
            // Ledger ICP app, which calls `handle_ui_message` to chunk the
            // value into device-sized pages.
            let mut fields = vec![
                (
                    "Amount".to_string(),
                    Value::TokenAmount {
                        decimals: DECIMALS,
                        amount: args.amount,
                        symbol: ckbtc.to_string(),
                    },
                ),
                (
                    format!("{btc} address"),
                    Value::Text {
                        content: args.address.clone(),
                    },
                ),
            ];
            if let Some(subaccount) = args.from_subaccount {
                fields.push((
                    "From subaccount".to_string(),
                    Value::Text {
                        content: hex::encode(subaccount),
                    },
                ));
            }
            ConsentMessage::FieldsDisplayMessage(FieldsDisplay {
                intent: format!("{ckbtc} to {btc}"),
                fields,
            })
        }
    }
}

fn build_retrieve_btc_message(
    args: &RetrieveBtcArgs,
    display_type: &DisplayMessageType,
    symbols: TokenSymbols,
) -> ConsentMessage {
    let TokenSymbols { ckbtc, btc } = symbols;
    let amount = format_amount(args.amount, DECIMALS);
    match display_type {
        DisplayMessageType::GenericDisplay => ConsentMessage::GenericDisplayMessage(format!(
            "# Convert {ckbtc} to {btc}\n\n\
             Withdraw {ckbtc} previously deposited to your withdrawal account \
             with the {ckbtc} minter and send the equivalent amount in {btc} \
             (minus network and minter fees) to the Bitcoin address below.\n\n\
             **Amount to convert:** `{amount} {ckbtc}`\n\n\
             **Bitcoin destination address:**\n`{address}`",
            address = args.address,
        )),
        DisplayMessageType::FieldsDisplay => ConsentMessage::FieldsDisplayMessage(FieldsDisplay {
            intent: format!("{ckbtc} to {btc}"),
            fields: vec![
                (
                    "Amount".to_string(),
                    Value::TokenAmount {
                        decimals: DECIMALS,
                        amount: args.amount,
                        symbol: ckbtc.to_string(),
                    },
                ),
                (
                    format!("{btc} address"),
                    Value::Text {
                        content: args.address.clone(),
                    },
                ),
            ],
        }),
    }
}

/// Verifies that `address` parses as a valid Bitcoin address on the configured
/// network before it gets interpolated into a consent message. This both
/// guarantees the user is shown a meaningful (parseable) destination and rules
/// out Markdown-injection vectors in the GenericDisplay output (e.g. an
/// "address" that contains newlines or backticks crafted to fake additional
/// fields). Uses the same parser as `retrieve_btc[_with_approval]`, so any
/// address the consent endpoint accepts is also accepted by the actual call.
fn validate_address(address: &str, network: Network) -> Result<(), Icrc21Error> {
    BitcoinAddress::parse(address, network).map_err(|e| {
        Icrc21Error::UnsupportedCanisterCall(ErrorInfo {
            description: format!("Invalid Bitcoin destination address: {e}"),
        })
    })?;
    Ok(())
}

fn format_amount(amount: u64, decimals: u8) -> String {
    let divisor = 10_u64.pow(decimals as u32);
    let whole = amount / divisor;
    let frac = amount % divisor;
    if frac == 0 {
        format!("{whole}")
    } else {
        let frac_str = format!("{frac:0width$}", width = decimals as usize);
        let trimmed = frac_str.trim_end_matches('0');
        format!("{whole}.{trimmed}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use candid::Encode;
    use icrc_ledger_types::icrc21::requests::ConsentMessageSpec;

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

    #[test]
    fn test_format_amount() {
        assert_eq!(format_amount(0, 8), "0");
        assert_eq!(format_amount(1, 8), "0.00000001");
        assert_eq!(format_amount(100_000_000, 8), "1");
        assert_eq!(format_amount(150_000_000, 8), "1.5");
        assert_eq!(format_amount(123_456_789, 8), "1.23456789");
    }

    #[test]
    fn test_unsupported_method() {
        let req = make_request("update_balance", vec![], None);
        let err = build_consent_info(req, Network::Mainnet).unwrap_err();
        assert!(matches!(err, Icrc21Error::UnsupportedCanisterCall(_)));
    }

    #[test]
    fn test_argument_too_large() {
        let req = make_request(
            "retrieve_btc_with_approval",
            vec![0; MAX_CONSENT_MESSAGE_ARG_SIZE_BYTES as usize + 1],
            None,
        );
        let err = build_consent_info(req, Network::Mainnet).unwrap_err();
        match err {
            Icrc21Error::UnsupportedCanisterCall(info) => {
                assert!(info.description.contains("argument size is too large"));
            }
            _ => panic!("expected UnsupportedCanisterCall, got {err:?}"),
        }
    }

    #[test]
    fn test_retrieve_btc_with_approval_generic_display() {
        let args = RetrieveBtcWithApprovalArgs {
            amount: 150_000,
            address: "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq".to_string(),
            from_subaccount: None,
        };
        let req = make_request(
            "retrieve_btc_with_approval",
            Encode!(&args).unwrap(),
            Some(DisplayMessageType::GenericDisplay),
        );
        let info = build_consent_info(req, Network::Mainnet).unwrap();
        assert_eq!(info.metadata.language, "en");
        let message = match info.consent_message {
            ConsentMessage::GenericDisplayMessage(m) => m,
            other => panic!("expected GenericDisplayMessage, got {other:?}"),
        };
        assert!(message.starts_with("# Convert ckBTC to BTC"));
        assert!(message.contains("0.0015 ckBTC"));
        assert!(message.contains("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"));
        // No subaccount section if from_subaccount is None.
        assert!(!message.contains("source subaccount"));
    }

    #[test]
    fn test_retrieve_btc_with_approval_generic_display_with_subaccount() {
        let mut subaccount = [0_u8; 32];
        subaccount[31] = 0x42;
        let args = RetrieveBtcWithApprovalArgs {
            amount: 100_000_000,
            address: "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq".to_string(),
            from_subaccount: Some(subaccount),
        };
        let req = make_request("retrieve_btc_with_approval", Encode!(&args).unwrap(), None);
        let info = build_consent_info(req, Network::Mainnet).unwrap();
        let message = match info.consent_message {
            ConsentMessage::GenericDisplayMessage(m) => m,
            other => panic!("expected GenericDisplayMessage, got {other:?}"),
        };
        assert!(message.contains("1 ckBTC"));
        assert!(message.contains(&hex::encode(subaccount)));
    }

    #[test]
    fn test_retrieve_btc_with_approval_fields_display() {
        // Long values (Bitcoin address, subaccount hex) are emitted as a
        // single Value::Text — wallets paginate them across screens. The
        // number of fields is therefore independent of the value length.
        let mut subaccount = [0_u8; 32];
        subaccount[0] = 0xab;
        subaccount[31] = 0xcd;
        let address = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq".to_string();
        let args = RetrieveBtcWithApprovalArgs {
            amount: 250_000,
            address: address.clone(),
            from_subaccount: Some(subaccount),
        };
        let req = make_request(
            "retrieve_btc_with_approval",
            Encode!(&args).unwrap(),
            Some(DisplayMessageType::FieldsDisplay),
        );
        let info = build_consent_info(req, Network::Mainnet).unwrap();
        let fields_display = match info.consent_message {
            ConsentMessage::FieldsDisplayMessage(f) => f,
            other => panic!("expected FieldsDisplayMessage, got {other:?}"),
        };
        assert_eq!(fields_display.intent, "ckBTC to BTC");
        assert_eq!(
            fields_display.fields,
            vec![
                (
                    "Amount".to_string(),
                    Value::TokenAmount {
                        decimals: DECIMALS,
                        amount: 250_000,
                        symbol: "ckBTC".to_string(),
                    }
                ),
                ("BTC address".to_string(), Value::Text { content: address }),
                (
                    "From subaccount".to_string(),
                    Value::Text {
                        content: hex::encode(subaccount)
                    }
                ),
            ]
        );
    }

    #[test]
    fn test_retrieve_btc_with_approval_fields_display_no_subaccount() {
        let args = RetrieveBtcWithApprovalArgs {
            amount: 250_000,
            address: "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq".to_string(),
            from_subaccount: None,
        };
        let req = make_request(
            "retrieve_btc_with_approval",
            Encode!(&args).unwrap(),
            Some(DisplayMessageType::FieldsDisplay),
        );
        let info = build_consent_info(req, Network::Mainnet).unwrap();
        let fields_display = match info.consent_message {
            ConsentMessage::FieldsDisplayMessage(f) => f,
            other => panic!("expected FieldsDisplayMessage, got {other:?}"),
        };
        assert_eq!(fields_display.fields.len(), 2);
        // No subaccount field when from_subaccount is None.
        assert!(
            !fields_display
                .fields
                .iter()
                .any(|(label, _)| label == "From subaccount")
        );
    }

    #[test]
    fn test_retrieve_btc_fields_display() {
        let address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string();
        let args = RetrieveBtcArgs {
            amount: 50_000,
            address: address.clone(),
        };
        let req = make_request(
            "retrieve_btc",
            Encode!(&args).unwrap(),
            Some(DisplayMessageType::FieldsDisplay),
        );
        let info = build_consent_info(req, Network::Mainnet).unwrap();
        let fields_display = match info.consent_message {
            ConsentMessage::FieldsDisplayMessage(f) => f,
            other => panic!("expected FieldsDisplayMessage, got {other:?}"),
        };
        assert_eq!(fields_display.intent, "ckBTC to BTC");
        assert_eq!(
            fields_display.fields,
            vec![
                (
                    "Amount".to_string(),
                    Value::TokenAmount {
                        decimals: DECIMALS,
                        amount: 50_000,
                        symbol: "ckBTC".to_string(),
                    }
                ),
                ("BTC address".to_string(), Value::Text { content: address }),
            ]
        );
    }

    #[test]
    fn test_token_symbols_for_network() {
        assert_eq!(
            TokenSymbols::for_network(Network::Mainnet),
            TokenSymbols {
                ckbtc: "ckBTC",
                btc: "BTC"
            }
        );
        assert_eq!(
            TokenSymbols::for_network(Network::Testnet),
            TokenSymbols {
                ckbtc: "ckTESTBTC",
                btc: "TESTBTC"
            }
        );
        assert_eq!(
            TokenSymbols::for_network(Network::Regtest),
            TokenSymbols {
                ckbtc: "ckTESTBTC",
                btc: "TESTBTC"
            }
        );
    }

    #[test]
    fn test_retrieve_btc_with_approval_uses_testnet_symbols() {
        let args = RetrieveBtcWithApprovalArgs {
            amount: 250_000,
            address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
            from_subaccount: None,
        };
        let req = make_request(
            "retrieve_btc_with_approval",
            Encode!(&args).unwrap(),
            Some(DisplayMessageType::FieldsDisplay),
        );
        let info = build_consent_info(req, Network::Testnet).unwrap();
        let fields_display = match info.consent_message {
            ConsentMessage::FieldsDisplayMessage(f) => f,
            other => panic!("expected FieldsDisplayMessage, got {other:?}"),
        };
        assert_eq!(fields_display.intent, "ckTESTBTC to TESTBTC");
        match &fields_display.fields[0].1 {
            Value::TokenAmount { symbol, .. } => assert_eq!(symbol, "ckTESTBTC"),
            other => panic!("expected TokenAmount, got {other:?}"),
        }
        // FieldsDisplay address label uses the testnet native symbol too.
        assert_eq!(fields_display.fields[1].0, "TESTBTC address");
    }

    #[test]
    fn test_retrieve_btc_with_approval_generic_uses_testnet_symbols() {
        let args = RetrieveBtcWithApprovalArgs {
            amount: 100_000_000,
            address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string(),
            from_subaccount: None,
        };
        let req = make_request(
            "retrieve_btc_with_approval",
            Encode!(&args).unwrap(),
            Some(DisplayMessageType::GenericDisplay),
        );
        let info = build_consent_info(req, Network::Testnet).unwrap();
        let message = match info.consent_message {
            ConsentMessage::GenericDisplayMessage(m) => m,
            other => panic!("expected GenericDisplayMessage, got {other:?}"),
        };
        assert!(message.starts_with("# Convert ckTESTBTC to TESTBTC"));
        assert!(message.contains("1 ckTESTBTC"));
        assert!(message.contains("ckTESTBTC minter"));
        assert!(message.contains("equivalent amount in TESTBTC"));
    }

    #[test]
    fn test_retrieve_btc_generic_display() {
        let args = RetrieveBtcArgs {
            amount: 50_000,
            address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".to_string(),
        };
        let req = make_request("retrieve_btc", Encode!(&args).unwrap(), None);
        let info = build_consent_info(req, Network::Mainnet).unwrap();
        let message = match info.consent_message {
            ConsentMessage::GenericDisplayMessage(m) => m,
            other => panic!("expected GenericDisplayMessage, got {other:?}"),
        };
        assert!(message.contains("withdrawal account"));
        assert!(message.contains("0.0005 ckBTC"));
        assert!(message.contains("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"));
    }

    #[test]
    fn test_invalid_args() {
        let req = make_request("retrieve_btc_with_approval", vec![1, 2, 3], None);
        let err = build_consent_info(req, Network::Mainnet).unwrap_err();
        match err {
            Icrc21Error::UnsupportedCanisterCall(info) => {
                assert!(info.description.contains("Failed to decode"));
            }
            _ => panic!("expected UnsupportedCanisterCall, got {err:?}"),
        }
    }

    #[test]
    fn test_malformed_address_is_rejected() {
        // The minter must not interpolate an unparseable address into the
        // Markdown consent message — that would be a Markdown-injection vector
        // (e.g. an "address" containing newlines, backticks, or '#' that fakes
        // additional fields).
        for bad_address in [
            "not-a-real-address",
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq\n# You will receive 100 BTC",
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa`\n\n**Amount:** 100 BTC\n`",
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", // valid testnet but on Mainnet
        ] {
            let args = RetrieveBtcWithApprovalArgs {
                amount: 50_000,
                address: bad_address.to_string(),
                from_subaccount: None,
            };
            let req = make_request(
                "retrieve_btc_with_approval",
                Encode!(&args).unwrap(),
                Some(DisplayMessageType::GenericDisplay),
            );
            let err = build_consent_info(req, Network::Mainnet).unwrap_err();
            match err {
                Icrc21Error::UnsupportedCanisterCall(info) => {
                    assert!(
                        info.description
                            .contains("Invalid Bitcoin destination address"),
                        "unexpected error description: {}",
                        info.description
                    );
                }
                other => panic!("expected UnsupportedCanisterCall, got {other:?}"),
            }
        }
    }
}
