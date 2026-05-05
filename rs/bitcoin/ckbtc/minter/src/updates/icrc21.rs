//! Implementation of the [ICRC-21](https://github.com/dfinity/wg-identity-authentication/blob/main/topics/ICRC-21/icrc_21_consent_msg.md)
//! Canister Call Consent Message standard for the ckBTC minter.

use crate::Network;
use crate::state::read_state;
use crate::updates::retrieve_btc::{RetrieveBtcArgs, RetrieveBtcWithApprovalArgs};
use candid::{CandidType, Decode, Deserialize};
use icrc_ledger_types::icrc1::account::Subaccount;
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

/// Maximum number of characters per `Value::Text` field for the FieldsDisplay
/// variant. Hardware wallets like the Ledger Nano S+ have a small display and
/// cannot fit a full Bitcoin address (up to 62 characters for bech32m) or a
/// 64-character hex subaccount on a single screen. Long values are split into
/// multiple fields with a "(N/M)" pagination suffix in the label so each chunk
/// fits on a single screen with the label on top.
///
/// Field labels are kept short (e.g. "BTC address", "From subaccount") so that
/// even with a "(N/M)" suffix the label still fits on one line at the typical
/// hardware-wallet font size.
const FIELDS_DISPLAY_TEXT_CHUNK_LEN: usize = 18;

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
            url: "https://github.com/dfinity/wg-identity-authentication/blob/main/topics/ICRC-21/icrc_21_consent_msg.md".to_string(),
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
            build_retrieve_btc_with_approval_message(&args, &display_type, symbols)
        }
        "retrieve_btc" => {
            let args =
                Decode!(consent_msg_request.arg.as_slice(), RetrieveBtcArgs).map_err(|e| {
                    Icrc21Error::UnsupportedCanisterCall(ErrorInfo {
                        description: format!("Failed to decode RetrieveBtcArgs: {e}"),
                    })
                })?;
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
    match display_type {
        DisplayMessageType::GenericDisplay => {
            let mut message = String::new();
            message.push_str(&format!("# Convert {ckbtc} to {btc}"));
            message.push_str(&format!(
                "\n\nAuthorize the {ckbtc} minter to burn {ckbtc} from your account and \
                 send the equivalent amount in {btc} (minus network and minter fees) to \
                 the Bitcoin address below."
            ));
            message.push_str(&format!(
                "\n\n**Amount to convert:** `{} {ckbtc}`",
                format_amount(args.amount, DECIMALS)
            ));
            message.push_str(&format!(
                "\n\n**Bitcoin destination address:**\n`{}`",
                args.address
            ));
            if let Some(subaccount) = args.from_subaccount {
                message.push_str(&format!(
                    "\n\n**{ckbtc} source subaccount:**\n`{}`",
                    hex::encode(subaccount)
                ));
            }
            ConsentMessage::GenericDisplayMessage(message)
        }
        DisplayMessageType::FieldsDisplay => {
            let mut fields = Vec::new();
            fields.push((
                "Amount".to_string(),
                Value::TokenAmount {
                    decimals: DECIMALS,
                    amount: args.amount,
                    symbol: ckbtc.to_string(),
                },
            ));
            push_chunked_text(&mut fields, &format!("{btc} address"), &args.address);
            if let Some(subaccount) = args.from_subaccount {
                push_chunked_text(
                    &mut fields,
                    "From subaccount",
                    &format_subaccount(&subaccount),
                );
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
    match display_type {
        DisplayMessageType::GenericDisplay => {
            let mut message = String::new();
            message.push_str(&format!("# Convert {ckbtc} to {btc}"));
            message.push_str(&format!(
                "\n\nWithdraw {ckbtc} previously deposited to your withdrawal account \
                 with the {ckbtc} minter and send the equivalent amount in {btc} \
                 (minus network and minter fees) to the Bitcoin address below."
            ));
            message.push_str(&format!(
                "\n\n**Amount to convert:** `{} {ckbtc}`",
                format_amount(args.amount, DECIMALS)
            ));
            message.push_str(&format!(
                "\n\n**Bitcoin destination address:**\n`{}`",
                args.address
            ));
            ConsentMessage::GenericDisplayMessage(message)
        }
        DisplayMessageType::FieldsDisplay => {
            let mut fields = vec![(
                "Amount".to_string(),
                Value::TokenAmount {
                    decimals: DECIMALS,
                    amount: args.amount,
                    symbol: ckbtc.to_string(),
                },
            )];
            push_chunked_text(&mut fields, &format!("{btc} address"), &args.address);
            ConsentMessage::FieldsDisplayMessage(FieldsDisplay {
                intent: format!("{ckbtc} to {btc}"),
                fields,
            })
        }
    }
}

/// Pushes a `(label, Value::Text)` field, splitting `content` into chunks of at
/// most [`FIELDS_DISPLAY_TEXT_CHUNK_LEN`] characters when needed. When chunked,
/// the label gets a "(i/n)" suffix so a hardware-wallet user can tell where
/// each chunk fits in the whole value.
///
/// Bitcoin addresses and the chunked subaccount hex are pure ASCII, so chunking
/// on byte boundaries is identical to chunking on character boundaries here.
/// We still iterate on Unicode scalar values via [`char`] so the helper stays
/// safe for any future caller that passes non-ASCII text.
fn push_chunked_text(fields: &mut Vec<(String, Value)>, label: &str, content: &str) {
    let chunks = chunk_text(content, FIELDS_DISPLAY_TEXT_CHUNK_LEN);
    if chunks.len() <= 1 {
        fields.push((
            label.to_string(),
            Value::Text {
                content: content.to_string(),
            },
        ));
        return;
    }
    let total = chunks.len();
    for (i, chunk) in chunks.into_iter().enumerate() {
        fields.push((
            format!("{label} ({}/{total})", i + 1),
            Value::Text { content: chunk },
        ));
    }
}

fn chunk_text(content: &str, max_chars: usize) -> Vec<String> {
    assert!(max_chars > 0, "max_chars must be greater than zero");
    if content.is_empty() {
        return vec![String::new()];
    }
    let mut chunks = Vec::new();
    let mut current = String::new();
    let mut count = 0;
    for c in content.chars() {
        current.push(c);
        count += 1;
        if count == max_chars {
            chunks.push(std::mem::take(&mut current));
            count = 0;
        }
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    chunks
}

fn format_subaccount(subaccount: &Subaccount) -> String {
    hex::encode(subaccount)
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
    fn test_retrieve_btc_with_approval_fields_display_short_address() {
        // A 16-character address fits in a single chunk so the label is not
        // suffixed with "(i/n)".
        let args = RetrieveBtcWithApprovalArgs {
            amount: 250_000,
            address: "tb1qexampleaddres".to_string(),
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
        assert_eq!(fields_display.intent, "ckBTC to BTC");
        assert_eq!(fields_display.fields.len(), 2);
        assert_eq!(
            fields_display.fields[0],
            (
                "Amount".to_string(),
                Value::TokenAmount {
                    decimals: DECIMALS,
                    amount: 250_000,
                    symbol: "ckBTC".to_string(),
                }
            )
        );
        assert_eq!(
            fields_display.fields[1],
            (
                "BTC address".to_string(),
                Value::Text {
                    content: "tb1qexampleaddres".to_string(),
                }
            )
        );
    }

    #[test]
    fn test_retrieve_btc_with_approval_fields_display_long_address_and_subaccount() {
        // Bech32 address (42 chars) and subaccount (64 hex chars) both exceed
        // FIELDS_DISPLAY_TEXT_CHUNK_LEN and must be paginated.
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

        // Address: 42 chars / 18 = 3 chunks (18 + 18 + 6).
        // Subaccount: 64 chars / 18 = 4 chunks (18 + 18 + 18 + 10).
        // Plus 1 amount field => 1 + 3 + 4 = 8 fields.
        assert_eq!(fields_display.fields.len(), 8);

        assert_eq!(fields_display.fields[0].0, "Amount");
        assert!(matches!(
            fields_display.fields[0].1,
            Value::TokenAmount { .. }
        ));

        // Address chunks.
        assert_eq!(fields_display.fields[1].0, "BTC address (1/3)");
        assert_eq!(fields_display.fields[2].0, "BTC address (2/3)");
        assert_eq!(fields_display.fields[3].0, "BTC address (3/3)");
        let chunk_lens: Vec<usize> = (1..=3)
            .map(|i| match &fields_display.fields[i].1 {
                Value::Text { content } => content.chars().count(),
                _ => panic!("expected Text"),
            })
            .collect();
        assert_eq!(chunk_lens, vec![18, 18, 6]);
        // Reassemble and check the original is preserved exactly.
        let mut reassembled = String::new();
        for i in 1..=3 {
            if let Value::Text { content } = &fields_display.fields[i].1 {
                reassembled.push_str(content);
            }
        }
        assert_eq!(reassembled, address);

        // Subaccount chunks.
        for (i, expected_label) in [
            "From subaccount (1/4)",
            "From subaccount (2/4)",
            "From subaccount (3/4)",
            "From subaccount (4/4)",
        ]
        .iter()
        .enumerate()
        {
            assert_eq!(fields_display.fields[4 + i].0, *expected_label);
        }
        let mut subaccount_reassembled = String::new();
        for i in 4..8 {
            if let Value::Text { content } = &fields_display.fields[i].1 {
                subaccount_reassembled.push_str(content);
            }
        }
        assert_eq!(subaccount_reassembled, hex::encode(subaccount));
    }

    #[test]
    fn test_retrieve_btc_fields_display() {
        // Mainnet legacy address — 34 chars => 2 chunks (18 + 16).
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
        assert_eq!(fields_display.fields.len(), 3);
        assert_eq!(fields_display.fields[1].0, "BTC address (1/2)");
        assert_eq!(fields_display.fields[2].0, "BTC address (2/2)");
        let mut reassembled = String::new();
        for i in 1..=2 {
            if let Value::Text { content } = &fields_display.fields[i].1 {
                reassembled.push_str(content);
                assert!(content.chars().count() <= FIELDS_DISPLAY_TEXT_CHUNK_LEN);
            }
        }
        assert_eq!(reassembled, address);
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
            address: "tb1qexampleaddress".to_string(),
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
            address: "tb1qexampleaddress".to_string(),
            from_subaccount: None,
        };
        let req = make_request(
            "retrieve_btc_with_approval",
            Encode!(&args).unwrap(),
            Some(DisplayMessageType::GenericDisplay),
        );
        let info = build_consent_info(req, Network::Regtest).unwrap();
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
    fn test_chunk_text() {
        assert_eq!(chunk_text("", 5), vec![""]);
        assert_eq!(chunk_text("abcde", 5), vec!["abcde"]);
        assert_eq!(chunk_text("abcdef", 5), vec!["abcde", "f"]);
        assert_eq!(chunk_text("abcdefghij", 5), vec!["abcde", "fghij"]);
        // Ensure splitting on char boundaries (multi-byte chars).
        let multi_byte = "αβγδε";
        let chunks = chunk_text(multi_byte, 2);
        assert_eq!(chunks, vec!["αβ", "γδ", "ε"]);
    }

    #[test]
    fn test_push_chunked_text_no_chunk_when_short() {
        let mut fields = Vec::new();
        push_chunked_text(&mut fields, "Label", "short");
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].0, "Label");
        assert_eq!(
            fields[0].1,
            Value::Text {
                content: "short".to_string()
            }
        );
    }

    #[test]
    fn test_push_chunked_text_chunks_when_long() {
        let mut fields = Vec::new();
        // 36 chars => 2 chunks of 18.
        let content: String = (0..36).map(|i| (b'a' + (i % 26) as u8) as char).collect();
        push_chunked_text(&mut fields, "Long", &content);
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].0, "Long (1/2)");
        assert_eq!(fields[1].0, "Long (2/2)");
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
}
