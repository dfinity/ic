//! Implementation of the [ICRC-21](https://github.com/dfinity/ICRC/blob/main/ICRCs/ICRC-21/ICRC-21.md)
//! Canister Call Consent Message standard for the ckBTC minter.

use crate::Network;
use crate::address::BitcoinAddress;
use crate::state::read_state;
use crate::updates::retrieve_btc::RetrieveBtcWithApprovalArgs;
use candid::{CandidType, Decode, Deserialize};
use icrc_ledger_types::icrc21::errors::{ErrorInfo, Icrc21Error};
use icrc_ledger_types::icrc21::lib::MAX_CONSENT_MESSAGE_ARG_SIZE_BYTES;
use icrc_ledger_types::icrc21::requests::{
    ConsentMessageMetadata, ConsentMessageRequest, DisplayMessageType,
};
use icrc_ledger_types::icrc21::responses::{ConsentInfo, ConsentMessage, FieldsDisplay, Value};

/// The number of decimals used to display token amounts.
/// Both ckBTC and BTC use 8 decimals (1 BTC = 10^8 satoshis).
pub(super) const DECIMALS: u8 = 8;

/// Token symbols used in consent messages. They depend on the configured
/// Bitcoin network so that test deployments use the test-token names.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(super) struct TokenSymbols {
    /// The ledger token, e.g. "ckBTC" on mainnet, "ckTESTBTC" otherwise.
    pub(super) ckbtc: &'static str,
    /// The native Bitcoin token, e.g. "BTC" on mainnet, "TESTBTC" otherwise.
    pub(super) btc: &'static str,
}

impl TokenSymbols {
    pub(super) fn for_network(network: Network) -> Self {
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

pub(super) fn build_consent_info(
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

/// Verifies that `address` parses as a valid Bitcoin address on the configured
/// network before it gets interpolated into a consent message. This both
/// guarantees the user is shown a meaningful (parseable) destination and rules
/// out Markdown-injection vectors in the GenericDisplay output (e.g. an
/// "address" that contains newlines or backticks crafted to fake additional
/// fields). Uses the same parser as `retrieve_btc_with_approval`, so any
/// address the consent endpoint accepts is also accepted by the actual call.
fn validate_address(address: &str, network: Network) -> Result<(), Icrc21Error> {
    BitcoinAddress::parse(address, network).map_err(|e| {
        Icrc21Error::UnsupportedCanisterCall(ErrorInfo {
            description: format!("Invalid Bitcoin destination address: {e}"),
        })
    })?;
    Ok(())
}

pub(super) fn format_amount(amount: u64, decimals: u8) -> String {
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
