//! Implementation of the [ICRC-21](https://github.com/dfinity/ICRC/blob/main/ICRCs/ICRC-21/ICRC-21.md)
//! Canister Call Consent Message standard for the ckETH minter.

#[cfg(test)]
mod tests;

use crate::address::validate_address_as_destination;
use crate::endpoints::WithdrawalArg;
use crate::endpoints::ckerc20::WithdrawErc20Arg;
use crate::erc20::CkErc20Token;
use crate::lifecycle::EthereumNetwork;
use crate::numeric::{Erc20Value, Wei};
use crate::state::{State, read_state};
use candid::{CandidType, Decode, Deserialize, Nat, Principal};
use ic_ethereum_types::Address;
use icrc_ledger_client_cdk::{CdkRuntime, ICRC1Client};
use icrc_ledger_types::icrc1::account::Subaccount;
use icrc_ledger_types::icrc21::errors::{ErrorInfo, Icrc21Error};
use icrc_ledger_types::icrc21::lib::MAX_CONSENT_MESSAGE_ARG_SIZE_BYTES;
use icrc_ledger_types::icrc21::requests::{
    ConsentMessageMetadata, ConsentMessageRequest, DisplayMessageType,
};
use icrc_ledger_types::icrc21::responses::{ConsentInfo, ConsentMessage, FieldsDisplay, Value};
use num_bigint::BigUint;
use num_traits::{ToPrimitive, Zero};

/// The number of decimals of ckETH and ETH (1 ETH = 10^18 wei).
const CKETH_DECIMALS: u8 = 18;

/// Token symbols used in consent messages. They depend on the configured
/// Ethereum network so that test deployments use the test-token names.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct TokenSymbols {
    /// The ledger token, e.g. "ckETH" on Mainnet, "ckSepoliaETH" on Sepolia.
    cketh: &'static str,
    /// The native Ethereum token, e.g. "ETH" on Mainnet, "SepoliaETH" on Sepolia.
    eth: &'static str,
}

impl TokenSymbols {
    fn for_network(network: EthereumNetwork) -> Self {
        match network {
            EthereumNetwork::Mainnet => Self {
                cketh: "ckETH",
                eth: "ETH",
            },
            EthereumNetwork::Sepolia => Self {
                cketh: "ckSepoliaETH",
                eth: "SepoliaETH",
            },
        }
    }
}

/// The part of the minter state needed to build a consent message.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ConsentMessageConfig {
    ethereum_network: EthereumNetwork,
    cketh_minimum_withdrawal_amount: Wei,
    /// The ckERC20 tokens supported by the minter. Empty if the ckERC20 feature is not active.
    ckerc20_tokens: Vec<CkErc20Token>,
}

impl ConsentMessageConfig {
    fn from_state(state: &State) -> Self {
        Self {
            ethereum_network: state.ethereum_network(),
            cketh_minimum_withdrawal_amount: state.cketh_minimum_withdrawal_amount,
            ckerc20_tokens: if state.is_ckerc20_feature_active() {
                state.supported_ck_erc20_tokens().collect()
            } else {
                vec![]
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

pub async fn icrc21_canister_call_consent_message(
    consent_msg_request: ConsentMessageRequest,
) -> Result<ConsentInfo, Icrc21Error> {
    let config = read_state(ConsentMessageConfig::from_state);
    build_consent_info(consent_msg_request, &config, ckerc20_ledger_decimals).await
}

/// The minter does not keep track of the number of decimals of ckERC20 tokens,
/// so they are retrieved from the ckERC20 ledger, which uses the same number of
/// decimals as the corresponding ERC-20 token.
async fn ckerc20_ledger_decimals(ckerc20_ledger_id: Principal) -> Result<u8, Icrc21Error> {
    ICRC1Client {
        runtime: CdkRuntime,
        ledger_canister_id: ckerc20_ledger_id,
    }
    .decimals()
    .await
    .map_err(|(code, message)| {
        Icrc21Error::ConsentMessageUnavailable(ErrorInfo {
            description: format!(
                "Failed to retrieve the decimals of the ckERC20 ledger {ckerc20_ledger_id}: \
                 {message} (code {code})"
            ),
        })
    })
}

/// Builds the consent message for the given request.
///
/// `ckerc20_decimals` is only called for a valid `withdraw_erc20` request, to retrieve the
/// number of decimals of the token identified by the given ckERC20 ledger ID.
async fn build_consent_info(
    consent_msg_request: ConsentMessageRequest,
    config: &ConsentMessageConfig,
    ckerc20_decimals: impl AsyncFnOnce(Principal) -> Result<u8, Icrc21Error>,
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

    let symbols = TokenSymbols::for_network(config.ethereum_network);

    let consent_message = match consent_msg_request.method.as_str() {
        "withdraw_eth" => {
            let args = Decode!(consent_msg_request.arg.as_slice(), WithdrawalArg).map_err(|e| {
                Icrc21Error::UnsupportedCanisterCall(ErrorInfo {
                    description: format!("Failed to decode WithdrawalArg: {e}"),
                })
            })?;
            let destination = validate_destination(&args.recipient)?;
            let amount: Wei = validate_amount(&args.amount)?;
            if amount < config.cketh_minimum_withdrawal_amount {
                return Err(Icrc21Error::UnsupportedCanisterCall(ErrorInfo {
                    description: format!(
                        "The amount is below the minimum withdrawal amount of {} {}.",
                        format_amount(
                            &Nat::from(config.cketh_minimum_withdrawal_amount),
                            CKETH_DECIMALS
                        ),
                        symbols.cketh
                    ),
                }));
            }
            build_withdraw_eth_message(&args, destination, &display_type, symbols)
        }
        "withdraw_erc20" => {
            let args =
                Decode!(consent_msg_request.arg.as_slice(), WithdrawErc20Arg).map_err(|e| {
                    Icrc21Error::UnsupportedCanisterCall(ErrorInfo {
                        description: format!("Failed to decode WithdrawErc20Arg: {e}"),
                    })
                })?;
            let ckerc20_token = config
                .ckerc20_tokens
                .iter()
                .find(|token| token.ckerc20_ledger_id == args.ckerc20_ledger_id)
                .ok_or_else(|| {
                    Icrc21Error::UnsupportedCanisterCall(ErrorInfo {
                        description: format!(
                            "The ckERC20 ledger {} is not supported by the minter.",
                            args.ckerc20_ledger_id
                        ),
                    })
                })?;
            let destination = validate_destination(&args.recipient)?;
            let _: Erc20Value = validate_amount(&args.amount)?;
            let decimals = ckerc20_decimals(ckerc20_token.ckerc20_ledger_id).await?;
            build_withdraw_erc20_message(
                &args,
                destination,
                ckerc20_token,
                decimals,
                &display_type,
                symbols,
            )
        }
        method => {
            return Err(Icrc21Error::UnsupportedCanisterCall(ErrorInfo {
                description: format!(
                    "The method '{method}' is not supported by the ckETH minter ICRC-21 endpoint."
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

fn build_withdraw_eth_message(
    args: &WithdrawalArg,
    destination: Address,
    display_type: &DisplayMessageType,
    symbols: TokenSymbols,
) -> ConsentMessage {
    let TokenSymbols { cketh, eth } = symbols;
    match display_type {
        DisplayMessageType::GenericDisplay => {
            let mut message = format!(
                "# Convert {cketh} to {eth}\n\n\
                 Authorize the {cketh} minter to burn {cketh} from your account and \
                 send the equivalent amount in {eth}, minus the Ethereum transaction fee, to \
                 the Ethereum address below. The fee is estimated by the minter when it \
                 processes the withdrawal. Any unused part of the fee is not refunded.\n\n\
                 **Amount to convert:** `{amount} {cketh}`\n\n\
                 **Ethereum destination address:**\n`{destination}`",
                amount = format_amount(&args.amount, CKETH_DECIMALS),
            );
            if let Some(subaccount) = args.from_subaccount {
                message.push_str(&format!(
                    "\n\n**{cketh} source subaccount:**\n`{}`",
                    hex::encode(subaccount)
                ));
            }
            ConsentMessage::GenericDisplayMessage(message)
        }
        DisplayMessageType::FieldsDisplay => {
            // Long values (Ethereum addresses, subaccount hex) are sent as a
            // single `Value::Text` per the ICRC-21 spec — wallets are
            // responsible for paginating them across screens.
            let mut fields = vec![
                (
                    "Amount".to_string(),
                    token_amount(&args.amount, CKETH_DECIMALS, cketh),
                ),
                (
                    "Ethereum address".to_string(),
                    Value::Text {
                        content: destination.to_string(),
                    },
                ),
                (
                    "Transaction fee".to_string(),
                    Value::Text {
                        content: "Deducted from the amount as estimated by the minter; any \
                                  unused part is not refunded"
                            .to_string(),
                    },
                ),
            ];
            push_subaccount_field(&mut fields, "From subaccount", args.from_subaccount);
            ConsentMessage::FieldsDisplayMessage(FieldsDisplay {
                intent: format!("{cketh} to {eth}"),
                fields,
            })
        }
    }
}

fn build_withdraw_erc20_message(
    args: &WithdrawErc20Arg,
    destination: Address,
    ckerc20_token: &CkErc20Token,
    decimals: u8,
    display_type: &DisplayMessageType,
    symbols: TokenSymbols,
) -> ConsentMessage {
    let TokenSymbols { cketh, .. } = symbols;
    let ckerc20 = ckerc20_token.ckerc20_token_symbol.to_string();
    // ckERC20 token symbols are guaranteed to start with "ck", see `CkTokenSymbol`.
    let erc20 = ckerc20.strip_prefix("ck").unwrap_or(&ckerc20);
    match display_type {
        DisplayMessageType::GenericDisplay => {
            let mut message = format!(
                "# Convert {ckerc20} to {erc20}\n\n\
                 Authorize the {cketh} minter to burn {ckerc20} from your account and \
                 send the same amount in {erc20} to the Ethereum address below.\n\n\
                 The minter also burns {cketh} from your account to pay for the Ethereum \
                 transaction fee. The fee is estimated by the minter when it processes the \
                 withdrawal and is limited by the {cketh} allowance you granted to the minter. \
                 Any unused part of the fee is not refunded.\n\n\
                 **Amount to convert:** `{amount} {ckerc20}`\n\n\
                 **Ethereum destination address:**\n`{destination}`",
                amount = format_amount(&args.amount, decimals),
            );
            if let Some(subaccount) = args.from_ckerc20_subaccount {
                message.push_str(&format!(
                    "\n\n**{ckerc20} source subaccount:**\n`{}`",
                    hex::encode(subaccount)
                ));
            }
            if let Some(subaccount) = args.from_cketh_subaccount {
                message.push_str(&format!(
                    "\n\n**{cketh} source subaccount (transaction fee):**\n`{}`",
                    hex::encode(subaccount)
                ));
            }
            ConsentMessage::GenericDisplayMessage(message)
        }
        DisplayMessageType::FieldsDisplay => {
            let mut fields = vec![
                (
                    "Amount".to_string(),
                    token_amount(&args.amount, decimals, &ckerc20),
                ),
                (
                    "Ethereum address".to_string(),
                    Value::Text {
                        content: destination.to_string(),
                    },
                ),
                (
                    "Transaction fee".to_string(),
                    Value::Text {
                        content: format!(
                            "Paid in {cketh} as estimated by the minter; any unused part \
                             is not refunded"
                        ),
                    },
                ),
            ];
            push_subaccount_field(&mut fields, "From subaccount", args.from_ckerc20_subaccount);
            push_subaccount_field(&mut fields, "Fee subaccount", args.from_cketh_subaccount);
            ConsentMessage::FieldsDisplayMessage(FieldsDisplay {
                intent: format!("{ckerc20} to {erc20}"),
                fields,
            })
        }
    }
}

fn push_subaccount_field(
    fields: &mut Vec<(String, Value)>,
    label: &str,
    subaccount: Option<Subaccount>,
) {
    if let Some(subaccount) = subaccount {
        fields.push((
            label.to_string(),
            Value::Text {
                content: hex::encode(subaccount),
            },
        ));
    }
}

/// Verifies that `recipient` is a valid Ethereum destination address before it gets
/// interpolated into a consent message. This both guarantees the user is shown a
/// meaningful destination and rules out Markdown-injection vectors in the GenericDisplay
/// output (e.g. an "address" that contains newlines or backticks crafted to fake additional
/// fields). Uses the same validation as `withdraw_eth` and `withdraw_erc20`, so blocked
/// addresses are rejected as they would be by the actual call. The returned address is
/// displayed in its EIP-55 checksummed form.
fn validate_destination(recipient: &str) -> Result<Address, Icrc21Error> {
    validate_address_as_destination(recipient).map_err(|e| {
        Icrc21Error::UnsupportedCanisterCall(ErrorInfo {
            description: format!("Invalid Ethereum destination address: {e}"),
        })
    })
}

/// Verifies that `amount` fits in a 256-bit unsigned integer, as the actual call does.
fn validate_amount<T: TryFrom<Nat, Error = String>>(amount: &Nat) -> Result<T, Icrc21Error> {
    T::try_from(amount.clone()).map_err(|e| {
        Icrc21Error::UnsupportedCanisterCall(ErrorInfo {
            description: format!("Invalid amount: {e}"),
        })
    })
}

/// Returns a `Value::TokenAmount` if `amount` fits in the `nat64` amount of the ICRC-21
/// `TokenAmount` value, and otherwise falls back to a `Value::Text` with the formatted amount.
/// With 18 decimals, amounts larger than about 18.4 ckETH do not fit in a `nat64`.
fn token_amount(amount: &Nat, decimals: u8, symbol: &str) -> Value {
    match amount.0.to_u64() {
        Some(amount) => Value::TokenAmount {
            decimals,
            amount,
            symbol: symbol.to_string(),
        },
        None => Value::Text {
            content: format!("{} {symbol}", format_amount(amount, decimals)),
        },
    }
}

fn format_amount(amount: &Nat, decimals: u8) -> String {
    let divisor = BigUint::from(10_u8).pow(decimals as u32);
    let whole = &amount.0 / &divisor;
    let frac = &amount.0 % &divisor;
    if frac.is_zero() {
        format!("{whole}")
    } else {
        let frac_str = format!("{frac:0width$}", width = decimals as usize);
        let trimmed = frac_str.trim_end_matches('0');
        format!("{whole}.{trimmed}")
    }
}
