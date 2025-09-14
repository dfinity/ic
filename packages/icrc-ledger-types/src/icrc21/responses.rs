use crate::icrc21::{
    errors::Icrc21Error,
    lib::{GenericMemo, Icrc21Function},
};

use super::requests::ConsentMessageMetadata;
use candid::{CandidType, Deserialize, Nat};
use num_traits::{Pow, ToPrimitive};
use serde::Serialize;

#[derive(CandidType, Deserialize, Eq, PartialEq, Debug, Serialize, Clone)]
pub enum Value {
    TokenAmount {
        decimals: u8,
        amount: u64,
        symbol: String,
    },
    TimestampSeconds {
        amount: u64,
    },
    DurationSeconds {
        amount: u64,
    },
    Text {
        content: String,
    },
}

#[derive(Debug, CandidType, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct FieldsDisplay {
    pub intent: String,
    pub fields: Vec<(String, Value)>,
}

#[derive(Debug, CandidType, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConsentMessage {
    GenericDisplayMessage(String),
    FieldsDisplayMessage(FieldsDisplay),
}

#[derive(Debug, CandidType, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsentInfo {
    pub consent_message: ConsentMessage,
    pub metadata: ConsentMessageMetadata,
}

impl ConsentMessage {
    pub fn add_intent(&mut self, intent: Icrc21Function, token_name: Option<String>) {
        match self {
            ConsentMessage::GenericDisplayMessage(message) => match intent {
                Icrc21Function::Transfer | Icrc21Function::GenericTransfer => {
                    assert!(token_name.is_some());
                    message.push_str(&format!("# Send {}", token_name.unwrap()));
                    message
                        .push_str("\n\nYou are approving a transfer of funds from your account.");
                }
                Icrc21Function::Approve => {
                    message.push_str("# Approve spending");
                    message.push_str(
                            "\n\nYou are authorizing another address to withdraw funds from your account.",
                        );
                }
                Icrc21Function::TransferFrom => {
                    assert!(token_name.is_some());
                    message.push_str(&format!("# Spend {}", token_name.unwrap()));
                    message.push_str(
                        "\n\nYou are approving a transfer of funds from a withdrawal account.",
                    );
                }
            },
            ConsentMessage::FieldsDisplayMessage(fields_display) => match intent {
                Icrc21Function::Transfer | Icrc21Function::GenericTransfer => {
                    assert!(token_name.is_some());
                    fields_display.intent = format!("Send {}", token_name.unwrap());
                }
                Icrc21Function::Approve => {
                    fields_display.intent = "Approve spending".to_string();
                }
                Icrc21Function::TransferFrom => {
                    assert!(token_name.is_some());
                    fields_display.intent = format!("Spend {}", token_name.unwrap());
                }
            },
        }
    }

    pub fn add_account(&mut self, name: &str, account: String) {
        match self {
            ConsentMessage::GenericDisplayMessage(message) => {
                message.push_str(&format!("\n\n**{name}:**\n`{account}`"))
            }
            ConsentMessage::FieldsDisplayMessage(fields_display) => fields_display.fields.push((
                name.to_string(),
                Value::Text {
                    content: account.to_string(),
                },
            )),
        }
    }

    pub fn add_amount(
        &mut self,
        amount: Option<Nat>,
        decimals: u8,
        token_symbol: &String,
    ) -> Result<(), Icrc21Error> {
        let amount = amount.ok_or(Icrc21Error::GenericError {
            error_code: Nat::from(500u64),
            description: "Amount has to be specified.".to_owned(),
        })?;
        match self {
            ConsentMessage::GenericDisplayMessage(message) => {
                let amount = convert_tokens_to_string_representation(amount, decimals)?;
                message.push_str(&format!("\n\n**Amount:** `{amount} {token_symbol}`"));
            }
            ConsentMessage::FieldsDisplayMessage(fields_display) => fields_display.fields.push((
                "Amount".to_string(),
                Value::TokenAmount {
                    decimals,
                    amount: nat_to_u64(amount)?,
                    symbol: token_symbol.to_string(),
                },
            )),
        }
        Ok(())
    }

    pub fn add_fee(
        &mut self,
        intent: Icrc21Function,
        amount: Option<Nat>,
        decimals: u8,
        token_symbol: &String,
    ) -> Result<(), Icrc21Error> {
        let amount = amount.ok_or(Icrc21Error::GenericError {
            error_code: Nat::from(500u64),
            description: "Amount has to be specified.".to_owned(),
        })?;
        match self {
            ConsentMessage::GenericDisplayMessage(message) => {
                let fee = convert_tokens_to_string_representation(amount, decimals)?;
                match intent {
                    Icrc21Function::Approve => message.push_str(&format!(
                        "\n\n**Approval fees:** `{fee} {token_symbol}`\nCharged for processing the approval."
                    )),
                    Icrc21Function::Transfer
                    | Icrc21Function::TransferFrom
                    | Icrc21Function::GenericTransfer => message.push_str(&format!(
                        "\n\n**Fees:** `{fee} {token_symbol}`\nCharged for processing the transfer."
                    )),
                };
            }
            ConsentMessage::FieldsDisplayMessage(fields_display) => {
                let token_amount = Value::TokenAmount {
                    decimals,
                    amount: nat_to_u64(amount)?,
                    symbol: token_symbol.to_string(),
                };
                match intent {
                    Icrc21Function::Approve => fields_display
                        .fields
                        .push(("Approval fees".to_string(), token_amount)),
                    Icrc21Function::Transfer
                    | Icrc21Function::TransferFrom
                    | Icrc21Function::GenericTransfer => fields_display
                        .fields
                        .push(("Fees".to_string(), token_amount)),
                };
            }
        }
        Ok(())
    }

    pub fn add_allowance(
        &mut self,
        amount: Option<Nat>,
        decimals: u8,
        token_symbol: &String,
    ) -> Result<(), Icrc21Error> {
        let amount = amount.ok_or(Icrc21Error::GenericError {
            error_code: Nat::from(500u64),
            description: "Amount has to be specified.".to_owned(),
        })?;
        match self {
            ConsentMessage::GenericDisplayMessage(message) => {
                let amount = convert_tokens_to_string_representation(amount, decimals)?;
                message.push_str(&format!(
                            "\n\n**Requested allowance:** `{amount} {token_symbol}`\nThis is the withdrawal limit that will apply upon approval."
                        ));
            }
            ConsentMessage::FieldsDisplayMessage(fields_display) => fields_display.fields.push((
                "Requested allowance".to_string(),
                Value::TokenAmount {
                    decimals,
                    amount: nat_to_u64(amount)?,
                    symbol: token_symbol.to_string(),
                },
            )),
        }
        Ok(())
    }

    pub fn add_existing_allowance(
        &mut self,
        expected_allowance: Nat,
        decimals: u8,
        token_symbol: &String,
    ) -> Result<(), Icrc21Error> {
        match self {
            ConsentMessage::GenericDisplayMessage(message) => {
                let expected_allowance =
                    convert_tokens_to_string_representation(expected_allowance, decimals)?;
                message.push_str(&format!("\n\n**Existing allowance:** `{expected_allowance} {token_symbol}`\nUntil approval, this allowance remains in effect."));
            }
            ConsentMessage::FieldsDisplayMessage(fields_display) => fields_display.fields.push((
                "Existing allowance".to_string(),
                Value::TokenAmount {
                    decimals,
                    amount: nat_to_u64(expected_allowance)?,
                    symbol: token_symbol.to_string(),
                },
            )),
        }
        Ok(())
    }

    pub fn add_expiration(&mut self, expires_at: Option<u64>, utc_offset_minutes: Option<i16>) {
        match self {
            ConsentMessage::GenericDisplayMessage(message) => {
                let expires_at = expires_at
                    .map(|ts| {
                        let seconds = (ts as i64) / 10_i64.pow(9);
                        let nanos = ((ts as i64) % 10_i64.pow(9)) as u32;

                        let utc_dt = match (match time::OffsetDateTime::from_unix_timestamp(seconds)
                        {
                            Ok(dt) => dt,
                            Err(_) => return format!("Invalid timestamp: {ts}"),
                        })
                        .replace_nanosecond(nanos)
                        {
                            Ok(dt) => dt,
                            Err(_) => return format!("Invalid nanosecond: {nanos}"),
                        };

                        // Apply the offset minutes
                        let offset = time::UtcOffset::from_whole_seconds(
                            (utc_offset_minutes.unwrap_or(0) * 60).into(),
                        )
                        .expect("Invalid offset");
                        let offset_dt = utc_dt.to_offset(offset);

                        // Format as a string including the offset
                        match offset_dt.format(&time::format_description::well_known::Rfc2822) {
                            Ok(formatted) => formatted,
                            Err(_) => format!("Invalid timestamp: {ts}"),
                        }
                    })
                    .unwrap_or("This approval does not have an expiration.".to_owned());
                message.push_str(&format!("\n\n**Approval expiration:**\n{expires_at}"));
            }
            ConsentMessage::FieldsDisplayMessage(fields_display) => {
                match expires_at {
                    Some(expires_at) => {
                        let seconds = (expires_at as i64) / 10_i64.pow(9);
                        fields_display.fields.push((
                            "Approval expiration".to_string(),
                            Value::TimestampSeconds {
                                amount: seconds as u64,
                            },
                        ))
                    }
                    None => fields_display.fields.push((
                        "Approval expiration".to_string(),
                        Value::Text {
                            content: "This approval does not have an expiration.".to_string(),
                        },
                    )),
                };
            }
        }
    }

    pub fn add_memo(&mut self, memo: GenericMemo) {
        match memo {
            GenericMemo::Icrc1Memo(memo) => {
                // Check if the memo is a valid UTF-8 string and display it as such if it is.
                let memo_str = match std::str::from_utf8(memo.as_slice()) {
                    Ok(valid_str) => valid_str.to_string(),
                    Err(_) => hex::encode(memo.as_slice()),
                };
                match self {
                    ConsentMessage::GenericDisplayMessage(message) => {
                        message.push_str(&format!("\n\n**Memo:**\n`{memo_str}`"));
                    }
                    ConsentMessage::FieldsDisplayMessage(fields_display) => fields_display
                        .fields
                        .push(("Memo".to_string(), Value::Text { content: memo_str })),
                }
            }
            GenericMemo::IntMemo(memo) => match self {
                ConsentMessage::GenericDisplayMessage(message) => {
                    message.push_str(&format!("\n\n**Memo:**\n`{memo}`"));
                }
                ConsentMessage::FieldsDisplayMessage(fields_display) => {
                    fields_display.fields.push((
                        "Memo".to_string(),
                        Value::Text {
                            content: memo.to_string(),
                        },
                    ))
                }
            },
        };
    }
}

fn convert_tokens_to_string_representation(
    tokens: Nat,
    decimals: u8,
) -> Result<String, Icrc21Error> {
    let tokens = tokens.0.to_f64().ok_or(Icrc21Error::GenericError {
        error_code: Nat::from(500u64),
        description: "Failed to convert tokens to u64".to_owned(),
    })?;
    Ok(format!("{}", tokens / 10_f64.pow(decimals)))
}

fn nat_to_u64(tokens: Nat) -> Result<u64, Icrc21Error> {
    tokens.0.to_u64().ok_or(Icrc21Error::GenericError {
        error_code: Nat::from(500u64),
        description: "Failed to convert tokens to u64".to_owned(),
    })
}
