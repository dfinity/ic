use crate::{icrc1::account::Account, icrc21::lib::Icrc21Function};

use super::requests::ConsentMessageMetadata;
use candid::{CandidType, Deserialize};
use serde::Serialize;
use serde_bytes::ByteBuf;

#[derive(Debug, CandidType, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct FieldsDisplay {
    pub intent: String,
    pub fields: Vec<(String, String)>,
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
                Icrc21Function::Transfer => {
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
                Icrc21Function::Transfer => {
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

    pub fn add_account(&mut self, name: &str, account: &Account) {
        match self {
            ConsentMessage::GenericDisplayMessage(message) => {
                message.push_str(&format!("\n\n**{}:**\n`{}`", name, account))
            }
            ConsentMessage::FieldsDisplayMessage(fields_display) => fields_display
                .fields
                .push((name.to_string(), account.to_string())),
        }
    }

    pub fn add_amount(&mut self, amount: &String, token_symbol: &String) {
        match self {
            ConsentMessage::GenericDisplayMessage(message) => {
                message.push_str(&format!("\n\n**Amount:** `{} {}`", amount, token_symbol));
            }
            ConsentMessage::FieldsDisplayMessage(fields_display) => fields_display
                .fields
                .push(("Amount".to_string(), format!("{} {}", amount, token_symbol))),
        }
    }

    pub fn add_fee(&mut self, intent: Icrc21Function, fee: &String, token_symbol: &String) {
        match self {
            ConsentMessage::GenericDisplayMessage(message) => {
                match intent {
                    Icrc21Function::Approve => message.push_str(&format!(
                        "\n\n**Approval fees:** `{} {}`\nCharged for processing the approval.",
                        fee, token_symbol
                    )),
                    Icrc21Function::Transfer | Icrc21Function::TransferFrom => message.push_str(&format!(
                        "\n\n**Fees:** `{} {}`\nCharged for processing the transfer.",
                        fee, token_symbol
                    )),
                };
            }
            ConsentMessage::FieldsDisplayMessage(fields_display) => {
                match intent {
                    Icrc21Function::Approve => fields_display.fields.push((
                        "Approval fees".to_string(),
                        format!("{} {}", fee, token_symbol),
                    )),
                    Icrc21Function::Transfer | Icrc21Function::TransferFrom => fields_display
                        .fields
                        .push(("Fees".to_string(), format!("{} {}", fee, token_symbol))),
                };
            }
        }
    }

    pub fn add_allowance(&mut self, amount: &String, token_symbol: &String) {
        match self {
            ConsentMessage::GenericDisplayMessage(message) => {
                message.push_str(&format!(
                            "\n\n**Requested allowance:** `{} {}`\nThis is the withdrawal limit that will apply upon approval.",
                            amount, token_symbol
                        ));
            }
            ConsentMessage::FieldsDisplayMessage(fields_display) => fields_display.fields.push((
                "Requested allowance".to_string(),
                format!("{} {}", amount, token_symbol),
            )),
        }
    }

    pub fn add_existing_allowance(&mut self, expected_allowance: &String, token_symbol: &String) {
        match self {
            ConsentMessage::GenericDisplayMessage(message) => {
                message.push_str(&format!("\n\n**Existing allowance:** `{} {}`\nUntil approval, this allowance remains in effect.", expected_allowance, token_symbol));
            }
            ConsentMessage::FieldsDisplayMessage(fields_display) => fields_display.fields.push((
                "Existing allowance".to_string(),
                format!("{} {}", expected_allowance, token_symbol),
            )),
        }
    }

    pub fn add_expiration(&mut self, expires_at: &String) {
        match self {
            ConsentMessage::GenericDisplayMessage(message) => {
                message.push_str(&format!("\n\n**Approval expiration:**\n{}", expires_at));
            }
            ConsentMessage::FieldsDisplayMessage(fields_display) => fields_display
                .fields
                .push(("Approval expiration".to_string(), expires_at.to_string())),
        }
    }

    pub fn add_memo(&mut self, memo: ByteBuf) {
        // Check if the memo is a valid UTF-8 string and display it as such if it is.
        let memo_str = match std::str::from_utf8(memo.as_slice()) {
            Ok(valid_str) => valid_str.to_string(),
            Err(_) => hex::encode(memo.as_slice()),
        };
        match self {
            ConsentMessage::GenericDisplayMessage(message) => {
                message.push_str(&format!("\n\n**Memo:**\n`{}`", memo_str));
            }
            ConsentMessage::FieldsDisplayMessage(fields_display) => {
                fields_display.fields.push(("Memo".to_string(), memo_str))
            }
        }
    }
}
