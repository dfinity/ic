use crate::icrc1::account::Account;

use super::requests::ConsentMessageMetadata;
use candid::{CandidType, Deserialize};
use serde::Serialize;
use serde_bytes::ByteBuf;

#[derive(Debug, CandidType, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConsentMessage {
    GenericDisplayMessage(String),
}

#[derive(Debug, CandidType, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsentInfo {
    pub consent_message: ConsentMessage,
    pub metadata: ConsentMessageMetadata,
}

pub enum Intent {
    Transfer,
    Approve,
    TransferFrom,
}

impl ConsentMessage {
    pub fn add_intent(&mut self, intent: Intent, token_symbol: String) {
        match self {
            ConsentMessage::GenericDisplayMessage(message) => match intent {
                Intent::Transfer => {
                    message.push_str(&format!("# Send {}", token_symbol));
                    message
                        .push_str("\n\nYou are approving a transfer of funds from your account.");
                }
                Intent::Approve => {
                    message.push_str("# Approve spending");
                    message.push_str(
                    "\n\nYou are authorizing another address to withdraw funds from your account.",
                );
                }
                Intent::TransferFrom => {
                    message.push_str(&format!("# Spend {}", token_symbol));
                    message.push_str(
                        "\n\nYou are approving a transfer of funds from a withdrawal account.",
                    );
                }
            },
        }
    }

    pub fn add_account(&mut self, name: &str, account: Account) {
        match self {
            ConsentMessage::GenericDisplayMessage(message) => {
                message.push_str(&format!("\n\n**{}:**\n`{}`", name, account));
            }
        }
    }

    pub fn add_amount(&mut self, amount: String, token_symbol: String) {
        match self {
            ConsentMessage::GenericDisplayMessage(message) => {
                message.push_str(&format!("\n\n**Amount:** `{} {}`", amount, token_symbol));
            }
        }
    }

    pub fn add_fee(&mut self, fee: String, token_symbol: String, intent: Intent) {
        match self {
            ConsentMessage::GenericDisplayMessage(message) => {
                match intent {
                    Intent::Approve => message.push_str(&format!(
                        "\n\n**Approval fees:** `{} {}`\nCharged for processing the approval.",
                        fee, token_symbol
                    )),
                    _ => message.push_str(&format!(
                        "\n\n**Fees:** `{} {}`\nCharged for processing the transfer.",
                        fee, token_symbol
                    )),
                };
            }
        }
    }

    pub fn add_allowance(&mut self, amount: String, token_symbol: String) {
        match self {
            ConsentMessage::GenericDisplayMessage(message) => {
                message.push_str(&format!(
                    "\n\n**Requested allowance:** `{} {}`\nThis is the withdrawal limit that will apply upon approval.",
                    amount, token_symbol
                ));
            }
        }
    }

    pub fn add_existing_allowance(&mut self, expected_allowance: String, token_symbol: String) {
        match self {
            ConsentMessage::GenericDisplayMessage(message) => {
                message.push_str(&format!("\n\n**Existing allowance:** `{} {}`\nUntil approval, this allowance remains in effect.", expected_allowance, token_symbol));
            }
        }
    }

    pub fn add_expiration(&mut self, expires_at: String) {
        match self {
            ConsentMessage::GenericDisplayMessage(message) => {
                message.push_str(&format!("\n\n**Approval expiration:**\n{}", expires_at));
            }
        }
    }

    pub fn add_memo(&mut self, memo: ByteBuf) {
        match self {
            ConsentMessage::GenericDisplayMessage(message) => {
                message.push_str(&format!(
                    "\n\n**Memo:**\n`{}`",
                    // Check if the memo is a valid UTF-8 string and display it as such if it is.
                    &match std::str::from_utf8(memo.as_slice()) {
                        Ok(valid_str) => valid_str.to_string(),
                        Err(_) => hex::encode(memo.as_slice()),
                    }
                ));
            }
        }
    }
}
