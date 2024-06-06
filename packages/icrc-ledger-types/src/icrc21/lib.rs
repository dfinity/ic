use super::responses::ConsentMessage;
use super::{requests::DisplayMessageType, responses::LineDisplayPage};
use crate::icrc1::account::Account;
use crate::icrc21::errors::Icrc21Error;
use candid::Nat;
use itertools::Itertools;
use serde_bytes::ByteBuf;
use strum;
use strum::EnumString;

pub const ICRC1_TRANSFER_DISPLAY_MESSAGE: &str = "Transfers {AMOUNT} {TOKEN_SYMBOL} from {SENDER_ACCOUNT} to {RECEIVER_ACCOUNT}. Fee paid by {SENDER_ACCOUNT} is {LEDGER_FEE} {TOKEN_SYMBOL}.";
pub const ICRC2_APPROVE_DISPLAY_MESSAGE: &str = "Approves {AMOUNT} {TOKEN_SYMBOL} from {APPROVER_ACCOUNT} to be spent by {SPENDER_ACCOUNT}. Fee paid by {SENDER_ACCOUNT} is {LEDGER_FEE} {TOKEN_SYMBOL}.";
pub const ICRC2_TRANSFER_FROM_DISPLAY_MESSAGE: &str = "Transfers {AMOUNT} {TOKEN_SYMBOL} from {SENDER_ACCOUNT} to {RECEIVER_ACCOUNT}. The tokens are spent by {SPENDER_ACCOUNT}. Fee paid by {SENDER_ACCOUNT} is {LEDGER_FEE} {TOKEN_SYMBOL}.";

// Maximum number of bytes that an argument to an ICRC-1 ledger function can have when passed to the ICRC-21 endpoint.
pub const MAX_CONSENT_MESSAGE_ARG_SIZE_BYTES: u16 = 500;

#[derive(Debug, EnumString)]
enum Icrc21Function {
    #[strum(serialize = "icrc1_transfer")]
    Transfer,
    #[strum(serialize = "icrc2_approve")]
    Approve,
    #[strum(serialize = "icrc2_transfer_from")]
    TransferFrom,
}

pub struct ConsentMessageBuilder {
    function: Icrc21Function,
    display_type: Option<DisplayMessageType>,
    approver: Option<Account>,
    spender: Option<Account>,
    sender: Option<Account>,
    receiver: Option<Account>,
    amount: Option<Nat>,
    token_symbol: Option<String>,
    fee_set: Option<Nat>,
    ledger_fee: Option<Nat>,
    memo: Option<ByteBuf>,
    created_at_time: Option<u64>,
    expected_allowance: Option<Nat>,
    expires_at: Option<u64>,
}

impl ConsentMessageBuilder {
    pub fn new(icrc21_function: &str) -> Result<Self, Icrc21Error> {
        let icrc21_function =
            icrc21_function
                .parse::<Icrc21Function>()
                .map_err(|err| Icrc21Error::GenericError {
                    error_code: Nat::from(500u64),
                    description: format!("Invalid ICRC21 function: {:?}", err),
                })?;

        Ok(Self {
            function: icrc21_function,
            display_type: None,
            approver: None,
            spender: None,
            sender: None,
            receiver: None,
            amount: None,
            token_symbol: None,
            fee_set: None,
            ledger_fee: None,
            memo: None,
            created_at_time: None,
            expected_allowance: None,
            expires_at: None,
        })
    }

    pub fn with_approver(mut self, approver: Account) -> Self {
        self.approver = Some(approver);
        self
    }

    pub fn with_spender(mut self, spender: Account) -> Self {
        self.spender = Some(spender);
        self
    }

    pub fn with_sender(mut self, sender: Account) -> Self {
        self.sender = Some(sender);
        self
    }

    pub fn with_receiver(mut self, receiver: Account) -> Self {
        self.receiver = Some(receiver);
        self
    }

    pub fn with_amount(mut self, amount: Nat) -> Self {
        self.amount = Some(amount);
        self
    }

    pub fn with_token_symbol(mut self, token_symbol: String) -> Self {
        self.token_symbol = Some(token_symbol);
        self
    }

    pub fn with_fee_set(mut self, fee_set: Nat) -> Self {
        self.fee_set = Some(fee_set);
        self
    }

    pub fn with_ledger_fee(mut self, ledger_fee: Nat) -> Self {
        self.ledger_fee = Some(ledger_fee);
        self
    }

    pub fn with_memo(mut self, memo: ByteBuf) -> Self {
        self.memo = Some(memo);
        self
    }

    pub fn with_created_at_time(mut self, created_at_time: u64) -> Self {
        self.created_at_time = Some(created_at_time);
        self
    }

    pub fn with_expected_allowance(mut self, expected_allowance: Nat) -> Self {
        self.expected_allowance = Some(expected_allowance);
        self
    }

    pub fn with_expires_at(mut self, expires_at: u64) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    pub fn with_display_type(mut self, display_type: DisplayMessageType) -> Self {
        self.display_type = Some(display_type);
        self
    }

    pub fn build(self) -> Result<ConsentMessage, Icrc21Error> {
        let mut message = match self.function {
            Icrc21Function::Transfer => ICRC1_TRANSFER_DISPLAY_MESSAGE
                .replace(
                    "{SENDER_ACCOUNT}",
                    &self
                        .sender
                        .ok_or(Icrc21Error::GenericError {
                            error_code: Nat::from(500u64),
                            description: "Sender Account has to be specified.".to_owned(),
                        })?
                        .to_string(),
                )
                .replace(
                    "{RECEIVER_ACCOUNT}",
                    &self
                        .receiver
                        .ok_or(Icrc21Error::GenericError {
                            error_code: Nat::from(500u64),
                            description: "Receiver Account has to be specified.".to_owned(),
                        })?
                        .to_string(),
                ),
            Icrc21Function::Approve => ICRC2_APPROVE_DISPLAY_MESSAGE
                .replace(
                    "{APPROVER_ACCOUNT}",
                    &self
                        .approver
                        .ok_or(Icrc21Error::GenericError {
                            error_code: Nat::from(500u64),
                            description: "Approver Account has to be specified.".to_owned(),
                        })?
                        .to_string(),
                )
                .replace(
                    "{SPENDER_ACCOUNT}",
                    &self
                        .spender
                        .ok_or(Icrc21Error::GenericError {
                            error_code: Nat::from(500u64),
                            description: "Spender Account has to be specified.".to_owned(),
                        })?
                        .to_string(),
                ),
            Icrc21Function::TransferFrom => ICRC2_TRANSFER_FROM_DISPLAY_MESSAGE
                .replace(
                    "{SENDER_ACCOUNT}",
                    &self
                        .sender
                        .ok_or(Icrc21Error::GenericError {
                            error_code: Nat::from(500u64),
                            description: "Sender Account has to be specified.".to_owned(),
                        })?
                        .to_string(),
                )
                .replace(
                    "{RECEIVER_ACCOUNT}",
                    &self
                        .receiver
                        .ok_or(Icrc21Error::GenericError {
                            error_code: Nat::from(500u64),
                            description: "Receiver Account has to be specified.".to_owned(),
                        })?
                        .to_string(),
                )
                .replace(
                    "{SPENDER_ACCOUNT}",
                    &self
                        .spender
                        .ok_or(Icrc21Error::GenericError {
                            error_code: Nat::from(500u64),
                            description: "Spender Account has to be specified.".to_owned(),
                        })?
                        .to_string(),
                ),
        }
        .replace(
            "{AMOUNT}",
            &self
                .amount
                .ok_or(Icrc21Error::GenericError {
                    error_code: Nat::from(500u64),
                    description: "Amount has to be specified.".to_owned(),
                })?
                .to_string(),
        )
        .replace(
            "{TOKEN_SYMBOL}",
            &self.token_symbol.ok_or(Icrc21Error::GenericError {
                error_code: Nat::from(500u64),
                description: "Token Symbol must be specified.".to_owned(),
            })?,
        )
        .replace(
            "{LEDGER_FEE}",
            &self
                .ledger_fee
                .ok_or(Icrc21Error::GenericError {
                    error_code: Nat::from(500u64),
                    description: "Ledger Fee must be specified.".to_owned(),
                })?
                .to_string(),
        );

        match self.display_type {
            Some(DisplayMessageType::GenericDisplay) | None => {
                message.push_str("\n---\n Request Details\n");
                if let Some(memo) = self.memo {
                    message.push_str(&format!(
                        "\n*Transaction Memo is: {}",
                        String::from_utf8_lossy(&memo)
                    ));
                }
                if let Some(created_at_time) = self.created_at_time {
                    message.push_str(&format!(
                        "\n*Transaction was created by the user at: {}",
                        created_at_time
                    ));
                }
                if let Some(expected_allowance) = self.expected_allowance {
                    message.push_str(&format!(
                        "\n*The expected allowance before approving the requested amount is: {}",
                        expected_allowance
                    ));
                }
                if let Some(expires_at) = self.expires_at {
                    message.push_str(&format!("\n*The approval expires at: {}", expires_at));
                }
                Ok(ConsentMessage::GenericDisplayMessage(message))
            }
            Some(DisplayMessageType::LineDisplay {
                lines_per_page,
                characters_per_line,
            }) => {
                if let Some(memo) = self.memo {
                    message.push_str(&format!("\nMemo is {}", String::from_utf8_lossy(&memo)));
                }
                let pages = consent_msg_text_pages(&message, characters_per_line, lines_per_page);
                Ok(ConsentMessage::LineDisplayMessage { pages })
            }
        }
    }
}

/// This function was taken from the reference implementation: https://github.com/dfinity/wg-identity-authentication/blob/3ed140225b283c0a1cc88344d0cfb9912aec73cd/reference-implementations/ICRC-21/src/lib.rs#L73
pub fn consent_msg_text_pages(
    message: &str,
    characters_per_line: u16,
    lines_per_page: u16,
) -> Vec<LineDisplayPage> {
    if characters_per_line == 0 || lines_per_page == 0 {
        return vec![];
    }

    // Split text into word chunks that fit on a line (breaking long words)
    let words = message.split_whitespace().flat_map(|word| {
        word.chars()
            .chunks(characters_per_line as usize)
            .into_iter()
            .map(|chunk| chunk.collect::<String>())
            .collect::<Vec<String>>()
    });

    // Add words to lines until the line is full
    let mut lines = vec![];
    let mut current_line = "".to_string();
    for word in words {
        if current_line.is_empty() {
            // all words are guaranteed to fit on a line
            current_line = word;
            continue;
        }
        if current_line.len() + word.len() < characters_per_line as usize {
            current_line.push(' ');
            current_line.push_str(word.as_str());
        } else {
            lines.push(current_line);
            current_line = word;
        }
    }
    lines.push(current_line);

    // Group lines into pages
    lines
        .into_iter()
        .chunks(lines_per_page as usize)
        .into_iter()
        .map(|page| LineDisplayPage {
            lines: page.collect(),
        })
        .collect()
}
