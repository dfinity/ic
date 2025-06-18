use super::errors::ErrorInfo;
use super::requests::ConsentMessageRequest;
use super::requests::DisplayMessageType;
use super::responses::{ConsentInfo, ConsentMessage};
use crate::icrc1::account::Account;
use crate::icrc1::transfer::TransferArg;
use crate::icrc2::approve::ApproveArgs;
use crate::icrc2::transfer_from::TransferFromArgs;
use crate::icrc21::errors::Icrc21Error;
use crate::icrc21::requests::ConsentMessageMetadata;
use crate::icrc21::responses::Intent;
use candid::Decode;
use candid::{Nat, Principal};
use num_traits::{Pow, ToPrimitive};
use serde_bytes::ByteBuf;
use strum::{self, IntoEnumIterator};
use strum_macros::{Display, EnumIter, EnumString};

// Maximum number of bytes that an argument to an ICRC-1 ledger function can have when passed to the ICRC-21 endpoint.
pub const MAX_CONSENT_MESSAGE_ARG_SIZE_BYTES: u16 = 500;

#[derive(Debug, EnumString, EnumIter, Display)]
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
    from: Option<Account>,
    receiver: Option<Account>,
    amount: Option<Nat>,
    token_symbol: Option<String>,
    ledger_fee: Option<Nat>,
    memo: Option<ByteBuf>,
    expected_allowance: Option<Nat>,
    expires_at: Option<u64>,
    utc_offset_minutes: Option<i16>,
    decimals: u8,
}

impl ConsentMessageBuilder {
    pub fn new(icrc21_function: &str, decimals: u8) -> Result<Self, Icrc21Error> {
        let icrc21_function =
            icrc21_function
                .parse::<Icrc21Function>()
                .map_err(|err| Icrc21Error::UnsupportedCanisterCall(ErrorInfo {                    description: format!("The function provided is not supported: {}.\n Supported functions for ICRC-21 are: {:?}.\n Error is: {:?}",icrc21_function,Icrc21Function::iter().map(|f|f.to_string()).collect::<Vec<String>>(),err)})
                )?;

        Ok(Self {
            function: icrc21_function,
            display_type: None,
            approver: None,
            spender: None,
            from: None,
            receiver: None,
            amount: None,
            token_symbol: None,
            ledger_fee: None,
            utc_offset_minutes: None,
            memo: None,
            expected_allowance: None,
            expires_at: None,
            decimals,
        })
    }

    pub fn with_approver_account(mut self, approver: Account) -> Self {
        self.approver = Some(approver);
        self
    }

    pub fn with_spender_account(mut self, spender: Account) -> Self {
        self.spender = Some(spender);
        self
    }

    pub fn with_from_account(mut self, from: Account) -> Self {
        self.from = Some(from);
        self
    }

    pub fn with_receiver_account(mut self, receiver: Account) -> Self {
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

    pub fn with_ledger_fee(mut self, ledger_fee: Nat) -> Self {
        self.ledger_fee = Some(ledger_fee);
        self
    }

    pub fn with_memo(mut self, memo: ByteBuf) -> Self {
        self.memo = Some(memo);
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

    pub fn with_utc_offset_minutes(mut self, utc_offset_minutes: i16) -> Self {
        self.utc_offset_minutes = Some(utc_offset_minutes);
        self
    }

    pub fn build(self) -> Result<ConsentMessage, Icrc21Error> {
        let mut message = match self.display_type {
            Some(DisplayMessageType::GenericDisplay) | None => {
                ConsentMessage::GenericDisplayMessage("".to_string())
            }
            Some(DisplayMessageType::FieldsDisplay) => todo!(),
        };
        match self.function {
            Icrc21Function::Transfer => {
                let from_account = self.from.ok_or(Icrc21Error::GenericError {
                    error_code: Nat::from(500u64),
                    description: "From account has to be specified.".to_owned(),
                })?;
                let receiver_account = self.receiver.ok_or(Icrc21Error::GenericError {
                    error_code: Nat::from(500u64),
                    description: "Receiver account has to be specified.".to_owned(),
                })?;
                let fee = convert_tokens_to_string_representation(
                    self.ledger_fee.ok_or(Icrc21Error::GenericError {
                        error_code: Nat::from(500u64),
                        description: "Ledger fee must be specified.".to_owned(),
                    })?,
                    self.decimals,
                )?;
                let token_symbol = self.token_symbol.ok_or(Icrc21Error::GenericError {
                    error_code: Nat::from(500u64),
                    description: "Token Symbol must be specified.".to_owned(),
                })?;
                let amount = convert_tokens_to_string_representation(
                    self.amount.ok_or(Icrc21Error::GenericError {
                        error_code: Nat::from(500u64),
                        description: "Amount has to be specified.".to_owned(),
                    })?,
                    self.decimals,
                )?;

                message.add_intent(Intent::Transfer, token_symbol.clone());
                if from_account.owner != Principal::anonymous() {
                    message.add_account("From", from_account);
                }
                message.add_amount(amount, token_symbol.clone());
                message.add_account("To", receiver_account);
                message.add_fee(fee, token_symbol.clone(), Intent::Transfer);
            }
            Icrc21Function::Approve => {
                let approver_account = self.approver.ok_or(Icrc21Error::GenericError {
                    error_code: Nat::from(500u64),
                    description: "Approver account has to be specified.".to_owned(),
                })?;
                let spender_account = self.spender.ok_or(Icrc21Error::GenericError {
                    error_code: Nat::from(500u64),
                    description: "Spender account has to be specified.".to_owned(),
                })?;
                let fee = convert_tokens_to_string_representation(
                    self.ledger_fee.ok_or(Icrc21Error::GenericError {
                        error_code: Nat::from(500u64),
                        description: "Ledger fee must be specified.".to_owned(),
                    })?,
                    self.decimals,
                )?;
                let token_symbol = self.token_symbol.ok_or(Icrc21Error::GenericError {
                    error_code: Nat::from(500u64),
                    description: "Token symbol must be specified.".to_owned(),
                })?;
                let amount = convert_tokens_to_string_representation(
                    self.amount.ok_or(Icrc21Error::GenericError {
                        error_code: Nat::from(500u64),
                        description: "Amount has to be specified.".to_owned(),
                    })?,
                    self.decimals,
                )?;
                let expires_at = self
                    .expires_at
                    .map(|ts| {
                        let seconds = (ts as i64) / 10_i64.pow(9);
                        let nanos = ((ts as i64) % 10_i64.pow(9)) as u32;

                        let utc_dt = match (match time::OffsetDateTime::from_unix_timestamp(seconds)
                        {
                            Ok(dt) => dt,
                            Err(_) => return format!("Invalid timestamp: {}", ts),
                        })
                        .replace_nanosecond(nanos)
                        {
                            Ok(dt) => dt,
                            Err(_) => return format!("Invalid nanosecond: {}", nanos),
                        };

                        // Apply the offset minutes
                        let offset = time::UtcOffset::from_whole_seconds(
                            (self.utc_offset_minutes.unwrap_or(0) * 60).into(),
                        )
                        .expect("Invalid offset");
                        let offset_dt = utc_dt.to_offset(offset);

                        // Format as a string including the offset
                        match offset_dt.format(&time::format_description::well_known::Rfc2822) {
                            Ok(formatted) => formatted,
                            Err(_) => format!("Invalid timestamp: {}", ts),
                        }
                    })
                    .unwrap_or("This approval does not have an expiration.".to_owned());

                message.add_intent(Intent::Approve, "NONE".to_string());
                if approver_account.owner != Principal::anonymous() {
                    message.add_account("From", approver_account);
                }
                message.add_account("Approve to spender", spender_account);
                message.add_allowance(amount, token_symbol.clone());
                if let Some(expected_allowance) = self.expected_allowance {
                    message.add_existing_allowance(
                        convert_tokens_to_string_representation(expected_allowance, self.decimals)?,
                        token_symbol.clone(),
                    );
                }
                message.add_expiration(expires_at);
                message.add_fee(fee, token_symbol.clone(), Intent::Approve);
                if approver_account.owner != Principal::anonymous() {
                    message.add_account("Fees paid by", approver_account);
                }
            }
            Icrc21Function::TransferFrom => {
                let from_account = self.from.ok_or(Icrc21Error::GenericError {
                    error_code: Nat::from(500u64),
                    description: "From account has to be specified.".to_owned(),
                })?;
                let receiver_account = self.receiver.ok_or(Icrc21Error::GenericError {
                    error_code: Nat::from(500u64),
                    description: "Receiver account has to be specified.".to_owned(),
                })?;
                let spender_account = self.spender.ok_or(Icrc21Error::GenericError {
                    error_code: Nat::from(500u64),
                    description: "Spender account has to be specified.".to_owned(),
                })?;
                let fee = convert_tokens_to_string_representation(
                    self.ledger_fee.ok_or(Icrc21Error::GenericError {
                        error_code: Nat::from(500u64),
                        description: "Ledger fee must be specified.".to_owned(),
                    })?,
                    self.decimals,
                )?;

                let token_symbol = self.token_symbol.ok_or(Icrc21Error::GenericError {
                    error_code: Nat::from(500u64),
                    description: "Token symbol must be specified.".to_owned(),
                })?;
                let amount = convert_tokens_to_string_representation(
                    self.amount.ok_or(Icrc21Error::GenericError {
                        error_code: Nat::from(500u64),
                        description: "Amount has to be specified.".to_owned(),
                    })?,
                    self.decimals,
                )?;
                message.add_intent(Intent::TransferFrom, token_symbol.clone());
                message.add_account("From", from_account);
                message.add_amount(amount, token_symbol.clone());
                if spender_account.owner != Principal::anonymous() {
                    message.add_account("Spender", spender_account);
                }
                message.add_account("To", receiver_account);
                message.add_fee(fee, token_symbol.clone(), Intent::TransferFrom);
            }
        };

        if let Some(memo) = self.memo {
            message.add_memo(memo);
        }

        Ok(message)
    }
}

pub fn build_icrc21_consent_info_for_icrc1_and_icrc2_endpoints(
    consent_msg_request: ConsentMessageRequest,
    caller_principal: Principal,
    ledger_fee: Nat,
    token_symbol: String,
    decimals: u8,
) -> Result<ConsentInfo, Icrc21Error> {
    if consent_msg_request.arg.len() > MAX_CONSENT_MESSAGE_ARG_SIZE_BYTES as usize {
        return Err(Icrc21Error::UnsupportedCanisterCall(ErrorInfo {
            description: format!(
                "The argument size is too large. The maximum allowed size is {} bytes.",
                MAX_CONSENT_MESSAGE_ARG_SIZE_BYTES
            ),
        }));
    }

    // for now, respond in English regardless of what the client requested
    let metadata = ConsentMessageMetadata {
        language: "en".to_string(),
        utc_offset_minutes: consent_msg_request
            .user_preferences
            .metadata
            .utc_offset_minutes,
    };

    let mut display_message_builder =
        ConsentMessageBuilder::new(&consent_msg_request.method, decimals)?
            .with_ledger_fee(ledger_fee)
            .with_token_symbol(token_symbol);

    if let Some(offset) = consent_msg_request
        .user_preferences
        .metadata
        .utc_offset_minutes
    {
        display_message_builder = display_message_builder.with_utc_offset_minutes(offset);
    }

    if let Some(display_type) = consent_msg_request.user_preferences.device_spec {
        display_message_builder = display_message_builder.with_display_type(display_type);
    }

    let consent_message = match display_message_builder.function {
        Icrc21Function::Transfer => {
            let TransferArg {
                memo,
                amount,
                from_subaccount,
                to,
                fee: _,
                created_at_time: _,
            } = Decode!(&consent_msg_request.arg, TransferArg).map_err(|e| {
                Icrc21Error::UnsupportedCanisterCall(ErrorInfo {
                    description: format!("Failed to decode TransferArg: {}", e),
                })
            })?;
            let sender = Account {
                owner: caller_principal,
                subaccount: from_subaccount,
            };
            display_message_builder = display_message_builder
                .with_amount(amount)
                .with_receiver_account(to)
                .with_from_account(sender);

            if let Some(memo) = memo {
                display_message_builder = display_message_builder.with_memo(memo.0);
            }
            display_message_builder.build()
        }
        Icrc21Function::TransferFrom => {
            let TransferFromArgs {
                memo,
                amount,
                from,
                to,
                spender_subaccount,
                fee: _,
                created_at_time: _,
            } = Decode!(&consent_msg_request.arg, TransferFromArgs).map_err(|e| {
                Icrc21Error::UnsupportedCanisterCall(ErrorInfo {
                    description: format!("Failed to decode TransferFromArgs: {}", e),
                })
            })?;
            let spender = Account {
                owner: caller_principal,
                subaccount: spender_subaccount,
            };
            display_message_builder = display_message_builder
                .with_amount(amount)
                .with_receiver_account(to)
                .with_from_account(from)
                .with_spender_account(spender);

            if let Some(memo) = memo {
                display_message_builder = display_message_builder.with_memo(memo.0);
            }
            display_message_builder.build()
        }
        Icrc21Function::Approve => {
            let ApproveArgs {
                memo,
                amount,
                from_subaccount,
                spender,
                expires_at,
                expected_allowance,
                fee: _,
                created_at_time: _,
            } = Decode!(&consent_msg_request.arg, ApproveArgs).map_err(|e| {
                Icrc21Error::UnsupportedCanisterCall(ErrorInfo {
                    description: format!("Failed to decode ApproveArgs: {}", e),
                })
            })?;
            let approver = Account {
                owner: caller_principal,
                subaccount: from_subaccount,
            };
            let spender = Account {
                owner: spender.owner,
                subaccount: spender.subaccount,
            };
            display_message_builder = display_message_builder
                .with_amount(amount)
                .with_approver_account(approver)
                .with_spender_account(spender);

            if let Some(memo) = memo {
                display_message_builder = display_message_builder.with_memo(memo.0);
            }
            if let Some(expires_at) = expires_at {
                display_message_builder = display_message_builder.with_expires_at(expires_at);
            }
            if let Some(expected_allowance) = expected_allowance {
                display_message_builder =
                    display_message_builder.with_expected_allowance(expected_allowance);
            }
            display_message_builder.build()
        }
    }?;

    Ok(ConsentInfo {
        metadata,
        consent_message,
    })
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
