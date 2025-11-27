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
use candid::Decode;
use candid::{Nat, Principal};
use serde_bytes::ByteBuf;
use std::fmt::{self, Display};
use strum::{self, IntoEnumIterator};
use strum_macros::{Display, EnumIter, EnumString};

// Maximum number of bytes that an argument to an ICRC-1 ledger function can have when passed to the ICRC-21 endpoint.
pub const MAX_CONSENT_MESSAGE_ARG_SIZE_BYTES: u16 = 500;

#[derive(Debug, EnumString, EnumIter, Display)]
pub enum Icrc21Function {
    #[strum(serialize = "icrc1_transfer")]
    Transfer,
    #[strum(serialize = "icrc2_approve")]
    Approve,
    #[strum(serialize = "icrc2_transfer_from")]
    TransferFrom,
    #[strum(serialize = "transfer")]
    GenericTransfer,
}

pub enum AccountOrId {
    Account(Account),
    AccountIdAddress(Option<String>),
}

impl AccountOrId {
    pub fn is_anonymous(&self) -> bool {
        match self {
            AccountOrId::Account(account) => account.owner == Principal::anonymous(),
            AccountOrId::AccountIdAddress(addr) => addr.is_none(),
        }
    }
}

impl Display for AccountOrId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AccountOrId::Account(account) => write!(f, "{account}"),
            AccountOrId::AccountIdAddress(Some(str)) => write!(f, "{str}"),
            AccountOrId::AccountIdAddress(None) => write!(f, ""),
        }
    }
}

pub enum GenericMemo {
    Icrc1Memo(ByteBuf),
    IntMemo(u64),
}

pub struct ConsentMessageBuilder {
    function: Icrc21Function,
    display_type: Option<DisplayMessageType>,
    approver: Option<Account>,
    spender: Option<Account>,
    from: Option<AccountOrId>,
    receiver: Option<AccountOrId>,
    amount: Option<Nat>,
    token_symbol: Option<String>,
    token_name: Option<String>,
    ledger_fee: Option<Nat>,
    memo: Option<GenericMemo>,
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
            token_name: None,
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

    pub fn with_from_account(mut self, from: AccountOrId) -> Self {
        self.from = Some(from);
        self
    }

    pub fn with_receiver_account(mut self, receiver: AccountOrId) -> Self {
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

    pub fn with_token_name(mut self, token_name: String) -> Self {
        self.token_name = Some(token_name);
        self
    }

    pub fn with_ledger_fee(mut self, ledger_fee: Nat) -> Self {
        self.ledger_fee = Some(ledger_fee);
        self
    }

    pub fn with_memo(mut self, memo: GenericMemo) -> Self {
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
                ConsentMessage::GenericDisplayMessage(Default::default())
            }
            Some(DisplayMessageType::FieldsDisplay) => {
                ConsentMessage::FieldsDisplayMessage(Default::default())
            }
        };
        match self.function {
            Icrc21Function::Transfer | Icrc21Function::GenericTransfer => {
                let from_account = self.from.ok_or(Icrc21Error::GenericError {
                    error_code: Nat::from(500u64),
                    description: "From account has to be specified.".to_owned(),
                })?;
                let receiver_account = self.receiver.ok_or(Icrc21Error::GenericError {
                    error_code: Nat::from(500u64),
                    description: "Receiver account has to be specified.".to_owned(),
                })?;

                let token_symbol = self.token_symbol.ok_or(Icrc21Error::GenericError {
                    error_code: Nat::from(500u64),
                    description: "Token Symbol must be specified.".to_owned(),
                })?;
                let token_name = self.token_name.ok_or(Icrc21Error::GenericError {
                    error_code: Nat::from(500u64),
                    description: "Token Name must be specified.".to_owned(),
                })?;

                message.add_intent(Icrc21Function::Transfer, Some(token_name));
                if !from_account.is_anonymous() {
                    message.add_account("From", from_account.to_string());
                }
                message.add_amount(self.amount, self.decimals, &token_symbol)?;
                message.add_account("To", receiver_account.to_string());
                message.add_fee(
                    Icrc21Function::Transfer,
                    self.ledger_fee,
                    self.decimals,
                    &token_symbol,
                )?;
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
                let token_symbol = self.token_symbol.ok_or(Icrc21Error::GenericError {
                    error_code: Nat::from(500u64),
                    description: "Token symbol must be specified.".to_owned(),
                })?;

                message.add_intent(Icrc21Function::Approve, None);
                if approver_account.owner != Principal::anonymous() {
                    message.add_account("From", approver_account.to_string());
                }
                message.add_account("Approve to spender", spender_account.to_string());
                message.add_allowance(self.amount, self.decimals, &token_symbol)?;
                if let Some(expected_allowance) = self.expected_allowance {
                    message.add_existing_allowance(
                        expected_allowance,
                        self.decimals,
                        &token_symbol,
                    )?;
                }
                message.add_expiration(self.expires_at, self.utc_offset_minutes);
                message.add_fee(
                    Icrc21Function::Approve,
                    self.ledger_fee,
                    self.decimals,
                    &token_symbol,
                )?;
                if approver_account.owner != Principal::anonymous() {
                    message.add_account("Fees paid by", approver_account.to_string());
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

                let token_symbol = self.token_symbol.ok_or(Icrc21Error::GenericError {
                    error_code: Nat::from(500u64),
                    description: "Token symbol must be specified.".to_owned(),
                })?;
                let token_name = self.token_name.ok_or(Icrc21Error::GenericError {
                    error_code: Nat::from(500u64),
                    description: "Token Name must be specified.".to_owned(),
                })?;
                message.add_intent(Icrc21Function::TransferFrom, Some(token_name));
                message.add_account("From", from_account.to_string());
                message.add_amount(self.amount, self.decimals, &token_symbol)?;
                if spender_account.owner != Principal::anonymous() {
                    message.add_account("Spender", spender_account.to_string());
                }
                message.add_account("To", receiver_account.to_string());
                message.add_fee(
                    Icrc21Function::TransferFrom,
                    self.ledger_fee,
                    self.decimals,
                    &token_symbol,
                )?;
            }
        };

        if let Some(memo) = self.memo {
            message.add_memo(memo);
        }

        Ok(message)
    }
}

pub struct GenericTransferArgs {
    pub from: AccountOrId,
    pub receiver: AccountOrId,
    pub amount: Nat,
    pub memo: Option<GenericMemo>,
}

pub fn build_icrc21_consent_info_for_icrc1_and_icrc2_endpoints(
    consent_msg_request: ConsentMessageRequest,
    caller_principal: Principal,
    ledger_fee: Nat,
    token_symbol: String,
    token_name: String,
    decimals: u8,
) -> Result<ConsentInfo, Icrc21Error> {
    build_icrc21_consent_info(
        consent_msg_request,
        caller_principal,
        ledger_fee,
        token_symbol,
        token_name,
        decimals,
        None,
    )
}

pub fn build_icrc21_consent_info(
    consent_msg_request: ConsentMessageRequest,
    caller_principal: Principal,
    ledger_fee: Nat,
    token_symbol: String,
    token_name: String,
    decimals: u8,
    transfer_args: Option<GenericTransferArgs>,
) -> Result<ConsentInfo, Icrc21Error> {
    if consent_msg_request.arg.len() > MAX_CONSENT_MESSAGE_ARG_SIZE_BYTES as usize {
        return Err(Icrc21Error::UnsupportedCanisterCall(ErrorInfo {
            description: format!(
                "The argument size is too large. The maximum allowed size is {MAX_CONSENT_MESSAGE_ARG_SIZE_BYTES} bytes."
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
            .with_ledger_fee(ledger_fee.clone())
            .with_token_symbol(token_symbol)
            .with_token_name(token_name);

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
                fee,
                created_at_time: _,
            } = Decode!(&consent_msg_request.arg, TransferArg).map_err(|e| {
                Icrc21Error::UnsupportedCanisterCall(ErrorInfo {
                    description: format!("Failed to decode TransferArg: {e}"),
                })
            })?;
            icrc21_check_fee(&fee, &ledger_fee)?;
            let sender = Account {
                owner: caller_principal,
                subaccount: from_subaccount,
            };
            display_message_builder = display_message_builder
                .with_amount(amount)
                .with_receiver_account(AccountOrId::Account(to))
                .with_from_account(AccountOrId::Account(sender));

            if let Some(memo) = memo {
                display_message_builder =
                    display_message_builder.with_memo(GenericMemo::Icrc1Memo(memo.0));
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
                fee,
                created_at_time: _,
            } = Decode!(&consent_msg_request.arg, TransferFromArgs).map_err(|e| {
                Icrc21Error::UnsupportedCanisterCall(ErrorInfo {
                    description: format!("Failed to decode TransferFromArgs: {e}"),
                })
            })?;
            icrc21_check_fee(&fee, &ledger_fee)?;
            let spender = Account {
                owner: caller_principal,
                subaccount: spender_subaccount,
            };
            display_message_builder = display_message_builder
                .with_amount(amount)
                .with_receiver_account(AccountOrId::Account(to))
                .with_from_account(AccountOrId::Account(from))
                .with_spender_account(spender);

            if let Some(memo) = memo {
                display_message_builder =
                    display_message_builder.with_memo(GenericMemo::Icrc1Memo(memo.0));
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
                fee,
                created_at_time: _,
            } = Decode!(&consent_msg_request.arg, ApproveArgs).map_err(|e| {
                Icrc21Error::UnsupportedCanisterCall(ErrorInfo {
                    description: format!("Failed to decode ApproveArgs: {e}"),
                })
            })?;
            icrc21_check_fee(&fee, &ledger_fee)?;
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
                display_message_builder =
                    display_message_builder.with_memo(GenericMemo::Icrc1Memo(memo.0));
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
        Icrc21Function::GenericTransfer => {
            let transfer_args = match transfer_args {
                Some(args) => args,
                None => {
                    return Err(Icrc21Error::UnsupportedCanisterCall(ErrorInfo {
                        description: "transfer args should be provided".to_string(),
                    }));
                }
            };
            display_message_builder = display_message_builder
                .with_amount(transfer_args.amount)
                .with_receiver_account(transfer_args.receiver)
                .with_from_account(transfer_args.from);
            if let Some(memo) = transfer_args.memo {
                display_message_builder = display_message_builder.with_memo(memo);
            }
            display_message_builder.build()
        }
    }?;

    Ok(ConsentInfo {
        metadata,
        consent_message,
    })
}

pub fn icrc21_check_fee(fee: &Option<Nat>, ledger_fee: &Nat) -> Result<(), Icrc21Error> {
    if let Some(fee) = fee
        && fee != ledger_fee
    {
        return Err(Icrc21Error::UnsupportedCanisterCall(ErrorInfo {
            description: format!(
                "The fee specified in the arguments ({fee}) is different than the ledger fee ({ledger_fee})"
            ),
        }));
    }
    Ok(())
}
