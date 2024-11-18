use crate::protobuf::{send::Extension as PExt, transaction::Transfer as PTransfer};
use crate::{protobuf, TransferFee, TransferFeeArgs};
use crate::{
    AccountBalanceArgs, AccountIdentifier, Block, BlockArg, BlockRes, CyclesResponse, EncodedBlock,
    GetBlocksArgs, GetBlocksRes, HashOf, IterBlocksArgs, IterBlocksRes, Memo, NotifyCanisterArgs,
    Operation, SendArgs, Subaccount, TimeStamp, TipOfChainRes, Tokens, TotalSupplyArgs,
    Transaction, TransactionNotification, DEFAULT_TRANSFER_FEE,
};
use dfn_protobuf::ToProto;
use ic_base_types::{CanisterId, CanisterIdError};
use ic_ledger_hash_of::HASH_LENGTH;
use protobuf::cycles_notification_response::Response;
use serde_bytes::ByteBuf;
use std::convert::{TryFrom, TryInto};

/// The point of this file is to validate protobufs as they're received and turn
/// them into a validated data type
/// ENDPOINTS.
impl ToProto for TotalSupplyArgs {
    type Proto = protobuf::TotalSupplyRequest;
    fn from_proto(_: Self::Proto) -> Result<Self, String> {
        Ok(TotalSupplyArgs {})
    }

    fn into_proto(self) -> protobuf::TotalSupplyRequest {
        protobuf::TotalSupplyRequest {}
    }
}

pub fn tokens_from_proto(pb: protobuf::Tokens) -> Tokens {
    Tokens::from_e8s(pb.e8s)
}

pub fn tokens_into_proto(tokens: Tokens) -> protobuf::Tokens {
    protobuf::Tokens {
        e8s: tokens.get_e8s(),
    }
}

impl ToProto for AccountBalanceArgs {
    type Proto = protobuf::AccountBalanceRequest;
    fn from_proto(pb: Self::Proto) -> Result<Self, String> {
        pb.account
            .ok_or_else(|| "Received an account balance request with no account".to_string())
            .and_then(AccountIdentifier::from_proto)
            .map(AccountBalanceArgs::new)
    }

    fn into_proto(self) -> Self::Proto {
        protobuf::AccountBalanceRequest {
            account: Some(self.account.into_proto()),
        }
    }
}

impl ToProto for TransferFeeArgs {
    type Proto = protobuf::TransferFeeRequest;

    fn from_proto(_: Self::Proto) -> Result<Self, String> {
        Ok(TransferFeeArgs {})
    }

    fn into_proto(self) -> Self::Proto {
        protobuf::TransferFeeRequest {}
    }
}

impl ToProto for TransferFee {
    type Proto = protobuf::TransferFeeResponse;

    fn from_proto(pb: Self::Proto) -> Result<Self, String> {
        let transfer_fee = pb
            .transfer_fee
            .ok_or_else(|| "transaction_fee should be set".to_string())
            .map(tokens_from_proto)?;
        Ok(Self { transfer_fee })
    }

    fn into_proto(self) -> Self::Proto {
        protobuf::TransferFeeResponse {
            transfer_fee: Some(tokens_into_proto(self.transfer_fee)),
        }
    }
}

impl ToProto for TipOfChainRes {
    type Proto = protobuf::TipOfChainResponse;

    fn from_proto(pb: Self::Proto) -> Result<Self, String> {
        let chain_length = pb
            .chain_length
            .ok_or("Didn't receive a chain length")?
            .height;
        Ok(TipOfChainRes {
            certification: pb.certification.map(|pb| pb.certification),
            tip_index: chain_length,
        })
    }

    fn into_proto(self) -> Self::Proto {
        protobuf::TipOfChainResponse {
            certification: self
                .certification
                .map(|certification| protobuf::Certification { certification }),
            chain_length: Some(protobuf::BlockIndex {
                height: self.tip_index,
            }),
        }
    }
}

impl ToProto for CyclesResponse {
    type Proto = protobuf::CyclesNotificationResponse;

    fn from_proto(pb: Self::Proto) -> Result<Self, String> {
        match pb
            .response
            .ok_or("No response field received from the cycles canister")?
        {
            Response::Refund(protobuf::Refund { error, refund }) => {
                Ok(CyclesResponse::Refunded(error, refund.map(|bh| bh.height)))
            }
            Response::ToppedUp(_) => Ok(CyclesResponse::ToppedUp(())),
            Response::CreatedCanisterId(pid) => {
                let cid = CanisterId::try_from(pid).map_err(|e| e.to_string())?;
                Ok(CyclesResponse::CanisterCreated(cid))
            }
        }
    }

    fn into_proto(self) -> Self::Proto {
        let response = match self {
            CyclesResponse::Refunded(error, refund) => Response::Refund(protobuf::Refund {
                error,
                refund: refund.map(|height| protobuf::BlockIndex { height }),
            }),
            CyclesResponse::ToppedUp(()) => Response::ToppedUp(protobuf::ToppedUp {}),
            CyclesResponse::CanisterCreated(cid) => Response::CreatedCanisterId(cid.get()),
        };
        Self::Proto {
            response: Some(response),
        }
    }
}

impl ToProto for GetBlocksArgs {
    type Proto = protobuf::GetBlocksRequest;

    fn from_proto(pb: Self::Proto) -> Result<Self, String> {
        let length = pb
            .length
            .try_into()
            .map_err(|_| format!("{} count not be converted to a usize", pb.length))?;
        Ok(GetBlocksArgs {
            start: pb.start,
            length,
        })
    }

    fn into_proto(self) -> Self::Proto {
        protobuf::GetBlocksRequest {
            start: self.start,
            length: self.length as u64,
        }
    }
}

impl ToProto for GetBlocksRes {
    type Proto = protobuf::GetBlocksResponse;

    fn from_proto(pb: Self::Proto) -> Result<Self, String> {
        match pb
            .get_blocks_content
            .expect("get_blocks() response with no content")
        {
            protobuf::get_blocks_response::GetBlocksContent::Blocks(protobuf::EncodedBlocks {
                blocks,
            }) => {
                let blocks: Vec<EncodedBlock> = blocks
                    .into_iter()
                    .map(|protobuf::EncodedBlock { block }| EncodedBlock::from(block))
                    .collect();
                Ok(GetBlocksRes(Ok(blocks)))
            }
            protobuf::get_blocks_response::GetBlocksContent::Error(error) => {
                Ok(GetBlocksRes(Err(error)))
            }
        }
    }

    fn into_proto(self) -> Self::Proto {
        match self.0 {
            Ok(blocks) => {
                let blocks = blocks
                    .into_iter()
                    .map(|b| protobuf::EncodedBlock {
                        block: b.into_vec(),
                    })
                    .collect();
                protobuf::GetBlocksResponse {
                    get_blocks_content: Some(
                        protobuf::get_blocks_response::GetBlocksContent::Blocks(
                            protobuf::EncodedBlocks { blocks },
                        ),
                    ),
                }
            }
            Err(err) => protobuf::GetBlocksResponse {
                get_blocks_content: Some(protobuf::get_blocks_response::GetBlocksContent::Error(
                    err,
                )),
            },
        }
    }
}

impl ToProto for IterBlocksArgs {
    type Proto = protobuf::IterBlocksRequest;

    fn from_proto(pb: Self::Proto) -> Result<Self, String> {
        let start = pb
            .start
            .try_into()
            .map_err(|_| format!("{} count not be converted to a usize", pb.start))?;
        let length = pb
            .length
            .try_into()
            .map_err(|_| format!("{} count not be converted to a usize", pb.length))?;
        Ok(IterBlocksArgs { start, length })
    }

    fn into_proto(self) -> Self::Proto {
        protobuf::IterBlocksRequest {
            start: self.start as u64,
            length: self.length as u64,
        }
    }
}

impl ToProto for IterBlocksRes {
    type Proto = protobuf::IterBlocksResponse;

    fn from_proto(pb: Self::Proto) -> Result<Self, String> {
        let blocks: Vec<EncodedBlock> = pb
            .blocks
            .into_iter()
            .map(|protobuf::EncodedBlock { block }| EncodedBlock::from(block))
            .collect();
        Ok(IterBlocksRes(blocks))
    }

    fn into_proto(self) -> Self::Proto {
        let blocks = self
            .0
            .into_iter()
            .map(|b| protobuf::EncodedBlock {
                block: b.into_vec(),
            })
            .collect();
        protobuf::IterBlocksResponse { blocks }
    }
}

impl ToProto for BlockArg {
    type Proto = protobuf::IterBlocksRequest;

    fn from_proto(pb: Self::Proto) -> Result<Self, String> {
        Ok(BlockArg(pb.start))
    }

    fn into_proto(self) -> Self::Proto {
        protobuf::IterBlocksRequest {
            start: self.0,
            length: 1,
        }
    }
}

impl ToProto for BlockRes {
    type Proto = protobuf::BlockResponse;

    fn from_proto(pb: Self::Proto) -> Result<Self, String> {
        match pb.block_content {
            Some(protobuf::block_response::BlockContent::Block(protobuf::EncodedBlock {
                block,
            })) => Ok(BlockRes(Some(Ok(EncodedBlock::from(block))))),
            Some(protobuf::block_response::BlockContent::CanisterId(canister_id)) => Ok(BlockRes(
                Some(Err(CanisterId::unchecked_from_principal(canister_id))),
            )),
            None => Ok(BlockRes(None)),
        }
    }

    fn into_proto(self) -> Self::Proto {
        match self.0 {
            None => protobuf::BlockResponse {
                block_content: None,
            },
            Some(Ok(block)) => protobuf::BlockResponse {
                block_content: Some(protobuf::block_response::BlockContent::Block(
                    protobuf::EncodedBlock {
                        block: block.0.to_vec(),
                    },
                )),
            },
            Some(Err(canister_id)) => {
                let block_content = Some(protobuf::block_response::BlockContent::CanisterId(
                    canister_id.get(),
                ));
                protobuf::BlockResponse { block_content }
            }
        }
    }
}
impl ToProto for SendArgs {
    type Proto = protobuf::SendRequest;

    fn from_proto(
        protobuf::SendRequest {
            memo,
            payment,
            max_fee,
            from_subaccount,
            to,
            created_at: _,
            created_at_time,
        }: Self::Proto,
    ) -> Result<Self, String> {
        let memo = match memo {
            Some(m) => Memo(m.memo),
            None => Memo(0),
        };
        let amount = payment
            .and_then(|p| p.receiver_gets)
            .ok_or("Payment is missing or incomplete")?;
        let fee = match max_fee {
            Some(f) => tokens_from_proto(f),
            None => DEFAULT_TRANSFER_FEE,
        };
        let from_subaccount = match from_subaccount {
            Some(sa) => Some(Subaccount::from_proto(sa)?),
            None => None,
        };
        let to = AccountIdentifier::from_proto(
            to.ok_or("The send endpoint requires a field _to to be filled")?,
        )?;
        Ok(SendArgs {
            memo,
            amount: tokens_from_proto(amount),
            fee,
            from_subaccount,
            to,
            created_at_time: created_at_time.map(timestamp_from_proto),
        })
    }
    fn into_proto(self) -> Self::Proto {
        let SendArgs {
            memo,
            amount,
            fee,
            from_subaccount,
            to,
            created_at_time,
        } = self;
        let amount = tokens_into_proto(amount);
        let payment = Some(protobuf::Payment {
            receiver_gets: Some(amount),
        });
        protobuf::SendRequest {
            memo: Some(protobuf::Memo { memo: memo.0 }),
            payment,
            max_fee: Some(tokens_into_proto(fee)),
            from_subaccount: from_subaccount.map(|sa| sa.into_proto()),
            to: Some(to.into_proto()),
            created_at: None,
            created_at_time: created_at_time.map(timestamp_into_proto),
        }
    }
}

impl ToProto for NotifyCanisterArgs {
    type Proto = protobuf::NotifyRequest;

    fn from_proto(
        protobuf::NotifyRequest {
            block_height,
            max_fee,
            from_subaccount,
            to_canister,
            to_subaccount,
        }: Self::Proto,
    ) -> Result<Self, String> {
        let from_subaccount = match from_subaccount {
            Some(sa) => Some(Subaccount::from_proto(sa)?),
            None => None,
        };

        let to_subaccount = match to_subaccount {
            Some(sa) => Some(Subaccount::from_proto(sa)?),
            None => None,
        };
        let to_canister: CanisterId = to_canister
            .ok_or("to_canister is missing")?
            .try_into()
            .map_err(|e: CanisterIdError| e.to_string())?;

        let max_fee = match max_fee {
            Some(f) => tokens_from_proto(f),
            None => DEFAULT_TRANSFER_FEE,
        };

        let block_height = block_height.ok_or("Missing block height")?.height;

        Ok(NotifyCanisterArgs {
            block_height,
            max_fee,
            from_subaccount,
            to_canister,
            to_subaccount,
        })
    }
    fn into_proto(self) -> Self::Proto {
        let NotifyCanisterArgs {
            block_height,
            max_fee,
            to_subaccount,
            to_canister,
            from_subaccount,
        } = self;
        protobuf::NotifyRequest {
            block_height: Some(protobuf::BlockIndex {
                height: block_height,
            }),
            max_fee: Some(tokens_into_proto(max_fee)),
            to_subaccount: to_subaccount.map(|sa| sa.into_proto()),
            to_canister: Some(to_canister.get()),
            from_subaccount: from_subaccount.map(|sa| sa.into_proto()),
        }
    }
}

impl ToProto for TransactionNotification {
    type Proto = protobuf::TransactionNotificationRequest;

    fn from_proto(
        protobuf::TransactionNotificationRequest {
            from,
            from_subaccount,
            to,
            to_subaccount,
            block_height,
            amount,
            memo,
        }: Self::Proto,
    ) -> Result<Self, String> {
        let from_subaccount = match from_subaccount {
            Some(sa) => Some(Subaccount::from_proto(sa)?),
            None => None,
        };

        let to_subaccount = match to_subaccount {
            Some(sa) => Some(Subaccount::from_proto(sa)?),
            None => None,
        };

        let to: CanisterId = to
            .ok_or("to_canister is missing")?
            .try_into()
            .map_err(|e: CanisterIdError| e.to_string())?;

        Ok(TransactionNotification {
            from: from.ok_or("From missing")?,
            from_subaccount,
            to,
            to_subaccount,
            block_height: block_height.ok_or("Block height missing")?.height,
            amount: tokens_from_proto(amount.ok_or("Tokens missing")?),
            memo: Memo(memo.ok_or("Memo missing")?.memo),
        })
    }

    fn into_proto(self) -> Self::Proto {
        let TransactionNotification {
            from,
            from_subaccount,
            to,
            to_subaccount,
            block_height,
            amount,
            memo,
        } = self;
        protobuf::TransactionNotificationRequest {
            from: Some(from.into_proto()),
            from_subaccount: from_subaccount.map(|sa| sa.into_proto()),
            to: Some(to.get().into_proto()),
            to_subaccount: to_subaccount.map(|sa| sa.into_proto()),
            block_height: Some(protobuf::BlockIndex {
                height: block_height,
            }),
            amount: Some(tokens_into_proto(amount)),
            memo: Some(protobuf::Memo { memo: memo.0 }),
        }
    }
}

/// TYPES
impl ToProto for Subaccount {
    type Proto = protobuf::Subaccount;

    fn from_proto(pb: Self::Proto) -> Result<Self, String> {
        Subaccount::try_from(&pb.sub_account[..]).map_err(|e| e.to_string())
    }

    fn into_proto(self) -> Self::Proto {
        protobuf::Subaccount {
            sub_account: self.to_vec(),
        }
    }
}

impl ToProto for AccountIdentifier {
    type Proto = protobuf::AccountIdentifier;

    fn from_proto(pb: Self::Proto) -> Result<Self, String> {
        AccountIdentifier::from_slice(&pb.hash[..]).map_err(|e| e.to_string())
    }

    fn into_proto(self) -> Self::Proto {
        protobuf::AccountIdentifier {
            hash: self.to_vec(),
        }
    }
}

impl ToProto for Block {
    type Proto = protobuf::Block;

    fn from_proto(pb: Self::Proto) -> Result<Self, String> {
        let parent_hash = match pb.parent_hash {
            Some(h) => Some(hash_from_proto(h)?),
            None => None,
        };

        let transaction = pb.transaction.ok_or("This block lacks a transaction")?;

        let timestamp = pb.timestamp.ok_or("This block lacks a timestamp")?;

        Ok(Block {
            parent_hash,
            transaction: Transaction::from_proto(transaction)?,
            timestamp: timestamp_from_proto(timestamp),
        })
    }

    fn into_proto(self) -> Self::Proto {
        protobuf::Block {
            parent_hash: self.parent_hash.map(hash_into_proto),
            transaction: Some(self.transaction.into_proto()),
            timestamp: Some(timestamp_into_proto(self.timestamp)),
        }
    }
}

impl ToProto for Transaction {
    type Proto = protobuf::Transaction;

    fn from_proto(pb: Self::Proto) -> Result<Self, String> {
        let memo: Memo = match pb.memo {
            Some(m) => Memo(m.memo),
            None => Memo(0),
        };
        let icrc1_memo = match pb.icrc1_memo {
            Some(m) => Some(ByteBuf::from(m.memo)),
            None => None,
        };
        let created_at_time: Option<TimeStamp> = pb.created_at_time.map(timestamp_from_proto);
        let operation = match pb.transfer.ok_or("This block has no transaction")? {
            PTransfer::Burn(protobuf::Burn {
                from: Some(from),
                amount: Some(amount),
                spender,
            }) => Operation::Burn {
                from: AccountIdentifier::from_proto(from)?,
                amount: tokens_from_proto(amount),
                spender: match spender {
                    Some(spender) => Some(AccountIdentifier::from_proto(spender)?),
                    None => None,
                },
            },
            PTransfer::Mint(protobuf::Mint {
                to: Some(to),
                amount: Some(amount),
            }) => Operation::Mint {
                to: AccountIdentifier::from_proto(to)?,
                amount: tokens_from_proto(amount),
            },
            PTransfer::Send(protobuf::Send {
                to: Some(to),
                from: Some(from),
                amount: Some(amount),
                max_fee,
                extension,
            }) => match extension {
                None => Operation::Transfer {
                    to: AccountIdentifier::from_proto(to)?,
                    from: AccountIdentifier::from_proto(from)?,
                    spender: None,
                    amount: tokens_from_proto(amount),
                    fee: match max_fee {
                        Some(fee) => tokens_from_proto(fee),
                        None => DEFAULT_TRANSFER_FEE,
                    },
                },
                Some(PExt::TransferFrom(protobuf::TransferFrom { spender })) => {
                    let spender = spender.ok_or_else(|| {
                        "Transfer from transaction: missing field `spender`".to_string()
                    })?;
                    Operation::Transfer {
                        from: AccountIdentifier::from_proto(from)?,
                        to: AccountIdentifier::from_proto(to)?,
                        spender: Some(AccountIdentifier::from_proto(spender)?),
                        amount: tokens_from_proto(amount),
                        fee: match max_fee {
                            Some(fee) => tokens_from_proto(fee),
                            None => DEFAULT_TRANSFER_FEE,
                        },
                    }
                }
                Some(PExt::Approve(protobuf::Approve {
                    allowance,
                    expires_at,
                    expected_allowance,
                })) => {
                    let allowance = allowance.ok_or_else(|| {
                        "Approve transaction: missing field `allowance`".to_string()
                    })?;

                    Operation::Approve {
                        from: AccountIdentifier::from_proto(from)?,
                        spender: AccountIdentifier::from_proto(to)?,
                        allowance: tokens_from_proto(allowance),
                        expected_allowance: expected_allowance.map(tokens_from_proto),
                        expires_at: expires_at.map(timestamp_from_proto),
                        fee: match max_fee {
                            Some(fee) => tokens_from_proto(fee),
                            None => DEFAULT_TRANSFER_FEE,
                        },
                    }
                }
            },
            t => return Err(format!("Transaction lacked a required field: {:?}", t)),
        };
        Ok(Transaction {
            operation,
            memo,
            icrc1_memo,
            created_at_time,
        })
    }

    fn into_proto(self) -> Self::Proto {
        let Transaction {
            memo,
            icrc1_memo,
            created_at_time,
            operation,
        } = self;
        let icrc1_memo_proto = icrc1_memo.map(|b| protobuf::Icrc1Memo { memo: b.to_vec() });
        let transfer = match operation {
            Operation::Burn {
                from,
                amount,
                spender,
            } => PTransfer::Burn(protobuf::Burn {
                from: Some(from.into_proto()),
                amount: Some(tokens_into_proto(amount)),
                spender: spender.map(|s| s.into_proto()),
            }),

            Operation::Mint { to, amount } => PTransfer::Mint(protobuf::Mint {
                to: Some(to.into_proto()),
                amount: Some(tokens_into_proto(amount)),
            }),

            Operation::Transfer {
                to,
                amount,
                from,
                fee,
                spender,
            } => PTransfer::Send(protobuf::Send {
                to: Some(to.into_proto()),
                amount: Some(tokens_into_proto(amount)),
                from: Some(from.into_proto()),
                max_fee: Some(tokens_into_proto(fee)),
                extension: spender.map(|spender| {
                    PExt::TransferFrom(protobuf::TransferFrom {
                        spender: Some(spender.into_proto()),
                    })
                }),
            }),
            Operation::Approve {
                from,
                spender,
                allowance,
                fee,
                expires_at,
                expected_allowance,
            } => PTransfer::Send(protobuf::Send {
                from: Some(from.into_proto()),
                to: Some(spender.into_proto()),
                amount: Some(tokens_into_proto(Tokens::ZERO)),
                max_fee: Some(tokens_into_proto(fee)),
                extension: Some(PExt::Approve(protobuf::Approve {
                    allowance: Some(tokens_into_proto(allowance)),
                    expires_at: expires_at.map(timestamp_into_proto),
                    expected_allowance: expected_allowance.map(tokens_into_proto),
                })),
            }),
        };
        protobuf::Transaction {
            memo: Some(protobuf::Memo { memo: memo.0 }),
            icrc1_memo: icrc1_memo_proto,
            created_at: None,
            created_at_time: created_at_time.map(timestamp_into_proto),
            transfer: Some(transfer),
        }
    }
}

pub fn timestamp_from_proto(pb: protobuf::TimeStamp) -> ic_ledger_core::timestamp::TimeStamp {
    ic_ledger_core::timestamp::TimeStamp::from_nanos_since_unix_epoch(pb.timestamp_nanos)
}

pub fn timestamp_into_proto(ts: ic_ledger_core::timestamp::TimeStamp) -> protobuf::TimeStamp {
    protobuf::TimeStamp {
        timestamp_nanos: ts.as_nanos_since_unix_epoch(),
    }
}

pub fn hash_from_proto<T>(pb: protobuf::Hash) -> Result<HashOf<T>, String> {
    let boxed_slice = pb.hash.into_boxed_slice();
    let hash: Box<[u8; 32]> = match boxed_slice.clone().try_into() {
        Ok(s) => s,
        Err(_) => {
            return Err(format!(
                "Expected a Vec of length {} but it was {}",
                HASH_LENGTH,
                boxed_slice.len(),
            ))
        }
    };
    Ok(HashOf::new(*hash))
}

pub fn hash_into_proto<T>(hash: HashOf<T>) -> protobuf::Hash {
    protobuf::Hash {
        hash: hash.into_bytes().to_vec(),
    }
}
