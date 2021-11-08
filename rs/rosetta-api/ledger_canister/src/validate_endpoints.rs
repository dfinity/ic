use crate::protobuf;
use crate::protobuf::transaction::Transfer as PTransfer;
use crate::{
    AccountBalanceArgs, AccountIdentifier, Block, BlockArg, BlockRes, CyclesResponse, EncodedBlock,
    GetBlocksArgs, GetBlocksRes, HashOf, ICPTs, IterBlocksArgs, IterBlocksRes, Memo,
    NotifyCanisterArgs, Operation, SendArgs, Subaccount, TimeStamp, TipOfChainRes, TotalSupplyArgs,
    Transaction, TransactionNotification, HASH_LENGTH, TRANSACTION_FEE,
};
use dfn_protobuf::ToProto;
use ic_base_types::{CanisterId, CanisterIdError};
use protobuf::cycles_notification_response::Response;
use std::convert::{TryFrom, TryInto};

/// The point of this file is to validate protobufs as they're received and turn
/// them into a validated data type
/// ENDPOINTS
impl ToProto for TotalSupplyArgs {
    type Proto = protobuf::TotalSupplyRequest;
    fn from_proto(_: Self::Proto) -> Result<Self, String> {
        Ok(TotalSupplyArgs {})
    }

    fn into_proto(self) -> protobuf::TotalSupplyRequest {
        protobuf::TotalSupplyRequest {}
    }
}

/// Res
impl ToProto for ICPTs {
    type Proto = protobuf::IcpTs;
    fn from_proto(sel: Self::Proto) -> Result<Self, String> {
        Ok(ICPTs::from_e8s(sel.e8s))
    }

    fn into_proto(self) -> Self::Proto {
        protobuf::IcpTs {
            e8s: self.get_e8s(),
        }
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
            chain_length: Some(protobuf::BlockHeight {
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
                refund: refund.map(|height| protobuf::BlockHeight { height }),
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
            .map_err(|_| format!("{} count not be convered to a usize", pb.length))?;
        Ok(GetBlocksArgs {
            start: pb.start,
            length,
        })
    }

    fn into_proto(self) -> Self::Proto {
        protobuf::GetBlocksRequest {
            start: self.start as u64,
            length: self.length as u64,
        }
    }
}

impl ToProto for GetBlocksRes {
    type Proto = protobuf::GetBlocksResponse;

    fn from_proto(pb: Self::Proto) -> Result<Self, String> {
        match pb
            .get_blocks_content
            .expect("get_blocks() reponse with no content")
        {
            protobuf::get_blocks_response::GetBlocksContent::Blocks(protobuf::EncodedBlocks {
                blocks,
            }) => {
                let blocks: Vec<EncodedBlock> = blocks
                    .into_iter()
                    .map(|protobuf::EncodedBlock { block }| EncodedBlock(block.into_boxed_slice()))
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
                        block: b.0.into_vec(),
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
            .map_err(|_| format!("{} count not be convered to a usize", pb.start))?;
        let length = pb
            .length
            .try_into()
            .map_err(|_| format!("{} count not be convered to a usize", pb.length))?;
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
            .map(|protobuf::EncodedBlock { block }| EncodedBlock(block.into_boxed_slice()))
            .collect();
        Ok(IterBlocksRes(blocks))
    }

    fn into_proto(self) -> Self::Proto {
        let blocks = self
            .0
            .into_iter()
            .map(|b| protobuf::EncodedBlock {
                block: b.0.into_vec(),
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
            })) => Ok(BlockRes(Some(Ok(EncodedBlock(block.into_boxed_slice()))))),
            Some(protobuf::block_response::BlockContent::CanisterId(canister_id)) => {
                Ok(BlockRes(Some(Err(CanisterId::new(canister_id).unwrap()))))
            }
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
            Some(f) => ICPTs::from_proto(f)?,
            None => TRANSACTION_FEE,
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
            amount: ICPTs::from_proto(amount)?,
            fee,
            from_subaccount,
            to,
            created_at_time,
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
        let amount = amount.into_proto();
        let payment = Some(protobuf::Payment {
            receiver_gets: Some(amount),
        });
        protobuf::SendRequest {
            memo: Some(protobuf::Memo { memo: memo.0 }),
            payment,
            max_fee: Some(fee.into_proto()),
            from_subaccount: from_subaccount.map(|sa| sa.into_proto()),
            to: Some(to.into_proto()),
            created_at: None,
            created_at_time,
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
            Some(f) => ICPTs::from_proto(f)?,
            None => TRANSACTION_FEE,
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
            block_height: Some(protobuf::BlockHeight {
                height: block_height,
            }),
            max_fee: Some(max_fee.into_proto()),
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
            amount: ICPTs::from_proto(amount.ok_or("ICPTs missing")?)?,
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
            block_height: Some(protobuf::BlockHeight {
                height: block_height,
            }),
            amount: Some(amount.into_proto()),
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
            Some(h) => Some(HashOf::from_proto(h)?),
            None => None,
        };

        let transaction = pb.transaction.ok_or("This block lacks a transaction")?;

        let timestamp = pb.timestamp.ok_or("This block lacks a timestamp")?;

        Ok(Block {
            parent_hash,
            transaction: Transaction::from_proto(transaction)?,
            timestamp: TimeStamp::from_proto(timestamp)?,
        })
    }

    fn into_proto(self) -> Self::Proto {
        protobuf::Block {
            parent_hash: self.parent_hash.map(|h| h.into_proto()),
            transaction: Some(self.transaction.into_proto()),
            timestamp: Some(self.timestamp.into_proto()),
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
        let created_at_time: TimeStamp = pb.created_at_time.unwrap_or_else(|| TimeStamp::new(0, 0));
        let operation = match pb.transfer.ok_or("This block has no transaction")? {
            PTransfer::Burn(protobuf::Burn {
                from: Some(from),
                amount: Some(amount),
            }) => Operation::Burn {
                from: AccountIdentifier::from_proto(from)?,
                amount: ICPTs::from_proto(amount)?,
            },
            PTransfer::Mint(protobuf::Mint {
                to: Some(to),
                amount: Some(amount),
            }) => Operation::Mint {
                to: AccountIdentifier::from_proto(to)?,
                amount: ICPTs::from_proto(amount)?,
            },
            PTransfer::Send(protobuf::Send {
                to: Some(to),
                from: Some(from),
                amount: Some(amount),
                max_fee,
            }) => Operation::Transfer {
                to: AccountIdentifier::from_proto(to)?,
                from: AccountIdentifier::from_proto(from)?,
                amount: ICPTs::from_proto(amount)?,
                fee: match max_fee {
                    Some(fee) => ICPTs::from_proto(fee)?,
                    None => TRANSACTION_FEE,
                },
            },
            t => return Err(format!("Transaction lacked a required field: {:?}", t)),
        };
        Ok(Transaction {
            operation,
            memo,
            created_at_time,
        })
    }

    fn into_proto(self) -> Self::Proto {
        let Transaction {
            memo,
            created_at_time,
            operation,
        } = self;
        let transfer = match operation {
            Operation::Burn { from, amount } => PTransfer::Burn(protobuf::Burn {
                from: Some(from.into_proto()),
                amount: Some(amount.into_proto()),
            }),

            Operation::Mint { to, amount } => PTransfer::Mint(protobuf::Mint {
                to: Some(to.into_proto()),
                amount: Some(amount.into_proto()),
            }),

            Operation::Transfer {
                to,
                amount,
                from,
                fee,
            } => PTransfer::Send(protobuf::Send {
                to: Some(to.into_proto()),
                amount: Some(amount.into_proto()),
                from: Some(from.into_proto()),
                max_fee: Some(fee.into_proto()),
            }),
        };
        protobuf::Transaction {
            memo: Some(protobuf::Memo { memo: memo.0 }),
            created_at: None,
            created_at_time: Some(created_at_time),
            transfer: Some(transfer),
        }
    }
}

impl<T> ToProto for HashOf<T> {
    type Proto = protobuf::Hash;

    fn from_proto(pb: Self::Proto) -> Result<Self, String> {
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

    fn into_proto(self) -> Self::Proto {
        protobuf::Hash {
            hash: self.into_bytes().to_vec(),
        }
    }
}
