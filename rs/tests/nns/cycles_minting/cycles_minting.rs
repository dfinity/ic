use anyhow::Result;
use cycles_minting_canister::{
    CreateCanisterResult, NotifyCreateCanister, NotifyError, NotifyTopUp, SubnetSelection,
    TopUpCanisterResult, create_canister_txn, top_up_canister_txn,
};
use dfn_candid::CandidOne;
use dfn_protobuf::{ProtoBuf, ToProto};
use ic_canister_client::{Agent, Ed25519KeyPair, HttpClient, Sender};
use ic_ledger_core::{block::BlockType, tokens::CheckedAdd};
use ic_nns_constants::LEDGER_CANISTER_ID;
use ic_types::{CanisterId, Cycles, PrincipalId};
use icp_ledger::{
    AccountBalanceArgs, AccountIdentifier, Block, BlockArg, BlockIndex, BlockRes, CyclesResponse,
    DEFAULT_TRANSFER_FEE, Memo, NotifyCanisterArgs, Operation, Subaccount, TipOfChainRes, Tokens,
    TransferArgs, TransferError, protobuf::TipOfChainRequest, tokens_from_proto,
};
use on_wire::{FromWire, IntoWire};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::atomic::{AtomicU64, Ordering};
use url::Url;

pub struct UserHandle {
    user_keypair: Ed25519KeyPair,
    agent: Agent,
    ledger_id: CanisterId,
    cmc_id: CanisterId,
    nonce: AtomicU64,
}

impl UserHandle {
    pub fn new(
        ic_url: &Url,
        http_client: &HttpClient,
        user_keypair: &Ed25519KeyPair,
        ledger_id: CanisterId,
        cmc_id: CanisterId,
    ) -> Self {
        let agent = Agent::new_with_client(
            http_client.clone(),
            ic_url.clone(),
            Sender::from_keypair(user_keypair),
        );
        let user_keypair = *user_keypair;

        Self {
            user_keypair,
            agent,
            ledger_id,
            cmc_id,
            nonce: AtomicU64::new(0),
        }
    }

    fn get_nonce(&self) -> Vec<u8> {
        self.nonce
            .fetch_add(1, Ordering::Relaxed)
            .to_be_bytes()
            .to_vec()
    }

    pub async fn update_pb<Payload: ToProto, Res: ToProto>(
        &self,
        canister_id: &CanisterId,
        method: &str,
        payload: Payload,
    ) -> Result<Res, String> {
        let arg = ProtoBuf(payload).into_bytes()?;
        let bytes = self
            .agent
            .execute_update(canister_id, canister_id, method, arg, self.get_nonce())
            .await?
            .ok_or_else(|| "Reply payload was empty".to_string())?;
        ProtoBuf::from_bytes(bytes).map(|c| c.0)
    }

    pub async fn update_did<
        Payload: candid::CandidType,
        Res: serde::de::DeserializeOwned + candid::CandidType,
    >(
        &self,
        canister_id: &CanisterId,
        method: &str,
        payload: Payload,
    ) -> Result<Res, String> {
        let arg = CandidOne(payload).into_bytes()?;
        let bytes = self
            .agent
            .execute_update(canister_id, canister_id, method, arg, self.get_nonce())
            .await?
            .ok_or_else(|| "Reply payload was empty".to_string())?;
        CandidOne::from_bytes(bytes).map(|c| c.0)
    }

    /// Creates a canister using the notify_create_canister flow. That is,
    ///
    ///     1. Send ICP to the CMC.
    ///
    ///     2. Call CMC.notify_create_canister.
    pub async fn create_canister_cmc(
        &self,
        amount: Tokens,
        sender_subaccount: Option<Subaccount>,
        controller: &UserHandle,
        subnet_type: Option<String>,
        subnet_selection: Option<SubnetSelection>,
    ) -> CreateCanisterResult {
        let block = self
            .pay_for_canister(amount, sender_subaccount, &controller.principal_id())
            .await;
        controller
            .notify_canister_create_cmc(
                block,
                sender_subaccount,
                &controller.principal_id(),
                subnet_type,
                subnet_selection,
            )
            .await
    }

    pub fn principal_id(&self) -> PrincipalId {
        PrincipalId::new_self_authenticating(&ic_canister_client_sender::ed25519_public_key_to_der(
            self.user_keypair.public_key.to_vec(),
        ))
    }

    pub async fn top_up_canister_cmc(
        &self,
        amount: Tokens,
        sender_subaccount: Option<Subaccount>,
        target_canister_id: &CanisterId,
    ) -> TopUpCanisterResult {
        let block_idx = self
            .pay_for_top_up(amount, sender_subaccount, target_canister_id)
            .await;
        self.notify_top_up_cmc(block_idx, sender_subaccount, target_canister_id)
            .await
    }

    pub fn acc_for_top_up(&self, target_canister_id: &CanisterId) -> AccountIdentifier {
        AccountIdentifier::new(self.cmc_id.into(), Some(target_canister_id.into()))
    }

    pub async fn transfer(&self, amount: Tokens, destination_principal_id: PrincipalId) {
        let transfer_args = TransferArgs {
            amount,
            to: AccountIdentifier::new(destination_principal_id, None).to_address(),

            fee: DEFAULT_TRANSFER_FEE,
            memo: Memo(0),
            from_subaccount: None,
            created_at_time: None,
        };

        let result: Result</* block index */ u64, TransferError> = self
            .update_did(&self.ledger_id, "transfer", transfer_args)
            .await
            .unwrap();
        result.unwrap();
    }

    pub async fn pay_for_canister(
        &self,
        amount: Tokens,
        sender_subaccount: Option<Subaccount>,
        controller_id: &PrincipalId,
    ) -> BlockIndex {
        let (send_args, _subaccount) =
            create_canister_txn(amount, sender_subaccount, &self.cmc_id, controller_id);

        self.update_pb(&self.ledger_id, "send_pb", send_args)
            .await
            .unwrap()
    }

    pub async fn pay_for_top_up(
        &self,
        amount: Tokens,
        sender_subaccount: Option<Subaccount>,
        target_canister_id: &CanisterId,
    ) -> BlockIndex {
        let (send_args, _subaccount) =
            top_up_canister_txn(amount, sender_subaccount, &self.cmc_id, target_canister_id);

        self.update_pb(&self.ledger_id, "send_pb", send_args)
            .await
            .unwrap()
    }

    pub async fn notify_canister_create_cmc(
        &self,
        block: BlockIndex,
        _sender_subaccount: Option<Subaccount>,
        controller_id: &PrincipalId,
        subnet_type: Option<String>,
        subnet_selection: Option<SubnetSelection>,
    ) -> CreateCanisterResult {
        #[allow(deprecated)]
        let notify_arg = NotifyCreateCanister {
            block_index: block,
            controller: *controller_id,
            subnet_type,
            subnet_selection,
            settings: None,
        };

        let result: Result<CanisterId, NotifyError> = self
            .update_did(&self.cmc_id, "notify_create_canister", notify_arg)
            .await
            .map_err(|err| (err, None))?;

        match result {
            Ok(cid) => Ok(cid),
            Err(NotifyError::Refunded {
                reason,
                block_index,
            }) => Err((reason, block_index)),
            Err(e) => Err((e.to_string(), None)),
        }
    }

    /// Notify the ledger canister about a canister creation. This deprecated path is no longer
    /// supported - the ledger traps when the `notify_pb` method is called, so this will always fail.
    pub async fn notify_canister_create_ledger(
        &self,
        block: BlockIndex,
        sender_subaccount: Option<Subaccount>,
        controller_id: &PrincipalId,
    ) -> CreateCanisterResult {
        let subaccount = controller_id.into();
        let notify_args = NotifyCanisterArgs {
            block_height: block,
            max_fee: DEFAULT_TRANSFER_FEE,
            from_subaccount: sender_subaccount,
            to_canister: self.cmc_id,
            to_subaccount: Some(subaccount),
        };

        match self
            .update_pb(&self.ledger_id, "notify_pb", notify_args)
            .await
            .map_err(|err| (err, None))?
        {
            CyclesResponse::CanisterCreated(cid) => Ok(cid),
            CyclesResponse::ToppedUp(()) => {
                Err(("Unexpected response, 'topped up'".to_string(), None))
            }
            CyclesResponse::Refunded(err, height) => Err((err, height)),
        }
    }

    pub async fn notify_top_up_cmc(
        &self,
        block_idx: BlockIndex,
        _sender_subaccount: Option<Subaccount>,
        target_canister_id: &CanisterId,
    ) -> TopUpCanisterResult {
        let notify_arg = NotifyTopUp {
            block_index: block_idx,
            canister_id: *target_canister_id,
        };

        let result: Result<Cycles, NotifyError> = self
            .update_did(&self.cmc_id, "notify_top_up", notify_arg)
            .await
            .map_err(|err| (err, None))?;

        match result {
            Ok(_) => Ok(()),
            Err(NotifyError::Refunded {
                reason,
                block_index,
            }) => Err((reason, block_index)),
            Err(e) => Err((e.to_string(), None)),
        }
    }

    /// Notify the ledger canister about a canister top-up. This deprecated path is no longer
    /// supported - the ledger traps when the `notify_pb` method is called, so this will always fail.
    pub async fn notify_top_up_ledger(
        &self,
        block: BlockIndex,
        sender_subaccount: Option<Subaccount>,
        target_canister_id: &CanisterId,
    ) -> TopUpCanisterResult {
        let subaccount = target_canister_id.into();
        let notify_args = NotifyCanisterArgs {
            block_height: block,
            max_fee: DEFAULT_TRANSFER_FEE,
            from_subaccount: sender_subaccount,
            to_canister: self.cmc_id,
            to_subaccount: Some(subaccount),
        };

        match self
            .update_pb(&self.ledger_id, "notify_pb", notify_args)
            .await
            .map_err(|err| (err, None))?
        {
            CyclesResponse::CanisterCreated(_) => {
                Err(("Unexpected response, 'created canister'".to_string(), None))
            }
            CyclesResponse::ToppedUp(()) => Ok(()),
            CyclesResponse::Refunded(err, height) => Err((err, height)),
        }
    }
}

pub fn make_user_ed25519(seed: u64) -> (ic_canister_client_sender::Ed25519KeyPair, PrincipalId) {
    let mut rng = StdRng::seed_from_u64(seed);
    let kp = ic_canister_client_sender::Ed25519KeyPair::generate(&mut rng);
    let public_key_der =
        ic_canister_client_sender::ed25519_public_key_to_der(kp.public_key.to_vec());
    let pid = PrincipalId::new_self_authenticating(&public_key_der);
    (kp, pid)
}

pub struct TestAgent {
    agent: Agent,
}

impl TestAgent {
    pub fn new(ic_url: &Url, agent_client: &HttpClient) -> Self {
        let agent = Agent::new_with_client(agent_client.clone(), ic_url.clone(), Sender::Anonymous);
        Self { agent }
    }

    pub async fn query_pb<Payload: ToProto, Res: ToProto>(
        &self,
        canister_id: &CanisterId,
        method: &str,
        payload: Payload,
    ) -> Result<Res, String> {
        let arg = ProtoBuf(payload).into_bytes()?;
        let bytes = self
            .agent
            .execute_query(canister_id, method, arg)
            .await?
            .ok_or_else(|| "Reply payload was empty".to_string())?;
        ProtoBuf::from_bytes(bytes).map(|c| c.0)
    }

    pub async fn query(
        &self,
        canister_id: &CanisterId,
        method: &str,
        arg: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        self.agent
            .execute_query(canister_id, method, arg)
            .await?
            .ok_or_else(|| "Reply payload was empty".to_string())
    }

    pub async fn get_block(&self, h: BlockIndex) -> Result<Option<Block>, String> {
        match self
            .query_pb(&LEDGER_CANISTER_ID, "block_pb", BlockArg(h))
            .await?
        {
            BlockRes(None) => Ok(None),
            BlockRes(Some(Ok(block))) => Ok(Some(Block::decode(block).unwrap())),
            BlockRes(Some(Err(canister_id))) => unimplemented! {"FIXME: {}", canister_id},
        }
    }

    pub async fn get_balance(&self, acc: AccountIdentifier) -> Tokens {
        let arg = AccountBalanceArgs::new(acc);
        let res: Result<Tokens, String> = self
            .query_pb(&LEDGER_CANISTER_ID, "account_balance_pb", arg)
            .await
            .map(tokens_from_proto);
        res.unwrap()
    }

    pub async fn get_tip(&self) -> Result<Block, String> {
        let resp: Result<TipOfChainRes, String> = self
            .query_pb(&LEDGER_CANISTER_ID, "tip_of_chain_pb", TipOfChainRequest {})
            .await;
        let tip_idx = resp.expect("tip_of_chain failed").tip_index;
        self.get_block(tip_idx).await.map(|opt| opt.unwrap())
    }

    pub async fn check_refund(
        &self,
        refund_block: BlockIndex,
        send_amount: Tokens,
        refund_fee: Tokens,
        expected_destination_principal_id: PrincipalId,
    ) {
        let block = self.get_block(refund_block).await.unwrap().unwrap();
        let txn = block.transaction();

        match txn.operation {
            Operation::Transfer { amount, to, .. } => {
                assert_eq!(
                    amount
                        .checked_add(&DEFAULT_TRANSFER_FEE)
                        .unwrap()
                        .checked_add(&refund_fee)
                        .unwrap(),
                    send_amount
                );
                assert_eq!(
                    to,
                    AccountIdentifier::new(expected_destination_principal_id, None)
                );
            }
            _ => panic!("unexpected block {txn:?}"),
        }

        let block = self.get_block(refund_block + 1).await.unwrap().unwrap();
        let txn = block.transaction();

        match txn.operation {
            Operation::Burn {
                from,
                amount,
                spender,
            } => {
                assert_eq!(refund_fee, amount);
                let balance = self.get_balance(from).await;
                assert_eq!(balance, Tokens::ZERO, "All funds should have been burned");
                assert_eq!(spender, None);
            }
            _ => panic!("unexpected block {txn:?}"),
        }
    }
}
