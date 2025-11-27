use crate::IcRpcClientType;
use bitcoin::{Amount, consensus::deserialize};
use candid::{Encode, Principal};
use ic_agent::{Agent, AgentError, agent::RejectCode};
use ic_btc_adapter_test_utils::rpc_client::{ListUnspentResultEntry, RpcClient, RpcClientType};
use ic_config::execution_environment::BITCOIN_MAINNET_CANISTER_ID;
use ic_management_canister_types_private::{
    BitcoinGetSuccessorsArgs, BitcoinGetSuccessorsRequestInitial, BitcoinGetSuccessorsResponse,
    BitcoinGetSuccessorsResponsePartial, BitcoinSendTransactionInternalArgs, Method as Ic00Method,
    Payload,
};
use ic_system_test_driver::util::{MESSAGE_CANISTER_WASM, MessageCanister};
use ic_types::PrincipalId;
use ic_utils::interfaces::{ManagementCanister, management_canister::CanisterStatus};
use slog::{Logger, info};
use std::{str::FromStr, time::Duration};

/// A proxy to make requests to the bitcoin adapter
///
/// Under the hood, this is a messaging canister that has privileged access to make
/// bitcoin calls to the management canister and simply proxies the calls from the
/// agent.
/// This allows to make arbitrary calls to the adapter, but they will go through the
/// entire replica code path.
#[derive(Clone)]
pub struct AdapterProxy<'a, T: IcRpcClientType> {
    _network: T,
    msg_can: MessageCanister<'a>,
    log: Logger,
}

impl<'a, T: IcRpcClientType> AdapterProxy<'a, T> {
    pub async fn new(_network: T, agent: &'a Agent, log: Logger) -> Self {
        let bitcoin_principal_id = PrincipalId::from_str(BITCOIN_MAINNET_CANISTER_ID).unwrap();
        let bitcoin_principal = bitcoin_principal_id.into();

        let mgr = ManagementCanister::create(agent);

        match mgr.canister_status(&bitcoin_principal).await {
            Ok((status,)) => {
                if status.status != CanisterStatus::Running {
                    panic!("Message canister in unexpected status");
                }
            }
            Err(err) => match err {
                AgentError::UncertifiedReject { ref reject, .. }
                    if reject.reject_code == RejectCode::DestinationInvalid =>
                {
                    // Since we need to install the messaging canister at a
                    // specific PrincipalId, we need to install it manually here
                    mgr.create_canister()
                        .as_provisional_create_with_specified_id(bitcoin_principal)
                        .call_and_wait()
                        .await
                        .expect("Failed to provision id");
                    mgr.install_code(&(bitcoin_principal), &MESSAGE_CANISTER_WASM)
                        .call_and_wait()
                        .await
                        .expect("Failed to install code");
                }
                _ => panic!("Unexpected error"),
            },
        };

        let msg_can = MessageCanister::from_canister_id(agent, bitcoin_principal_id.into());
        Self {
            _network,
            msg_can,
            log,
        }
    }

    /// Make a `bitcoin_get_succesors` call
    pub async fn get_successors(
        &self,
        anchor: Vec<u8>,
        headers: Vec<Vec<u8>>,
    ) -> Result<(Vec<T::Block>, Vec<T::Header>), AgentError> {
        let get_successors_request =
            BitcoinGetSuccessorsArgs::Initial(BitcoinGetSuccessorsRequestInitial {
                network: T::REGTEST_REPLICA,
                anchor,
                processed_block_hashes: headers,
            });

        let result = self
            .msg_can
            .forward_to(
                &Principal::management_canister(),
                &Ic00Method::BitcoinGetSuccessors.to_string(),
                Encode!(&get_successors_request).unwrap(),
            )
            .await?;

        let result = BitcoinGetSuccessorsResponse::decode(&result)
            .expect("Failed to decode response of get_successors_response");

        info!(self.log, "Got get_successor_response");

        let (blocks, next) = match result {
            BitcoinGetSuccessorsResponse::Complete(response) => (response.blocks, response.next),
            BitcoinGetSuccessorsResponse::Partial(response) => self.follow_up(response).await?,
            BitcoinGetSuccessorsResponse::FollowUp(_) => panic!("Received an unexpected follow up"),
        };

        let blocks = blocks
            .iter()
            .map(|block| {
                deserialize::<T::Block>(block).expect("Failed to deserialize a bitcoin block")
            })
            .collect();
        let next = next
            .iter()
            .map(|next| {
                deserialize::<T::Header>(next).expect("Failed to deserialize a bitcoin header")
            })
            .collect();

        info!(self.log, "Parsed get_successors response");
        Ok((blocks, next))
    }

    /// Make a `bitcoin_send_tx` call
    pub async fn send_tx(&self, transaction: Vec<u8>) -> Result<(), AgentError> {
        let send_tx_request = BitcoinSendTransactionInternalArgs {
            network: T::REGTEST_REPLICA,
            transaction,
        };

        self.msg_can
            .forward_to(
                &Principal::management_canister(),
                &Ic00Method::BitcoinSendTransactionInternal.to_string(),
                Encode!(&send_tx_request).unwrap(),
            )
            .await?;

        info!(self.log, "Sent transaction");
        Ok(())
    }

    pub async fn sync_blocks(
        &self,
        headers: &mut Vec<Vec<u8>>,
        anchor: Vec<u8>,
        max_num_blocks: usize,
        max_tries: u64,
    ) -> Result<Vec<T::Block>, AgentError> {
        let mut blocks = vec![];
        let mut tries = 0;

        while blocks.len() < max_num_blocks && tries < max_tries {
            let (new_blocks, _) = loop {
                match self.get_successors(anchor.clone(), headers.clone()).await {
                    // Break inner loop, if adapter returned data
                    Ok(successor) => break successor,
                    // Retry if the call returned an `Unavailable` error
                    Err(AgentError::CertifiedReject { reject, .. })
                    | Err(AgentError::UncertifiedReject { reject, .. })
                        if reject.reject_code == RejectCode::SysTransient
                            && reject.reject_message.starts_with("Unavailable") => {}
                    // Other errors are fatal
                    Err(err) => return Err(err),
                }

                tries += 1;
                tokio::time::sleep(Duration::from_secs(1)).await;
            };

            let new_headers = new_blocks
                .iter()
                .map(|block| T::block_hash(block)[..].to_vec())
                .collect::<Vec<_>>();

            headers.extend(new_headers);
            blocks.extend(new_blocks);

            tries += 1;
            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        Ok(blocks)
    }

    async fn follow_up(
        &self,
        initial: BitcoinGetSuccessorsResponsePartial,
    ) -> Result<(Vec<Vec<u8>>, Vec<Vec<u8>>), AgentError> {
        let mgr = Principal::management_canister();

        let partial_block = initial.partial_block;
        let next = initial.next;

        // Make the follow up calls in parallel
        let follow_ups = (0..initial.remaining_follow_ups)
            .map(|idx| {
                Encode!(&BitcoinGetSuccessorsArgs::FollowUp(idx))
                    .expect("Failed to encode follow up request")
            })
            .map(|request| {
                self.msg_can
                    .forward_to(&mgr, "bitcoin_get_successors", request)
            });
        let results = futures::future::join_all(follow_ups).await;

        // Return if any of them was an error
        let results = results.into_iter().collect::<Result<Vec<_>, _>>()?;

        // Flatten the partial block into a single Vec
        let reconstructed_block = std::iter::once(partial_block)
            .chain(results.into_iter())
            .flatten()
            .collect::<Vec<_>>();

        Ok((vec![reconstructed_block], next))
    }
}

pub fn fund_with_btc<T: RpcClientType>(
    to_fund_client: &RpcClient<T>,
    to_fund_address: &T::Address,
) -> ListUnspentResultEntry {
    let initial_amount = to_fund_client
        .get_balance_of(None, to_fund_address)
        .unwrap();

    let initial_height = to_fund_client.get_blockchain_info().unwrap().blocks;
    let expected_rewards = calculate_regtest_reward::<T>(initial_height);

    let initial_utxos = to_fund_client.list_unspent(None, None).unwrap();

    to_fund_client
        .generate_to_address(1, to_fund_address)
        .unwrap();

    let blackhole_address = to_fund_client.get_new_address().unwrap();
    to_fund_client
        .generate_to_address(T::REGTEST_COINBASE_MATURITY, &blackhole_address)
        .unwrap();

    assert_eq!(
        to_fund_client.get_blockchain_info().unwrap().blocks,
        initial_height + T::REGTEST_COINBASE_MATURITY + 1
    );

    assert_eq!(
        to_fund_client
            .get_balance_of(None, to_fund_address)
            .unwrap(),
        initial_amount + expected_rewards
    );

    // Find the coinbase UTXO
    let coinbase_utxo = to_fund_client
        .list_unspent(None, None)
        .unwrap()
        .into_iter()
        .find(|utxo| utxo.amount == expected_rewards)
        .expect("Failed to find the coinbase utxo");

    // Check that the coinbase UTXO is not part of the initial set of UTXOs
    assert!(!initial_utxos.iter().any(|utxo| utxo == &coinbase_utxo));

    coinbase_utxo
}

fn calculate_regtest_reward<T: RpcClientType>(height: u64) -> Amount {
    let halvings = (height / 150) as u32;
    let base_reward = T::REGTEST_INITIAL_BLOCK_REWARDS;
    base_reward / 2u64.pow(halvings)
}
