use bitcoin::{block::Header, consensus::deserialize, Address, Amount, Block};
use bitcoincore_rpc::{json::ListUnspentResultEntry, Auth, Client, RpcApi};
use candid::{Encode, Principal};
use ic_agent::{agent::RejectCode, Agent, AgentError};
use ic_btc_interface::Network;
use ic_config::execution_environment::BITCOIN_MAINNET_CANISTER_ID;
use ic_management_canister_types_private::{
    BitcoinGetSuccessorsArgs, BitcoinGetSuccessorsRequestInitial, BitcoinGetSuccessorsResponse,
    BitcoinGetSuccessorsResponsePartial, BitcoinSendTransactionInternalArgs, Method as Ic00Method,
    Payload,
};
use ic_system_test_driver::{
    driver::{test_env::TestEnv, test_env_api::retry, universal_vm::UniversalVms},
    util::{MessageCanister, MESSAGE_CANISTER_WASM},
};
use ic_types::PrincipalId;
use ic_utils::interfaces::{management_canister::CanisterStatus, ManagementCanister};
use slog::{info, Logger};
use std::{str::FromStr, time::Duration};

use crate::{utils::UNIVERSAL_VM_NAME, BITCOIND_RPC_PORT};

/// A proxy to make requests to the bitcoin adapter
///
/// Under the hood, this is a messaging canister that has privileged access to make
/// bitcoin calls to the management canister and simply proxies the calls from the
/// agent.
/// This allows to make arbitrary calls to the adapter, but they will go through the
/// entire replica code path.
#[derive(Clone)]
pub struct AdapterProxy<'a> {
    msg_can: MessageCanister<'a>,
    log: Logger,
}

impl<'a> AdapterProxy<'a> {
    pub async fn new(agent: &'a Agent, log: Logger) -> Self {
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
                    mgr.install_code(&(bitcoin_principal), MESSAGE_CANISTER_WASM)
                        .call_and_wait()
                        .await
                        .expect("Failed to install code");
                }
                _ => panic!("Unexpected error"),
            },
        };

        let msg_can = MessageCanister::from_canister_id(agent, bitcoin_principal_id.into());
        Self { msg_can, log }
    }

    /// Make a `bitcoin_get_succesors` call
    pub async fn get_successors(
        &self,
        anchor: Vec<u8>,
        headers: Vec<Vec<u8>>,
    ) -> Result<(Vec<Block>, Vec<Header>), AgentError> {
        let get_successors_request =
            BitcoinGetSuccessorsArgs::Initial(BitcoinGetSuccessorsRequestInitial {
                network: Network::Regtest,
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
                deserialize::<Block>(block).expect("Failed to deserialize a bitcoin block")
            })
            .collect();
        let next = next
            .iter()
            .map(|next| {
                deserialize::<Header>(next).expect("Failed to deserialize a bitcoin header")
            })
            .collect();

        info!(self.log, "Parsed get_successors response");
        Ok((blocks, next))
    }

    /// Make a `bitcoin_send_tx` call
    pub async fn send_tx(&self, transaction: Vec<u8>) -> Result<(), AgentError> {
        let send_tx_request = BitcoinSendTransactionInternalArgs {
            network: Network::Mainnet,
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
    ) -> Result<Vec<Block>, AgentError> {
        let mut blocks = vec![];
        let mut tries = 0;

        while blocks.len() < max_num_blocks && tries < max_tries {
            let (new_blocks, _) = self.get_successors(anchor.clone(), headers.clone()).await?;
            let new_headers = new_blocks
                .iter()
                .map(|block| block.block_hash()[..].to_vec())
                .collect::<Vec<_>>();

            headers.extend(new_headers);
            blocks.extend(new_blocks);

            tries += 1;
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
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

pub fn get_alice_and_bob_wallets(env: &TestEnv) -> (Client, Client, Address, Address) {
    let (alice_client, alice_address) = get_test_wallet(env, "alice");
    let (bob_client, bob_address) = get_test_wallet(env, "bob");

    (alice_client, bob_client, alice_address, bob_address)
}

fn get_test_wallet(env: &TestEnv, name: &str) -> (Client, Address) {
    let deployed_universal_vm = env.get_deployed_universal_vm(UNIVERSAL_VM_NAME).unwrap();
    let bitcoind_addr = deployed_universal_vm.get_vm().unwrap().ipv6;

    let client = Client::new(
        format!(
            "http://[{}]:{}/wallet/{}",
            bitcoind_addr, BITCOIND_RPC_PORT, name
        )
        .as_str(),
        Auth::UserPass(
            crate::BITCOIND_RPC_USER.to_string(),
            crate::BITCOIND_RPC_PASSWORD.to_string(),
        ),
    )
    .unwrap();

    let wallets = retry(
        "client.list_wallets",
        env.logger(),
        Duration::from_secs(100),
        Duration::from_secs(1),
        || Ok(client.list_wallets()?),
    )
    .expect("Failed to list wallets");

    // Create wallet if it doesn't exist
    if !wallets.iter().any(|wallet| wallet == name) {
        retry(
            "client.create_wallet",
            env.logger(),
            Duration::from_secs(100),
            Duration::from_secs(1),
            || Ok(client.create_wallet(name, None, None, None, None)?),
        )
        .expect("Failed to create wallet");
    }

    let address = client.get_new_address(None, None).unwrap().assume_checked();
    (client, address)
}

pub fn fund_with_btc(to_fund_client: &Client, to_fund_address: &Address) -> ListUnspentResultEntry {
    let initial_amount = to_fund_client
        .get_received_by_address(to_fund_address, Some(0))
        .unwrap();

    let initial_height = to_fund_client.get_blockchain_info().unwrap().blocks;
    let expected_rewards = calculate_regtest_reward(initial_height);

    let initial_utxos = to_fund_client
        .list_unspent(None, None, None, None, None)
        .unwrap();

    to_fund_client
        .generate_to_address(1, to_fund_address)
        .unwrap();

    // Generate 100 blocks for coinbase maturity
    to_fund_client
        .generate_to_address(100, &get_blackhole_address())
        .unwrap();

    assert_eq!(
        to_fund_client
            .get_received_by_address(to_fund_address, Some(0))
            .unwrap(),
        initial_amount + expected_rewards
    );

    // Find the coinbase UTXO
    let coinbase_utxo = to_fund_client
        .list_unspent(None, None, None, None, None)
        .unwrap()
        .into_iter()
        .find(|utxo| utxo.amount == expected_rewards)
        .expect("Failed to find the coinbase utxo");

    assert!(initial_utxos
        .iter()
        .find(|&utxo| utxo == &coinbase_utxo)
        .is_none());

    coinbase_utxo
}

fn calculate_regtest_reward(height: u64) -> Amount {
    let halvings = (height / 150) as u32;
    let base_reward = Amount::from_btc(50.0).unwrap();
    base_reward / 2u64.pow(halvings)
}

pub fn get_blackhole_address() -> Address {
    Address::from_str("mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn")
        .unwrap()
        .assume_checked()
}
