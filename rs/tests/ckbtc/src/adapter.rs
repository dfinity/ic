use bitcoin::{block::Header, consensus::deserialize, Block};
use candid::{Encode, Principal};
use ic_agent::{Agent, AgentError};
use ic_btc_interface::Network;
use ic_config::execution_environment::BITCOIN_MAINNET_CANISTER_ID;
use ic_management_canister_types_private::{
    BitcoinGetSuccessorsArgs, BitcoinGetSuccessorsRequestInitial, BitcoinGetSuccessorsResponse,
    BitcoinGetSuccessorsResponsePartial, BitcoinSendTransactionInternalArgs, Payload,
};
use ic_system_test_driver::util::{MessageCanister, MESSAGE_CANISTER_WASM};
use ic_types::PrincipalId;
use ic_utils::interfaces::ManagementCanister;
use slog::{info, Logger};
use std::str::FromStr;

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

        // Since we need to install the messaging canister at a specific PrincipalId,
        // we need to install it manually here
        let mgr = ManagementCanister::create(agent);
        mgr.create_canister()
            .as_provisional_create_with_specified_id(bitcoin_principal)
            .call_and_wait()
            .await
            .expect("Failed to provision id");
        mgr.install_code(&(bitcoin_principal), MESSAGE_CANISTER_WASM)
            .call_and_wait()
            .await
            .expect("Failed to install code");

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
                network: Network::Mainnet,
                anchor,
                processed_block_hashes: headers,
            });

        let result = self
            .msg_can
            .forward_to(
                &Principal::management_canister(),
                "bitcoin_get_successors",
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
                "bitcoin_send_transaction_internal",
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
        let results = results
            .into_iter()
            .collect::<Result<Vec<_>>, AgentError>()?;

        // Flatten the partial block into a single Vec
        let reconstructed_block = std::iter::once(partial_block)
            .chain(results.into_iter())
            .flatten()
            .collect::<Vec<_>>();

        Ok((reconstructed_block, next))
    }
}
