use bitcoin::{consensus::deserialize, Block};
use candid::{Encode, Principal};
use ic_agent::{Agent, AgentError};
use ic_btc_interface::Network;
use ic_config::execution_environment::BITCOIN_MAINNET_CANISTER_ID;
use ic_management_canister_types_private::{
    BitcoinGetSuccessorsArgs, BitcoinGetSuccessorsRequestInitial, BitcoinGetSuccessorsResponse,
    Payload,
};
use ic_system_test_driver::util::{MessageCanister, MESSAGE_CANISTER_WASM};
use ic_types::PrincipalId;
use ic_utils::interfaces::ManagementCanister;
use slog::{info, Logger};
use std::str::FromStr;

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

    pub async fn get_successors(
        &self,
        anchor: Vec<u8>,
        headers: Vec<Vec<u8>>,
    ) -> Result<BitcoinGetSuccessorsResponse, AgentError> {
        let get_successors_request =
            BitcoinGetSuccessorsArgs::Initial(BitcoinGetSuccessorsRequestInitial {
                network: Network::Mainnet,
                anchor,
                processed_block_hashes: headers,
            });

        self.msg_can
            .forward_to(
                &Principal::management_canister(),
                "bitcoin_get_successors",
                Encode!(&get_successors_request).unwrap(),
            )
            .await
            .map(|result| {
                BitcoinGetSuccessorsResponse::decode(&result)
                    .expect("Failed to decode response of get_successors_response")
            })
            .inspect(|_| info!(self.log, "Got get_successor_response"))
    }

    // TODO: Send tx fn

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
            match self.get_successors(anchor.clone(), headers.clone()).await? {
                BitcoinGetSuccessorsResponse::Complete(response) => {
                    let new_blocks = response
                        .blocks
                        .iter()
                        .map(|block| {
                            deserialize::<Block>(block)
                                .expect("Failed to deserialize a bitcoin block")
                        })
                        .collect::<Vec<_>>();

                    let new_headers = new_blocks
                        .iter()
                        .map(|block| block.block_hash()[..].to_vec())
                        .collect::<Vec<_>>();

                    headers.extend(new_headers);
                    blocks.extend(new_blocks);
                }
                BitcoinGetSuccessorsResponse::Partial(_response) => {
                    panic!("Partial responses are unimplemented")
                }
                BitcoinGetSuccessorsResponse::FollowUp(_items) => {
                    panic!("Follow up responses are unimplemented")
                }
            }

            tries += 1;
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }

        Ok(blocks)
    }
}
