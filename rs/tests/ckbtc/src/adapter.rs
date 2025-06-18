use bitcoin::{consensus::deserialize, Block};
use candid::{Encode, Principal};
use ic_agent::{Agent, AgentError};
use ic_btc_interface::Network;
use ic_config::execution_environment::BITCOIN_MAINNET_CANISTER_ID;
use ic_management_canister_types_private::{
    BitcoinGetSuccessorsArgs, BitcoinGetSuccessorsRequestInitial, BitcoinGetSuccessorsResponse,
    Payload,
};
use ic_system_test_driver::util::MessageCanister;
use ic_types::PrincipalId;
use std::str::FromStr;

pub struct AdapterProxy<'a> {
    msg_can: MessageCanister<'a>,
}

impl<'a> AdapterProxy<'a> {
    pub async fn new(agent: &'a Agent) -> Self {
        let msg_can = MessageCanister::new(
            &agent,
            PrincipalId::from_str(BITCOIN_MAINNET_CANISTER_ID).unwrap(),
        )
        .await;
        Self { msg_can }
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
                "get_successors_response",
                Encode!(&get_successors_request).unwrap(),
            )
            .await
            .map(|result| {
                BitcoinGetSuccessorsResponse::decode(&result)
                    .expect("Failed to decode response of get_successors_response")
            })
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
