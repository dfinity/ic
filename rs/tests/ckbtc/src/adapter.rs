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

    // TODO: Send tx
    // TODO: Sync blocks
}
