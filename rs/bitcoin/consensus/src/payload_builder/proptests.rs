use std::sync::Arc;

use ic_btc_interface::Network;
use ic_btc_replica_types::{
    BitcoinAdapterRequestWrapper, BitcoinAdapterResponse, BitcoinAdapterResponseWrapper,
    GetSuccessorsRequestInitial, GetSuccessorsResponseComplete, SendTransactionResponse,
};
use ic_config::bitcoin_payload_builder_config::Config;
use ic_interfaces::batch_payload::{BatchPayloadBuilder, ProposalContext};
use ic_logger::replica_logger::no_op_logger;
use ic_metrics::MetricsRegistry;
use ic_test_utilities_types::ids::{node_test_id, subnet_test_id};
use ic_types::{batch::ValidationContext, time::UNIX_EPOCH, Height, NumBytes};
use proptest::{prelude::*, proptest};

use crate::{
    payload_builder::tests::{
        mock_registry_client, mock_state_manager, MockBitcoinAdapterClient, CERTIFIED_HEIGHT,
        REGISTRY_VERSION,
    },
    BitcoinPayloadBuilder,
};

const MAX_BTC_BLOCK_SIZE: usize = 4 * 1024 * 1024;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 512,
        max_shrink_time: 60000,
        ..ProptestConfig::default()
    })]

    #[test]
    fn proptest_bitcoin_payload_builder(
        max_size in (0..MAX_BTC_BLOCK_SIZE),
        response in prop_adapter_response_wrapper()
    ) {
        proptest_round(Height::new(10), NumBytes::new(max_size as u64), response);
    }
}

fn proptest_round(
    height: Height,
    max_size: NumBytes,
    bitcoin_payload: BitcoinAdapterResponseWrapper,
) {
    let mut adapter_client = MockBitcoinAdapterClient::new();
    adapter_client
        .expect_send_blocking()
        .times(1)
        .returning(move |_, _| Ok(bitcoin_payload.clone()));

    // TODO: What to put in here?
    let state_manager =
        mock_state_manager(vec![BitcoinAdapterRequestWrapper::GetSuccessorsRequest(
            GetSuccessorsRequestInitial {
                processed_block_hashes: vec![vec![10; 32]],
                anchor: vec![10; 32],
                network: Network::Testnet,
            },
        )]);

    let bitcoin_payload_builder = BitcoinPayloadBuilder::new(
        Arc::new(state_manager),
        &MetricsRegistry::new(),
        Box::new(MockBitcoinAdapterClient::new()),
        Box::new(adapter_client),
        subnet_test_id(0),
        Arc::new(mock_registry_client(NumBytes::new(
            MAX_BTC_BLOCK_SIZE as u64,
        ))),
        Config::default(),
        no_op_logger(),
    );

    let validation_context = ValidationContext {
        registry_version: REGISTRY_VERSION,
        certified_height: CERTIFIED_HEIGHT,
        time: UNIX_EPOCH,
    };

    let payload = bitcoin_payload_builder.build_payload(height, max_size, &[], &validation_context);

    let proposal_context = ProposalContext {
        proposer: node_test_id(1),
        validation_context: &validation_context,
    };

    assert!(bitcoin_payload_builder
        .validate_payload(height, &proposal_context, &payload, &[])
        .is_ok());
}

fn prop_adapter_responses() -> impl Strategy<Value = Vec<BitcoinAdapterResponse>> {
    proptest::collection::vec(prop_adapter_response(), 0..100)
}

fn prop_adapter_response() -> impl Strategy<Value = BitcoinAdapterResponse> {
    (any::<u64>(), prop_adapter_response_wrapper()).prop_map(|(callback_id, response)| {
        BitcoinAdapterResponse {
            response,
            callback_id,
        }
    })
}

fn prop_adapter_response_wrapper() -> impl Strategy<Value = BitcoinAdapterResponseWrapper> {
    prop_oneof![
        Just(BitcoinAdapterResponseWrapper::SendTransactionResponse(
            SendTransactionResponse {}
        )),
        prop_get_successors_response_complete()
            .prop_map(BitcoinAdapterResponseWrapper::GetSuccessorsResponse)
    ]
}

fn prop_get_successors_response_complete() -> impl Strategy<Value = GetSuccessorsResponseComplete> {
    (
        proptest::collection::vec(any::<u8>(), 0..1_000),
        proptest::collection::vec(any::<u8>(), 0..MAX_BTC_BLOCK_SIZE),
    )
        .prop_map(|(next, blocks)| GetSuccessorsResponseComplete {
            // TODO: Multiple blocks
            blocks: vec![blocks],
            next: vec![next],
        })
}
