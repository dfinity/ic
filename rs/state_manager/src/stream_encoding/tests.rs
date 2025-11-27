use super::*;
use ic_base_types::NumSeconds;
use ic_canonical_state::MAX_SUPPORTED_CERTIFICATION_VERSION;
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{ReplicatedState, Stream, testing::ReplicatedStateTesting};
use ic_test_utilities_state::{arb_stream, new_canister_state};
use ic_test_utilities_types::ids::{canister_test_id, subnet_test_id, user_test_id};
use ic_types::{Cycles, xnet::StreamSlice};

const INITIAL_CYCLES: Cycles = Cycles::new(1 << 36);

#[test_strategy::proptest]
fn stream_encode_decode_roundtrip(
    #[strategy(arb_stream(
        0, // min_size
        10, // max_size
        0, // min_signal_count
        10, // max_signal_count
    ))]
    stream: Stream,
) {
    let mut state = ReplicatedState::new(subnet_test_id(1), SubnetType::Application);

    let subnet = subnet_test_id(42);
    let stream_slice: StreamSlice = stream.clone().into();
    state.modify_streams(|streams| {
        streams.insert(subnet, stream);
    });
    state.metadata.certification_version = MAX_SUPPORTED_CERTIFICATION_VERSION;

    // Add some noise, for good measure.
    state.put_canister_state(new_canister_state(
        canister_test_id(13),
        user_test_id(24).get(),
        INITIAL_CYCLES,
        NumSeconds::from(100_000),
    ));

    let tree_encoding = encode_stream_slice(
        &state,
        subnet,
        stream_slice.header().begin(),
        stream_slice.header().end(),
        None,
    )
    .0;
    let bytes = encode_tree(tree_encoding.clone());
    assert_eq!(
        decode_stream_slice(&bytes[..]),
        Ok((subnet, stream_slice)),
        "failed to decode tree {tree_encoding:?}"
    );
}

#[test_strategy::proptest]
fn stream_encode_with_size_limit(
    #[strategy(arb_stream(
        0, // min_size
        10, // max_size
        0, // min_signal_count
        10, // max_signal_count
    ))]
    stream: Stream,
    #[strategy(0..1000usize)] size_limit: usize,
) {
    let mut state = ReplicatedState::new(subnet_test_id(1), SubnetType::Application);

    let subnet = subnet_test_id(42);
    let stream_slice: StreamSlice = stream.clone().into();
    state.modify_streams(|streams| {
        streams.insert(subnet, stream);
    });
    state.metadata.certification_version = MAX_SUPPORTED_CERTIFICATION_VERSION;

    let tree_encoding = encode_stream_slice(
        &state,
        subnet,
        stream_slice.header().begin(),
        stream_slice.header().end(),
        Some(size_limit),
    )
    .0;
    let bytes = encode_tree(tree_encoding.clone());
    match decode_stream_slice(&bytes[..]) {
        Ok((actual_subnet, actual_slice)) => {
            assert_eq!(subnet, actual_subnet);
            match stream_slice.messages() {
                // Expect at least one message.
                Some(messages) => {
                    assert_eq!(stream_slice.header(), actual_slice.header());
                    assert_eq!(stream_slice.header().begin(), messages.begin());
                    assert!(messages.begin() < messages.end());
                }

                // `stream` had no messages.
                None => assert_eq!(stream_slice, actual_slice),
            }
        }
        Err(e) => panic!("Failed to decode tree {tree_encoding:?}: {e}"),
    }
}
