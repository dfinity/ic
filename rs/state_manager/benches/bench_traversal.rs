use criterion::{black_box, Criterion};
use criterion_time::ProcessTime;
use ic_crypto_tree_hash::{
    flatmap, FlatMap, Label, LabeledTree, WitnessGenerator, WitnessGeneratorImpl,
};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{metadata_state::Stream, ReplicatedState};
use ic_state_manager::{stream_encoding::encode_stream_slice, tree_hash::hash_state};
use ic_test_utilities::{
    mock_time,
    types::{
        ids::{canister_test_id, message_test_id, subnet_test_id, user_test_id},
        messages::{RequestBuilder, ResponseBuilder},
    },
};
use ic_types::{
    messages::{CallbackId, Payload, RequestOrResponse},
    xnet::StreamIndex,
    Cycles, Funds, ICP,
};
use std::convert::TryFrom;

fn bench_traversal(c: &mut Criterion<ProcessTime>) {
    let subnet_type = SubnetType::Application;
    let mut state = ReplicatedState::new_rooted_at(subnet_test_id(1), subnet_type, "TEST".into());

    state.modify_streams(|streams| {
        for remote_subnet in 2..10 {
            let mut stream = Stream::default();

            for i in 0..1000u64 {
                stream.signals_end.inc_assign();
                let msg = if i % 2 == 0 {
                    RequestOrResponse::Request(
                        RequestBuilder::new()
                            .receiver(canister_test_id(i))
                            .sender(canister_test_id(i))
                            .sender_reply_callback(CallbackId::from(i))
                            .payment(Funds::new(Cycles::from(10), ICP::zero()))
                            .method_name("test".to_string())
                            .method_payload(vec![1; 100])
                            .build(),
                    )
                } else {
                    RequestOrResponse::Response(
                        ResponseBuilder::new()
                            .originator(canister_test_id(i))
                            .respondent(canister_test_id(i))
                            .originator_reply_callback(CallbackId::from(i))
                            .refund(Funds::new(Cycles::from(10), ICP::zero()))
                            .response_payload(Payload::Data(vec![2, 100]))
                            .build(),
                    )
                };
                stream.messages.push(msg);
            }

            streams.insert(subnet_test_id(remote_subnet), stream);
        }
    });

    let user_id = user_test_id(1);
    let time = mock_time();

    for i in 1..30000u64 {
        use ic_types::{
            ingress::{IngressStatus::*, WasmResult::*},
            user_error::{ErrorCode, UserError},
        };

        let status = match i % 6 {
            0 => Received {
                receiver: canister_test_id(i).get(),
                user_id,
                time,
            },
            1 => Completed {
                receiver: canister_test_id(i).get(),
                user_id,
                result: Reply(vec![1; 100]),
                time,
            },
            2 => Completed {
                receiver: canister_test_id(i).get(),
                user_id,
                result: Reject("bad request".to_string()),
                time,
            },
            3 => Failed {
                receiver: canister_test_id(i).get(),
                user_id,
                error: UserError::new(ErrorCode::CanisterNotFound, "canister XXX not found"),
                time,
            },
            4 => Processing {
                receiver: canister_test_id(i).get(),
                user_id,
                time,
            },
            5 => Unknown,
            _ => unreachable!(),
        };
        state.set_ingress_status(message_test_id(i), status);
    }

    c.bench_function("traverse/hash_tree", |b| {
        b.iter(|| black_box(hash_state(&state)));
    });

    c.bench_function("traverse/encode_streams", |b| {
        b.iter(|| {
            black_box(encode_stream_slice(
                &state,
                subnet_test_id(2),
                StreamIndex::from(0),
                StreamIndex::from(100),
                None,
            ))
        });
    });

    c.bench_function("traverse/build_witness_gen", |b| {
        let hash_tree = hash_state(&state);
        b.iter(|| {
            black_box(WitnessGeneratorImpl::try_from(hash_tree.clone()).unwrap());
        })
    });

    c.bench_function("traverse/certify_response/1", |b| {
        use LabeledTree::*;
        let hash_tree = hash_state(&state);
        let witness_gen = WitnessGeneratorImpl::try_from(hash_tree).unwrap();

        let data_tree = SubTree(flatmap! {
            Label::from("request_status") => SubTree(flatmap!{
                Label::from(message_test_id(13)) => SubTree(flatmap!{
                    Label::from("reply") => Leaf(vec![1; 100]),
                    Label::from("status") => Leaf(b"replied".to_vec()),
                })
            })
        });

        b.iter(|| {
            black_box(witness_gen.mixed_hash_tree(&data_tree).unwrap());
        });
    });

    c.bench_function("traverse/certify_response/100", |b| {
        use LabeledTree::*;

        let hash_tree = hash_state(&state);
        let witness_gen = WitnessGeneratorImpl::try_from(hash_tree).unwrap();

        let replied_tree = SubTree(flatmap! {
            Label::from("reply") => Leaf(vec![1; 100]),
            Label::from("status") => Leaf(b"replied".to_vec()),
        });

        let entries: Vec<_> = (1..100)
            .map(|i| {
                (
                    Label::from(message_test_id(1 + 6 * i)),
                    replied_tree.clone(),
                )
            })
            .collect();

        let data_tree = SubTree(flatmap! {
            Label::from("request_status") => SubTree(FlatMap::from_key_values(entries))
        });

        b.iter(|| {
            black_box(witness_gen.mixed_hash_tree(&data_tree).unwrap());
        });
    });
}

fn main() {
    let mut c = Criterion::default()
        .with_measurement(ProcessTime::UserTime)
        .sample_size(20)
        .configure_from_args();
    bench_traversal(&mut c);
    c.final_summary();
}
