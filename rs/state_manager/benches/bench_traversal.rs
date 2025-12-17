use criterion::{BatchSize, BenchmarkId, Criterion, black_box};
use criterion_time::ProcessTime;
use ic_base_types::NumBytes;
use ic_canonical_state::{lazy_tree_conversion::replicated_state_as_lazy_tree, traverse};
use ic_canonical_state_tree_hash::hash_tree::hash_lazy_tree;
use ic_canonical_state_tree_hash_test_utils::{build_witness_gen, crypto_hash_lazy_tree};
use ic_certification_version::CURRENT_CERTIFICATION_VERSION;
use ic_crypto_tree_hash::{FlatMap, Label, LabeledTree, MixedHashTree, WitnessGenerator, flatmap};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::{
    ReplicatedState,
    canister_state::execution_state::{CustomSection, CustomSectionType, WasmMetadata},
    metadata_state::Stream,
    testing::ReplicatedStateTesting,
};
use ic_state_manager::labeled_tree_visitor::LabeledTreeVisitor;
use ic_state_manager::{stream_encoding::encode_stream_slice, tree_hash::hash_state};
use ic_test_utilities_state::{get_initial_state, get_running_canister};
use ic_test_utilities_types::{
    ids::{canister_test_id, message_test_id, subnet_test_id, user_test_id},
    messages::{RequestBuilder, ResponseBuilder},
};
use ic_types::{
    Cycles,
    messages::{CallbackId, Payload},
    time::UNIX_EPOCH,
    xnet::StreamIndex,
};
use maplit::btreemap;

fn bench_traversal(c: &mut Criterion<ProcessTime>) {
    const NUM_STREAM_MESSAGES: u64 = 1_000;
    const NUM_CANISTERS: u64 = 10_000;
    const NUM_STATUSES: u64 = 30_000;

    let subnet_type = SubnetType::Application;
    let mut state = ReplicatedState::new(subnet_test_id(1), subnet_type);

    state.modify_streams(|streams| {
        for remote_subnet in 2..10 {
            let mut stream = Stream::default();

            for i in 0..NUM_STREAM_MESSAGES {
                stream.push_accept_signal();
                let msg = if i % 2 == 0 {
                    RequestBuilder::new()
                        .receiver(canister_test_id(i))
                        .sender(canister_test_id(i))
                        .sender_reply_callback(CallbackId::from(i))
                        .payment(Cycles::new(10))
                        .method_name("test".to_string())
                        .method_payload(vec![1; 100])
                        .build()
                        .into()
                } else {
                    ResponseBuilder::new()
                        .originator(canister_test_id(i))
                        .respondent(canister_test_id(i))
                        .originator_reply_callback(CallbackId::from(i))
                        .refund(Cycles::new(10))
                        .response_payload(Payload::Data(vec![2, 100]))
                        .build()
                        .into()
                };
                stream.push(msg);
            }

            streams.insert(subnet_test_id(remote_subnet), stream);
        }
    });

    for i in 0..NUM_CANISTERS {
        state.canister_states.insert(
            canister_test_id(i),
            get_running_canister(canister_test_id(i)),
        );
    }

    let user_id = user_test_id(1);
    let time = UNIX_EPOCH;

    for i in 1..NUM_STATUSES {
        use ic_error_types::{ErrorCode, UserError};
        use ic_types::ingress::{IngressState::*, IngressStatus::*, WasmResult::*};

        let status = match i % 6 {
            0 => Known {
                receiver: canister_test_id(i).get(),
                user_id,
                time,
                state: Received,
            },
            1 => Known {
                receiver: canister_test_id(i).get(),
                user_id,
                time,
                state: Completed(Reply(vec![1; 100])),
            },
            2 => Known {
                receiver: canister_test_id(i).get(),
                user_id,
                time,
                state: Completed(Reject("bad request".to_string())),
            },
            3 => Known {
                receiver: canister_test_id(i).get(),
                user_id,
                time,
                state: Failed(UserError::new(
                    ErrorCode::CanisterNotFound,
                    "canister XXX not found",
                )),
            },
            4 => Known {
                receiver: canister_test_id(i).get(),
                user_id,
                time,
                state: Processing,
            },
            5 => Unknown,
            _ => unreachable!(),
        };
        state.set_ingress_status(message_test_id(i), status, NumBytes::from(u64::MAX), |_| {});
    }

    assert_eq!(
        hash_state(&state).digest(),
        hash_lazy_tree(&replicated_state_as_lazy_tree(&state))
            .unwrap()
            .root_hash(),
    );

    c.bench_function("traverse/hash_tree", |b| {
        b.iter(|| black_box(hash_state(&state)));
    });

    c.bench_function("traverse/hash_tree_new", |b| {
        b.iter(|| black_box(hash_lazy_tree(&replicated_state_as_lazy_tree(&state)).unwrap()))
    });

    c.bench_function("traverse/hash_tree_direct", |b| {
        b.iter(|| {
            black_box(crypto_hash_lazy_tree(&replicated_state_as_lazy_tree(
                &state,
            )))
        })
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
        let labeled_tree = traverse(&state, LabeledTreeVisitor::default());
        b.iter(|| {
            black_box(build_witness_gen(&labeled_tree));
        })
    });

    c.bench_function("traverse/certify_response/1", |b| {
        use LabeledTree::*;

        let labeled_tree = traverse(&state, LabeledTreeVisitor::default());
        let witness_gen = build_witness_gen(&labeled_tree);

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

    let data_tree_100_statuses = {
        use LabeledTree::*;

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

        SubTree(flatmap! {
            Label::from("request_status") => SubTree(FlatMap::from_key_values(entries))
        })
    };

    c.bench_function("traverse/certify_response/100", |b| {
        let labeled_tree = traverse(&state, LabeledTreeVisitor::default());
        let witness_gen = build_witness_gen(&labeled_tree);

        b.iter(|| {
            black_box(
                witness_gen
                    .mixed_hash_tree(&data_tree_100_statuses)
                    .unwrap(),
            );
        });
    });

    c.bench_function("traverse/certify_response/100/new", |b| {
        let hash_tree = hash_lazy_tree(&replicated_state_as_lazy_tree(&state)).unwrap();
        b.iter(|| {
            black_box(
                hash_tree
                    .witness::<MixedHashTree>(&data_tree_100_statuses)
                    .expect("Failed to generate witness."),
            );
        });
    });

    let state_100_custom_sections = {
        let mut state = get_initial_state(/*num_canisters=*/ 100u64, 0);
        state.metadata.certification_version = CURRENT_CERTIFICATION_VERSION;
        assert_eq!(state.canister_states.len(), 100);
        for canister in state.canister_states.values_mut() {
            canister.execution_state.as_mut().unwrap().metadata = WasmMetadata::new(btreemap! {
                "large_section".to_string() => CustomSection::new(CustomSectionType::Public, vec![1u8; 1 << 20]),
            });
        }
        state
    };

    c.bench_function("traverse/hash_custom_sections/100", |b| {
        b.iter(|| {
            black_box(
                hash_lazy_tree(&replicated_state_as_lazy_tree(&state_100_custom_sections)).unwrap(),
            )
        });
    });

    let mut group = c.benchmark_group("drop_tree");
    group.bench_function(BenchmarkId::new("crypto::HashTree", NUM_STATUSES), |b| {
        let hash_tree = hash_state(&state);
        b.iter_batched(|| hash_tree.clone(), std::mem::drop, BatchSize::LargeInput)
    });
    group.bench_function(
        BenchmarkId::new("canonical_state::HashTree", NUM_STATUSES),
        |b| {
            let hash_tree = hash_lazy_tree(&replicated_state_as_lazy_tree(&state)).unwrap();
            b.iter_batched(|| hash_tree.clone(), std::mem::drop, BatchSize::LargeInput)
        },
    );
    group.finish();
}

fn main() {
    let mut c = Criterion::default()
        .with_measurement(ProcessTime::UserTime)
        .sample_size(20)
        .configure_from_args();
    bench_traversal(&mut c);
    c.final_summary();
}
