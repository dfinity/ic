use crate::{CheckpointError, PageMapType, StateManagerMetrics, NUMBER_OF_CHECKPOINT_THREADS};
use crossbeam_channel::{unbounded, Sender};
use ic_logger::{fatal, ReplicaLogger};
#[allow(unused)]
use ic_replicated_state::{
    canister_state::execution_state::SandboxMemory, BitcoinState, CanisterState, NumWasmPages,
    PageMap, ReplicatedState,
};
use ic_state_layout::{
    error::LayoutError, BitcoinStateBits, BitcoinStateLayout, CanisterStateBits, CheckpointLayout,
    ExecutionStateBits, ReadOnly, RwPolicy, StateLayout, TipHandler,
};
use ic_types::{CanisterId, Height};
use ic_utils::fs::defrag_file_partially;
use ic_utils::thread::parallel_map;
use ic_utils::thread::JoinOnDrop;
use prometheus::HistogramTimer;
use rand::prelude::SliceRandom;
use rand::{seq::IteratorRandom, Rng, SeedableRng};
use rand_chacha::ChaChaRng;
use std::collections::BTreeSet;
use std::os::unix::prelude::MetadataExt;
use std::path::{Path, PathBuf};

const DEFRAG_SIZE: u64 = 1 << 29; // 500 MB
const DEFRAG_SAMPLE: usize = 100;

/// Request for the Tip directory handling thread.
pub enum TipRequest {
    /// Create checkpoint from the current tip for the given height.
    /// Return the created checkpoint or error into the sender.
    TipToCheckpoint {
        height: Height,
        sender: Sender<Result<CheckpointLayout<ReadOnly>, LayoutError>>,
    },
    /// Filter canisters in tip. Remove ones not present in the set.
    FilterTipCanisters {
        height: Height,
        ids: BTreeSet<CanisterId>,
    },
    /// Truncate PageMaps's path.
    TruncatePageMapsPath {
        height: Height,
        page_map_type: PageMapType,
    },
    /// Flush PageMaps's round delta on disc.
    FlushRoundDelta {
        height: Height,
        page_map: PageMap,
        page_map_type: PageMapType,
    },
    /// Reset tip folder to the checkpoint with given height.
    ResetTipTo {
        checkpoint_layout: CheckpointLayout<ReadOnly>,
    },
    /// Serialize the data from ReplicatedState to the tip folder.
    SerializeToTip {
        height: Height,
        replicated_state: Box<ReplicatedState>,
    },
    /// Run one round of tip defragmentation.
    DefragTip {
        height: Height,
        page_map_types: Vec<PageMapType>,
    },
    Wait {
        sender: Sender<()>,
    },
}

fn request_timer(metrics: &StateManagerMetrics, name: &str) -> HistogramTimer {
    metrics
        .checkpoint_metrics
        .tip_handler_request_duration
        .with_label_values(&[name])
        .start_timer()
}

fn page_map_path(
    log: &ReplicaLogger,
    tip_handler: &mut TipHandler,
    height: Height,
    page_map_type: &PageMapType,
) -> PathBuf {
    page_map_type
        .path(&tip_handler.tip(height).unwrap_or_else(|err| {
            fatal!(log, "Failed to flush page map: {}", err);
        }))
        .unwrap_or_else(|err| {
            fatal!(log, "Failed to get path for page map: {}", err);
        })
}

pub fn spawn_tip_thread(
    log: ReplicaLogger,
    mut tip_handler: TipHandler,
    state_layout: StateLayout,
    metrics: StateManagerMetrics,
) -> (JoinOnDrop<()>, Sender<TipRequest>) {
    let (tip_sender, tip_receiver) = unbounded();
    let mut thread_pool = scoped_threadpool::Pool::new(NUMBER_OF_CHECKPOINT_THREADS);
    let tip_handle = JoinOnDrop::new(
        std::thread::Builder::new()
            .name("TipThread".to_string())
            .spawn(move || {
                while let Ok(req) = tip_receiver.recv() {
                    match req {
                        TipRequest::FilterTipCanisters { height, ids } => {
                            let _timer = request_timer(&metrics, "filter_tip_canisters");
                            tip_handler
                                .filter_tip_canisters(height, &ids)
                                .unwrap_or_else(|err| {
                                    fatal!(
                                        log,
                                        "Failed to filter tip canisters for height @{}: {}",
                                        height,
                                        err
                                    )
                                });
                        }
                        TipRequest::TipToCheckpoint { height, sender } => {
                            let cp = {
                                let _timer =
                                    request_timer(&metrics, "tip_to_checkpoint_send_checkpoint");
                                let tip = tip_handler.tip(height);
                                match tip {
                                    Err(err) => {
                                        sender
                                            .send(Err(err))
                                            .expect("Failed to return TipToCheckpoint error");
                                        continue;
                                    }
                                    Ok(tip) => {
                                        let cp_or_err = state_layout.scratchpad_to_checkpoint(
                                            tip,
                                            height,
                                            Some(&mut thread_pool),
                                        );
                                        match cp_or_err {
                                            Err(err) => {
                                                sender.send(Err(err)).expect(
                                                    "Failed to return TipToCheckpoint error",
                                                );
                                                continue;
                                            }
                                            Ok(cp) => {
                                                sender.send(Ok(cp.clone())).expect(
                                                    "Failed to return TipToCheckpoint result",
                                                );
                                                cp
                                            }
                                        }
                                    }
                                }
                            };

                            let _timer = request_timer(&metrics, "tip_to_checkpoint_reset_tip_to");
                            tip_handler
                                .reset_tip_to(&state_layout, &cp, Some(&mut thread_pool))
                                .unwrap_or_else(|err| {
                                    fatal!(
                                        log,
                                        "Failed to reset tip to checkpoint @{}: {}",
                                        height,
                                        err
                                    );
                                });
                        }
                        TipRequest::TruncatePageMapsPath {
                            height,
                            page_map_type,
                        } => {
                            let _timer = request_timer(&metrics, "truncate_page_maps_path");
                            let path =
                                page_map_path(&log, &mut tip_handler, height, &page_map_type);
                            truncate_path(&log, &path);
                        }

                        TipRequest::FlushRoundDelta {
                            height,
                            page_map,
                            page_map_type,
                        } => {
                            let _timer = request_timer(&metrics, "flush_round_delta");
                            let path =
                                page_map_path(&log, &mut tip_handler, height, &page_map_type);
                            if !page_map.round_delta_is_empty() {
                                page_map.persist_round_delta(&path).unwrap_or_else(|err| {
                                    fatal!(log, "Failed to persist round delta: {}", err);
                                });
                            }
                        }
                        TipRequest::SerializeToTip {
                            height,
                            replicated_state,
                        } => {
                            let _timer = request_timer(&metrics, "serialize_to_tip");
                            serialize_to_tip(
                                &log,
                                &replicated_state,
                                &tip_handler.tip(height).unwrap_or_else(|err| {
                                    fatal!(
                                        log,
                                        "Failed to get tip @{} to serialize to: {}",
                                        height,
                                        err
                                    );
                                }),
                                &mut thread_pool,
                            )
                            .unwrap_or_else(|err| {
                                fatal!(log, "Failed to serialize to tip @{}: {}", height, err);
                            });
                        }
                        TipRequest::ResetTipTo { checkpoint_layout } => {
                            let _timer = request_timer(&metrics, "reset_tip_to");
                            tip_handler
                                .reset_tip_to(
                                    &state_layout,
                                    &checkpoint_layout,
                                    Some(&mut thread_pool),
                                )
                                .unwrap_or_else(|err| {
                                    fatal!(
                                        log,
                                        "Failed to reset tip to height @{}: {}",
                                        checkpoint_layout.height(),
                                        err
                                    );
                                });
                        }
                        TipRequest::DefragTip {
                            height,
                            page_map_types,
                        } => {
                            let _timer = request_timer(&metrics, "defrag_tip");
                            defrag_tip(
                                &tip_handler.tip(height).unwrap_or_else(|err| {
                                    fatal!(log, "Failed to get tip @{} to defrag: {}", height, err);
                                }),
                                &page_map_types,
                                DEFRAG_SIZE,
                                DEFRAG_SAMPLE,
                                height.get(),
                            )
                            .unwrap_or_else(|err| {
                                fatal!(log, "Failed to defrag tip @{}: {}", height, err);
                            });
                        }

                        TipRequest::Wait { sender } => {
                            let _timer = request_timer(&metrics, "wait");
                            let _ = sender.send(());
                        }
                    }
                }
            })
            .expect("failed to spawn tip thread"),
    );
    (tip_handle, tip_sender)
}

fn serialize_to_tip(
    log: &ReplicaLogger,
    state: &ReplicatedState,
    tip: &CheckpointLayout<RwPolicy<TipHandler>>,
    thread_pool: &mut scoped_threadpool::Pool,
) -> Result<(), CheckpointError> {
    tip.system_metadata()
        .serialize(state.system_metadata().into())?;

    tip.subnet_queues()
        .serialize((state.subnet_queues()).into())?;

    let results = parallel_map(thread_pool, state.canisters_iter(), |canister_state| {
        serialize_canister_to_tip(log, canister_state, tip)
    });

    for result in results.into_iter() {
        result?;
    }

    serialize_bitcoin_state_to_tip(state.bitcoin(), &tip.bitcoin()?)?;

    Ok(())
}

fn serialize_canister_to_tip(
    log: &ReplicaLogger,
    canister_state: &CanisterState,
    tip: &CheckpointLayout<RwPolicy<TipHandler>>,
) -> Result<(), CheckpointError> {
    let canister_layout = tip.canister(&canister_state.canister_id())?;
    canister_layout
        .queues()
        .serialize(canister_state.system_state.queues().into())?;

    let execution_state_bits = match &canister_state.execution_state {
        Some(execution_state) => {
            let wasm_binary = &execution_state.wasm_binary.binary;
            match wasm_binary.file() {
                Some(path) => {
                    let wasm = canister_layout.wasm();
                    if !wasm.raw_path().exists() {
                        ic_state_layout::utils::do_copy(log, path, wasm.raw_path()).map_err(
                            |io_err| CheckpointError::IoError {
                                path: path.to_path_buf(),
                                message: "failed to copy Wasm file".to_string(),
                                io_err: io_err.to_string(),
                            },
                        )?;
                    }
                }
                None => {
                    // Canister was installed/upgraded. Persist the new wasm binary.
                    canister_layout
                        .wasm()
                        .serialize(&execution_state.wasm_binary.binary)?;
                }
            }
            execution_state
                .wasm_memory
                .page_map
                .persist_delta(&canister_layout.vmemory_0())?;
            execution_state
                .stable_memory
                .page_map
                .persist_delta(&canister_layout.stable_memory_blob())?;

            Some(ExecutionStateBits {
                exported_globals: execution_state.exported_globals.clone(),
                heap_size: execution_state.wasm_memory.size,
                exports: execution_state.exports.clone(),
                last_executed_round: execution_state.last_executed_round,
                metadata: execution_state.metadata.clone(),
                binary_hash: Some(execution_state.wasm_binary.binary.module_hash().into()),
            })
        }
        None => {
            truncate_path(log, &canister_layout.vmemory_0());
            truncate_path(log, &canister_layout.stable_memory_blob());
            None
        }
    };
    // Priority credit must be zero at this point
    assert_eq!(canister_state.scheduler_state.priority_credit.get(), 0);
    canister_layout
        .canister()
        .serialize(
            CanisterStateBits {
                controllers: canister_state.system_state.controllers.clone(),
                last_full_execution_round: canister_state.scheduler_state.last_full_execution_round,
                call_context_manager: canister_state.system_state.call_context_manager().cloned(),
                compute_allocation: canister_state.scheduler_state.compute_allocation,
                accumulated_priority: canister_state.scheduler_state.accumulated_priority,
                memory_allocation: canister_state.system_state.memory_allocation,
                freeze_threshold: canister_state.system_state.freeze_threshold,
                cycles_balance: canister_state.system_state.balance(),
                cycles_debit: canister_state.system_state.cycles_debit(),
                execution_state_bits,
                status: canister_state.system_state.status.clone(),
                scheduled_as_first: canister_state
                    .system_state
                    .canister_metrics
                    .scheduled_as_first,
                skipped_round_due_to_no_messages: canister_state
                    .system_state
                    .canister_metrics
                    .skipped_round_due_to_no_messages,
                executed: canister_state.system_state.canister_metrics.executed,
                interruped_during_execution: canister_state
                    .system_state
                    .canister_metrics
                    .interruped_during_execution,
                certified_data: canister_state.system_state.certified_data.clone(),
                consumed_cycles_since_replica_started: canister_state
                    .system_state
                    .canister_metrics
                    .consumed_cycles_since_replica_started,
                stable_memory_size: canister_state
                    .execution_state
                    .as_ref()
                    .map(|es| es.stable_memory.size)
                    .unwrap_or_else(|| NumWasmPages::from(0)),
                heap_delta_debit: canister_state.scheduler_state.heap_delta_debit,
                install_code_debit: canister_state.scheduler_state.install_code_debit,
                time_of_last_allocation_charge_nanos: canister_state
                    .scheduler_state
                    .time_of_last_allocation_charge
                    .as_nanos_since_unix_epoch(),
                task_queue: canister_state
                    .system_state
                    .task_queue
                    .clone()
                    .into_iter()
                    .collect(),
                global_timer_nanos: canister_state
                    .system_state
                    .global_timer
                    .to_nanos_since_unix_epoch(),
                canister_version: canister_state.system_state.canister_version,
            }
            .into(),
        )
        .map_err(CheckpointError::from)
}

fn serialize_bitcoin_state_to_tip(
    state: &BitcoinState,
    layout: &BitcoinStateLayout<RwPolicy<TipHandler>>,
) -> Result<(), CheckpointError> {
    state
        .utxo_set
        .utxos_small
        .persist_delta(&layout.utxos_small())?;

    state
        .utxo_set
        .utxos_medium
        .persist_delta(&layout.utxos_medium())?;

    state
        .utxo_set
        .address_outpoints
        .persist_delta(&layout.address_outpoints())?;

    layout
        .bitcoin_state()
        .serialize(
            // TODO(EXC-1076): Remove unnecessary clone.
            (&BitcoinStateBits {
                adapter_queues: state.adapter_queues.clone(),
                unstable_blocks: state.unstable_blocks.clone(),
                stable_height: state.stable_height,
                network: state.utxo_set.network,
                utxos_large: state.utxo_set.utxos_large.clone(),
            })
                .into(),
        )
        .map_err(CheckpointError::from)
}

/// Defragments part of the tip directory.
///
/// The way we use PageMap files in the tip, namely by having a
/// long-living file, that we alternatively write to in small 4KB
/// pages and reflink copy to the checkpoint folder, the files end up
/// fragmented on disk. In particular, the metadata the file system
/// keeps on which pages are shared between files and which pages are
/// unique to a file grows quite complicated, which noticebly slows
/// down reflink copying of those files. It can therefore be
/// beneficial to defragment files, especially in situations where a
/// file had a lot of writes in the past but is mostly being read now.
///
/// The current defragmentation strategy is to pseudorandomly choose a
/// chunk of size max_size among the eligble files, read it to memory,
/// and write it back to the file. The effect is that this chunk is
/// definitely unique to the tip at the end of defragmentation. For
/// now, only the bitcoin PageMap files are being considered.
pub fn defrag_tip(
    tip: &CheckpointLayout<RwPolicy<TipHandler>>,
    page_maps: &[PageMapType],
    max_size: u64,
    max_files: usize,
    seed: u64,
) -> Result<(), CheckpointError> {
    let mut rng = ChaChaRng::seed_from_u64(seed);

    // We sample the set of page maps down in order to avoid reading
    // the metadata of each file. This is a compromise between
    // weighting the probabilities by size and picking a uniformly
    // random file.  The former (without subsampling) would be
    // unnecessarily expensive, the latter would perform poorly in a
    // situation with many empty files and a few large ones, doing
    // no-ops on empty files with high probability.
    let page_map_subset = page_maps.iter().choose_multiple(&mut rng, max_files);

    let path_with_sizes: Vec<(PathBuf, u64)> = page_map_subset
        .iter()
        .filter_map(|entry| {
            let path = entry.path(tip).ok()?;
            let size = path.metadata().ok()?.size();
            Some((path, size))
        })
        .collect();

    // We choose a file weighted by its size. This way, every bit in
    // the state has (roughly) the same probability of being
    // defragmented. If we chose the file uniformaly at random, we
    // would end up defragmenting the smallest file too often. The choice
    // failing is not an error, as it will happen if all files are
    // empty
    if let Ok((path, size)) = path_with_sizes.choose_weighted(&mut rng, |entry| entry.1) {
        let write_size = size.min(&max_size);
        let offset = rng.gen_range(0..=size - write_size);

        defrag_file_partially(path, offset, write_size.to_owned() as usize).map_err(|err| {
            CheckpointError::IoError {
                path: path.to_path_buf(),
                message: "failed to defrag file".into(),
                io_err: err.to_string(),
            }
        })?;
    }
    Ok(())
}

fn truncate_path(log: &ReplicaLogger, path: &Path) {
    if let Err(err) = nix::unistd::truncate(path, 0) {
        // It's OK if the file doesn't exist, everything else is a fatal error.
        if err != nix::errno::Errno::ENOENT {
            fatal!(
                log,
                "failed to truncate page map stored at {}: {}",
                path.display(),
                err
            )
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::BitcoinPageMap;
    use ic_metrics::MetricsRegistry;
    use ic_test_utilities::types::ids::canister_test_id;
    use ic_test_utilities_logger::with_test_replica_logger;
    use ic_test_utilities_tmpdir::tmpdir;

    #[test]
    fn dont_crash_or_hang() {
        with_test_replica_logger(|log| {
            let tmp = tmpdir("checkpoint");
            let root = tmp.path().to_path_buf();
            let layout = StateLayout::try_new(log.clone(), root, &MetricsRegistry::new()).unwrap();
            let metrics_registry = ic_metrics::MetricsRegistry::new();
            let metrics = StateManagerMetrics::new(&metrics_registry);
            let tip_handler = layout.capture_tip_handler();
            let (_h, _s) = spawn_tip_thread(log, tip_handler, layout, metrics);
        });
    }

    #[test]
    fn defrag_is_safe() {
        with_test_replica_logger(|log| {
            let tmp = tmpdir("checkpoint");
            let root = tmp.path().to_path_buf();
            let mut tip_handler = StateLayout::try_new(log, root, &MetricsRegistry::new())
                .unwrap()
                .capture_tip_handler();
            let tip = tip_handler.tip(Height::new(42)).unwrap();

            let defrag_size = 1 << 20; // 1MB

            let page_maps: Vec<PageMapType> = vec![
                PageMapType::Bitcoin(BitcoinPageMap::AddressOutpoints),
                PageMapType::Bitcoin(BitcoinPageMap::UtxosSmall),
                PageMapType::Bitcoin(BitcoinPageMap::UtxosMedium),
                PageMapType::StableMemory(canister_test_id(100)),
                PageMapType::WasmMemory(canister_test_id(100)),
            ];

            let paths: Vec<PathBuf> = page_maps
                .iter()
                .map(|page_map_type| page_map_type.path(&tip).unwrap())
                .collect();

            for path in &paths {
                assert!(!path.exists());
            }

            defrag_tip(&tip, &page_maps, defrag_size, 100, 0).unwrap();

            for path in &paths {
                assert!(!path.exists());
            }

            for factor in 1..3 {
                let short_data: Vec<u8> = vec![42; (defrag_size / factor) as usize];
                let long_data: Vec<u8> = vec![43; (defrag_size * factor) as usize];
                let empty: &[u8] = &[];

                std::fs::write(&paths[0], &short_data).unwrap();
                std::fs::write(&paths[1], &long_data).unwrap();
                // third file is an empty file
                std::fs::write(&paths[2], empty).unwrap();

                let check_files = || {
                    assert_eq!(std::fs::read(&paths[0]).unwrap(), short_data);
                    assert_eq!(std::fs::read(&paths[1]).unwrap(), long_data);
                    assert!(paths[2].exists());
                    assert_eq!(std::fs::read(&paths[2]).unwrap(), empty);
                };

                check_files();

                for i in 0..100 {
                    defrag_tip(&tip, &page_maps, defrag_size, i as usize, i).unwrap();
                    check_files();
                }
            }
        });
    }
}
