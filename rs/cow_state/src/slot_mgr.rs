//! Slot manager is a "persistent" generic implementation to manage free
//! regions, allocations, mappings, snapshots and checkpointing for any
//! arbitrary object which can be viewed as a collection of slots.
//! A slot can be anything for example a block within a file, index in an array,
//! pages within memory region where the object is file, array and memory
//! respectively.
//!
//! Internally slot manager keeps track of unused slots and provides allocator
//! to allocate them. It also provides mechanism to persist arbitrary mappings
//! between slots and any u64 number. Mappings can be used, for example, to
//! implement a virtual addressing where discontiguous slots can be a part of
//! contiguous virtual address range.
//!
//! Lastly slot manager also supports rounds (snapshots) for mapping with
//! sharing of slots between multiple rounds. Also multiple rounds can be folded
//! into a single checkpoint freeing all overwritten slots.

use crate::error::{CowError, SlotDbOp};
use lmdb::{
    self, Cursor, Database, DatabaseFlags, EnvironmentFlags, RoCursor, RoTransaction,
    RwTransaction, Transaction, WriteFlags,
};
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

pub struct SlotMgr {
    env: lmdb::Environment,
    default_table: lmdb::Database,
    meta_table: lmdb::Database,
    free_list_table: lmdb::Database,
    completed_rounds: lmdb::Database,
    current_round_table: lmdb::Database,
    slots_to_gc: lmdb::Database,
    last_executed_round: AtomicU64,
    nr_slots: u64,
    last_checkpointed_round: u64,
}
const KB: u64 = 1024;
const MB: u64 = KB * KB;
const GB: u64 = MB * KB;

fn reading<'env, R>(
    mgr: &'env SlotMgr,
    label: &str,
    f: impl FnOnce(&RoTransaction<'env>) -> R,
) -> R {
    let ro_txn = mgr.env.begin_ro_txn().unwrap();
    let res = f(&ro_txn);
    ro_txn
        .commit()
        .unwrap_or_else(|err| panic!("ro_txn.commit() failed: {}: {}", label, err));
    res
}

fn writing<'env, R>(
    mgr: &'env SlotMgr,
    label: &str,
    f: impl FnOnce(&mut RwTransaction<'env>) -> R,
) -> R {
    let mut rw_txn = mgr.env.begin_rw_txn().unwrap();
    let res = f(&mut rw_txn);
    rw_txn
        .commit()
        .unwrap_or_else(|err| panic!("rw_txn.commit() failed: {}: {}", label, err));
    res
}

pub struct RoundDb(Database);

// The purpose of the `RoundDb` structure is to encapsulate all the required
// uses of `unsafe` in this module.
impl RoundDb {
    fn create(rw_txn: &mut RwTransaction, round: u64) -> Self {
        let roundb = unsafe {
            rw_txn
                .create_db(
                    Some(format!("round-{}", round).as_str()),
                    DatabaseFlags::INTEGER_KEY,
                )
                .unwrap_or_else(|err| panic!("failed to create round-{}: {}", round, err))
        };
        RoundDb(roundb)
    }
    fn open(ro_txn: &RoTransaction, round: u64) -> Self {
        let roundb = unsafe {
            ro_txn
                .open_db(Some(format!("round-{}", round).as_str()))
                .map_err(|err| CowError::SlotDbError {
                    op: SlotDbOp::OpenDb,
                    round,
                    err,
                })
                .unwrap_or_else(|err| panic!("failed to open round-{}: {}", round, err))
        };
        RoundDb(roundb)
    }
    fn drop(rw_txn: &mut RwTransaction, round: u64) {
        let roundb = unsafe {
            rw_txn
                .open_db(Some(format!("round-{}", round).as_str()))
                .unwrap_or_else(|err| panic!("failed to open round-{}: {}", round, err))
        };
        unsafe {
            rw_txn
                .drop_db(roundb)
                .unwrap_or_else(|err| panic!("failed to drop round-{}: {}", round, err))
        };
    }
}

// invalid slots are also treated as shared in mappings
pub const INVALID_SLOT: u64 = std::u64::MAX;

const MAX_SLOT_MGR_INTERNAL_DBS: u32 = 10;
const SLOT_NR_VALID_BITS: u32 = 63;
const SHARED_MASK: u64 = 0x7FFF_FFFF_FFFF_FFFF;

// 4G initial size is a good starting point for
// the initial mapsize based on how we are storing
// the mappings. We need to revisit this if we end up
// expanding the maps often
const INITIAL_MAP_SIZE: usize = 4 * GB as usize;
#[derive(Debug)]
pub struct SingleContigRange {
    pub logical_slot: u64,
    pub physical_slot: u64,
    pub map_len: u64,
}
#[derive(Debug)]
pub struct SlotMappings(Vec<SingleContigRange>);

pub struct SlotMappingIteratorHelper<'a> {
    iter: std::slice::Iter<'a, SingleContigRange>,
}

impl<'a> IntoIterator for &'a SlotMappings {
    type Item = SingleContigRange;
    type IntoIter = SlotMappingIteratorHelper<'a>;
    fn into_iter(self) -> Self::IntoIter {
        SlotMappingIteratorHelper {
            iter: self.0.as_slice().iter(),
        }
    }
}

impl<'a> Iterator for SlotMappingIteratorHelper<'a> {
    type Item = SingleContigRange;
    fn next(&mut self) -> Option<Self::Item> {
        let item = self.iter.next();
        item.map(|cr| SingleContigRange {
            logical_slot: cr.logical_slot,
            map_len: cr.map_len,
            physical_slot: SlotMgr::get_slot(cr.physical_slot),
        })
    }
}

impl SlotMappings {
    pub fn get_slot_info(&self, slot: u64) -> (bool, u64) {
        // This has to be a lookup inside range
        let pba = match self.0.binary_search_by(|sm| {
            if slot < sm.logical_slot {
                std::cmp::Ordering::Greater
            } else if slot >= sm.logical_slot + sm.map_len {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        }) {
            Ok(loc) => self.0[loc].physical_slot + slot - self.0[loc].logical_slot,
            Err(_) => INVALID_SLOT,
        };

        let is_shared = SlotMgr::is_shared(pba);
        let pba = match pba {
            INVALID_SLOT => INVALID_SLOT,
            _ => SlotMgr::get_slot(pba),
        };

        (is_shared, pba)
    }

    pub fn get_last_slot(&self) -> Option<u64> {
        self.0.last().map(|cr| cr.logical_slot + cr.map_len)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[allow(dead_code)]
    fn get_raw_iter(&self) -> std::slice::Iter<SingleContigRange> {
        self.0.as_slice().iter()
    }
}

impl SlotMgr {
    pub fn is_shared(slot_nr: u64) -> bool {
        slot_nr == INVALID_SLOT || (slot_nr >> SLOT_NR_VALID_BITS) & 1 == 0
    }

    // returns the actual slot number removing any private
    // indication so it can be used for writes
    pub fn get_slot(slot_nr: u64) -> u64 {
        assert_ne!(slot_nr, INVALID_SLOT);
        slot_nr & SHARED_MASK
    }

    pub fn new(db_base: &Path, max_rounds: u32, max_slots: u64) -> Self {
        let mut env_builder = lmdb::Environment::new();
        env_builder.set_max_dbs(max_rounds + MAX_SLOT_MGR_INTERNAL_DBS);

        env_builder.set_map_size(INITIAL_MAP_SIZE);

        let data_mdb = db_base.join("data.mdb");
        let read_only = data_mdb.exists() && data_mdb.metadata().unwrap().permissions().readonly();
        let mut slot_mgr = if read_only {
            env_builder.set_flags(
                EnvironmentFlags::NO_LOCK
                    | EnvironmentFlags::NO_TLS
                    | EnvironmentFlags::NO_MEM_INIT
                    | EnvironmentFlags::READ_ONLY,
            );
            let env = env_builder
                .open_with_permissions(db_base, 0o400)
                .expect("Unable to open db");
            Self::open_db(env)
        } else {
            let env_flags = EnvironmentFlags::NO_TLS
                | EnvironmentFlags::NO_MEM_INIT
                | EnvironmentFlags::WRITE_MAP;

            env_builder.set_flags(env_flags);
            let env = env_builder
                .open(db_base)
                .unwrap_or_else(|e| panic!("Unable to open db {:?} while trying to construct a new slot manager -- received: {:?}", db_base, e));
            Self::create_db(env, max_slots)
        };

        slot_mgr.recover();
        slot_mgr
    }

    fn open_db(env: lmdb::Environment) -> SlotMgr {
        let default_table = env.open_db(None).expect("default_table created");

        let meta_table = env.open_db(Some("MetaTable")).expect("meta_table created");

        let free_list_table = env
            .open_db(Some("FreeList"))
            .expect("free_list_table created");

        let completed_rounds = env
            .open_db(Some("CompletedRounds"))
            .expect("completed_rounds created");

        let current_round_table = env
            .open_db(Some("Current".to_string().as_str()))
            .expect("current_round_table created");

        let slots_to_gc = env
            .open_db(Some("CurrentRoundOverwritten".to_string().as_str()))
            .expect("current_round_table created");

        SlotMgr {
            env,
            default_table,
            meta_table,
            free_list_table,
            completed_rounds,
            current_round_table,
            slots_to_gc,
            last_executed_round: AtomicU64::new(0),
            nr_slots: 0,
            last_checkpointed_round: 0,
        }
    }

    fn create_db(env: lmdb::Environment, nr_slots: u64) -> SlotMgr {
        let default_table = env
            .create_db(None, DatabaseFlags::empty())
            .expect("default_table created");
        let meta_table = env
            .create_db(Some("MetaTable"), DatabaseFlags::empty())
            .expect("meta_table created");
        let free_list_table = env
            .create_db(Some("FreeList"), DatabaseFlags::INTEGER_KEY)
            .expect("free_list_table created");
        let completed_rounds = env
            .create_db(Some("CompletedRounds"), DatabaseFlags::INTEGER_KEY)
            .expect("completed_rounds created");
        let current_round_table = env
            .create_db(
                Some("Current".to_string().as_str()),
                DatabaseFlags::INTEGER_KEY,
            )
            .expect("current_round_table created");
        let slots_to_gc = env
            .create_db(
                Some("CurrentRoundOverwritten".to_string().as_str()),
                DatabaseFlags::INTEGER_KEY,
            )
            .expect("current_round_table created");

        SlotMgr {
            env,
            default_table,
            meta_table,
            free_list_table,
            completed_rounds,
            current_round_table,
            slots_to_gc,
            last_executed_round: AtomicU64::new(0),
            nr_slots,
            last_checkpointed_round: 0,
        }
    }

    fn first_init(&self) {
        let nr_slots = self.nr_slots;
        let canid: u64 = 111;
        let last_checkpointed_round: u64 = 0;

        writing(self, "SlotMgr::first_init", |rw_txn| {
            rw_txn
                .put(
                    self.meta_table,
                    &b"NrSlots",
                    &nr_slots.to_le_bytes(),
                    WriteFlags::NO_DUP_DATA,
                )
                .expect("put is successful");
            rw_txn
                .put(
                    self.meta_table,
                    &b"CanisterID",
                    &canid.to_le_bytes(),
                    WriteFlags::NO_DUP_DATA,
                )
                .expect("put is successful");
            rw_txn
                .put(
                    self.meta_table,
                    &b"LastCheckpointedRound",
                    &last_checkpointed_round.to_le_bytes(),
                    WriteFlags::NO_DUP_DATA,
                )
                .expect("put is successful");
        });

        self.init_free_list();
    }

    fn init_free_list(&self) {
        writing(self, "SlotMgr::init_free_list", |rw_txn| {
            rw_txn
                .put(
                    self.free_list_table,
                    &0_u64.to_le_bytes(),
                    &self.nr_slots.to_le_bytes(),
                    WriteFlags::NO_DUP_DATA,
                )
                .expect("put is successful");
        })
    }

    fn recover(&mut self) {
        let (nr_slots, last_checkpointed_round) = reading(
            self,
            "SlotMgr::recover",
            |ro_txn| -> (Option<u64>, Option<u64>) {
                let mut ro_cursor = ro_txn
                    .open_ro_cursor(self.meta_table)
                    .expect("default table cursor");

                if ro_cursor.iter().peekable().peek().is_none() {
                    drop(ro_cursor);
                    // Table has not been initialized. Lets create now
                    self.first_init();
                    return (None, None);
                }

                let mut nr_slots: Option<u64> = None;
                let mut last_checkpointed_round: Option<u64> = None;
                for (k, v) in ro_cursor.iter().map(Result::unwrap) {
                    let s = String::from_utf8(k.to_vec()).unwrap();
                    match s.as_str() {
                        "NrSlots" => nr_slots = Some(Self::decode_u64(v)),
                        "LastCheckpointedRound" => {
                            last_checkpointed_round = Some(Self::decode_u64(v))
                        }
                        _ => panic!("Unknown table found: {}", s),
                    }
                }
                (nr_slots, last_checkpointed_round)
            },
        );
        if let Some(v) = nr_slots {
            self.nr_slots = v;
        }
        if let Some(v) = last_checkpointed_round {
            self.last_checkpointed_round = v;
        }

        self.last_executed_round
            .store(self.last_checkpointed_round, Ordering::Relaxed);

        // recover the current mapping table
        let current_round = self
            .env
            .open_db(Some("Current"))
            .expect("current_round_table created");
        self.current_round_table = current_round;
    }

    // To clear current we need to make sure all private mappings that belong
    // to current round are returned to the free list. We can safely ignore
    // all shared mappings as they will be garbage collected once their
    // respective rounds are cleared
    pub fn clear_current(&self) {
        writing(self, "SlotMgr::clear_current", |rw_txn| {
            reading(self, "SlotMgr::clear_current", |ro_txn| {
                let mut ro_cursor = ro_txn.open_ro_cursor(self.current_round_table).unwrap();

                for (_rawk, rawv) in ro_cursor.iter().map(Result::unwrap) {
                    let val = Self::decode_u64(rawv);

                    // add all non shared slots to free list as they wont be required
                    // anymore
                    if !Self::is_shared(val) {
                        rw_txn
                            .put(
                                self.free_list_table,
                                &val.to_le_bytes(),
                                &1_u64.to_le_bytes(),
                                WriteFlags::NO_DUP_DATA,
                            )
                            .expect("copy should succeed");
                    }
                }
            });

            rw_txn.clear_db(self.current_round_table).unwrap();
        })
    }

    pub fn end_round(&self, round: u64) {
        // create a new round db and inherit mappingss from previous round
        writing(self, "SlotMgr::end_round", |rw_txn| {
            let end_round = RoundDb::create(rw_txn, round);
            reading(self, "SlotMgr::end_round", |ro_txn| {
                let mut ro_cursor = ro_txn.open_ro_cursor(self.current_round_table).unwrap();

                for (rawk, rawv) in ro_cursor.iter().map(Result::unwrap) {
                    let key = Self::decode_u64(rawk);
                    let mut val = Self::decode_u64(rawv);

                    // convert all private mappings as shared when we create a new mappings
                    // This will help us distinguish when we need a allocation and what
                    // allocations can be reused
                    if !Self::is_shared(val) {
                        val &= SHARED_MASK;
                        rw_txn
                            .put(
                                self.current_round_table,
                                &key.to_le_bytes(),
                                &val.to_le_bytes(),
                                WriteFlags::NO_DUP_DATA,
                            )
                            .expect("copy should succeed");
                    }
                    rw_txn
                        .put(
                            end_round.0,
                            &key.to_le_bytes(),
                            &val.to_le_bytes(),
                            WriteFlags::NO_DUP_DATA,
                        )
                        .expect("copy should succeed");
                }
            });

            rw_txn
                .put(
                    self.completed_rounds,
                    &round.to_le_bytes(),
                    &[],
                    WriteFlags::NO_DUP_DATA,
                )
                .expect("put is successful");
        });

        self.last_executed_round.store(round, Ordering::Relaxed);
    }

    pub fn checkpoint(&self) {
        // update the last checkpointed round to the current one
        let last_executed_round = self.last_executed_round.load(Ordering::Relaxed);
        writing(self, "SlotMgr::checkpoint", |rw_txn| {
            rw_txn
                .put(
                    self.meta_table,
                    &b"LastCheckpointedRound",
                    &last_executed_round.to_le_bytes(),
                    WriteFlags::NO_DUP_DATA,
                )
                .expect("unable to set last checkpointed round");
        });
        // Flush everything out that was lying around in memory is flushed to disk
        self.sync();
    }

    // Checkpoint accomplishes freeing of slots that are no longer required.
    // All the slots that ever were overwritten are tracked in the gc lists.
    // These slots cannot be unilaterally freed as they might still be
    // referred by older rounds. Current implementation just deletes all
    // previous rounds there by keeping the problem simple.
    // Alternatively we can find out the oldest round on which query might be
    // progressing All rounds older than that can free all the slots that were
    // overwritten in the later rounds. Find such slots and then mark them as
    // free. If all slots from the gc table are freed in such a way empty that
    // table.
    pub fn remove_rounds_below(&self, max_to_keep: u64) {
        let mut free_slot_list = HashSet::new();

        let mut rounds = Vec::new();

        // Find rounds to delete
        reading(self, "SlotMgr::remove_rounds_below", |ro_txn| {
            let mut ro_cursor = ro_txn.open_ro_cursor(self.completed_rounds).unwrap();

            for (round, _) in ro_cursor.iter().map(Result::unwrap) {
                let round = Self::decode_u64(round);
                if round < max_to_keep {
                    rounds.push(round);
                }
            }

            // Get all the slots that can be gced
            let mut ro_cursor = ro_txn.open_ro_cursor(self.slots_to_gc).unwrap();
            for (rawk, dropped_at_round) in ro_cursor.iter().map(Result::unwrap) {
                let slot = Self::decode_u64(rawk);
                let dropped_at_round = Self::decode_u64(dropped_at_round);
                if dropped_at_round < max_to_keep {
                    free_slot_list.insert(slot);
                }
            }
        });

        // Add the gc candidate slots to the free list for future allocation
        writing(self, "SlotMgr::remove_rounds_below", |rw_txn| {
            for free_blk in free_slot_list {
                rw_txn
                    .put(
                        self.free_list_table,
                        &free_blk.to_le_bytes(),
                        &1_u64.to_le_bytes(),
                        WriteFlags::NO_DUP_DATA,
                    )
                    .expect("put failed");
            }

            // drop the round specific mappings
            for round in rounds {
                RoundDb::drop(rw_txn, round);
                rw_txn
                    .del(self.completed_rounds, &round.to_le_bytes(), None)
                    .expect("deleting from the completed rounds")
            }
        });

        // Flush everything out that was lying around in memory is flushed to disk
        self.sync();
    }

    fn get_mappings(&self, ro_cursor: &mut RoCursor) -> SlotMappings {
        let mut mappings = Vec::new();

        let mut logical_slot = INVALID_SLOT;
        let mut physical_slot = INVALID_SLOT;
        let mut map_len = 0;

        for (rawk, rawv) in ro_cursor.iter().map(Result::unwrap) {
            let key = Self::decode_u64(rawk);
            let val = Self::decode_u64(rawv);

            if logical_slot == INVALID_SLOT {
                logical_slot = key;
                physical_slot = val;
                map_len = 1;
            } else if key == logical_slot + map_len && val == physical_slot + map_len {
                map_len += 1;
            } else {
                mappings.push(SingleContigRange {
                    logical_slot,
                    physical_slot,
                    map_len,
                });

                logical_slot = key;
                physical_slot = val;
                map_len = 1;
            }
        }
        if map_len > 0 {
            mappings.push(SingleContigRange {
                logical_slot,
                physical_slot,
                map_len,
            });
        }
        SlotMappings(mappings)
    }

    pub fn get_current_round_mappings(&self) -> SlotMappings {
        reading(self, "SlotMgr::get_current_round_mappings", |ro_txn| {
            let mut ro_cursor = ro_txn.open_ro_cursor(self.current_round_table).unwrap();
            self.get_mappings(&mut ro_cursor)
        })
    }

    pub fn get_mappings_for_round(&self, round: u64) -> Result<SlotMappings, CowError> {
        reading(self, "SlotMgr::get_mappings_for_round", |ro_txn| {
            let roundb = RoundDb::open(ro_txn, round);
            let mut ro_cursor = ro_txn.open_ro_cursor(roundb.0).unwrap();
            Ok(self.get_mappings(&mut ro_cursor))
        })
    }

    pub fn get_completed_rounds(&self) -> Vec<u64> {
        let mut rounds = Vec::new();
        reading(self, "SlotMgr::get_completed_rounds", |ro_txn| {
            let mut ro_cursor = ro_txn.open_ro_cursor(self.completed_rounds).unwrap();
            for (rawk, _) in ro_cursor.iter().map(Result::unwrap) {
                rounds.push(Self::decode_u64(rawk));
            }
        });
        rounds
    }

    #[allow(dead_code)]
    pub fn get_free_slot(&self) -> u64 {
        self.alloc_free_slots(1)[0]
    }

    pub fn alloc_free_slots(&self, count: u32) -> Vec<u64> {
        let mut allocated_slots = Vec::new();
        let mut count = count as u64;

        writing(self, "SlotMgr::alloc_free_slots", |rw_txn| {
            let mut rw_cursor = rw_txn.open_rw_cursor(self.free_list_table).unwrap();
            let mut alloc_iter = rw_cursor.iter_start();
            while count > 0 {
                let (key, value) = alloc_iter.next().unwrap().unwrap();

                let free_start_slot = Self::decode_u64(key);
                let available = Self::decode_u64(value);

                // delete the entry so we can readjust and
                // put back updated remaining blocks
                rw_cursor
                    .del(WriteFlags::NO_DUP_DATA)
                    .expect("unable to delete allocated value");

                let allocated = if available > count {
                    let new_start: u64 = free_start_slot + count;
                    let remaining: u64 = available - count;
                    rw_cursor
                        .put(
                            &new_start.to_le_bytes(),
                            &remaining.to_le_bytes(),
                            WriteFlags::NO_DUP_DATA,
                        )
                        .expect("unable to put back remaining allocation");
                    count
                } else {
                    available
                };

                for i in free_start_slot..free_start_slot + allocated {
                    allocated_slots.push(i);
                }

                count -= allocated;
            }
        });

        allocated_slots
    }

    pub fn free_unused_slots(&self, slots_to_free: Vec<u64>) {
        if !slots_to_free.is_empty() {
            writing(self, "SlotMgr::free_unused_slots", |rw_txn| {
                for slot in slots_to_free {
                    rw_txn
                        .put(
                            self.free_list_table,
                            &slot.to_le_bytes(),
                            &1_u64.to_le_bytes(),
                            WriteFlags::NO_DUP_DATA,
                        )
                        .expect("Remove slot from the free list");
                }
            })
        }
    }

    fn update_mappings(
        &self,
        rw_txn: &mut lmdb::RwTransaction<'_>,
        logical_slot: u64,
        physical_slot: u64,
        overwritten_physical_slot: u64,
    ) {
        let last_executed_round = self.last_executed_round.load(Ordering::Relaxed);

        if overwritten_physical_slot != INVALID_SLOT {
            // the overwritten slot is valid and shared then add it to the free list
            // println!("Adding {} to gc list", overwritten_physical_slot);
            rw_txn
                .put(
                    self.slots_to_gc,
                    &overwritten_physical_slot.to_le_bytes(),
                    &last_executed_round.to_le_bytes(),
                    WriteFlags::NO_DUP_DATA,
                )
                .expect("Remove slot from the free list");
        }

        // mark the current mapping as private so subsequent overwrites to the slots can
        // be handled in place
        let physical_slot = 1 << SLOT_NR_VALID_BITS | physical_slot;
        rw_txn
            .put(
                self.current_round_table,
                &logical_slot.to_le_bytes(),
                &physical_slot.to_le_bytes(),
                WriteFlags::NO_DUP_DATA,
            )
            .expect("Remove slot from the free list");
    }

    #[allow(dead_code)]
    pub fn put_mapping(
        &self,
        logical_slot: u64,
        physical_slot: u64,
        overwritten_physical_slot: u64,
    ) {
        writing(self, "SlotMgr::put_mapping", |mut rw_txn| {
            self.update_mappings(
                &mut rw_txn,
                logical_slot,
                physical_slot,
                overwritten_physical_slot,
            );
        })
    }

    pub fn put_all_mappings(&self, mappings: HashMap<u64, (u64, u64)>) {
        writing(self, "SlotMgr::put_all_mappings", |mut rw_txn| {
            for (logical_slot, (physical_slot, overwritten_physical_slot)) in mappings {
                self.update_mappings(
                    &mut rw_txn,
                    logical_slot,
                    physical_slot,
                    overwritten_physical_slot,
                );
            }
        })
    }

    pub fn sync(&self) {
        let _res = self.env.sync(true);
    }

    fn decode_u64(key: &[u8]) -> u64 {
        let (raw_bytes, _) = key.split_at(std::mem::size_of::<u64>());
        u64::from_le_bytes(raw_bytes.try_into().unwrap())
    }

    #[allow(dead_code)]
    pub fn dump_db(&self) {
        reading(self, "SlotMgr::dump_db", |ro_txn| {
            let mut ro_cursor = ro_txn
                .open_ro_cursor(self.default_table)
                .expect("default table cursor");
            for (k, _) in ro_cursor.iter().map(Result::unwrap) {
                let s = String::from_utf8(k.to_vec());
                println!("{}", s.unwrap());
            }
        })
    }

    #[allow(dead_code)]
    pub fn dbg_get_free_list(&self) -> (usize, Vec<(u64, u64)>) {
        reading(self, "SlotMgr::dbg_get_free_list", |ro_txn| {
            let mut ro_cursor = ro_txn
                .open_ro_cursor(self.free_list_table)
                .expect("default table cursor");
            let free_count = ro_cursor.iter().count();

            let mut remaining = Vec::new();
            for (k, v) in ro_cursor.iter_start().map(Result::unwrap) {
                let start_free_slot = Self::decode_u64(k);
                let available = Self::decode_u64(v);
                remaining.push((start_free_slot, available));
            }

            (free_count, remaining)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    #[test]
    fn slot_mgr_test_one_round() {
        // This test validates that slots can be allocated, mappings persist
        // correctly and finally the are correctly presented when rounds are created
        let mapping_db = tempdir().expect("Unable to create temp directory");
        let smgr = SlotMgr::new(mapping_db.path(), 10, 2 * 1024 * 1024_u64);
        let curr_mappings = smgr.get_current_round_mappings();

        // Make sure that we start with empty mappings
        assert_eq!(curr_mappings.len(), 0);

        let mut allocated_slots = smgr.alloc_free_slots(10);
        assert_eq!(allocated_slots.len(), 10);

        let mut mappings_to_put = HashMap::new();
        let mut mappings_to_validate = HashMap::new();

        for i in 0..allocated_slots.len() {
            let allocated = allocated_slots.pop().unwrap();
            mappings_to_put.insert(i as u64, (allocated, INVALID_SLOT));
            mappings_to_validate.insert(i as u64, allocated);
        }
        smgr.put_all_mappings(mappings_to_put);

        let curr_mappings = smgr.get_current_round_mappings();

        // since we inserted in the reverse order, there should not
        // be any contiguous run hence the length of current
        // mappings should be 10
        assert_eq!(curr_mappings.len(), 10);

        let mut mappings_to_check = HashMap::new();
        for SingleContigRange {
            logical_slot,
            physical_slot,
            map_len: _,
        } in curr_mappings.get_raw_iter()
        {
            assert!(!SlotMgr::is_shared(*physical_slot));
            mappings_to_check.insert(*logical_slot, SlotMgr::get_slot(*physical_slot));
        }
        //validate that all the mappings were stored correctly
        assert_eq!(mappings_to_validate, mappings_to_check);

        // End the round, this should mark all "current" mappings
        // as shared and also preserve the round specific mappings
        smgr.end_round(1);

        let rounds = smgr.get_completed_rounds();
        assert_eq!(rounds, [1]);

        let mut mappings_to_check = HashMap::new();
        let curr_mappings = smgr.get_current_round_mappings();
        for SingleContigRange {
            logical_slot,
            physical_slot,
            map_len: _,
        } in curr_mappings.get_raw_iter()
        {
            assert!(SlotMgr::is_shared(*physical_slot));
            mappings_to_check.insert(*logical_slot, SlotMgr::get_slot(*physical_slot));
        }
        //validate that all the mappings were stored correctly
        assert_eq!(mappings_to_validate, mappings_to_check);

        let mut mappings_to_check = HashMap::new();
        let curr_mappings = smgr.get_mappings_for_round(1).unwrap();
        for SingleContigRange {
            logical_slot,
            physical_slot,
            map_len: _,
        } in curr_mappings.get_raw_iter()
        {
            assert!(SlotMgr::is_shared(*physical_slot));
            mappings_to_check.insert(*logical_slot, SlotMgr::get_slot(*physical_slot));
        }
        //validate that all the mappings were stored correctly
        assert_eq!(mappings_to_validate, mappings_to_check);

        // allocate 10 more slots, but these are overwrites
        let allocated_slots = smgr.alloc_free_slots(10);
        assert_eq!(allocated_slots.len(), 10);

        let mut mappings_to_put = HashMap::new();
        let mut mappings_to_validate = HashMap::new();

        for (i, allocated) in allocated_slots.iter().enumerate() {
            mappings_to_put.insert(
                i as u64,
                (
                    *allocated,
                    curr_mappings.get_raw_iter().nth(i).unwrap().physical_slot,
                ),
            );
            mappings_to_validate.insert(i as u64, *allocated);
        }
        smgr.put_all_mappings(mappings_to_put);

        let curr_mappings = smgr.get_current_round_mappings();

        // since we inserted in sequential order we should get
        // a contiguous range
        assert_eq!(curr_mappings.len(), 1);
        let SingleContigRange {
            logical_slot: _,
            physical_slot,
            map_len,
        } = curr_mappings.get_raw_iter().next().unwrap();

        // make sure that we got correct size contiguos range over the slots
        // we allocated
        assert_eq!(*map_len, 10);
        assert_eq!(SlotMgr::get_slot(*physical_slot), allocated_slots[0]);
        assert_eq!(
            SlotMgr::get_slot(*physical_slot) + map_len - 1,
            allocated_slots[9]
        );
    }

    #[test]
    fn slot_mgr_can_allocate_full() {
        let mapping_db = tempdir().expect("Unable to create temp directory");
        let smgr = SlotMgr::new(mapping_db.path(), 10, 100_u64);

        let mut rounds_to_verify = Vec::new();
        for rnd in 0..10 {
            let curr_mappings = smgr.get_current_round_mappings();

            let mut allocated_slots = smgr.alloc_free_slots(10);
            assert_eq!(allocated_slots.len(), 10);

            let mut mappings_to_put = HashMap::new();

            for i in 0..allocated_slots.len() {
                let (_, existing_pba) = curr_mappings.get_slot_info(i as u64);
                let allocated = allocated_slots.pop().unwrap();
                mappings_to_put.insert(i as u64, (allocated, existing_pba));
            }

            smgr.put_all_mappings(mappings_to_put);
            smgr.end_round(rnd);
            rounds_to_verify.push(rnd);
        }
        assert_eq!(smgr.get_completed_rounds(), rounds_to_verify);

        // This should purge all old rounds except the last one
        // and free all the overwritten slots
        smgr.checkpoint();

        assert_eq!(smgr.get_completed_rounds(), (0..10u64).collect::<Vec<_>>());

        smgr.remove_rounds_below(9);
        assert_eq!(smgr.get_completed_rounds(), [9]);

        let mut rounds_to_verify = vec![9];

        // Validate that we can allocate space for 9 more rounds
        for rnd in 10..19 {
            let mut allocated_slots = smgr.alloc_free_slots(10);
            assert_eq!(allocated_slots.len(), 10);

            let mut mappings_to_put = HashMap::new();

            for i in 0..allocated_slots.len() {
                let allocated = allocated_slots.pop().unwrap();
                mappings_to_put.insert(i as u64, (allocated, INVALID_SLOT));
            }
            smgr.put_all_mappings(mappings_to_put);
            smgr.end_round(rnd);
            rounds_to_verify.push(rnd);
        }

        let rounds = smgr.get_completed_rounds();
        assert_eq!(rounds, rounds_to_verify);
    }

    #[test]
    fn slot_mgr_allocator_test() {
        let mapping_db = tempdir().expect("Unable to create temp directory");
        let smgr = SlotMgr::new(mapping_db.path(), 10, 30_u64);

        let (free_count, remaining) = smgr.dbg_get_free_list();
        // we should have 1 single range
        assert_eq!(free_count, 1);
        assert_eq!(remaining[0], (0, 30));

        let allocated_slots = smgr.alloc_free_slots(10);
        assert_eq!(allocated_slots.len(), 10);

        let (free_count, remaining) = smgr.dbg_get_free_list();
        // we should have 1 single range
        assert_eq!(free_count, 1);
        assert_eq!(remaining[0], (10, 20));

        let allocated_slots1 = smgr.alloc_free_slots(10);
        assert_eq!(allocated_slots1.len(), 10);

        let (free_count, remaining) = smgr.dbg_get_free_list();
        // we should have 1 single range
        assert_eq!(free_count, 1);
        assert_eq!(remaining[0], (20, 10));

        smgr.free_unused_slots(allocated_slots);
        let (free_count, remaining) = smgr.dbg_get_free_list();
        // we should have 11 ranges
        assert_eq!(free_count, 11);
        assert_eq!(
            remaining,
            [
                (0, 1),
                (1, 1),
                (2, 1),
                (3, 1),
                (4, 1),
                (5, 1),
                (6, 1),
                (7, 1),
                (8, 1),
                (9, 1),
                (20, 10)
            ]
        );

        let allocated_slots2 = smgr.alloc_free_slots(15);
        assert_eq!(allocated_slots2.len(), 15);

        let (free_count, remaining) = smgr.dbg_get_free_list();
        // we should have 1 single range
        assert_eq!(free_count, 1);
        assert_eq!(remaining, [(25, 5)]);

        let allocated_slots3 = smgr.alloc_free_slots(5);
        assert_eq!(allocated_slots3.len(), 5);

        let (free_count, remaining) = smgr.dbg_get_free_list();
        // No blocks should be left to allocate as we have allocated everything
        assert_eq!(free_count, 0);
        assert_eq!(remaining.len(), 0);

        smgr.free_unused_slots(allocated_slots1);
        smgr.free_unused_slots(allocated_slots2);
        smgr.free_unused_slots(allocated_slots3);

        let (free_count, remaining) = smgr.dbg_get_free_list();
        // We should have all the blocks free
        assert_eq!(free_count, 30);
        assert_eq!(remaining.len(), 30);
    }
}
