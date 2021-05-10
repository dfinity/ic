//! A LMDB iterator that can be passed by value without having to worry about
//! lifetime constraints. It won't see changes made to the DB after its creation
//! because it is created from read-only transaction and cursor that are kept
//! live as long as the iterator is live.
//
// In order to store these parent/child/sibling/cousin relationships under
// the same struct it's necessary to use unsafe operation as the borrow checker
// won't allow it.
use crate::lmdb_pool::HeightKey;
use ic_logger::{error, ReplicaLogger};
use lmdb::{Cursor, Database, Environment, Iter, RoCursor, RoTransaction, Transaction};
use std::sync::Arc;

/// A standalone iterator for LMDB.
//
// The dependency relationship of its DB related fields is given below:
//
//     iter -> cursor -> tx -> db_env
//
// where:
//
// - iter is to iterate through multi-valued entry of the index table;
// - cursor is to set the start position using min_key;
// - tx is used to read data;
// - db_env is the overall DB handle.
//
// Among them, cursor and db_env are not used after being initialized in the
// struct. They are still necessary because of we need to free the chain of
// dependencies in order.
//
// NOTE: Because the fields in this struct are interdependent the order of the
// fields matters. Rust RFC 1857 stabilized the drop order of fields to make it
// so fields are always dropped in the order they are declared.
pub(crate) struct LMDBIterator<'a, F> {
    log: ReplicaLogger,
    max_key: HeightKey,
    deserialize: F,
    iter: Option<Iter<'a>>,
    #[allow(dead_code)]
    cursor: RoCursor<'a>,
    tx: RoTransaction<'a>,
    #[allow(dead_code)]
    db_env: Arc<Environment>,
}

impl<'a, F> LMDBIterator<'a, F> {
    /// Return a new iterator that will iterator through DB objects between
    /// min_key and max_key (inclusive) that are deserialized using the
    /// given deserialize function.
    pub fn new(
        db_env: Arc<Environment>,
        db: Database,
        min_key: HeightKey,
        max_key: HeightKey,
        deserialize: F,
        log: ReplicaLogger,
    ) -> Self {
        let tx: RoTransaction<'_> = unsafe { std::mem::transmute(db_env.begin_ro_txn().unwrap()) };
        let mut cursor: RoCursor<'_> =
            unsafe { std::mem::transmute(tx.open_ro_cursor(db).unwrap()) };
        let iter: Iter<'_> = unsafe { std::mem::transmute(cursor.iter_from(min_key)) };
        Self {
            log,
            db_env,
            tx,
            cursor,
            iter: Some(iter),
            max_key,
            deserialize,
        }
    }
}

impl<'a, T, F: Fn(&RoTransaction<'_>, &[u8]) -> lmdb::Result<T>> Iterator for LMDBIterator<'a, F> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        let mut iter = self.iter.take()?;
        let (key, bytes) = iter
            .next()
            .transpose()
            .map_err(|err| error!(self.log, "iterator error {:?}", err))
            .ok()
            .flatten()?;
        if HeightKey::from(key) > self.max_key {
            None
        } else {
            self.iter = Some(iter);
            (self.deserialize)(&self.tx, bytes)
                .map_err(|err| error!(self.log, "deserialization error: {:?}", err))
                .ok()
        }
    }
}
