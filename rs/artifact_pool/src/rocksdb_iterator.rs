/// A RockDB iterator that can be passed by value without having to worry about
/// lifetime constraints. It won't see changes made to the DB after its creation
/// because it is created from a read-only snapshot.
///
/// In order for this to work, a snapshot and an iterator are created from
/// Arc<DB>, and the iterator will hold this reference, which means the DB
/// remains live as long as any such iterators remain live.
// The hierarchy of required references is the following:
//
//                       DB
//                       ^
//                      / \
//                     /   \
//                    /     \
//              Snapshot  ColumnFamily
//                 ^         ^
//                 |        /
//                 |      /
//               DBIterator
//
// So, in order to build an iterator, we first must build a Snapshot, which
// must live >= than the iterator and in turn has a reference to the
// DB, which must also live >= than the Snapshot. To build an iterator,
// we also need a handle to the column family, which will live as long
// as the column family lives in the DB, which for us is the same
// lifetime as the DB itself.
//
// In order to store these parent/child/sibling/cousin relationships under
// the same struct it's necessary to use raw pointers (and thus unsafe)
// as the borrow checker won't allow it.
//
// See the following link for another example of unsafe being required in a
// similar, though simpler, situation:
// https://github.com/mobilipia/ibchain/blob/6b1a7f9d54a2bec177d04629f2346759fef2c319\
// /components/merkledb/src/backends/rocksdb.rs
use rocksdb::{DBRawIterator, ReadOptions, Snapshot, DB};
use std::sync::Arc;

/// A standalone iterator for RocksDB read-only snapshots.
///
/// Its interfaces mostly mirror those of 'DBIterator' except for the 'new'
/// function.
//
// Both the 'snapshot' and 'db' fields are no longer used once the struct is
// created. They are only kept here for their 'Drop' trait implementation. This
// explains why #[allow(dead_code)] is necessary. For the same reason, we don't
// have to keep the 'cf_handle' in the struct because it doesn't implement
// `Drop`.
//
// NOTE: Because the fields in this struct are interdependent the order of the
// fields matters. Rust RFC 1857 stabilized the drop order of fields to make it
// so fields are always dropped in the order they are declared. The 'iter'
// field must be dropped first, followed by the 'snapshot' field and only then
// can the 'db' field be dropped.
pub struct StandaloneIterator<'a, F> {
    status: Status,
    min_key: Vec<u8>,
    max_key: Vec<u8>,
    iter: DBRawIterator<'a>,
    deserializer: F,
    pub(crate) snapshot: Arc<StandaloneSnapshot<'a>>,
}

trait DeserializeFn<'a, T>: Fn(Arc<StandaloneSnapshot<'a>>, &[u8]) -> Option<T> {}

/// Status of the iterator, one of NotStarted, Started, or Stopped.
enum Status {
    NotStarted,
    Started,
    Stopped,
}

impl<'a, F> StandaloneIterator<'a, F> {
    /// Create an iterator for the given column family 'name' of the given 'db'
    /// starting from 'start_key'
    pub fn new(
        db: Arc<DB>,
        name: &str,
        min_key: &[u8],
        max_key: &[u8],
        deserializer: F,
    ) -> Result<Self, String> {
        let mut read_options = ReadOptions::default();
        read_options.set_total_order_seek(true);

        let cf_handle = db
            .cf_handle(name)
            .ok_or("column family does not exist: ".to_string() + name)?;

        let snapshot: StandaloneSnapshot<'_> = StandaloneSnapshot::new(db.clone());

        // Unsafe operation is necessary to circumvent sibling pointer restrictions.
        // Also, we use raw iterator to avoid having to memcpy key & value.
        let iter: DBRawIterator<'_> = unsafe {
            std::mem::transmute(
                snapshot
                    .snapshot
                    .raw_iterator_cf_opt(cf_handle, read_options),
            )
        };

        Ok(StandaloneIterator {
            status: Status::NotStarted,
            min_key: min_key.to_vec(),
            max_key: max_key.to_vec(),
            iter,
            deserializer,
            snapshot: Arc::new(snapshot),
        })
    }
}

impl<'a, T, F: Fn(Arc<StandaloneSnapshot<'a>>, &[u8]) -> Option<T>> Iterator
    for StandaloneIterator<'a, F>
{
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        match self.status {
            Status::NotStarted => {
                // If this is the start, we want to seek to min_key.
                self.iter.seek(&self.min_key);
                self.status = Status::Started;
            }
            Status::Started => {
                // If we have already started, we want to call iter.next().
                self.iter.next();
            }
            Status::Stopped => return None,
        }

        if self.iter.valid() {
            if let Some(key) = self.iter.key() {
                match key.cmp(&self.max_key) {
                    std::cmp::Ordering::Equal => {
                        self.status = Status::Stopped;
                    }
                    std::cmp::Ordering::Greater => {
                        self.status = Status::Stopped;
                        return None;
                    }
                    _ => {}
                }
                let value = self.iter.value()?;
                return (self.deserializer)(self.snapshot.clone(), value);
            }
        }
        self.status = Status::Stopped;
        None
    }
}

pub struct StandaloneSnapshot<'a> {
    pub(crate) snapshot: Snapshot<'a>,
    pub(crate) db: Arc<DB>,
}

impl<'a> StandaloneSnapshot<'a> {
    pub fn new(db: Arc<DB>) -> StandaloneSnapshot<'a> {
        // Unsafe operation is necessary to circumvent sibling pointer restrictions.
        let snapshot: Snapshot<'_> = unsafe { std::mem::transmute(db.snapshot()) };
        StandaloneSnapshot { snapshot, db }
    }
}
