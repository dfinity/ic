//! This makes it easy to implement "fail if another async call is in progress".
//!
//! See tests.rs for an example of how to use this.
use std::{cell::RefCell, collections::HashMap, fmt::Debug, hash::Hash, thread::LocalKey};

/// Internal trait for abstracting over different lock storage types.
/// This is an implementation detail and should not be used directly.
pub trait LockStorage<V> {
    type Key: Clone;
    type Error;

    fn try_acquire(&self, key: Self::Key, value: V) -> Result<(), Self::Error>;
    fn release(&self, key: Self::Key);
}

// Implementation for single-lock storage (existing behavior)
impl<V: Debug + Copy> LockStorage<V> for &'static LocalKey<RefCell<Option<V>>> {
    type Key = ();
    type Error = V;

    fn try_acquire(&self, _key: (), value: V) -> Result<(), V> {
        self.with(|cell| {
            let mut current = cell.borrow_mut();
            if let Some(existing) = *current {
                return Err(existing);
            }
            *current = Some(value);
            Ok(())
        })
    }

    fn release(&self, _key: ()) {
        self.with(|cell| *cell.borrow_mut() = None)
    }
}

// Implementation for map-based storage (new functionality)
impl<K: Hash + Eq + Clone + Debug + 'static, V: Debug + Copy> LockStorage<V>
    for &'static LocalKey<RefCell<HashMap<K, Option<V>>>>
{
    type Key = K;
    type Error = V;

    fn try_acquire(&self, key: K, value: V) -> Result<(), V> {
        self.with(|cell| {
            let mut map = cell.borrow_mut();
            if let Some(Some(existing)) = map.get(&key) {
                return Err(*existing);
            }
            map.insert(key, Some(value));
            Ok(())
        })
    }

    fn release(&self, key: K) {
        self.with(|cell| {
            cell.borrow_mut().remove(&key);
        })
    }
}

// Type aliases for cleaner public API
pub type ResourceGuard<V> = GenericResourceGuard<&'static LocalKey<RefCell<Option<V>>>, V>;
pub type NamedResourceGuard<K, V> =
    GenericResourceGuard<&'static LocalKey<RefCell<HashMap<K, Option<V>>>>, V>;

/// If current_resource_flag is None (the happy case), this does a few things:
///
/// 1. Sets current_resource_flag to Some(new_resource_flag).
/// 2. Returns Ok.
/// 3. Returns an object that when dropped sets current_resource_flag (back) to None.
///
/// In the sad case (i.e. current_resource_flag is Some(...)), returns Err(current_resource_flag).
///
/// Returns immediately; does not wait for others to release.
pub fn acquire<ResourceFlag: Debug + Copy + 'static>(
    current_resource_flag: &'static LocalKey<RefCell<Option<ResourceFlag>>>,
    new_resource_flag: ResourceFlag,
) -> Result<ResourceGuard<ResourceFlag>, ResourceFlag> {
    GenericResourceGuard::new(current_resource_flag, (), new_resource_flag)
}

/// Acquires a named lock from a map of locks. If the lock is already held for the given key,
/// returns an error with the existing value. Otherwise, acquires the lock and returns a guard
/// that will release the lock when dropped.
///
/// Returns immediately; does not wait for others to release.
pub fn acquire_for<K, V>(
    lock_map: &'static LocalKey<RefCell<HashMap<K, Option<V>>>>,
    lock_name: K,
    lock_object: V,
) -> Result<NamedResourceGuard<K, V>, V>
where
    K: Hash + Eq + Clone + Debug + 'static,
    V: Debug + Copy + 'static,
{
    GenericResourceGuard::new(lock_map, lock_name, lock_object)
}

#[derive(Debug)]
pub struct GenericResourceGuard<S, V>
where
    S: LockStorage<V>,
    V: Debug + Copy + 'static,
{
    storage: Option<S>,
    key: S::Key,
}

impl<S, V> GenericResourceGuard<S, V>
where
    S: LockStorage<V>,
    V: Debug + Copy + 'static,
{
    fn new(storage: S, key: S::Key, value: V) -> Result<Self, S::Error> {
        storage.try_acquire(key.clone(), value)?;
        Ok(GenericResourceGuard {
            storage: Some(storage),
            key,
        })
    }
}

impl<S, V> Drop for GenericResourceGuard<S, V>
where
    S: LockStorage<V>,
    V: Debug + Copy + 'static,
{
    fn drop(&mut self) {
        if let Some(storage) = self.storage.take() {
            storage.release(self.key.clone());
        }
    }
}

#[cfg(test)]
mod tests;
