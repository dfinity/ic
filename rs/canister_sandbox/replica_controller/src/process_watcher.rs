use ic_types::CanisterId;
use lru::LruCache;
use std::collections::{hash_set::Iter, HashSet};

/// Keeps track of canister incoming requests and orders their
/// eviction from the active sandboxed processes pool. A canister is
/// evicted if its corresponding sandboxed process has been
/// shutdown. See `touch` for particular details.
///
/// We utilize the max_soft_limit of 0 to indicate an unlimited cache. We
/// still track usage, but never evict canisters.
///
/// # Explicit Pinning Requirement
///
/// We can not simply do RAII via a smart pointer like Rc. Besides
/// that, with RAII, we can not support asynchronous shutdowns, due to
/// the inability to async drop(), more importantly though, we end up
/// with leaking processes and unreachable state sessions without
/// pinning support.
///
/// Consider the have the following scenario:
///
/// Assume we have setup references (via Arc) for the runner_state and
/// the state sessions (via a map for instance).
///
/// The LRU pops the Arc pointer.  We close only execution on
/// exec_finished (e.g. possible callback/no signal from the
/// CallContextManager). At this point a single reference remains.  An
/// incoming request arrives. The Controller queries the LRU for a
/// process handle; none exists. The Controller starts a new process.
/// The new ControllerServer, part of the process handle, tries to
/// access the new wasm objects or worse might try to access the
/// session states that exist in the orphaned and unreachable (besides
/// in the future the CallContextManager) old process. This will lead
/// to a deadlock or abort in the latter case.
///
/// In the end, we require a pinning LRU mechanism, which is not
/// something the average cache crate provides. Therefore we have to
/// implement pinning. We try to treat the underlying cache in the
/// process as a black box oracle to move to a weighted and more
/// sophisticated one.
///
/// # Requirements
///
/// We divide the problem. The `ProcessWatcher` is responsible for
/// deciding evictions and keeping a set of canisters to be
/// evicted. If a canister is active is the responsibility of the
/// `ControllerServer`.
pub(crate) struct ProcessWatcher {
    cache: LruCache<CanisterId, ()>,
    max_soft_limit: u16,
    /// Keep a list of canisters to be evicted. As canisters can be
    /// active, we might not be able to actually evict the canister.
    to_be_deleted: HashSet<CanisterId>,
}

impl ProcessWatcher {
    /// Signify that the provided canister was the target of a new
    /// request.
    ///
    /// Also updates the to_be_deleted table.
    ///
    /// # Algorithm
    /// Input: Canister `C`
    /// 1. Add the canister_id in the LRU cache
    /// 2. Check if the upper soft max bound = 0 or if we are below the soft max
    /// 3. If yes, remove `C` from the to_be_deleted set and return None
    /// Otherwise:
    /// 4. Remove the least recently accessed element `D`
    /// 5. Ensure it is not the same canister as the input; if it is abort
    /// 6. Insert the canister in the to_be_deleted set
    /// 7. Remove `C` from the to_be_deleted set
    /// 8. Return Some(`D`)
    pub fn touch(&mut self, canister_id: CanisterId) -> Option<CanisterId> {
        self.cache.put(canister_id, ());
        let to_cool_canister =
            if self.max_soft_limit != 0 && (self.cache.len() > self.max_soft_limit as usize) {
                // As the capacity of the cache is 1 or greater, and we
                // apply an LRU algorithm, the element we pop must differ
                // from the canister we just inserted.
                let to_cool_canister: Option<CanisterId> = match self.cache.pop_lru() {
                    Some(popped_canister) => {
                        let popped_canister = popped_canister.0;
                        // There is one IMPORTANT RULE to ensure effective liveness:
                        // The canister we dictate that needs to shutdown MUST NOT be
                        // the one referenced by the triggering event.
                        //
                        // Otherwise, we will be constantly fluctuating processes up
                        // and down.
                        assert_ne!(popped_canister, canister_id);
                        // Update the list of canister whose processes we want to
                        // shutdown.
                        self.to_be_deleted.insert(popped_canister);
                        Some(popped_canister)
                    }
                    None => None,
                };
                to_cool_canister
            } else {
                None
            };
        // Finally update the set of canisters to be deleted to
        // ensure, we do not try to shutdown a process that was just
        // invoked.
        self.to_be_deleted.remove(&canister_id);

        to_cool_canister
    }

    /// Mark the process as killed.
    pub fn process_killed(&mut self, canister_id: &CanisterId) -> bool {
        self.to_be_deleted.remove(canister_id)
    }

    #[allow(dead_code)]
    /// Mark all processes as killed.
    pub fn all_processes_killed(&mut self) {
        self.to_be_deleted.clear()
    }

    /// Return all processes to be deleted.
    pub fn processes_to_be_deleted(&self) -> Iter<CanisterId> {
        self.to_be_deleted.iter()
    }

    /// Construct a ProcessWatcher with the soft max limit as a
    /// parameter. That is the number of processes it will try to
    /// keep. We assume a bound of 65k processes (thus a u16).
    pub fn new(max_soft_limit: u16) -> Self {
        Self {
            // We are constructing an unbounded cache with the default
            // hasher to keep things simple. We do not have any
            // particular user characteristics to define a right or
            // more appropriate hasher, and we want to do the eviction
            // ourselves to reduce logical errors.
            cache: LruCache::unbounded(),
            max_soft_limit,
            to_be_deleted: HashSet::new(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::iter::FromIterator;

    #[test]
    fn basic_test() {
        let canister_1 = CanisterId::from_u64(1);
        let canister_2 = CanisterId::from_u64(2);
        let canister_3 = CanisterId::from_u64(3);
        let canister_4 = CanisterId::from_u64(4);

        let mut watcher = ProcessWatcher::new(1);

        assert!(watcher.touch(canister_1).is_none());
        assert!(watcher.to_be_deleted.is_empty());
        assert!(watcher.touch(canister_1).is_none());
        assert!(watcher.to_be_deleted.is_empty());
        assert!(watcher.touch(canister_1).is_none());
        assert!(watcher.to_be_deleted.is_empty());
        assert!(watcher.touch(canister_1).is_none());

        assert_eq!(watcher.touch(canister_2), Some(canister_1));
        assert!(watcher.to_be_deleted.contains(&canister_1));
        assert_eq!(watcher.to_be_deleted.len(), 1);
        // The cache length must be always 1 after each touch
        // operation.
        assert_eq!(watcher.cache.len(), 1);
        assert_eq!(watcher.touch(canister_3), Some(canister_2));
        assert!(watcher.to_be_deleted.contains(&canister_1));
        assert!(watcher.to_be_deleted.contains(&canister_2));
        assert_eq!(watcher.to_be_deleted.len(), 2);
        assert_eq!(watcher.cache.len(), 1);
        assert_eq!(
            watcher.to_be_deleted,
            HashSet::from_iter(vec![canister_1, canister_2])
        );
        let correct_set: HashSet<CanisterId> = HashSet::from_iter(vec![canister_1, canister_2]);
        for c in watcher.processes_to_be_deleted() {
            assert!(correct_set.contains(c));
        }
        assert_eq!(watcher.processes_to_be_deleted().len(), correct_set.len());

        watcher.all_processes_killed();
        assert_eq!(watcher.to_be_deleted.len(), 0);
        assert_eq!(watcher.cache.len(), 1);

        assert_eq!(watcher.touch(canister_4), Some(canister_3));
        assert!(watcher.to_be_deleted.contains(&canister_3));
    }

    #[test]
    fn basic_test_2() {
        let canister_1 = CanisterId::from_u64(1);
        let canister_2 = CanisterId::from_u64(2);
        let canister_3 = CanisterId::from_u64(3);
        let canister_4 = CanisterId::from_u64(4);

        let mut watcher = ProcessWatcher::new(3);

        assert!(watcher.touch(canister_1).is_none());
        assert!(watcher.to_be_deleted.is_empty());
        assert!(watcher.touch(canister_1).is_none());
        assert!(watcher.to_be_deleted.is_empty());
        assert!(watcher.touch(canister_1).is_none());
        assert!(watcher.to_be_deleted.is_empty());
        assert!(watcher.touch(canister_1).is_none());

        assert_eq!(watcher.touch(canister_2), None);
        assert!(watcher.to_be_deleted.is_empty());
        assert_eq!(watcher.to_be_deleted.len(), 0);
        // The cache length must be 2.
        assert_eq!(watcher.cache.len(), 2);
        assert_eq!(watcher.touch(canister_3), None);
        assert_eq!(watcher.to_be_deleted.len(), 0);
        assert_eq!(watcher.cache.len(), 3);
        // We don't derive FromIterator for CanisterId.
        let correct_set: HashSet<CanisterId> =
            HashSet::from_iter(vec![canister_1, canister_2, canister_3]);
        for c in watcher.cache.iter() {
            assert!(correct_set.contains(c.0));
        }
        assert_eq!(watcher.cache.iter().len(), correct_set.len());

        watcher.all_processes_killed();
        assert_eq!(watcher.to_be_deleted.len(), 0);
        assert_eq!(watcher.cache.len(), 3);
        assert_eq!(watcher.cache.peek_lru(), Some((&canister_1, &())));

        assert_eq!(watcher.touch(canister_4), Some(canister_1));
        assert!(watcher.to_be_deleted.contains(&canister_1));
        assert_eq!(watcher.cache.peek_lru(), Some((&canister_2, &())));
        assert_eq!(watcher.touch(canister_2), None);
        assert_eq!(watcher.cache.peek_lru(), Some((&canister_3, &())));
    }

    #[test]
    fn test_adding_clear_elements_unbounded() {
        let canister_1 = CanisterId::from_u64(1);
        let canister_2 = CanisterId::from_u64(2);
        let canister_3 = CanisterId::from_u64(3);
        let canister_4 = CanisterId::from_u64(4);

        let mut watcher = ProcessWatcher::new(0);

        assert!(watcher.touch(canister_1).is_none());
        assert!(watcher.to_be_deleted.is_empty());
        assert!(watcher.touch(canister_1).is_none());
        assert!(watcher.to_be_deleted.is_empty());
        assert!(watcher.touch(canister_1).is_none());
        assert!(watcher.to_be_deleted.is_empty());
        assert!(watcher.touch(canister_1).is_none());

        assert_eq!(watcher.touch(canister_2), None);
        assert!(watcher.to_be_deleted.is_empty());
        assert_eq!(watcher.to_be_deleted.len(), 0);

        assert!(watcher.touch(canister_3).is_none());
        assert!(watcher.to_be_deleted.is_empty());
        assert!(watcher.touch(canister_4).is_none());
        assert_eq!(watcher.cache.peek_lru(), Some((&canister_1, &())));

        assert_eq!(watcher.touch(canister_2), None);
        assert_eq!(watcher.cache.peek_lru(), Some((&canister_1, &())));
    }
}
