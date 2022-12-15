use std::{
    collections::HashMap,
    sync::{Arc, Mutex, Weak},
};

use super::{PageAllocatorId, PageAllocatorInner};

lazy_static::lazy_static! {
    static ref PAGE_ALLOCATOR_REGISTRY: Mutex<PageAllocatorRegistry> = Mutex::new(PageAllocatorRegistry::new());
}

/// A process-wide registry of page allocators. It is used to deduplicate page
/// allocators after deserialization in the sandbox process in order to ensure
/// the 1:1 correspondence between page allocators in the replica and sandbox
/// processes.
pub struct PageAllocatorRegistry {
    // This table is empty in the replica process because replica never
    // deserializes page allocators. In the sandbox process, the table will
    // contain only dozen of entries at any time because each canister has
    // a few live page allocators per checkpoint interval.
    table: HashMap<PageAllocatorId, Weak<PageAllocatorInner>>,

    // The table will be compacted once its length reaches this threshold.
    // Compaction means filtering out empty weak references.
    compaction_threshold: usize,
}

impl PageAllocatorRegistry {
    fn new() -> Self {
        Self {
            table: HashMap::default(),
            compaction_threshold: 10,
        }
    }

    /// Returns a page allocator with the given id if it exists.
    /// Otherwise, inserts a new page allocator constructed with the given
    /// function.
    pub fn lookup_or_insert_with<F>(id: &PageAllocatorId, f: F) -> Arc<PageAllocatorInner>
    where
        F: FnOnce() -> Arc<PageAllocatorInner>,
    {
        let mut registry = PAGE_ALLOCATOR_REGISTRY.lock().unwrap();
        if let Some(weak) = registry.table.get(id) {
            if let Some(pa) = weak.upgrade() {
                return pa;
            }
        }

        let pa = f();

        registry.table.insert(*id, Arc::downgrade(&pa));
        if registry.table.len() >= registry.compaction_threshold {
            // Perform amortized compaction of the table.
            registry
                .table
                .retain(|_key, value| value.strong_count() > 0);
            registry.compaction_threshold = registry.table.len() * 2;
        }

        pa
    }

    #[cfg(test)]
    fn number_of_entries() -> usize {
        let registry = PAGE_ALLOCATOR_REGISTRY.lock().unwrap();
        registry.table.len()
    }

    #[cfg(test)]
    fn number_of_nonempty_entries() -> usize {
        let registry = PAGE_ALLOCATOR_REGISTRY.lock().unwrap();
        registry
            .table
            .iter()
            .filter(|(_k, v)| v.strong_count() > 0)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::page_map::page_allocator::mmap::{PageAllocatorId, PageAllocatorInner};
    use std::sync::Arc;

    #[test]
    fn lookup_or_insert_with() {
        let id1 = PageAllocatorId::default();
        let pa1 = Arc::new(PageAllocatorInner::new_for_testing());

        let id2 = PageAllocatorId::default();
        let pa2 = Arc::new(PageAllocatorInner::new_for_testing());

        PageAllocatorRegistry::lookup_or_insert_with(&id1, || Arc::clone(&pa1));
        PageAllocatorRegistry::lookup_or_insert_with(&id2, || Arc::clone(&pa2));

        // This lookup returns `pa1`.
        let pa3 = PageAllocatorRegistry::lookup_or_insert_with(&id1, || {
            unreachable!("the entry should exists")
        });

        assert_eq!(pa1.serialize().id, pa3.serialize().id);
        assert_eq!(pa1.serialize().fd.fd, pa3.serialize().fd.fd);

        drop(pa2);

        let pa4 = Arc::new(PageAllocatorInner::new_for_testing());

        // Since we dropped `pa2`, this lookup returns `pa4`.
        let pa5 = PageAllocatorRegistry::lookup_or_insert_with(&id2, || Arc::clone(&pa4));

        assert_eq!(pa4.serialize().id, pa5.serialize().id);
        assert_eq!(pa4.serialize().fd.fd, pa5.serialize().fd.fd);

        drop(pa1);
        drop(pa3);
        drop(pa4);
        drop(pa5);

        assert_eq!(0, PageAllocatorRegistry::number_of_nonempty_entries())
    }

    #[test]
    fn compact() {
        for _ in 0..1000 {
            let id1 = PageAllocatorId::default();
            let pa1 = Arc::new(PageAllocatorInner::new_for_testing());
            PageAllocatorRegistry::lookup_or_insert_with(&id1, || pa1);
        }
        assert!(PageAllocatorRegistry::number_of_entries() < 10);
    }
}
