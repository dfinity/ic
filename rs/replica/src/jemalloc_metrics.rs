//! This module exposes jemalloc statistics as prometheus metrics.

use jemalloc_ctl::{epoch, stats};
use prometheus::core::{Collector, Desc};
use prometheus::proto::MetricFamily;
use prometheus::IntGauge;

#[derive(Clone)]
pub struct JemallocMetrics {
    active: IntGauge,
    allocated: IntGauge,
    mapped: IntGauge,
    metadata: IntGauge,
    resident: IntGauge,
    retained: IntGauge,
}

impl JemallocMetrics {
    pub fn new() -> Self {
        Self {
            active: IntGauge::new(
                "jemalloc_active_bytes",
                "Total number of bytes in active pages allocated by the application.",
            )
            .unwrap(),
            allocated: IntGauge::new(
                "jemalloc_allocated_bytes",
                "Total number of bytes allocated by the application.",
            )
            .unwrap(),
            mapped: IntGauge::new(
                "jemalloc_mapped_bytes",
                "Total number of bytes in active extents mapped by the allocator.",
            )
            .unwrap(),
            metadata: IntGauge::new(
                "jemalloc_metadata_bytes",
                "Total number of bytes dedicated to jemalloc metadata.",
            )
            .unwrap(),
            resident: IntGauge::new(
                "jemalloc_resident_bytes",
                "Total number of bytes in physically resident data pages mapped by the allocator.",
            )
            .unwrap(),
            retained: IntGauge::new(
                "jemalloc_retained_bytes",
                "Total number of bytes in virtual memory mappings that were retained rather than being returned to the operating system via e.g. munmap(2).",
            )
            .unwrap(),
        }
    }
}

impl Collector for JemallocMetrics {
    fn desc(&self) -> Vec<&Desc> {
        let mut result = self.active.desc();
        result.append(&mut self.allocated.desc());
        result.append(&mut self.mapped.desc());
        result.append(&mut self.metadata.desc());
        result.append(&mut self.resident.desc());
        result.append(&mut self.retained.desc());
        result
    }

    fn collect(&self) -> Vec<MetricFamily> {
        // Advance the epoch to flush the metrics cache.
        let e = epoch::mib().expect("failed to get Management Information Base");
        e.advance().expect("failed to advance jemalloc epoch");

        self.active
            .set(stats::active::mib().unwrap().read().unwrap() as i64);
        self.allocated
            .set(stats::allocated::mib().unwrap().read().unwrap() as i64);
        self.mapped
            .set(stats::mapped::mib().unwrap().read().unwrap() as i64);
        self.metadata
            .set(stats::metadata::mib().unwrap().read().unwrap() as i64);
        self.resident
            .set(stats::resident::mib().unwrap().read().unwrap() as i64);
        self.retained
            .set(stats::retained::mib().unwrap().read().unwrap() as i64);

        let mut result = self.active.collect();
        result.append(&mut self.allocated.collect());
        result.append(&mut self.mapped.collect());
        result.append(&mut self.metadata.collect());
        result.append(&mut self.resident.collect());
        result.append(&mut self.retained.collect());
        result
    }
}
