use prometheus::{
    core::{Collector, Desc, Opts},
    proto, Gauge,
};

/// The process IDs type.
pub use libc::pid_t;

/// The number of metrics exported by this collector.
const METRIC_COUNT: usize = 1;

/// A collector that exports process metrics missing from the `prometheus`
/// crate's `ProcessCollector` (i.e. thread count).
#[derive(Debug)]
pub struct ProcessCollector {
    pid: pid_t,
    descs: Vec<Desc>,

    threads: Gauge,
}

impl ProcessCollector {
    /// Creates a `ProcessCollector` for this process.
    pub fn new() -> ProcessCollector {
        let pid = unsafe { libc::getpid() };

        let mut descs = Vec::new();

        let threads =
            Gauge::with_opts(Opts::new("process_threads", "Number of OS threads.")).unwrap();
        descs.extend(threads.desc().into_iter().cloned());

        ProcessCollector {
            pid,
            descs,
            threads,
        }
    }
}

impl Collector for ProcessCollector {
    fn desc(&self) -> Vec<&Desc> {
        self.descs.iter().collect()
    }

    fn collect(&self) -> Vec<proto::MetricFamily> {
        let p = match procfs::process::Process::new(self.pid) {
            Ok(p) => p,
            Err(..) => {
                // No `Process`, no stats to gather.
                return Vec::new();
            }
        };

        self.threads.set(p.stat.num_threads as f64);

        let mut mfs = Vec::with_capacity(METRIC_COUNT);
        mfs.extend(self.threads.collect());
        mfs
    }
}

impl Default for ProcessCollector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus::Registry;

    #[test]
    fn test_process_collector() {
        let pc = ProcessCollector::new();
        {
            // Seven metrics per process collector.
            let descs = pc.desc();
            assert_eq!(descs.len(), super::METRIC_COUNT);
            let mfs = pc.collect();
            assert_eq!(mfs.len(), super::METRIC_COUNT);
        }

        let r = Registry::new();
        let res = r.register(Box::new(pc));
        assert!(res.is_ok());
    }
}
