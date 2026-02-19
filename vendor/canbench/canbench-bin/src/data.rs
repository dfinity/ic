use crate::fmt::{fmt_human_percent, fmt_human_u64, fmt_percent};
use crate::{BenchResult, Measurement};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Entry {
    pub(crate) status: String,
    pub(crate) benchmark: Benchmark,
    pub(crate) calls: Values,
    pub(crate) instructions: Values,
    pub(crate) heap_increase: Values,
    pub(crate) stable_memory_increase: Values,
}

impl Entry {
    pub(crate) fn has_scope(&self) -> bool {
        self.benchmark.scope.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Benchmark {
    name: String,
    scope: Option<String>,
}

impl Benchmark {
    pub(crate) fn new(name: &str, scope: Option<&str>) -> Self {
        Self {
            name: name.to_string(),
            scope: scope.map(str::to_string),
        }
    }

    pub(crate) fn full_name(&self) -> String {
        self.scope
            .as_ref()
            .map(|s| format!("{}::{}", self.name, s))
            .unwrap_or_else(|| self.name.clone())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Change {
    New,
    Improved,
    Regressed,
    Unchanged,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Values {
    curr: Option<u64>,
    prev: Option<u64>,
}

impl Values {
    #[cfg(test)]
    pub(crate) fn new(curr: Option<u64>, prev: Option<u64>) -> Self {
        Self { curr, prev }
    }

    pub(crate) fn current(&self) -> Option<u64> {
        self.curr
    }

    pub(crate) fn abs_delta(&self) -> Option<i64> {
        Some(self.curr? as i64 - self.prev? as i64)
    }

    pub(crate) fn percent_diff(&self) -> Option<f64> {
        let delta = self.abs_delta()?;
        let prev = self.prev?;

        Some(if prev == 0 {
            match delta {
                d if d < 0 => f64::NEG_INFINITY,
                d if d > 0 => f64::INFINITY,
                _ => 0.0,
            }
        } else {
            delta as f64 / prev as f64 * 100.0
        })
    }

    pub(crate) fn fmt_current(&self) -> String {
        self.current().map_or_else(String::new, |v| v.to_string())
    }

    pub(crate) fn fmt_human_current(&self) -> String {
        self.current().map_or_else(String::new, fmt_human_u64)
    }

    pub(crate) fn fmt_abs_delta(&self) -> String {
        self.abs_delta().map_or_else(String::new, |v| v.to_string())
    }

    pub(crate) fn fmt_percent(&self) -> String {
        self.percent_diff().map_or_else(String::new, fmt_percent)
    }

    pub(crate) fn fmt_human_percent(&self) -> String {
        self.percent_diff()
            .map_or_else(String::new, fmt_human_percent)
    }

    pub(crate) fn status(&self, noise_threshold: f64) -> Change {
        match (self.curr, self.prev) {
            (Some(_), Some(_)) => match self.percent_diff() {
                Some(p) if p.abs() < noise_threshold => Change::Unchanged,
                Some(p) if p < 0.0 => Change::Improved,
                Some(_) => Change::Regressed,
                None => Change::Unchanged,
            },
            (Some(_), None) => Change::New,
            (None, Some(_)) => {
                // This is actually a removed benchmark
                // but we don't track it at the moment,
                // so we treat it as unchanged.
                Change::Unchanged
            }
            (None, None) => Change::Unchanged,
        }
    }
}

pub(crate) fn extract(
    new_results: &BTreeMap<String, BenchResult>,
    old_results: &BTreeMap<String, BenchResult>,
) -> Vec<Entry> {
    let mut results = Vec::new();

    for (name, new_bench) in new_results {
        let old_bench = old_results.get(name);

        // Process total
        let benchmark = Benchmark::new(name, None);
        results.push(build_entry(
            if old_bench.is_none() { "new" } else { "" }.to_string(),
            benchmark,
            Some(&new_bench.total),
            old_bench.map(|b| &b.total),
        ));

        // Process scopes
        for (scope, new_m) in &new_bench.scopes {
            let old_m = old_bench.and_then(|b| b.scopes.get(scope));
            let benchmark = Benchmark::new(name, Some(scope));
            results.push(build_entry(
                if old_m.is_none() { "new" } else { "" }.to_string(),
                benchmark,
                Some(new_m),
                old_m,
            ));
        }
    }

    results
}

fn build_entry(
    status: String,
    benchmark: Benchmark,
    new_m: Option<&Measurement>,
    old_m: Option<&Measurement>,
) -> Entry {
    let extract_values = |f: fn(&Measurement) -> u64| Values {
        curr: new_m.map(f),
        prev: old_m.map(f),
    };

    Entry {
        status,
        benchmark,
        calls: extract_values(|m| m.calls),
        instructions: extract_values(|m| m.instructions),
        heap_increase: extract_values(|m| m.heap_increase),
        stable_memory_increase: extract_values(|m| m.stable_memory_increase),
    }
}
