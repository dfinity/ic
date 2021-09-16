use ic_config::subnet_config::SchedulerConfig;
use ic_metrics::{buckets::decimal_buckets_with_zero, MetricsRegistry};
use ic_types::{NumInstructions, NumMessages};
use prometheus::Histogram;
use std::{cell::RefCell, rc::Rc, time::Instant};

pub(crate) struct QueryHandlerMetrics {
    pub query: ScopedMetrics,
    pub query_initial_call: ScopedMetrics,
    pub query_retry_call: ScopedMetrics,
    pub query_spawned_calls: ScopedMetrics,
}

impl QueryHandlerMetrics {
    pub fn new(metrics_registry: &MetricsRegistry) -> Self {
        Self {
            query: ScopedMetrics {
                duration: duration_histogram(
                    "execution_query_duration_seconds",
                    "The duration of query handling",
                    metrics_registry,
                ),
                instructions: instructions_histogram(
                    "execution_query_instructions",
                    "The number of instructions executed in query handling",
                    metrics_registry,
                ),
                messages: messages_histogram(
                    "execution_query_messages",
                    "The number of messages executed in query handling",
                    metrics_registry,
                ),
            },
            query_initial_call: ScopedMetrics {
                duration: duration_histogram(
                    "execution_query_initial_call_duration_seconds",
                    "The duration of the initial call in query handling",
                    metrics_registry,
                ),
                instructions: instructions_histogram(
                    "execution_query_initial_call_instructions",
                    "The number of instructions executed in the initial call \
                    in query handling",
                    metrics_registry,
                ),
                messages: messages_histogram(
                    "execution_query_initial_call_messages",
                    "The number of messages executed in the initial call in \
                    query handling",
                    metrics_registry,
                ),
            },
            query_retry_call: ScopedMetrics {
                duration: duration_histogram(
                    "execution_query_retry_call_duration_seconds",
                    "The duration of the retry call in query handling",
                    metrics_registry,
                ),
                instructions: instructions_histogram(
                    "execution_query_retry_call_instructions",
                    "The number of instructions executed in the retry call \
                    in query handling",
                    metrics_registry,
                ),
                messages: messages_histogram(
                    "execution_query_retry_call_messages",
                    "The number of messages executed in the retry call in \
                    query handling",
                    metrics_registry,
                ),
            },
            query_spawned_calls: ScopedMetrics {
                duration: duration_histogram(
                    "execution_query_spawned_calls_duration_seconds",
                    "The duration of executing all calls spawned by the \
                    initial call in query handling",
                    metrics_registry,
                ),
                instructions: instructions_histogram(
                    "execution_query_spawned_calls_instructions",
                    "The number of instructions executed in calls spawned \
                    by the initial call in query handling",
                    metrics_registry,
                ),
                messages: messages_histogram(
                    "execution_query_spawned_calls_messages",
                    "The number of messages executed in calls spawned by \
                    the initial calls in query handling",
                    metrics_registry,
                ),
            },
        }
    }
}

/// A common set of metrics for various phases of execution
///
/// Currently the set includes:
/// - the duration of the phase,
/// - the number of instructions executed in the phase,
/// In the future, it will be extended with messages and cycles.
/// Use `MeasurementScope` instead of observing the metrics manually.
#[derive(Debug)]
pub(crate) struct ScopedMetrics {
    pub duration: Histogram,
    pub instructions: Histogram,
    pub messages: Histogram,
}

/// A convenience helper for measuring `ScopedMetrics`
///
/// It simplifies measuring of metrics for a hierarchy of phases and sub-phases
/// by automatically propagating metrics from sub-phases to outer phases and
/// automatically observing the metrics on drop.
///
/// It is intended to be stored in a local variable on the stack. Do not heap
/// allocate it or refer to it from other objects.
///
/// Usage:
/// 1) Define `ScopedMetrics` for each phase.
/// 2) Add `let scope = MeasurementScope::root(...)` in the top-most phase.
/// 3) Add `let scope = MeasurementScope::nested(...)` in a sub-phase.
/// 4) Tell the scopes about executed instructions using `scope.add()`.
/// See the `example_usage()` test below for details.
#[must_use = "Keep the scope in a local variable"]
#[derive(Debug)]
pub(crate) struct MeasurementScope<'a> {
    // `Rc<RefCell<...>>` is needed because we want to keep a reference to
    // the outer scope. Ordinary references do not work here because the
    // recursive definition would force the same lifetime for all references.
    core: Rc<RefCell<MeasurementScopeCore<'a>>>,
}

impl<'a> MeasurementScope<'a> {
    /// Returns a new root scope for tracking the given metrics.
    pub fn root(metrics: &'a ScopedMetrics) -> MeasurementScope<'a> {
        Self {
            core: Rc::new(RefCell::new(MeasurementScopeCore {
                metrics,
                instructions: NumInstructions::from(0),
                messages: NumMessages::from(0),
                outer: None,
                start_time: Instant::now(),
                record_zeros: true,
            })),
        }
    }

    /// Returns a new scope for tracking the given metrics that is
    /// nested in the given scope. It automatically propagates
    /// the instruction counter to the outer scope.
    pub fn nested(
        metrics: &'a ScopedMetrics,
        outer: &MeasurementScope<'a>,
    ) -> MeasurementScope<'a> {
        Self {
            core: Rc::new(RefCell::new(MeasurementScopeCore {
                metrics,
                instructions: NumInstructions::from(0),
                messages: NumMessages::from(0),
                outer: Some(outer.clone()),
                start_time: Instant::now(),
                record_zeros: true,
            })),
        }
    }

    /// Disable recording of scopes with zero messages, zero instructions.
    pub fn dont_record_zeros(self) -> Self {
        self.core.borrow_mut().record_zeros = false;
        self
    }

    /// Increments the instruction and message counters.
    pub fn add(&self, instructions: NumInstructions, messages: NumMessages) {
        let mut core = self.core.borrow_mut();
        core.instructions += instructions;
        core.messages += messages;
    }
}

impl<'a> Clone for MeasurementScope<'a> {
    fn clone(&self) -> MeasurementScope<'a> {
        Self {
            core: Rc::clone(&self.core),
        }
    }
}

/// Returns a histogram with buckets appropriate for durations.
pub fn duration_histogram<S: Into<String>>(
    name: S,
    help: S,
    metrics_registry: &MetricsRegistry,
) -> Histogram {
    let mut buckets = decimal_buckets_with_zero(-4, 1);
    buckets.push(100.0);
    // Buckets are [0, 100µs, 200µs, 500µs, ..., 10s, 20s, 50s, 100s].
    metrics_registry.histogram(name, help, buckets)
}

/// Returns a histogram with buckets appropriate for instructions.
pub fn instructions_histogram<S: Into<String>>(
    name: S,
    help: S,
    metrics_registry: &MetricsRegistry,
) -> Histogram {
    fn add_limits(buckets: &mut Vec<NumInstructions>, config: SchedulerConfig) {
        buckets.push(config.max_instructions_per_message);
        buckets.push(config.max_instructions_per_round);
        buckets.push(config.max_instructions_per_install_code);
    }
    let mut buckets: Vec<NumInstructions> = decimal_buckets_with_zero(4, 10)
        .into_iter()
        .map(|x| NumInstructions::from(x as u64))
        .collect();
    // Add buckets for counting no-op and small messages.
    buckets.push(NumInstructions::from(10));
    buckets.push(NumInstructions::from(1000));
    // Add buckets for all known instruction limits.
    add_limits(&mut buckets, SchedulerConfig::application_subnet());
    add_limits(&mut buckets, SchedulerConfig::verified_application_subnet());
    add_limits(&mut buckets, SchedulerConfig::system_subnet());
    // Ensure that all buckets are unique.
    buckets.sort_unstable();
    buckets.dedup();
    // Buckets are [0, 10, 1K, 10K, 20K, ...,  10B, 20B, 50B] + [subnet limits]
    metrics_registry.histogram(
        name,
        help,
        buckets.into_iter().map(|x| x.get() as f64).collect(),
    )
}

/// Returns a histogram with buckets appropriate for messages.
pub fn messages_histogram<S: Into<String>>(
    name: S,
    help: S,
    metrics_registry: &MetricsRegistry,
) -> Histogram {
    let mut buckets = decimal_buckets_with_zero(1, 4);
    buckets.push(100_000.0);
    // Buckets are [0, 10, 20, 50, ..., 10K, 20K, 50K].
    metrics_registry.histogram(name, help, buckets)
}

#[derive(Debug)]
struct MeasurementScopeCore<'a> {
    metrics: &'a ScopedMetrics,
    instructions: NumInstructions,
    messages: NumMessages,
    outer: Option<MeasurementScope<'a>>,
    start_time: Instant,
    record_zeros: bool,
}

impl<'a> Drop for MeasurementScopeCore<'a> {
    fn drop(&mut self) {
        if let Some(outer) = &self.outer {
            outer.add(self.instructions, self.messages);
        }
        if self.record_zeros || self.messages.get() != 0 {
            self.metrics
                .instructions
                .observe(self.instructions.get() as f64);
            self.metrics.messages.observe(self.messages.get() as f64);
            self.metrics
                .duration
                .observe(self.start_time.elapsed().as_secs_f64())
        }
    }
}

#[cfg(test)]
mod tests {
    use ic_types::NumMessages;

    use super::*;

    #[test]
    fn example_usage() {
        // Setup:
        let mr = MetricsRegistry::new();
        let round_metrics = ScopedMetrics {
            duration: duration_histogram("round_duration_seconds", "...", &mr),
            instructions: instructions_histogram("round_instructions", "...", &mr),
            messages: messages_histogram("round_messages", "...", &mr),
        };
        let canister_metrics = ScopedMetrics {
            duration: duration_histogram("canister_duration_seconds", "...", &mr),
            instructions: instructions_histogram("canister_instructions", "...", &mr),
            messages: messages_histogram("canister_messages", "...", &mr),
        };

        // Round execution:
        {
            let scope = MeasurementScope::root(&round_metrics);
            for _ in 0..10 {
                // Canister execution:
                let scope = MeasurementScope::nested(&canister_metrics, &scope);
                scope.add(NumInstructions::from(10), NumMessages::from(1));
            }
        }

        // Results:
        // - durations were measured automatically.
        // - instructions propagated from canisters to round automatically.
        assert_eq!(10, canister_metrics.duration.get_sample_count());
        assert_eq!(10, canister_metrics.instructions.get_sample_count());
        assert_eq!(100, canister_metrics.instructions.get_sample_sum() as u64);
        assert_eq!(10, canister_metrics.messages.get_sample_count());
        assert_eq!(10, canister_metrics.messages.get_sample_sum() as u64);
        assert_eq!(1, round_metrics.duration.get_sample_count());
        assert_eq!(1, round_metrics.instructions.get_sample_count());
        assert_eq!(100, round_metrics.instructions.get_sample_sum() as u64);
        assert_eq!(1, round_metrics.messages.get_sample_count());
        assert_eq!(10, round_metrics.messages.get_sample_sum() as u64);
    }

    #[test]
    fn multiple_nested_scopes() {
        let mr = MetricsRegistry::new();
        let l1 = ScopedMetrics {
            duration: duration_histogram("l1_duration_seconds", "...", &mr),
            instructions: instructions_histogram("l1_instructions", "...", &mr),
            messages: messages_histogram("l1_messages", "...", &mr),
        };
        let l2 = ScopedMetrics {
            duration: duration_histogram("l2_duration_seconds", "...", &mr),
            instructions: instructions_histogram("l2_instructions", "...", &mr),
            messages: messages_histogram("l2_messages", "...", &mr),
        };
        let l3 = ScopedMetrics {
            duration: duration_histogram("l3_duration_seconds", "...", &mr),
            instructions: instructions_histogram("l3_instructions", "...", &mr),
            messages: messages_histogram("l3_messages", "...", &mr),
        };

        {
            let scope = MeasurementScope::root(&l1);
            {
                let scope = MeasurementScope::nested(&l2, &scope);
                {
                    let scope = MeasurementScope::nested(&l3, &scope);
                    scope.add(NumInstructions::from(10), NumMessages::from(1));
                }
            }
        }
        assert_eq!(1, l1.duration.get_sample_count());
        assert_eq!(1, l1.instructions.get_sample_count());
        assert_eq!(10, l1.instructions.get_sample_sum() as u64);
        assert_eq!(1, l1.messages.get_sample_count());
        assert_eq!(1, l1.messages.get_sample_sum() as u64);
        assert_eq!(1, l2.duration.get_sample_count());
        assert_eq!(1, l2.instructions.get_sample_count());
        assert_eq!(10, l2.instructions.get_sample_sum() as u64);
        assert_eq!(1, l2.messages.get_sample_count());
        assert_eq!(1, l2.messages.get_sample_sum() as u64);
        assert_eq!(1, l3.duration.get_sample_count());
        assert_eq!(1, l3.instructions.get_sample_count());
        assert_eq!(10, l3.instructions.get_sample_sum() as u64);
        assert_eq!(1, l3.messages.get_sample_count());
        assert_eq!(1, l3.messages.get_sample_sum() as u64);
    }

    #[test]
    fn multiple_add_calls() {
        let mr = MetricsRegistry::new();
        let l1 = ScopedMetrics {
            duration: duration_histogram("l1_duration_seconds", "...", &mr),
            instructions: instructions_histogram("l1_instructions", "...", &mr),
            messages: messages_histogram("l1_messages", "...", &mr),
        };
        let l2 = ScopedMetrics {
            duration: duration_histogram("l2_duration_seconds", "...", &mr),
            instructions: instructions_histogram("l2_instructions", "...", &mr),
            messages: messages_histogram("l2_messages", "...", &mr),
        };

        {
            let scope = MeasurementScope::root(&l1);
            scope.add(NumInstructions::from(100), NumMessages::from(1));
            {
                let scope = MeasurementScope::nested(&l2, &scope);
                scope.add(NumInstructions::from(10), NumMessages::from(1));
                scope.add(NumInstructions::from(20), NumMessages::from(1));
                scope.add(NumInstructions::from(30), NumMessages::from(1));
            }
            scope.add(NumInstructions::from(200), NumMessages::from(1));
        }
        assert_eq!(1, l1.duration.get_sample_count());
        assert_eq!(1, l1.instructions.get_sample_count());
        assert_eq!(360, l1.instructions.get_sample_sum() as u64);
        assert_eq!(1, l1.messages.get_sample_count());
        assert_eq!(5, l1.messages.get_sample_sum() as u64);
        assert_eq!(1, l2.duration.get_sample_count());
        assert_eq!(1, l2.instructions.get_sample_count());
        assert_eq!(60, l2.instructions.get_sample_sum() as u64);
        assert_eq!(1, l2.messages.get_sample_count());
        assert_eq!(3, l2.messages.get_sample_sum() as u64);
    }

    #[test]
    fn dont_record_zeros() {
        let mr = MetricsRegistry::new();
        let outer = ScopedMetrics {
            duration: duration_histogram("l1_duration_seconds", "...", &mr),
            instructions: instructions_histogram("l1_instructions", "...", &mr),
            messages: messages_histogram("l1_messages", "...", &mr),
        };
        let middle = ScopedMetrics {
            duration: duration_histogram("l2_duration_seconds", "...", &mr),
            instructions: instructions_histogram("l2_instructions", "...", &mr),
            messages: messages_histogram("l2_messages", "...", &mr),
        };
        let inner = ScopedMetrics {
            duration: duration_histogram("l3_duration_seconds", "...", &mr),
            instructions: instructions_histogram("l3_instructions", "...", &mr),
            messages: messages_histogram("l3_messages", "...", &mr),
        };

        {
            let outer_scope = MeasurementScope::root(&outer);
            let milddle_scope = MeasurementScope::nested(&middle, &outer_scope).dont_record_zeros();
            let _inner_scope = MeasurementScope::nested(&inner, &milddle_scope);
        }

        // Outer scope should have recorded one zero sample for each metric.
        assert_eq!(1, outer.duration.get_sample_count());
        assert_eq!(1, outer.instructions.get_sample_count());
        assert_eq!(0, outer.instructions.get_sample_sum() as u64);
        assert_eq!(1, outer.messages.get_sample_count());
        assert_eq!(0, outer.messages.get_sample_sum() as u64);

        // Middle scope (with `dont_record_zeros()`) should not have recorded any
        // samples.
        assert_eq!(0, middle.duration.get_sample_count());
        assert_eq!(0, middle.instructions.get_sample_count());
        assert_eq!(0, middle.instructions.get_sample_sum() as u64);
        assert_eq!(0, middle.messages.get_sample_count());
        assert_eq!(0, middle.messages.get_sample_sum() as u64);

        // Inner scope should have alsp recorded one zero sample for each metric.
        assert_eq!(1, inner.duration.get_sample_count());
        assert_eq!(1, inner.instructions.get_sample_count());
        assert_eq!(0, inner.instructions.get_sample_sum() as u64);
        assert_eq!(1, inner.messages.get_sample_count());
        assert_eq!(0, inner.messages.get_sample_sum() as u64);
    }
}
