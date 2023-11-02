use crate::{ProfilerSink, SpanName};
use ic_metrics_encoder::LabeledHistogramBuilder;
use std::collections::BTreeMap;

/// The number of buckets in a histogram.
pub const BUCKET_COUNT: usize = 29;

/// Buckets for measuring span instruction consumption.
pub const BUCKETS: [u64; BUCKET_COUNT] = [
    10_000,
    20_000,
    50_000,
    100_000,
    200_000,
    500_000,
    1_000_000,
    2_000_000,
    5_000_000,
    10_000_000,
    20_000_000,
    50_000_000,
    100_000_000,
    200_000_000,
    500_000_000,
    1_000_000_000,
    2_000_000_000,
    5_000_000_000,
    10_000_000_000,
    20_000_000_000,
    50_000_000_000,
    100_000_000_000,
    200_000_000_000,
    500_000_000_000,
    1_000_000_000_000,
    2_000_000_000_000,
    5_000_000_000_000,
    10_000_000_000_000,
    u64::MAX,
];

/// The distribution of instruction consumption within a span.
///
/// `histogram[i]` contains the number of measurements m such that
/// `BUCKETS[i - 1] < m <= BUCKETS[i]`.
/// `BUCKETS[-1]` is defined to be zero.
type Histogram = [u64; BUCKET_COUNT];

#[derive(Default, Clone, Debug)]
pub struct SpanInfo {
    /// The histogram of observed values.  The [BUCKETS] constant
    /// defines the bucket sizes.
    pub histogram: Histogram,

    /// The sum of all observed values.  Together with the
    /// `num_samples` field, it allows us to compute the average.
    pub sum: u128,

    /// The maximum observed value.
    pub max: u64,

    /// The number of samples in the distribution.
    pub num_samples: u64,
}

impl SpanInfo {
    pub fn iter_buckets(&self) -> impl Iterator<Item = (f64, f64)> + '_ {
        BUCKETS
            .iter()
            .cloned()
            .zip(self.histogram.iter().cloned())
            .map(|(b, m)| (b as f64, m as f64))
    }
}

#[derive(Default)]
pub struct SpanStats(BTreeMap<SpanName, SpanInfo>);

impl SpanStats {
    /// Creates a new collection of span statistics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Looks up span stats by name.
    pub fn get_span(&self, span: SpanName) -> Option<&SpanInfo> {
        self.0.get(span)
    }

    /// Records the span stats as a collection of labaled histrograms.
    pub fn record_metrics<W: std::io::Write>(
        &self,
        mut builder: LabeledHistogramBuilder<'_, W>,
    ) -> std::io::Result<()> {
        for (span_name, span_info) in self.0.iter() {
            builder = builder.histogram(
                &[("span", span_name)],
                span_info.iter_buckets(),
                span_info.sum as f64,
            )?
        }
        Ok(())
    }
}

impl ProfilerSink for &mut SpanStats {
    fn record(self, span: SpanName, instructions: u64) {
        let span_info = self.0.entry(span).or_default();
        update_histogram(&mut span_info.histogram, instructions);
        span_info.sum += instructions as u128;
        span_info.max = span_info.max.max(instructions);
        span_info.num_samples += 1;
    }
}

fn update_histogram(histogram: &mut Histogram, sample: u64) {
    for (i, v) in histogram.iter_mut().enumerate() {
        if BUCKETS[i] >= sample {
            *v += 1;
            break;
        }
    }
}
