use crate::archive::ArchivingStats;

/// Bucket boundaries for the archiving duration histograms (seconds).
/// Used for both total archiving duration and per-chunk duration.
pub const ARCHIVING_DURATION_BUCKETS: [f64; 8] = [0.1, 0.2, 0.5, 1.0, 2.0, 5.0, 10.0, 20.0];

/// Bucket boundaries for the archiving chunks-per-operation histogram.
pub const ARCHIVING_CHUNKS_BUCKETS: [f64; 4] = [1.0, 2.0, 5.0, 10.0];

const NANOS_PER_SECOND: f64 = 1_000_000_000.0;

/// A simple histogram for collecting metric observations into predefined buckets.
#[derive(Debug, Clone)]
pub struct HistogramData<const N: usize> {
    /// Upper bounds for each bucket
    bucket_upper_bounds: &'static [f64; N],
    /// Cumulative count of observations in each bucket
    counts: [u64; N],
    /// Sum of all observations
    sum: f64,
    /// Total count of observations
    count: u64,
}

impl<const N: usize> HistogramData<N> {
    pub const fn new(bucket_upper_bounds: &'static [f64; N]) -> Self {
        let mut i = 1;
        while i < N {
            assert!(
                bucket_upper_bounds[i - 1] < bucket_upper_bounds[i],
                "HistogramData bucket upper bounds must be strictly ascending"
            );
            i += 1;
        }
        Self {
            bucket_upper_bounds,
            counts: [0; N],
            sum: 0.0,
            count: 0,
        }
    }

    /// Record an observation in the histogram.
    pub fn observe(&mut self, value: f64) {
        self.sum += value;
        self.count += 1;
        for (i, &bound) in self.bucket_upper_bounds.iter().enumerate() {
            if value <= bound {
                self.counts[i] += 1;
            }
        }
    }

    /// Get the buckets and their cumulative counts.
    pub fn buckets(&self) -> impl Iterator<Item = (f64, u64)> + '_ {
        self.bucket_upper_bounds
            .iter()
            .copied()
            .zip(self.counts.iter().copied())
    }

    /// Get the sum of all observations.
    pub fn sum(&self) -> f64 {
        self.sum
    }

    /// Get the total count of observations.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// Returns per-bucket (non-cumulative) counts with an additional `+Inf` bucket,
    /// suitable for passing directly to `ic_metrics_encoder::MetricsEncoder::encode_histogram`.
    pub fn per_bucket_counts(&self) -> Vec<(f64, f64)> {
        let mut result = Vec::with_capacity(N + 1);
        let mut prev_cumulative = 0_u64;
        for (le, cumulative) in self.buckets() {
            let per_bucket = cumulative.saturating_sub(prev_cumulative);
            result.push((le, per_bucket as f64));
            prev_cumulative = cumulative;
        }
        let inf_bucket_count = self.count.saturating_sub(prev_cumulative);
        result.push((f64::INFINITY, inf_bucket_count as f64));
        result
    }
}

/// Records an `ArchivingStats` observation into the three archiving histograms.
/// Duration values are converted from nanoseconds to seconds.
pub fn record_archiving_stats_into(
    stats: &ArchivingStats,
    total_duration: &mut HistogramData<8>,
    per_chunk_duration: &mut HistogramData<8>,
    num_chunks: &mut HistogramData<4>,
) {
    total_duration.observe(stats.duration_nanos as f64 / NANOS_PER_SECOND);
    for chunk_duration in &stats.chunk_durations_nanos {
        per_chunk_duration.observe(*chunk_duration as f64 / NANOS_PER_SECOND);
    }
    num_chunks.observe(stats.num_chunks as f64);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "bucket upper bounds must be strictly ascending")]
    fn unsorted_bucket_bounds_panic() {
        static BAD: [f64; 3] = [1.0, 3.0, 2.0];
        let _ = HistogramData::new(&BAD);
    }

    #[test]
    #[should_panic(expected = "bucket upper bounds must be strictly ascending")]
    fn duplicate_bucket_bounds_panic() {
        static BAD: [f64; 3] = [1.0, 2.0, 2.0];
        let _ = HistogramData::new(&BAD);
    }
}
