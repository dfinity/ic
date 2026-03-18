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
}
