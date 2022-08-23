use std::ops::Range;

/// Constructs a range starting at `start` and spanning `len` integers.
/// If `start` + `len` overflows u64, the len is truncated to the largest value that doesn't overflow
/// u64.
pub fn make_range(start: u64, len: usize) -> Range<u64> {
    Range {
        start,
        end: start.saturating_add(len as u64),
    }
}

/// Constructs an intersection of two ranges.
pub fn intersect(l: &Range<u64>, r: &Range<u64>) -> Range<u64> {
    Range {
        start: l.start.max(r.start),
        end: l.end.min(r.end),
    }
}

/// Returns true iff `r` contains each point of `l`.
pub fn is_subrange(l: &Range<u64>, r: &Range<u64>) -> bool {
    r.start <= l.start && l.end <= r.end
}

/// Returns the total number of elements in range `r`.
pub fn range_len(r: &Range<u64>) -> u64 {
    r.end.saturating_sub(r.start)
}

/// Returns the prefix of the range `r` that contains at most `n` elements.
pub fn head(r: &Range<u64>, n: usize) -> Range<u64> {
    Range {
        start: r.start,
        end: r.end.min(r.start.saturating_add(n as u64)),
    }
}

/// Constructs an interval by dropping at most `n` first elements of range `r`.
pub fn behead(r: &Range<u64>, n: usize) -> Range<u64> {
    Range {
        start: r.end.min(r.start.saturating_add(n as u64)),
        end: r.end,
    }
}

/// Constructs an interval by removing at most `n` last elements of range `r`.
pub fn curtail(r: &Range<u64>, n: usize) -> Range<u64> {
    Range {
        start: r.start,
        end: r.start + range_len(r).saturating_sub(n as u64),
    }
}

/// Converts the range of u64 integers into a range of array indices.
pub fn as_indices(r: &Range<u64>) -> Range<usize> {
    Range {
        start: r.start as usize,
        end: r.end as usize,
    }
}
