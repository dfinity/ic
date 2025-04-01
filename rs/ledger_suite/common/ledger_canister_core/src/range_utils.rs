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

/// An error indicating that an intersection of two intervals is not a
/// well-formed interval.
#[derive(Eq, PartialEq, Debug)]
pub struct NoIntersection;

/// Constructs an intersection of two ranges.
pub fn intersect(l: &Range<u64>, r: &Range<u64>) -> Result<Range<u64>, NoIntersection> {
    if l.end < r.start || r.end < l.start {
        return Err(NoIntersection);
    }
    Ok(Range {
        start: l.start.max(r.start),
        end: l.end.min(r.end),
    })
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
pub fn take(r: &Range<u64>, n: usize) -> Range<u64> {
    Range {
        start: r.start,
        end: r.end.min(r.start.saturating_add(n as u64)),
    }
}
