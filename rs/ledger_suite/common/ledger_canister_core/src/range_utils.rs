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
/// If the intersection is empty, `NoIntersection` is returned.
pub fn intersect(l: &Range<u64>, r: &Range<u64>) -> Result<Range<u64>, NoIntersection> {
    if l.is_empty() || r.is_empty() {
        return Err(NoIntersection);
    }
    if l.end < r.start || r.end < l.start {
        return Err(NoIntersection);
    }
    let candidate = Range {
        start: l.start.max(r.start),
        end: l.end.min(r.end),
    };
    match candidate.is_empty() {
        true => Err(NoIntersection),
        false => Ok(candidate),
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
pub fn take(r: &Range<u64>, n: usize) -> Range<u64> {
    Range {
        start: r.start,
        end: r.end.min(r.start.saturating_add(n as u64)),
    }
}

/// Constructs an interval by dropping at most `n` first elements of range `r`.
pub fn skip(r: &Range<u64>, n: usize) -> Range<u64> {
    Range {
        start: r.end.min(r.start.saturating_add(n as u64)),
        end: r.end,
    }
}

/// Constructs an interval by removing at most `n` last elements of range `r`.
pub fn drop_last(r: &Range<u64>, n: usize) -> Range<u64> {
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

/// Converts the specified range into a range of indices relative to the specified offset.
pub fn offset(r: &Range<u64>, offset: u64) -> Range<u64> {
    debug_assert!(offset <= r.start);
    let start = r.start.saturating_sub(offset);
    let end = start + range_len(r);
    Range { start, end }
}

/// Removes the intersection of two ranges from the first range.
/// If the resulting range would be two disjoint ranges (i.e., if the
/// `possibly_partially_intersecting_range` is in the middle of the `input_range`), return the
/// first of the resulting disjoint ranges.
pub fn remove_intersection(
    input_range: &Range<u64>,
    possibly_partially_intersecting_range: &Range<u64>,
) -> Range<u64> {
    let intersection = intersect(input_range, possibly_partially_intersecting_range);
    match intersection {
        Ok(intersection) => {
            if input_range.start < intersection.start {
                Range {
                    start: input_range.start,
                    end: intersection.start,
                }
            } else if input_range.end > intersection.end {
                Range {
                    start: intersection.end,
                    end: input_range.end,
                }
            } else {
                Range { start: 0, end: 0 }
            }
        }
        Err(NoIntersection) => input_range.clone(),
    }
}

/// Checks if any of the provided ranges intersect.
pub fn contains_intersections(ranges: &[Range<u64>]) -> bool {
    for i in 0..ranges.len() {
        if !ranges[i].is_empty() {
            for j in i + 1..ranges.len() {
                if !ranges[j].is_empty() && intersect(&ranges[i], &ranges[j]).is_ok() {
                    return true;
                }
            }
        }
    }
    false
}

#[test]
fn test_intersect() {
    // Two ranges that do not intersect.
    let input_range = Range { start: 0, end: 10 };
    let other_range = Range { start: 20, end: 30 };
    assert_eq!(intersect(&input_range, &other_range), Err(NoIntersection));

    // Two ranges that intersect.
    let input_range = Range { start: 0, end: 10 };
    let other_range = Range { start: 5, end: 15 };
    assert_eq!(
        intersect(&input_range, &other_range),
        Ok(Range { start: 5, end: 10 })
    );

    // Two adjacent ranges.
    let input_range = Range { start: 0, end: 10 };
    let other_range = Range { start: 10, end: 20 };
    assert_eq!(intersect(&input_range, &other_range), Err(NoIntersection));

    // Two ranges that are equal.
    let input_range = Range { start: 0, end: 10 };
    let other_range = Range { start: 0, end: 10 };
    assert_eq!(
        intersect(&input_range, &other_range),
        Ok(Range { start: 0, end: 10 })
    );

    // Two empty ranges.
    let input_range = Range { start: 0, end: 0 };
    let other_range = Range { start: 0, end: 0 };
    assert_eq!(intersect(&input_range, &other_range), Err(NoIntersection));
}

#[test]
fn test_remove_intersection() {
    // Two ranges that do not intersect.
    let input_range = Range { start: 0, end: 10 };
    let other_range = Range { start: 20, end: 30 };
    assert_eq!(remove_intersection(&input_range, &other_range), input_range);

    // Two ranges that intersect, with the input range being "lower".
    let input_range = Range { start: 0, end: 10 };
    let other_range = Range { start: 5, end: 15 };
    assert_eq!(
        remove_intersection(&input_range, &other_range),
        Range { start: 0, end: 5 }
    );

    // Two ranges that intersect, with the input range being "higher".
    let input_range = Range { start: 5, end: 15 };
    let other_range = Range { start: 0, end: 10 };
    assert_eq!(
        remove_intersection(&input_range, &other_range),
        Range { start: 10, end: 15 }
    );

    // Two ranges that intersect, with the other range being a subrange inside the input range.
    let input_range = Range { start: 0, end: 10 };
    let other_range = Range { start: 2, end: 5 };
    assert_eq!(
        remove_intersection(&input_range, &other_range),
        Range { start: 0, end: 2 }
    );

    // Two ranges that are equal.
    let input_range = Range { start: 0, end: 10 };
    let other_range = Range { start: 0, end: 10 };
    assert_eq!(
        remove_intersection(&input_range, &other_range),
        Range { start: 0, end: 0 }
    );

    // Two empty ranges.
    let input_range = Range { start: 0, end: 0 };
    let other_range = Range { start: 0, end: 0 };
    assert_eq!(remove_intersection(&input_range, &other_range), input_range);

    // Two empty ranges with start not at 0.
    let input_range = Range { start: 5, end: 5 };
    let other_range = Range { start: 5, end: 5 };
    assert_eq!(remove_intersection(&input_range, &other_range), input_range);

    // Empty input range.
    let input_range = Range { start: 0, end: 0 };
    let other_range = Range { start: 0, end: 10 };
    assert_eq!(remove_intersection(&input_range, &other_range), input_range);
}
