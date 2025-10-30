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

/// Remove any suffix of the `earlier_range` that intersects with the `later_range` by modifying
/// the `earlier_range` in place.
pub fn remove_suffix(earlier_range: &mut Range<u64>, later_range: &Range<u64>) {
    if !earlier_range.is_empty() && !later_range.is_empty() {
        debug_assert!(
            earlier_range.start <= later_range.start,
            "earlier_range: {earlier_range:?}, later_range: {later_range:?}"
        );
        earlier_range.end = earlier_range.end.min(later_range.start);
    }
}

/// Checks if any of the provided ranges intersect.
pub fn contains_intersections(ranges: &[&Range<u64>]) -> bool {
    for i in 0..ranges.len() {
        if !ranges[i].is_empty() {
            for j in i + 1..ranges.len() {
                if !ranges[j].is_empty() && intersect(ranges[i], ranges[j]).is_ok() {
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
#[should_panic(expected = "earlier_range: 5..15, later_range: 0..10")]
fn test_remove_suffix() {
    // Two ranges that do not intersect.
    let mut input_range = Range { start: 0, end: 10 };
    let other_range = Range { start: 20, end: 30 };
    remove_suffix(&mut input_range, &other_range);
    assert_eq!(input_range, Range { start: 0, end: 10 });

    // Two ranges that intersect, with the input range being "lower".
    let mut input_range = Range { start: 0, end: 10 };
    let other_range = Range { start: 5, end: 15 };
    remove_suffix(&mut input_range, &other_range);
    assert_eq!(input_range, Range { start: 0, end: 5 });

    // Two ranges that intersect, with the other range being a subrange inside the input range.
    let mut input_range = Range { start: 0, end: 10 };
    let other_range = Range { start: 2, end: 5 };
    remove_suffix(&mut input_range, &other_range);
    assert_eq!(input_range, Range { start: 0, end: 2 });

    // Two ranges that are equal.
    let mut input_range = Range { start: 0, end: 10 };
    let other_range = Range { start: 0, end: 10 };
    remove_suffix(&mut input_range, &other_range);
    assert_eq!(input_range, Range { start: 0, end: 0 });

    // Two empty ranges.
    let mut input_range = Range { start: 0, end: 0 };
    let other_range = Range { start: 0, end: 0 };
    remove_suffix(&mut input_range, &other_range);
    assert_eq!(input_range, Range { start: 0, end: 0 });

    // Two empty ranges with start not at 0.
    let mut input_range = Range { start: 5, end: 5 };
    let other_range = Range { start: 5, end: 5 };
    remove_suffix(&mut input_range, &other_range);
    assert_eq!(input_range, Range { start: 5, end: 5 });

    // Empty input range.
    let mut input_range = Range { start: 0, end: 0 };
    let other_range = Range { start: 0, end: 10 };
    remove_suffix(&mut input_range, &other_range);
    assert_eq!(input_range, Range { start: 0, end: 0 });

    // Two ranges that intersect, with the input range being "higher".
    // This should panic.
    let mut input_range = Range { start: 5, end: 15 };
    let other_range = Range { start: 0, end: 10 };
    remove_suffix(&mut input_range, &other_range);
}
