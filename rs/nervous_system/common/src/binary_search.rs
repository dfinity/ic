use std::ops::{Add, Div, Sub};

pub trait Mid: Sized {
    /// Returns the value halfway between `self` and `other`, rounded to -infinity.
    /// If there are no value between `l` and `r`, returns `None`.
    fn mid(&self, other: &Self) -> Option<Self>;
}

impl<T> Mid for T
where
    T: Add<Output = T> + Sub<Output = T> + Div<Output = T> + Ord + Copy + From<u8>,
{
    fn mid(&self, other: &Self) -> Option<Self> {
        let (small, large) = if self <= other {
            (self, other)
        } else {
            (other, self)
        };
        let difference = *large - *small;
        let two = T::from(2u8);

        let mid = *small + (difference / two);
        if mid == *small || mid == *large {
            None
        } else {
            Some(mid)
        }
    }
}

/// Performs a binary search to find a pair of values `(l, r)` that bracket the
/// point where a predicate `p` switches from `False` to `True`. Specifically,
/// `p(l)` will be `False` and `p(r)` will be `True`.
///
/// The function takes a range and a predicate.
/// Preconditions:
/// * It requires that the predicate is "monotonic". That is, if the predicate
///   returns true for some value `x`, it must return true for any value
///   `y` if `y >= x`.
/// * The range must be ascending (i.e. l < r). It is actually OK to reverse
///   the order, but then the predicate must be monotonic in the opposite
///   direction (i.e. once it returns false for `x` it must return false for any
///   value `y` if `y >= x`)
///
/// Returns:
/// - If the predicate is not monotonic, the function may return an incorrect
///   result, or return `(None, None)`.
/// - If the predicate is monotonic and switches from false to true within the
///   input range, the function will return `Some((l, r))` where l is the
///   highest value where the predicate is false and r is the lowest value where
///   the predicate is true.
/// - If the predicate is monotonic and always true, the function will return
///   `(None, Some(l))` where `l` is the bottom of the range.
/// - If the predicate is monotonic and always false, the function will return
///   `(Some(r), None)` where `r` is the top of the range.
pub fn search<T: Mid, G>(predicate: G, l: T, r: T) -> (Option<T>, Option<T>)
where
    G: Fn(&T) -> bool,
{
    let p = move |x: &T| Ok::<bool, ()>(predicate(x));
    search_with_fallible_predicate(p, l, r).unwrap() // can never fail because p is infallible
}

/// Like `search`, but takes a predicate that returns a Result. If the predicate
/// and returns an error while performing the binary search, this function returns
/// an error.
pub fn search_with_fallible_predicate<T: Mid, G, E>(
    predicate: G,
    mut l: T,
    mut r: T,
) -> Result<(Option<T>, Option<T>), E>
where
    G: Fn(&T) -> Result<bool, E>,
{
    match (predicate(&l)?, predicate(&r)?) {
        (false, true) => {}
        // Check if the predicate is "always true" or "always false" and return
        // early if so.
        (true, true) => return Ok((None, Some(l))),
        (false, false) => return Ok((Some(r), None)),
        // Sanity check that will detect some non-monotonic functions. This is a
        // precondition violation, so we return (None, None).
        (true, false) => return Ok((None, None)),
    }
    loop {
        // Sanity check: f must be false for l and true for r, otherwise
        // the input function was not monotonic
        if predicate(&l)? {
            return Ok((None, None));
        }
        if !predicate(&r)? {
            return Ok((None, None));
        }

        match l.mid(&r) {
            None => return Ok((Some(l), Some(r))),
            Some(m) => {
                if predicate(&m)? {
                    r = m;
                } else {
                    l = m;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_midpoint() {
        assert_eq!(10.mid(&20), Some(15));
        assert_eq!(20.mid(&10), Some(15));
        assert_eq!(0.mid(&20), Some(10));
        assert_eq!(20.mid(&00), Some(10));
        assert_eq!((u64::MAX - 2).mid(&u64::MAX), Some(u64::MAX - 1));
    }

    #[test]
    fn test_midpoint_rounding() {
        assert_eq!(10.mid(&13), Some(11));
        assert_eq!(13.mid(&10), Some(11));
        assert_eq!(10.mid(&12), Some(11));
        assert_eq!(12.mid(&10), Some(11));
    }

    #[test]
    fn test_midpoint_no_mid() {
        assert_eq!(0.mid(&0), None);
        assert_eq!(10.mid(&11), None);
        assert_eq!(11.mid(&10), None);
        assert_eq!(10.mid(&10), None);
        assert_eq!(u64::MAX.mid(&u64::MAX), None);
    }

    #[test]
    fn test_search_basic() {
        let predicate = |x: &u64| *x >= 5;

        let result = search(predicate, 0, u64::MAX);
        assert_eq!(result, (Some(4), Some(5)));
    }

    #[test]
    fn test_search_invalid_initial_conditions() {
        let predicate = |x: &u64| *x >= 5;

        let result = search(predicate, 6, 10);
        assert_eq!(result, (None, Some(6)));

        let result = search(predicate, 0, 4);
        assert_eq!(result, (Some(4), None));
    }

    #[test]
    fn test_search_cube_root_of_512() {
        let predicate = |x: &u64| x.pow(3) >= 512;

        let result = search(predicate, 0, 20);
        assert_eq!(result, (Some(7), Some(8)));
    }

    proptest! {
        #[test]
        fn test_search_properties(start in 0u64..50_000_000, pivot in 0u64..100_000_000, end in 50_000_001u64..100_000_000) {
            let predicate = |x: &u64| *x >= pivot;
            let (highest_false, lowest_true) = search(predicate, start, end);

            prop_assert!(highest_false.is_some() || lowest_true.is_some());

            // Verify that search returned some result
            if highest_false.is_none() {
                prop_assert!(predicate(&start));
            }
            if lowest_true.is_none() {
                prop_assert!(!predicate(&end));
            }

            if let (Some(l), Some(r)) = (highest_false, lowest_true) {
                // Check that f is false for l and true for r
                prop_assert!(!predicate(&l));
                prop_assert!(predicate(&r));

                // Ensure that l and r are in ascending order
                prop_assert!(l < r);

                // Validate the monotonicity of the predicate
                prop_assert!(predicate(&(l + 1)));
            }
        }
    }
}
