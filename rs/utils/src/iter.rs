//! Iterator helpers.

use std::borrow::Borrow;
use std::cmp::Ordering;

/// Performs a left outer join of two key-value iterators.
///
/// The inputs must be ordered by key in non-decreasing order, and keys should
/// be unique within each input. The join is streaming and does not allocate.
///
/// # Examples
///
/// ```
/// use ic_utils::iter::left_outer_join;
/// use std::collections::BTreeMap;
///
/// let left = BTreeMap::from([(1_u32, "a"), (2, "b"), (4, "d")]);
/// let right = BTreeMap::from([(1_u32, "A"), (3, "C"), (4, "D")]);
///
/// let joined: Vec<_> = left_outer_join(left.iter(), right.iter()).collect();
/// assert_eq!(
///     joined,
///     vec![
///         (&1, &"a", Some(&"A")),
///         (&2, &"b", None),
///         (&4, &"d", Some(&"D"))
///     ]
/// );
/// ```
pub fn left_outer_join<'l, 'r, L, R, K, LV, RK, RV>(
    left: L,
    mut right: R,
) -> LeftOuterJoin<L, R, K, LV, RK, RV>
where
    L: Iterator<Item = (K, LV)>,
    R: Iterator<Item = (RK, RV)>,
    K: Ord + 'l + 'r,
    LV: 'l,
    RK: Borrow<K>,
    RV: 'r,
{
    let right_peek = right.next();
    LeftOuterJoin {
        left,
        right,
        right_peek,
    }
}

/// Iterator produced by `left_outer_join`.
pub struct LeftOuterJoin<L, R, K, LV, RK, RV>
where
    L: Iterator<Item = (K, LV)>,
    R: Iterator<Item = (RK, RV)>,
    K: Ord,
    RK: Borrow<K>,
{
    left: L,
    right: R,
    /// The next right entry, peeked. `Some` while the right side is still active
    /// ("joining"); `None` once the right side is drained. `next` dispatches on
    /// this.
    right_peek: Option<(RK, RV)>,
}

impl<L, R, K, LV, RK, RV> LeftOuterJoin<L, R, K, LV, RK, RV>
where
    L: Iterator<Item = (K, LV)>,
    R: Iterator<Item = (RK, RV)>,
    K: Ord,
    RK: Borrow<K>,
{
    /// Behavior while the right side is active: matches the next left entry against
    /// the peeked right entry. Only ever called while `right_peek` is `Some`.
    #[inline]
    fn next_joining(&mut self) -> Option<(K, LV, Option<RV>)> {
        let (left_key, left_value) = self.left.next()?;

        loop {
            let (right_key, right_value) = self.right_peek.take().unwrap();

            match right_key.borrow().cmp(&left_key) {
                // This right entry precedes the left key, so it has no match; skip past
                // it and re-compare, or drain the right side if it was the last one.
                Ordering::Less => {
                    self.right_peek = self.right.next();
                    if self.right_peek.is_none() {
                        return Some((left_key, left_value, None));
                    }
                }

                // Match: emit the paired value and advance the right side.
                Ordering::Equal => {
                    self.right_peek = self.right.next();
                    return Some((left_key, left_value, Some(right_value)));
                }

                // No right entry for this left key; restore the peeked right entry
                // (it may match a later left key) and emit the left entry unmatched.
                Ordering::Greater => {
                    self.right_peek = Some((right_key, right_value));
                    return Some((left_key, left_value, None));
                }
            }
        }
    }

    /// Behavior once the right side is drained (`right_peek` is `None`): every
    /// remaining left entry simply pairs with `None`.
    #[inline]
    fn next_drained(&mut self) -> Option<(K, LV, Option<RV>)> {
        self.left
            .next()
            .map(|(left_key, left_value)| (left_key, left_value, None))
    }
}

impl<L, R, K, LV, RK, RV> Iterator for LeftOuterJoin<L, R, K, LV, RK, RV>
where
    L: Iterator<Item = (K, LV)>,
    R: Iterator<Item = (RK, RV)>,
    K: Ord,
    RK: Borrow<K>,
{
    type Item = (K, LV, Option<RV>);

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        // Split into a "joining" and a "drained" behavior.
        if self.right_peek.is_some() {
            self.next_joining()
        } else {
            self.next_drained()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::left_outer_join;

    #[test]
    fn left_outer_join_matches_and_skips() {
        let left = BTreeMap::from([(1_u32, "a"), (2, "b"), (4, "d")]);
        let right = BTreeMap::from([(1_u32, "A"), (3, "C"), (4, "D")]);

        let joined: Vec<_> = left_outer_join(left.iter(), right.iter()).collect();

        assert_eq!(
            joined,
            vec![
                (&1, &"a", Some(&"A")),
                (&2, &"b", None),
                (&4, &"d", Some(&"D"))
            ]
        );
    }

    #[test]
    fn left_outer_join_shifted_left() {
        let left = BTreeMap::from([(2_u32, "b"), (3, "c"), (4, "d")]);
        let right = BTreeMap::from([(1_u32, "A"), (2, "B"), (3, "C")]);

        let joined: Vec<_> = left_outer_join(left.iter(), right.iter()).collect();

        assert_eq!(
            joined,
            vec![
                (&2, &"b", Some(&"B")),
                (&3, &"c", Some(&"C")),
                (&4, &"d", None)
            ]
        );
    }

    #[test]
    fn left_outer_join_shifted_right() {
        let left = BTreeMap::from([(1_u32, "A"), (2, "B"), (3, "C")]);
        let right = BTreeMap::from([(2_u32, "b"), (3, "c"), (4, "d")]);

        let joined: Vec<_> = left_outer_join(left.iter(), right.iter()).collect();

        assert_eq!(
            joined,
            vec![
                (&1, &"A", None),
                (&2, &"B", Some(&"b")),
                (&3, &"C", Some(&"c"))
            ]
        );
    }
}
