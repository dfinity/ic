//! Iterator helpers.

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
pub fn left_outer_join<'l, 'r, L, R, K, LV, RV>(left: L, right: R) -> LeftOuterJoin<L, R, K, LV, RV>
where
    L: Iterator<Item = (K, LV)>,
    R: Iterator<Item = (K, RV)>,
    K: Ord + 'l + 'r,
    LV: 'l,
    RV: 'r,
{
    let mut right_iter = right;
    let right_peek = right_iter.next();
    LeftOuterJoin {
        left,
        right: right_iter,
        right_peek,
    }
}

/// Iterator produced by `left_outer_join`.
pub struct LeftOuterJoin<L, R, K, LV, RV>
where
    L: Iterator<Item = (K, LV)>,
    R: Iterator<Item = (K, RV)>,
    K: Ord,
{
    left: L,
    right: R,
    right_peek: Option<(K, RV)>,
}

impl<L, R, K, LV, RV> Iterator for LeftOuterJoin<L, R, K, LV, RV>
where
    L: Iterator<Item = (K, LV)>,
    R: Iterator<Item = (K, RV)>,
    K: Ord,
{
    type Item = (K, LV, Option<RV>);

    fn next(&mut self) -> Option<Self::Item> {
        let (left_key, left_value) = self.left.next()?;

        loop {
            let right_cmp = self
                .right_peek
                .as_ref()
                .map(|(right_key, _)| right_key.cmp(&left_key));

            match right_cmp {
                None => {
                    return Some((left_key, left_value, None));
                }
                Some(Ordering::Less) => {
                    self.right_peek = self.right.next();
                    continue;
                }
                Some(Ordering::Equal) => {
                    let (_, right_value) = self
                        .right_peek
                        .take()
                        .expect("right_peek must be Some when Ordering::Equal");
                    self.right_peek = self.right.next();
                    return Some((left_key, left_value, Some(right_value)));
                }
                Some(Ordering::Greater) => {
                    return Some((left_key, left_value, None));
                }
            }
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
