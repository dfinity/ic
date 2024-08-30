//! Canonical State [`Visitor`] that limits the byte size of blob leaves.
//!
//! Used for extracting stream slices of limited size for XNet Endpoint.

use crate::visitor::{Control, Visitor};

#[cfg(test)]
mod tests;

/// Simple label matcher: either any label matches; or only equal labels.
#[derive(PartialEq, Eq, Debug, Clone)]
pub enum Matcher {
    /// Match any label.
    Any,
    /// Match a specific label.
    Label(Vec<u8>),
}

impl Matcher {
    /// Tests whether a label matches this `Matcher`.
    fn matches(&self, label: &[u8]) -> bool {
        match self {
            Matcher::Any => true,
            Matcher::Label(expected) => expected.as_slice() == label,
        }
    }
}

/// Visitor that limits the byte size of blob leaves matching a given pattern by
/// skipping all leaves after at least one leaf was visited and the size limit
/// has been reached.
///
/// Skips whole leaves (label and value), by caching the label and invoking the
/// wrapped visitor on both iff the inclusion of the blob size would not exceed
/// the size limit.
///
/// # Panics
///
/// Because of the constraint above, only leaves may match the pattern. The
/// visitor will panic if it encounters a subtree under a matching node.
pub struct SizeLimitVisitor<V> {
    /// Leaves matching this pattern will be size limited.
    pattern: Vec<Matcher>,
    /// Size limit beyond which matching leaves will all be skipped.
    size_limit: usize,
    /// Wrapped visitor.
    visitor: V,

    /// Stack recording whether the visited path (partially) matches `pattern`.
    path_match: Vec<bool>,
    /// Accumulator of visited leaf sizes.
    size: usize,
    /// If set, one matching node must be included when present, even if
    /// `size_limit` is exceeded.
    include_one: bool,

    /// Label of most recently visited matching node.
    leaf_label: Option<Vec<u8>>,
}

impl<V> SizeLimitVisitor<V>
where
    V: Visitor,
{
    pub fn new(pattern: Vec<Matcher>, size_limit: usize, visitor: V) -> Self {
        assert!(!pattern.is_empty());

        Self {
            pattern,
            size_limit,
            visitor,

            path_match: vec![],
            size: 0,
            include_one: true,

            leaf_label: None,
        }
    }

    /// Tests whether the current node matches (a prefix of) `self.pattern`.
    fn is_partial_match(&self) -> bool {
        *self.path_match.last().unwrap_or(&true)
    }

    /// Tests whether the current node is a full match for `self.pattern`.
    fn is_full_match(&self) -> bool {
        self.path_match.len() == self.pattern.len() && self.is_partial_match()
    }
}

impl<V> Visitor for SizeLimitVisitor<V>
where
    V: Visitor,
{
    type Output = V::Output;

    fn start_subtree(&mut self) -> Result<(), V::Output> {
        assert!(
            !self.is_full_match(),
            "only expected leaves matching {:?}, found subtree",
            self.pattern
        );

        self.path_match.push(false);
        self.visitor.start_subtree()
    }

    fn enter_edge(&mut self, label: &[u8]) -> Result<Control, V::Output> {
        self.path_match
            .pop()
            .unwrap_or_else(|| panic!("edge outside subtree: {:?}", label));

        self.path_match.push(if self.is_partial_match() {
            let matcher = self.pattern.get(self.path_match.len()).unwrap();
            matcher.matches(label)
        } else {
            // If parent is not a (partial) match: node cannot be a (partial) match.
            false
        });

        if self.is_full_match() {
            if !self.include_one && self.size >= self.size_limit {
                // Size limit reached, skip.
                return Ok(Control::Skip);
            }

            self.leaf_label = Some(label.to_vec());
            return Ok(Control::Continue);
        }

        self.visitor.enter_edge(label)
    }

    fn end_subtree(&mut self) -> Result<(), V::Output> {
        self.path_match.pop().expect("unbalanced subtree end");
        self.leaf_label = None;
        self.visitor.end_subtree()
    }

    fn visit_blob(&mut self, blob: &[u8]) -> Result<(), V::Output> {
        if let Some(label) = self.leaf_label.take() {
            // Matching leaf.
            let value_size = blob.len();

            // We must assume the visitor will return `Ok(Continue)` from `enter_edge()`.
            self.size += value_size;
            if !self.include_one && self.size > self.size_limit {
                return Ok(());
            }

            let result = self.visitor.enter_edge(&label)?;
            if let Control::Skip = result {
                // Leaf is being skipped, deduct its size.
                self.size -= value_size;
                return Ok(());
            }

            // At least one node was included.
            self.include_one = false;
        }
        self.visitor.visit_blob(blob)
    }

    fn visit_num(&mut self, num: u64) -> Result<(), V::Output> {
        self.visitor.visit_num(num)
    }

    fn finish(self) -> V::Output {
        self.visitor.finish()
    }
}
