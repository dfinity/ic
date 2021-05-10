//! Canonical State [`Visitor`] that filters the nodes seen by a wrapped
//! `Visitor` to those matchng a given pattern.

use crate::visitor::{Control, Visitor};
use std::collections::BTreeMap;

/// Pattern defines a rule to filter a tree.
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct Pattern(PatternKind);

#[derive(PartialEq, Eq, Debug, Clone)]
enum PatternKind {
    // Match everything unconditionally.
    All,
    // Match any edge at this level, then apply the next pattern.
    Any(Box<PatternKind>),
    // Only match edges with labels from the map, then apply the next pattern by
    // consulting the map.
    MatchFinite(BTreeMap<Vec<u8>, PatternKind>),
    // Match edges with labels in range [l, r), then apply the next pattern.
    MatchRange(Vec<u8>, Vec<u8>, Box<PatternKind>),
}

impl Pattern {
    /// Match any subtree.
    pub fn all() -> Self {
        Pattern(PatternKind::All)
    }

    /// Discard any tree.
    pub fn none() -> Self {
        Pattern(PatternKind::MatchFinite(BTreeMap::new()))
    }

    /// Match all edges at first level and apply the pattern for the subtree
    /// they point to.
    pub fn any(p: Self) -> Self {
        Pattern(PatternKind::Any(Box::new(p.0)))
    }

    /// Create a constructor that matches a single edge with the given label and
    /// applies the pattern to the subtree this edge points to.
    pub fn match_only<L>(label: L, subpattern: Self) -> Self
    where
        L: AsRef<[u8]>,
    {
        let mut map = BTreeMap::new();
        map.insert(label.as_ref().to_vec(), subpattern.0);
        Pattern(PatternKind::MatchFinite(map))
    }

    /// Match the specified subset of edges and apply the corresponding patterns
    /// to subtrees these edges point to.
    pub fn match_any<L>(edge_patterns: impl Iterator<Item = (L, Pattern)>) -> Self
    where
        L: AsRef<[u8]>,
    {
        let entries: BTreeMap<_, _> = edge_patterns
            .map(|(l, p)| (l.as_ref().to_vec(), p.0))
            .collect();
        Pattern(PatternKind::MatchFinite(entries))
    }

    /// Match all the edges in range [from, to) and apply the `subpattern` to
    /// subtrees these edges point to.
    pub fn match_range<L1, L2>(from: L1, to: L2, subpattern: Pattern) -> Self
    where
        L1: AsRef<[u8]>,
        L2: AsRef<[u8]>,
    {
        Pattern(PatternKind::MatchRange(
            from.as_ref().to_vec(),
            to.as_ref().to_vec(),
            Box::new(subpattern.0),
        ))
    }
}

/// Visitor that applies visitor V to the subtree that matches a pattern.
pub struct SubtreeVisitor<'a, V> {
    pos: Vec<&'a PatternKind>,
    visitor: V,
}

impl<'a, V> SubtreeVisitor<'a, V> {
    pub fn new(pattern: &'a Pattern, visitor: V) -> Self {
        Self {
            pos: vec![&pattern.0],
            visitor,
        }
    }
}

impl<'a, V> Visitor for SubtreeVisitor<'a, V>
where
    V: Visitor,
{
    type Output = V::Output;

    fn start_subtree(&mut self) -> Result<(), V::Output> {
        self.visitor.start_subtree()
    }

    fn enter_edge(&mut self, name: &[u8]) -> Result<Control, V::Output> {
        let next_item = match self.pos.last().expect("unbalanced tree traversal") {
            p @ PatternKind::All => *p,
            PatternKind::Any(p) => &*p,
            PatternKind::MatchFinite(map) => match map.get(name) {
                Some(pattern) => pattern,
                None => {
                    return Ok(Control::Skip);
                }
            },
            PatternKind::MatchRange(from, to, pattern) => {
                if name < &from[..] || &to[..] <= name {
                    return Ok(Control::Skip);
                }
                &*pattern
            }
        };

        self.pos.push(next_item);

        let result = self.visitor.enter_edge(name);
        if let Ok(Control::Skip) = &result {
            self.pos.pop();
        }
        result
    }

    fn end_subtree(&mut self) -> Result<(), V::Output> {
        self.pos.pop().expect("unbalanced subtree end");
        self.visitor.end_subtree()
    }

    fn visit_blob(&mut self, blob: &[u8]) -> Result<(), V::Output> {
        self.pos.pop().expect("unbalanced edge exit");
        self.visitor.visit_blob(blob)
    }

    fn visit_num(&mut self, num: u64) -> Result<(), V::Output> {
        self.pos.pop().expect("unbalanced edge exit");
        self.visitor.visit_num(num)
    }

    fn finish(self) -> V::Output {
        self.visitor.finish()
    }
}

#[cfg(test)]
mod tests;
