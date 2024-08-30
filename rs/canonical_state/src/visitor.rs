//! Utilities for traversing the Replicated State as if it was a state in
//! canonical form.

/// Data structure controlling the traversal of the state tree.
#[derive(Debug, PartialEq, Eq)]
pub enum Control {
    /// Continue descending into the state tree.
    Continue,
    /// Skip the subtree this edge point to.
    Skip,
}

/// `Visitor` can compute a value on a canonical state tree without
/// using an explicit intermediate representation of the tree.
///
/// NOTE: once visitor returns a value, the traversal is considered complete.
///
/// # Example:
///
/// Assume we want to traverse the following tree:
///
/// ```text
/// *
/// |
/// +-- blobmap --+-- 0 -- [ 0xCAFEBABE ]
/// |             |
/// |             +-- 1 -- [ 0xDEADBEAF ]
/// |
/// +--   num   --+-- min -- [ 5 ]
///               |
///               +-- max -- [ 10 ]
/// ```
///
/// The traversal will produce the following trace (assuming all the calls
/// return `Ok`):
///
/// ```text
/// visitor.start_subtree(); // root
///
///   visitor.enter_edge(b"blobmap");
///   visitor.start_subtree();
///
///     visitor.enter_edge(b"0");
///     visitor.visit_blob(&[0xCA, 0xFE, 0xBA, 0xBE]);
///
///     visitor.enter_edge(b"1");
///     visitor.visit_blob(&[0xDE, 0xAD, 0xBE, 0xEF]);
///
///   visitor.end_subtree(); // "blobmap"
///
///   visitor.enter_edge(b"num");
///   visitor.start_subtree();
///
///     visitor.enter_edge(b"min");
///     visitor.visit_num(5);
///
///     visitor.enter_edge(b"max");
///     visitor.visit_num(10);
///
///   visitor.end_subtree(); // "num"
///
/// visitor.end_subtree(); // root
///
/// visitor.finish();
/// ```
pub trait Visitor {
    /// If the traversal succeeds, it produces a value of this type.
    type Output;

    /// Start a subtree traversal.
    fn start_subtree(&mut self) -> Result<(), Self::Output>;

    /// Complete the subtree traversal.
    fn end_subtree(&mut self) -> Result<(), Self::Output>;

    /// Descend into the subtree along the edge labeled with `label`.
    ///
    /// The visitor has a way to skip the subtree by returning
    /// `Ok(Control::Skip)`.  If that happens, none of the subtree traversal
    /// methods (`(start|end)_subtree`, `visit_(num|blob)`) will be invoked on
    /// this visitor.
    ///
    /// For example, assume that the visitor always returns `Ok(Control::Skip)`
    /// from this method.  This is how the trace for the example tree above will
    /// look like:
    ///
    /// ```text
    /// visitor.start_subtree();
    ///   visitor.enter_edge(b"blobmap"); // => Ok(Control::Skip)
    ///   visitor.enter_edge(b"num");     // => Ok(Control::Skip)
    /// visitor.end_subtree();
    /// ```
    fn enter_edge(&mut self, label: &[u8]) -> Result<Control, Self::Output>;

    /// Visit a leaf of the state tree that contains a number.
    fn visit_num(&mut self, num: u64) -> Result<(), Self::Output>;

    /// Visit a leaf of the state tree that contains a `blob`.
    fn visit_blob(&mut self, blob: &[u8]) -> Result<(), Self::Output>;

    /// Complete the tree traversal.
    ///
    /// This method is supposed to be called once the tree traversal is complete
    /// but the visitor haven't returned any value yet.
    fn finish(self) -> Self::Output;
}

/// Executes a function in the scope of a new subtree.
pub fn subtree<V: Visitor>(
    v: &mut V,
    f: impl FnOnce(&mut V) -> Result<(), V::Output>,
) -> Result<(), V::Output> {
    v.start_subtree()?;
    f(v)?;
    v.end_subtree()
}

/// Enter edge labeled as `name` and execute `f` if it was not skipped.
pub fn with_edge<V: Visitor, Name: AsRef<[u8]>>(
    v: &mut V,
    name: Name,
    f: impl FnOnce(&mut V) -> Result<(), V::Output>,
) -> Result<(), V::Output> {
    match v.enter_edge(name.as_ref())? {
        Control::Continue => f(v),
        Control::Skip => Ok(()),
    }
}

/// Executes a function in a scope of a new subtree after entering edge with the
/// given name.
///
/// The precise sequence is:
///   1. Enter an edge labeled as `name` on the visitor `v`.
///      If the visitor returns `Ok(Control::Skip)`, do nothing else.
///   2. Start a subtree.
///   3. Execute `f` on `v`.
///   3. Exit the subtree.
pub fn named_subtree<V: Visitor, Name: AsRef<[u8]>>(
    v: &mut V,
    name: Name,
    f: impl FnOnce(&mut V) -> Result<(), V::Output>,
) -> Result<(), V::Output> {
    with_edge(v, name, |v| subtree(v, f))
}

/// Visits the `blob` after entering edge with the given name.
pub fn named_blob<V: Visitor, Name: AsRef<[u8]>, Blob: AsRef<[u8]>>(
    v: &mut V,
    name: Name,
    blob: Blob,
) -> Result<(), V::Output> {
    with_edge(v, name, |v| v.visit_blob(blob.as_ref()))
}

/// Visits the `num` after entering edge with the given name.
pub fn named_num<V: Visitor, Name: AsRef<[u8]>>(
    v: &mut V,
    name: Name,
    num: u64,
) -> Result<(), V::Output> {
    with_edge(v, name, |v| v.visit_num(num))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_visitors::{PathError, PathVisitor, TraceEntry, TracingVisitor, Value};
    use TraceEntry::{EndSubtree, StartSubtree};

    fn enter<Name: AsRef<[u8]>>(name: Name) -> TraceEntry {
        TraceEntry::EnterEdge(name.as_ref().to_vec())
    }

    // Sample tree traversal:
    //
    // *
    // |
    // +- blobmap
    // |  +- 0 → [0xcafebabe]
    // |  `- 1 → [0xdeadbeef]
    // `- num
    //    +- from → 5
    //    `- to   → 10
    fn traverse_sample_tree<V: Visitor>(mut v: V) -> V::Output {
        let blobmap = [&[0xca, 0xfe, 0xba, 0xbe], &[0xde, 0xad, 0xbe, 0xef]];

        let t = subtree(&mut v, |v| {
            named_subtree(v, "blobmap", |v| {
                for (i, b) in blobmap.iter().enumerate() {
                    named_blob(v, i.to_string(), &b[..])?;
                }
                Ok(())
            })?;

            named_subtree(v, "num", |v| {
                named_num(v, "from", 5)?;
                named_num(v, "to", 10)
            })
        });

        match t {
            Err(output) => output,
            _ => v.finish(),
        }
    }

    #[test]
    fn find_value() {
        use TraceEntry::*;

        let visitor = TracingVisitor::new(PathVisitor::for_path(vec![
            b"num".to_vec(),
            b"from".to_vec(),
        ]));

        assert_eq!(
            traverse_sample_tree(visitor),
            (
                vec![
                    StartSubtree,
                    enter("blobmap"),
                    enter("num"),
                    StartSubtree,
                    enter("from"),
                    VisitNum(5)
                ],
                Ok(Value::Num(5))
            )
        );
    }

    #[test]
    fn not_found() {
        let visitor = TracingVisitor::new(PathVisitor::for_path(vec![
            b"blobmap".to_vec(),
            b"3".to_vec(),
        ]));

        assert_eq!(
            traverse_sample_tree(visitor),
            (
                vec![
                    StartSubtree,
                    enter("blobmap"),
                    StartSubtree,
                    enter("0"),
                    enter("1"),
                    EndSubtree,
                ],
                Err(PathError::NotFound)
            )
        );
    }
}
