use crate::visitor::{Control, Visitor};
use ic_utils::rle::DebugBlob;
use std::fmt;

/// A visitor that ignores all the inputs and produces a unit.
pub(crate) struct NoopVisitor;

impl Visitor for NoopVisitor {
    type Output = ();

    fn start_subtree(&mut self) -> Result<(), ()> {
        Ok(())
    }

    fn enter_edge(&mut self, _name: &[u8]) -> Result<Control, ()> {
        Ok(Control::Continue)
    }

    fn end_subtree(&mut self) -> Result<(), ()> {
        Ok(())
    }

    fn visit_blob(&mut self, _blob: &[u8]) -> Result<(), ()> {
        Ok(())
    }

    fn visit_num(&mut self, _num: u64) -> Result<(), ()> {
        Ok(())
    }

    fn finish(self) {}
}

/// An enum capturing a single call on visitor.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum TraceEntry {
    StartSubtree,
    EnterEdge(Vec<u8>),
    EndSubtree,
    VisitBlob(Vec<u8>),
    VisitNum(u64),
}

impl fmt::Debug for TraceEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StartSubtree => write!(f, "start"),
            Self::EnterEdge(v) => write!(f, "edge {:?}", DebugBlob(&v[..])),
            Self::EndSubtree => write!(f, "end"),
            Self::VisitBlob(v) => write!(f, "blob [{:?}]", DebugBlob(&v[..])),
            Self::VisitNum(n) => write!(f, "num {}", n),
        }
    }
}

/// A visitor that records all method invocations to the underlying
/// visitor `V` and produces the call trace.
pub(crate) struct TracingVisitor<V> {
    trace: Vec<TraceEntry>,
    nested_visitor: V,
}

impl<V> TracingVisitor<V> {
    pub fn new(nested_visitor: V) -> Self {
        Self {
            trace: Vec::new(),
            nested_visitor,
        }
    }
}

impl<V: Visitor> Visitor for TracingVisitor<V> {
    type Output = (Vec<TraceEntry>, V::Output);

    fn start_subtree(&mut self) -> Result<(), Self::Output> {
        self.trace.push(TraceEntry::StartSubtree);
        self.nested_visitor
            .start_subtree()
            .map_err(|out| (self.trace.clone(), out))
    }

    fn enter_edge(&mut self, name: &[u8]) -> Result<Control, Self::Output> {
        self.trace.push(TraceEntry::EnterEdge(name.to_vec()));
        self.nested_visitor
            .enter_edge(name)
            .map_err(|out| (self.trace.clone(), out))
    }

    fn end_subtree(&mut self) -> Result<(), Self::Output> {
        self.trace.push(TraceEntry::EndSubtree);
        self.nested_visitor
            .end_subtree()
            .map_err(|out| (self.trace.clone(), out))
    }

    fn visit_blob(&mut self, blob: &[u8]) -> Result<(), Self::Output> {
        self.trace.push(TraceEntry::VisitBlob(blob.to_vec()));
        self.nested_visitor
            .visit_blob(blob)
            .map_err(|out| (self.trace.clone(), out))
    }

    fn visit_num(&mut self, num: u64) -> Result<(), Self::Output> {
        self.trace.push(TraceEntry::VisitNum(num));
        self.nested_visitor
            .visit_num(num)
            .map_err(|out| (self.trace.clone(), out))
    }

    fn finish(self) -> Self::Output {
        (self.trace, self.nested_visitor.finish())
    }
}

/// A visitor that extracts a single value from the leaf at specified
/// path.
pub(crate) struct PathVisitor {
    // The path we are interested in.
    path: Vec<Vec<u8>>,
    // Current position in the path.
    pos: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Value {
    Blob(Vec<u8>),
    Num(u64),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PathError {
    NotALeaf(Vec<u8>),
    PathTooLong,
    NotFound,
}

impl PathVisitor {
    pub fn for_path(path: Vec<Vec<u8>>) -> Self {
        PathVisitor { path, pos: 0 }
    }
}

impl Visitor for PathVisitor {
    // The result of the traversal is the value at path, if any.
    type Output = Result<Value, PathError>;

    fn start_subtree(&mut self) -> Result<(), Self::Output> {
        Ok(())
    }

    fn enter_edge(&mut self, name: &[u8]) -> Result<Control, Self::Output> {
        if self.pos >= self.path.len() {
            Err(Err(PathError::NotALeaf(name.to_vec())))
        } else if name == &self.path[self.pos][..] {
            self.pos += 1;
            Ok(Control::Continue)
        } else {
            Ok(Control::Skip)
        }
    }

    fn end_subtree(&mut self) -> Result<(), Self::Output> {
        Err(Err(PathError::NotFound))
    }

    fn visit_num(&mut self, n: u64) -> Result<(), Self::Output> {
        if self.pos == self.path.len() {
            Err(Ok(Value::Num(n)))
        } else {
            Err(Err(PathError::PathTooLong))
        }
    }

    fn visit_blob(&mut self, blob: &[u8]) -> Result<(), Self::Output> {
        if self.pos == self.path.len() {
            Err(Ok(Value::Blob(blob.to_vec())))
        } else {
            Err(Err(PathError::PathTooLong))
        }
    }

    fn finish(self) -> Self::Output {
        Err(PathError::NotFound)
    }
}
