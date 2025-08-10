use super::*;
use crate::test_visitors::{NoopVisitor, PathVisitor, TraceEntry, TracingVisitor, Value};
use crate::visitor::{named_blob, named_num, named_subtree, subtree};
use Pattern as P;
use TraceEntry::{EndSubtree, EnterEdge, StartSubtree, VisitBlob, VisitNum};

/// Sample tree traversal:
///
/// ```text
/// *
/// |
/// +- blobmap
/// |  +- 0 → [0xcafebabe]
/// |  `- 1 → [0xdeadbeef]
/// `- num
///    +- from → 5
///    `- to   → 10
/// ```
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
fn can_pick_edges_to_visit() {
    let pattern = P::match_any(
        vec![
            ("num", P::match_only("from", P::all())),
            ("blobmap", P::match_only("0", P::all())),
        ]
        .into_iter(),
    );

    let visitor = SubtreeVisitor::new(&pattern, TracingVisitor::new(NoopVisitor));

    assert_eq!(
        traverse_sample_tree(visitor).0,
        vec![
            StartSubtree,
            EnterEdge(b"blobmap".to_vec()),
            StartSubtree,
            EnterEdge(b"0".to_vec()),
            VisitBlob(vec![0xca, 0xfe, 0xba, 0xbe]),
            EndSubtree, // blobmap
            EnterEdge(b"num".to_vec()),
            StartSubtree,
            EnterEdge(b"from".to_vec()),
            VisitNum(5),
            EndSubtree, // num
            EndSubtree,
        ],
    );
}

#[test]
fn can_visit_single_subtree() {
    let pattern = P::match_only("num", P::all());
    let visitor = SubtreeVisitor::new(&pattern, TracingVisitor::new(NoopVisitor));

    assert_eq!(
        traverse_sample_tree(visitor).0,
        vec![
            StartSubtree,
            EnterEdge(b"num".to_vec()),
            StartSubtree,
            EnterEdge(b"from".to_vec()),
            VisitNum(5),
            EnterEdge(b"to".to_vec()),
            VisitNum(10),
            EndSubtree, // num
            EndSubtree, // global
        ],
    );
}

#[test]
fn wildcard_visits_everything() {
    let pattern = P::all();
    let visit_subtree = SubtreeVisitor::new(&pattern, TracingVisitor::new(NoopVisitor));
    let visit_everything = TracingVisitor::new(NoopVisitor);

    assert_eq!(
        traverse_sample_tree(visit_subtree).0,
        traverse_sample_tree(visit_everything).0,
    );
}

#[test]
fn can_visit_one_level() {
    let pattern = P::any(P::none());
    let visitor = SubtreeVisitor::new(&pattern, TracingVisitor::new(NoopVisitor));

    assert_eq!(
        traverse_sample_tree(visitor).0,
        vec![
            StartSubtree,
            EnterEdge(b"blobmap".to_vec()),
            StartSubtree,
            EndSubtree,
            EnterEdge(b"num".to_vec()),
            StartSubtree,
            EndSubtree,
            EndSubtree,
        ],
    )
}

#[test]
fn respects_early_exit() {
    let pattern = P::match_only(b"num", P::match_only(b"from", P::all()));
    let visitor = SubtreeVisitor::new(
        &pattern,
        TracingVisitor::new(PathVisitor::for_path(vec![
            b"num".to_vec(),
            b"from".to_vec(),
        ])),
    );
    assert_eq!(
        traverse_sample_tree(visitor),
        (
            vec![
                StartSubtree,
                EnterEdge(b"num".to_vec()),
                StartSubtree,
                EnterEdge(b"from".to_vec()),
                VisitNum(5),
            ],
            Ok(Value::Num(5))
        )
    )
}

#[test]
fn subtree_composition_yields_intersection() {
    let pattern_1 = P::match_only("blobmap", P::all());
    let pattern_2 = P::any(P::match_only("1", P::all()));

    let visitor_12 = SubtreeVisitor::new(
        &pattern_1,
        SubtreeVisitor::new(&pattern_2, TracingVisitor::new(NoopVisitor)),
    );
    let visitor_21 = SubtreeVisitor::new(
        &pattern_2,
        SubtreeVisitor::new(&pattern_1, TracingVisitor::new(NoopVisitor)),
    );

    let trace_1 = traverse_sample_tree(visitor_12).0;
    let trace_2 = traverse_sample_tree(visitor_21).0;

    assert_eq!(trace_1, trace_2);
    assert_eq!(
        trace_1,
        vec![
            StartSubtree,
            EnterEdge(b"blobmap".to_vec()),
            StartSubtree,
            EnterEdge(b"1".to_vec()),
            VisitBlob(vec![0xde, 0xad, 0xbe, 0xef]),
            EndSubtree,
            EndSubtree,
        ]
    );
}

#[test]
fn can_match_range() {
    let pattern = P::match_only("blobmap", P::match_range("0", "1", P::all()));
    let visitor = SubtreeVisitor::new(&pattern, TracingVisitor::new(NoopVisitor));

    assert_eq!(
        traverse_sample_tree(visitor).0,
        vec![
            StartSubtree,
            EnterEdge(b"blobmap".to_vec()),
            StartSubtree,
            EnterEdge(b"0".to_vec()),
            VisitBlob(vec![0xca, 0xfe, 0xba, 0xbe]),
            EndSubtree, // blobmap
            EndSubtree, // root
        ],
    )
}
