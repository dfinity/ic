use super::*;
use crate::test_visitors::{NoopVisitor, TraceEntry, TracingVisitor};
use crate::visitor::{named_blob, named_num, named_subtree, subtree, Visitor};
use Matcher::*;
use TraceEntry::{EndSubtree, EnterEdge, StartSubtree, VisitBlob, VisitNum};

const MESSAGE_SIZE: usize = 3;
const HEADER_SIZE: usize = 2;

/// Sample streams traversal:
///
/// ```text
/// *- streams
///    +- 0
///    |  +- header → [b'H', 0]
///    |  +- messages
///    |     +- 0 → [b'M', 0, 0]
///    |     +- 1 → [b'M', 0, 1]
///    |     +- ...
///    |     +- <msg_count> → [b'M', 0, <msg_count>]
///    +- 1
///    |  +- header → [b'H', 1]
///    |  +- messages
///    |     +- 0 → [b'M', 1, 0]
///    |     +- ...
///    +- ...
///    |
///    `- <stream_count>
///       +- header → [b'H', <stream_count>]
///       +- messages
///          +- ...
/// ```
fn traverse_streams<V: Visitor>(
    mut v: SizeLimitVisitor<V>,
    stream_count: usize,
    msg_count: usize,
) -> (usize, V::Output) {
    let t = subtree(&mut v, |v| {
        named_num(v, "a_num", 13)?;
        named_subtree(v, "streams", |v| {
            for i in 0..stream_count {
                named_subtree(v, i.to_string(), |v| {
                    named_blob(v, "header", &[b'H', i as u8])?;
                    named_subtree(v, "messages", |v| {
                        for j in 0..msg_count {
                            named_blob(v, j.to_string(), &[b'M', i as u8, j as u8])?;
                        }
                        Ok(())
                    })
                })?
            }
            Ok(())
        })
    });

    match t {
        Err(output) => (v.size, output),
        _ => (v.size, v.finish()),
    }
}

/// Tests that matching nodes are correctly filtered across multiple subtrees.
#[test]
fn multiple_subtrees() {
    let pattern = vec![
        Label(b"streams".to_vec()),
        Any,
        Label(b"messages".to_vec()),
        Any,
    ];

    // Visitor allowing up to 3 messages.
    let visitor = SizeLimitVisitor::new(
        pattern,
        4 * MESSAGE_SIZE - 1,
        TracingVisitor::new(NoopVisitor),
    );

    // Traverse 3 streams with 2 messages each.
    let (size, (trace, _)) = traverse_streams(visitor, 3, 2);

    assert_eq!(
        trace,
        vec![
            StartSubtree,
            EnterEdge(b"a_num".to_vec()),
            VisitNum(13),
            EnterEdge(b"streams".to_vec()),
            StartSubtree,
            // Stream 0: 2 messages.
            EnterEdge(b"0".to_vec()),
            StartSubtree,
            EnterEdge(b"header".to_vec()),
            VisitBlob(vec![b'H', 0]),
            EnterEdge(b"messages".to_vec()),
            StartSubtree,
            EnterEdge(b"0".to_vec()),
            VisitBlob(vec![b'M', 0, 0]),
            EnterEdge(b"1".to_vec()),
            VisitBlob(vec![b'M', 0, 1]),
            EndSubtree, // messages
            EndSubtree, // 0
            // Stream 1: 1 message.
            EnterEdge(b"1".to_vec()),
            StartSubtree,
            EnterEdge(b"header".to_vec()),
            VisitBlob(vec![b'H', 1]),
            EnterEdge(b"messages".to_vec()),
            StartSubtree,
            EnterEdge(b"0".to_vec()),
            VisitBlob(vec![b'M', 1, 0]),
            EndSubtree, // messages
            EndSubtree, // 1
            // Stream 2: no messages.
            EnterEdge(b"2".to_vec()),
            StartSubtree,
            EnterEdge(b"header".to_vec()),
            VisitBlob(vec![b'H', 2]),
            EnterEdge(b"messages".to_vec()),
            StartSubtree,
            EndSubtree, // messages
            EndSubtree, // 2
            EndSubtree, // streams
            EndSubtree,
        ],
    );
    assert_eq!(4 * MESSAGE_SIZE, size) // 3 messages included, 4th message
                                       // exceeded the limit.
}

/// Tests stacking two `SizeLimitVisitors`.
#[test]
fn stacked_visitors() {
    let msg_pattern = vec![
        Label(b"streams".to_vec()),
        Any,
        Label(b"messages".to_vec()),
        Any,
    ];
    let header_pattern = vec![Label(b"streams".to_vec()), Any, Label(b"header".to_vec())];

    // Visitor allowing up to 3 messages1 on top of visitor 1 header.
    let visitor = SizeLimitVisitor::new(
        msg_pattern,
        3 * MESSAGE_SIZE,
        SizeLimitVisitor::new(
            header_pattern,
            HEADER_SIZE,
            TracingVisitor::new(NoopVisitor),
        ),
    );

    // 2 streams with 2 messages each
    let (msg_visitor_size, (trace, _)) = traverse_streams(visitor, 2, 2);

    assert_eq!(
        trace,
        vec![
            StartSubtree,
            EnterEdge(b"a_num".to_vec()),
            VisitNum(13),
            EnterEdge(b"streams".to_vec()),
            StartSubtree,
            // Stream 0: header and 2 messages.
            EnterEdge(b"0".to_vec()),
            StartSubtree,
            EnterEdge(b"header".to_vec()),
            VisitBlob(vec![b'H', 0]),
            EnterEdge(b"messages".to_vec()),
            StartSubtree,
            EnterEdge(b"0".to_vec()),
            VisitBlob(vec![b'M', 0, 0]),
            EnterEdge(b"1".to_vec()),
            VisitBlob(vec![b'M', 0, 1]),
            EndSubtree, // messages
            EndSubtree, // 0
            // Stream 1: no header, 1 message.
            EnterEdge(b"1".to_vec()),
            StartSubtree,
            EnterEdge(b"messages".to_vec()),
            StartSubtree,
            EnterEdge(b"0".to_vec()),
            VisitBlob(vec![b'M', 1, 0]),
            EndSubtree, // messages
            EndSubtree, // 1
            EndSubtree, // streams
            EndSubtree,
        ],
    );
    assert_eq!(3 * MESSAGE_SIZE, msg_visitor_size)
}
