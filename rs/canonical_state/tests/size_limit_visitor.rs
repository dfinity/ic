use ic_canonical_state::{
    size_limit_visitor::{Matcher::*, SizeLimitVisitor},
    subtree_visitor::{Pattern, SubtreeVisitor},
    traverse, Control, LabelLike, Visitor,
};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::ReplicatedState;
use ic_test_utilities::{state::arb_stream, types::ids::subnet_test_id};
use proptest::prelude::*;

/// A fixture consisting of a `ReplicatedState` wrapping a single stream;
/// context about that stream (`begin`, `end`, `size`); and a `slice_begin` and
/// `size_limit` values derived from these.
#[derive(Clone, Debug)]
struct Fixture {
    state: ReplicatedState,

    begin: u64,
    end: u64,
    slice_begin: u64,

    size: usize,
    size_limit: usize,
}

prop_compose! {
    /// An arbitrary fixture with default `slice_begin` and `size_limit` values.
    fn arb_barebone_fixture(max_size: usize)
                   (stream in arb_stream(0, max_size)) -> Fixture {
        let begin = stream.messages_begin().get();
        let end = stream.messages_end().get();

        let mut state = ReplicatedState::new_rooted_at(subnet_test_id(1), SubnetType::Application, "NOT_USED".into());
        let subnet = subnet_test_id(42);
        let mut streams = state.take_streams();
        streams.insert(subnet, stream);
        state.put_streams(streams);

        let size = compute_message_sizes(&state, begin, end);

        Fixture {
            state,
            begin,
            end,
            slice_begin: begin,
            size,
            size_limit: 0,
        }
    }
}

prop_compose! {
    /// An arbitrary fixture with `slice_begin` and `size_limit` derived from the stream.
    fn arb_fixture(max_size: usize)
                  (fixture in arb_barebone_fixture(max_size))
                  (
                      slice_begin in fixture.begin..fixture.end + 1,
                      size_limit in 0..fixture.size + 1,
                      fixture in Just(fixture),
                  ) -> Fixture {
        Fixture {
            slice_begin,
            size_limit,
            ..fixture
        }
    }
}

proptest! {
    #[test]
    fn size_limit_proptest(fixture in arb_fixture(10)) {
        let Fixture{ state, end, slice_begin, size_limit, .. } = fixture;

        // Produce a size-limited slice starting from `slice_begin`.
        let pattern = vec![
            Label(b"streams".to_vec()),
            Any,
            Label(b"messages".to_vec()),
            Any,
        ];
        let subtree_pattern = make_slice_pattern(slice_begin, end);
        let visitor = SizeLimitVisitor::new(
            pattern,
            size_limit,
            SubtreeVisitor::new(&subtree_pattern, MessageSpyVisitor::default()),
        );
        let (actual_size, actual_begin, actual_end) = traverse(&state, visitor);

        if let (Some(actual_begin), Some(actual_end)) = (actual_begin, actual_end) {
            // Non-empty slice.
            assert_eq!(slice_begin, actual_begin);
            assert!(actual_end <= end);

            // Size is below the limit or the slice consists of a single message.
            assert!(actual_size <= size_limit || actual_end - actual_begin == 1);
            // And must match the computed slice size.
            assert_eq!(compute_message_sizes(&state, actual_begin, actual_end), actual_size);

            if actual_end < end {
                // Including one more message should exceed `size_limit`.
                assert!(compute_message_sizes(&state, actual_begin, actual_end + 1) > size_limit);
            }
        } else {
            // Empty slice.
            assert_eq!(0, actual_size);
            // May only happen if `slice_begin == stream.messages.end`.
            assert_eq!(slice_begin, end);
        }
    }
}

/// Computes the sizes of messages between `[begin, end)` of the only `Stream`
/// in `state`.
fn compute_message_sizes(state: &ReplicatedState, begin: u64, end: u64) -> usize {
    // Traverse the stream once to collect its messages' total byte size.
    let pattern = make_slice_pattern(begin, end);
    let visitor = SubtreeVisitor::new(&pattern, MessageSpyVisitor::default());
    let (size, tbegin, tend) = traverse(&state, visitor);

    // Sanity check MessageSpyVisitor.
    if let (Some(tbegin), Some(tend)) = (tbegin, tend) {
        assert_eq!((begin, end), (tbegin, tend));
        // Messages should be at least 35 bytes.
        assert!(
            size as u64 > (end - begin) * 35,
            "size {}, begin {}, end {}",
            size,
            begin,
            end
        );
    } else {
        assert_eq!(begin, end);
        assert_eq!(0, size);
    }

    size
}

/// Creates a `SubtreeVisitor` pattern that filters for messages between `begin`
/// and `end`.
fn make_slice_pattern(begin: u64, end: u64) -> Pattern {
    use Pattern as P;

    P::match_only(
        b"streams",
        P::any(P::match_any(
            vec![
                ("header", P::all()),
                (
                    "messages",
                    P::match_range(
                        begin.to_label().as_bytes(),
                        end.to_label().as_bytes(),
                        P::all(),
                    ),
                ),
            ]
            .into_iter(),
        )),
    )
}

/// A visitor that sums the byte size of all messages; ensures the header was
/// visited and that there are no gaps between message indices; and extracts the
/// range of visited message indices.
#[derive(Default)]
pub(crate) struct MessageSpyVisitor {
    size: usize,
    header_visited: bool,
    last_label: Vec<u8>,
    visiting_messages: bool,
    begin: Option<u64>,
    end: Option<u64>,
}

impl Visitor for MessageSpyVisitor {
    type Output = (usize, Option<u64>, Option<u64>);

    fn start_subtree(&mut self) -> Result<(), Self::Output> {
        self.visiting_messages |= b"messages" == self.last_label.as_slice();
        Ok(())
    }

    fn enter_edge(&mut self, name: &[u8]) -> Result<Control, Self::Output> {
        self.last_label = name.to_vec();
        Ok(Control::Continue)
    }

    fn end_subtree(&mut self) -> Result<(), Self::Output> {
        self.visiting_messages = false;
        Ok(())
    }

    fn visit_blob(&mut self, blob: &[u8]) -> Result<(), Self::Output> {
        self.header_visited |= b"header" == self.last_label.as_slice();

        if self.visiting_messages {
            let stream_index = u64::from_label(&self.last_label[..]).unwrap();

            // Ensure there are no gaps,
            if let Some(end) = self.end {
                assert_eq!(end, stream_index);
            }

            // Update begin and end indices as necessary.
            self.begin.get_or_insert(stream_index);
            self.end = Some(stream_index + 1);

            // Add blob size to the sum.
            self.size += blob.len();
        }
        Ok(())
    }

    fn visit_num(&mut self, _num: u64) -> Result<(), Self::Output> {
        Ok(())
    }

    fn finish(self) -> Self::Output {
        // Ensure we have visited the header.
        assert!(self.header_visited);

        (self.size, self.begin, self.end)
    }
}
