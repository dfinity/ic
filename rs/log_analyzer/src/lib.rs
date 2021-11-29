//! The basic idea of this crate is that given an infinite stream of events of
//! type A, we can easily formulate linear temporal logical formulae over this
//! stream, to assert that certain patterns must or must not appear, but which
//! may require an arbitrary amount of input before this can be determined.
//!
//! A linear temporal logic is a modal logic over regular boolean logic. That
//! is, given a carrier type A, and predicates over A, LTL adds three new
//! "modalities" to boolean logic for reasoning about streams of A's.
//!
//! The boolean component should be quite familiar:
//!
//! - `top()`            -- Represents truth
//! - `bottom(<reason>)` -- Represents falsehood
//! - `P`                -- True if `P` is true (for the current element)
//! - `not(P)`           -- True if `P` is not true
//! - `and(P, Q)`        -- True if both `P` and `Q` are true
//! - `or(P, Q)`         -- True if either `P` or `Q` are true
//! - `impl(P, Q)`       -- True if `or(not(P), Q)`
//!
//! LTL then adds the following to these:
//!
//! - `next(P)`          -- True if `P` holds for the next element in the stream
//! - `until(P, Q)`      -- `P` must remain true until `Q` is true
//!
//! Given these two, we may derive several more:
//!
//! - `always(P)`        -- `P` must hold for all elements
//! - `eventually(P)`    -- `P` must become true at some point
//! - `release(P, Q)`    -- `Q` must remain true until and including once `P`
//!   becomes true
//!
//! There is also a special combinator provided by this library that is not
//! part of LTL proper, but allows us to reference past elements within
//! closures:
//!
//! - `examine(f)`        Accept the current element if, after applying 'f' to
//!   it, the formula returned by 'f' holds true.
//!
//! Using `examine`, it is trivial to build a rule that performs a regular
//! expression on each element, for example, and copies the capture groups
//! from that match into a closure that holds true only if a later regular
//! match is found based on those groups. There is an example of this in
//! `examples/logscan.rs`.
//!
//! For more information on this idea, I recommend the following article:
//!
//! [Sulzmann, Martin, and Axel Zechner. “Constructive Finite Trace Analysis with Linear Temporal Logic,” Vol. 7305, 2012](https://doi.org/10.1007/978-3-642-30473-6_11)

use std::cell::RefCell;
use std::rc::Rc;

type MutRc<A> = Rc<RefCell<A>>;

// This struct exists so that we only have to implement `Debug` for this type,
// and can then derive that trait for the `LTL` type.
pub type Examiner<'fml, A> = MutRc<dyn FnMut(&A) -> MutRc<Ltl<'fml, A>> + 'fml>;

pub enum Ltl<'fml, A> {
    Top,
    Bottom(String),
    Abort(String),

    // Examine rules take a state which is global to the aggregate LTL<'a, A> formula.
    // There is no way to "scope" information using closures, such as there is
    // in Coq or Haskell, so intermediate states must be represented the
    // old-fashioned way.
    Examine(Examiner<'fml, A>),

    And(MutRc<Ltl<'fml, A>>, MutRc<Ltl<'fml, A>>),
    Or(MutRc<Ltl<'fml, A>>, MutRc<Ltl<'fml, A>>),

    Next(MutRc<Ltl<'fml, A>>),

    Until(MutRc<Ltl<'fml, A>>, MutRc<Ltl<'fml, A>>),
    Release(MutRc<Ltl<'fml, A>>, MutRc<Ltl<'fml, A>>),

    Eventually(MutRc<Ltl<'fml, A>>),
    HardEventually(MutRc<Ltl<'fml, A>>),
    Always(MutRc<Ltl<'fml, A>>),
}

impl<'fml, A> std::fmt::Debug for Ltl<'fml, A> {
    fn fmt(&self, dest: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ltl::Top => write!(dest, "LTL::Top"),
            Ltl::Bottom(s) => write!(dest, "LTL::Bottom({:?})", s),
            Ltl::Abort(s) => write!(dest, "LTL::Abort({:?})", s),
            Ltl::Examine(_) => write!(dest, "LTL::Examine(_)"),
            Ltl::And(p, q) => write!(dest, "LTL::And({:#?}, {:#?})", p, q),
            Ltl::Or(p, q) => write!(dest, "LTL::Or({:#?}, {:#?})", p, q),
            Ltl::Next(p) => write!(dest, "LTL::Next({:#?})", p),
            Ltl::Until(p, q) => write!(dest, "LTL::Until({:#?}, {:#?})", p, q),
            Ltl::Release(p, q) => write!(dest, "LTL::Release({:#?}, {:#?})", p, q),
            Ltl::Eventually(p) => write!(dest, "LTL::Eventually({:#?})", p),
            Ltl::HardEventually(p) => write!(dest, "LTL::HardEventually({:#?})", p),
            Ltl::Always(p) => write!(dest, "LTL::Always({:#?})", p),
        }
    }
}

impl<'fml, A> PartialEq for Ltl<'fml, A> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Ltl::Top, Ltl::Top) => true,
            (Ltl::Bottom(s1), Ltl::Bottom(s2)) => s1 == s2,
            (Ltl::Abort(s1), Ltl::Abort(s2)) => s1 == s2,
            (Ltl::And(p1, q1), Ltl::And(p2, q2)) => p1 == p2 && q1 == q2,
            (Ltl::Or(p1, q1), Ltl::Or(p2, q2)) => p1 == p2 && q1 == q2,
            (Ltl::Next(p1), Ltl::Next(p2)) => p1 == p2,
            (Ltl::Until(p1, q1), Ltl::Until(p2, q2)) => p1 == p2 && q1 == q2,
            (Ltl::Release(p1, q1), Ltl::Release(p2, q2)) => p1 == p2 && q1 == q2,
            (Ltl::Eventually(p1), Ltl::Eventually(p2)) => p1 == p2,
            (Ltl::HardEventually(p1), Ltl::HardEventually(p2)) => p1 == p2,
            (Ltl::Always(p1), Ltl::Always(p2)) => p1 == p2,
            _ => false,
        }
    }
}

impl<'fml, A> Ltl<'fml, A> {
    /// Return the structural size of a given formula, after consideration of
    /// some specific element.
    pub fn size(&mut self, element: &A) -> usize {
        match self {
            Ltl::Top => 1,
            Ltl::Bottom(_) => 1,
            Ltl::Abort(_) => 1,
            Ltl::Examine(f) => 1 + (&mut *f.borrow_mut())(element).borrow_mut().size(element),
            Ltl::And(p, q) => 1 + p.borrow_mut().size(element) + q.borrow_mut().size(element),
            Ltl::Or(p, q) => 1 + p.borrow_mut().size(element) + q.borrow_mut().size(element),
            Ltl::Next(p) => 1 + p.borrow_mut().size(element),
            Ltl::Until(p, q) => 1 + p.borrow_mut().size(element) + q.borrow_mut().size(element),
            Ltl::Release(p, q) => 1 + p.borrow_mut().size(element) + q.borrow_mut().size(element),
            Ltl::Eventually(p) => 1 + p.borrow_mut().size(element),
            Ltl::HardEventually(p) => 1 + p.borrow_mut().size(element),
            Ltl::Always(p) => 1 + p.borrow_mut().size(element),
        }
    }
}

pub type Formula<'fml, A> = MutRc<Ltl<'fml, A>>;

pub fn top<'fml, A>() -> Formula<'fml, A> {
    Rc::new(RefCell::new(Ltl::Top))
}

pub fn bottom<'fml, A>(reason: &str) -> Formula<'fml, A> {
    Rc::new(RefCell::new(Ltl::Bottom(reason.to_string())))
}

fn fail<'fml, A>(reason: &str) -> Formula<'fml, A> {
    Rc::new(RefCell::new(Ltl::Abort(reason.to_string())))
}

pub fn with_examiner<A>(f: Examiner<'_, A>) -> Formula<'_, A> {
    Rc::new(RefCell::new(Ltl::Examine(f)))
}

pub fn examine<'fml, A>(f: impl FnMut(&A) -> Formula<'fml, A> + 'fml) -> Formula<'fml, A> {
    with_examiner(Rc::new(RefCell::new(f)))
}

pub fn not<A: 'static>(p: Formula<'_, A>) -> Formula<'_, A> {
    match &mut *p.borrow_mut() {
        Ltl::Top => bottom("not"),
        Ltl::Bottom(_) => top(),
        Ltl::Abort(s) => fail(s),
        Ltl::Examine(f) => examine({
            let f = f.clone();
            move |x| not((&mut *f.borrow_mut())(x))
        }),
        Ltl::And(p, q) => or(not(p.clone()), not(q.clone())),
        Ltl::Or(p, q) => and(not(p.clone()), not(q.clone())),
        Ltl::Next(p) => next(not(p.clone())),
        Ltl::Until(p, q) => release(not(p.clone()), not(q.clone())),
        Ltl::Release(p, q) => until(not(p.clone()), not(q.clone())),
        Ltl::Eventually(p) => always(not(p.clone())),
        Ltl::HardEventually(p) => always(not(p.clone())),
        Ltl::Always(p) => eventually(not(p.clone())),
    }
}

pub fn and<'fml, A>(p: Formula<'fml, A>, q: Formula<'fml, A>) -> Formula<'fml, A> {
    Rc::new(RefCell::new(Ltl::And(p, q)))
}

pub fn or<'fml, A>(p: Formula<'fml, A>, q: Formula<'fml, A>) -> Formula<'fml, A> {
    Rc::new(RefCell::new(Ltl::Or(p, q)))
}

pub fn implies<'fml, A: 'static>(p: Formula<'fml, A>, q: Formula<'fml, A>) -> Formula<'fml, A> {
    or(not(p), q)
}

pub fn next<A>(p: Formula<'_, A>) -> Formula<'_, A> {
    Rc::new(RefCell::new(Ltl::Next(p)))
}

pub fn until<'fml, A>(p: Formula<'fml, A>, q: Formula<'fml, A>) -> Formula<'fml, A> {
    Rc::new(RefCell::new(Ltl::Until(p, q)))
}

pub fn wait<'fml, A>(p: Formula<'fml, A>, q: Formula<'fml, A>) -> Formula<'fml, A> {
    or(always(p.clone()), until(p, q))
}

pub fn release<'fml, A>(p: Formula<'fml, A>, q: Formula<'fml, A>) -> Formula<'fml, A> {
    Rc::new(RefCell::new(Ltl::Release(p, q)))
}

pub fn eventually<A>(p: Formula<'_, A>) -> Formula<'_, A> {
    Rc::new(RefCell::new(Ltl::Eventually(p)))
}

pub fn hard_eventually<A>(p: Formula<'_, A>) -> Formula<'_, A> {
    Rc::new(RefCell::new(Ltl::HardEventually(p)))
}

pub fn always<A>(p: Formula<'_, A>) -> Formula<'_, A> {
    Rc::new(RefCell::new(Ltl::Always(p)))
}

/// True if the given boolean is true.
pub fn truth<'fml, A>(b: bool) -> Formula<'fml, A> {
    if b {
        top()
    } else {
        bottom("truth")
    }
}

/// True if the given predicate on the input is true.
pub fn is<'fml, A>(mut f: impl FnMut(&A) -> bool + Send + Sync + 'fml) -> Formula<'fml, A> {
    examine(move |x: &A| truth(f(x)))
}

/// Another name for 'is'.
pub fn test<'fml, A>(f: impl FnMut(&A) -> bool + Send + Sync + 'fml) -> Formula<'fml, A> {
    is(f)
}

// When the project function matches, the condition evaluate to be true.
pub fn true_when<'fml, A, B: 'fml>(
    mut proj: impl FnMut(&A) -> Option<B> + Send + Sync + 'fml,
    mut body: impl FnMut(B) -> bool + Send + Sync + 'fml,
) -> Formula<'fml, A> {
    eventually(examine(move |x: &A| {
        if let Some(b) = proj(x) {
            if body(b) {
                top()
            } else {
                fail("condition failed")
            }
        } else {
            bottom("condition not yet met")
        }
    }))
}

/// Enforces a property on every point a given projection returns a [Some]
pub fn always_when<'fml, A, B: 'fml>(
    mut proj: impl FnMut(&A) -> Option<B> + Send + Sync + 'fml,
    mut body: impl FnMut(B) -> Formula<'fml, A> + Send + Sync + 'fml,
) -> Formula<'fml, A> {
    always(examine(move |x: &A| {
        if let Some(b) = proj(x) {
            body(b)
        } else {
            top()
        }
    }))
}

/// Enforces a property on some point a given projection returns a [Some]
pub fn eventually_when<'fml, A, B: 'fml>(
    mut proj: impl FnMut(&A) -> Option<B> + Send + Sync + 'fml,
    mut body: impl FnMut(B) -> Formula<'fml, A> + Send + Sync + 'fml,
) -> Formula<'fml, A> {
    eventually(examine(move |x: &A| {
        if let Some(b) = proj(x) {
            body(b)
        } else {
            bottom("condition not yet met")
        }
    }))
}

/// The `liveness` function combines sufficient and necessary conditions to
/// create the basic expression of a liveness condition. Because the inner
/// necessary condition is re-created for every matching sufficient outer
/// condition, we restrict here to the use of non-mutable closures to avoid
/// the confusion caused by having multiple instances of the copied closure
/// evaluated (potentially) for every new element considered.
pub fn liveness<'fml, A, B: Send + Sync + Copy + 'fml>(
    proj: impl Fn(&A) -> Option<B> + Send + Sync + Copy + 'fml,
    body: impl Fn(B, B) -> Formula<'fml, A> + Send + Sync + Copy + 'fml,
) -> Formula<'fml, A> {
    always_when(proj, move |x| {
        next(eventually_when(proj, move |y| body(x, y)))
    })
}

/// True if the given predicate returns an `Ok` response. The main value being
/// that a textual rendering of the `Err` value is passed into to `Bottom`
/// value that might be generated.
pub fn returns_ok<'fml, A, B, E: std::fmt::Debug>(
    mut f: impl FnMut(&A) -> Result<B, E> + Send + Sync + 'fml,
) -> Formula<'fml, A> {
    examine(move |x: &A| match f(x) {
        Ok(_) => top(),
        Err(e) => bottom(&format!("{:?}", e)),
    })
}

/// Check for equality with the input.
pub fn eq<'fml, A: 'fml + Send + Sync + PartialEq>(x: A) -> Formula<'fml, A> {
    examine(move |y: &A| truth(x == *y))
}

/// Check for equality with the input, and annotate the `Bottom` with the
/// expected and received values if it does not match.
pub fn eq_show<'fml, A: 'fml + Send + Sync + PartialEq + std::fmt::Debug>(
    x: A,
) -> Formula<'fml, A> {
    examine(move |y: &A| {
        if x == *y {
            top()
        } else {
            bottom(&format!("Expected {:?}, saw {:?}", x, y))
        }
    })
}

#[derive(Clone, Debug, PartialEq)]
pub struct Failed {
    message: String,
}

impl Failed {
    pub fn new(msg: &str) -> Self {
        Failed {
            message: msg.to_string(),
        }
    }

    fn append_msg(self, msg: &str) -> Self {
        Failed {
            message: format!("{}; {}", self.message, msg),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Weakness {
    Weak,
    Strong,
}

#[derive(Clone, PartialEq)]
pub enum PartialAnswer<'fml, A> {
    Abort(Failed),
    Failure(Failed),
    Continue(Weakness, Formula<'fml, A>),
    Success,
}

impl<'fml, A> PartialAnswer<'fml, A> {
    pub fn new(f: Formula<'fml, A>) -> Self {
        PartialAnswer::Continue(Weakness::Strong, f)
    }
}

impl<'fml, A: std::fmt::Debug> std::fmt::Debug for PartialAnswer<'fml, A> {
    fn fmt(&self, dest: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PartialAnswer::Abort(f) => write!(dest, "PartialAnswer::Abort({:#?})", f),
            PartialAnswer::Failure(f) => write!(dest, "PartialAnswer::Failure({:#?})", f),
            PartialAnswer::Continue(w, _) => write!(dest, "PartialAnswer::Continue({:?}, ...)", w),
            PartialAnswer::Success => write!(dest, "PartialAnswer::Success"),
        }
    }
}

#[derive(Clone, PartialEq, Debug)]
pub enum Answer {
    Failure(Failed),
    Success,
}

fn eval_and<'fml, A>(
    p: Formula<'fml, A>,
    q: Formula<'fml, A>,
    mx: Option<&A>,
    weak: Weakness,
) -> PartialAnswer<'fml, A> {
    match eval(p, mx, weak) {
        PartialAnswer::Abort(e) => PartialAnswer::Abort(e),
        PartialAnswer::Failure(e) => PartialAnswer::Failure(e),
        PartialAnswer::Success => eval(q, mx, weak),
        PartialAnswer::Continue(w, f2) => match eval(q, mx, w) {
            PartialAnswer::Abort(e) => PartialAnswer::Abort(e),
            PartialAnswer::Failure(e) => PartialAnswer::Failure(e),
            PartialAnswer::Success => PartialAnswer::Continue(w, f2),
            PartialAnswer::Continue(w, g2) => PartialAnswer::Continue(w, and(f2, g2)),
        },
    }
}

fn eval_or<'fml, A>(
    p: Formula<'fml, A>,
    q: Formula<'fml, A>,
    mx: Option<&A>,
    weak: Weakness,
) -> PartialAnswer<'fml, A> {
    match eval(p, mx, weak) {
        PartialAnswer::Abort(e) => PartialAnswer::Abort(e),
        PartialAnswer::Success => PartialAnswer::Success,
        PartialAnswer::Failure(e1) => match eval(q, mx, weak) {
            PartialAnswer::Failure(e2) => PartialAnswer::Failure(e1.append_msg(&e2.message)),
            g2 => g2,
        },
        PartialAnswer::Continue(w, f2) => match eval(q, mx, w) {
            PartialAnswer::Abort(e) => PartialAnswer::Abort(e),
            PartialAnswer::Success => PartialAnswer::Success,
            PartialAnswer::Failure(_) => PartialAnswer::Continue(w, f2),
            PartialAnswer::Continue(w, g2) => PartialAnswer::Continue(w, or(f2, g2)),
        },
    }
}

fn success<'fml, A>() -> PartialAnswer<'fml, A> {
    PartialAnswer::Success
}

fn failure<'fml, A>(message: &str) -> PartialAnswer<'fml, A> {
    PartialAnswer::Failure(Failed {
        message: message.to_string(),
    })
}

fn eval<'fml, A>(l: Formula<'fml, A>, mx: Option<&A>, weak: Weakness) -> PartialAnswer<'fml, A> {
    // println!("eval {} {:?}", mx.is_some(), l);
    match &mut *l.borrow_mut() {
        Ltl::Top => PartialAnswer::Success,
        Ltl::Bottom(s) => failure(s),
        Ltl::Abort(s) => PartialAnswer::Abort(Failed { message: s.clone() }),

        Ltl::Examine(v) => match mx {
            None => {
                if let Weakness::Weak = weak {
                    success()
                } else {
                    failure("attempt to examine at end of stream")
                }
            }
            Some(x) => eval((&mut *v.borrow_mut())(x), mx, weak),
        },

        Ltl::And(p, q) => eval_and(Rc::clone(p), Rc::clone(q), mx, weak),
        Ltl::Or(p, q) => eval_or(Rc::clone(p), Rc::clone(q), mx, weak),

        Ltl::Next(p) => match mx {
            None => {
                if let Weakness::Weak = weak {
                    success()
                } else {
                    failure("next has no meaning at end of stream")
                }
            }
            Some(_) => PartialAnswer::Continue(weak, Rc::clone(p)),
        },

        Ltl::Until(p, q) => match mx {
            None => eval(Rc::clone(q), mx, weak),
            Some(_) => eval_or(
                Rc::clone(q),
                and(Rc::clone(p), next(until(Rc::clone(p), Rc::clone(q)))),
                mx,
                weak,
            ),
        },
        Ltl::Release(p, q) => match mx {
            None => success(),
            Some(_) => eval_and(
                Rc::clone(q),
                or(Rc::clone(p), next(release(Rc::clone(p), Rc::clone(q)))),
                mx,
                Weakness::Weak,
            ),
        },

        Ltl::Eventually(p) => match mx {
            None => {
                if let Weakness::Weak = weak {
                    success()
                } else {
                    failure("eventually reached end of stream without match")
                }
            }
            Some(_) => eval_or(Rc::clone(p), next(eventually(Rc::clone(p))), mx, weak),
        },
        Ltl::HardEventually(p) => match mx {
            None => failure("hard_eventually reached end of stream without match"),
            Some(_) => eval_or(
                Rc::clone(p),
                next(eventually(Rc::clone(p))),
                mx,
                Weakness::Strong,
            ),
        },
        Ltl::Always(p) => match mx {
            None => success(),
            Some(_) => eval_and(Rc::clone(p), next(always(Rc::clone(p))), mx, Weakness::Weak),
        },
    }
}

pub fn step<'fml, A>(m: PartialAnswer<'fml, A>, x: &A) -> PartialAnswer<'fml, A> {
    match m {
        PartialAnswer::Continue(w, l) => eval(l, Some(&Rc::new(x)), w),
        r => r,
    }
}

pub fn finish<A>(m: PartialAnswer<'_, A>) -> Answer {
    match m {
        PartialAnswer::Abort(s) => Answer::Failure(s),
        PartialAnswer::Failure(s) => Answer::Failure(s),
        PartialAnswer::Continue(w, l) => match eval(l, None, w) {
            PartialAnswer::Abort(s) => Answer::Failure(s),
            PartialAnswer::Failure(s) => Answer::Failure(s),
            PartialAnswer::Continue(_, _) => panic!("Cannot happen"),
            PartialAnswer::Success => Answer::Success,
        },
        PartialAnswer::Success => Answer::Success,
    }
}

pub fn run<A>(mut m: Formula<'_, A>, xs: impl Iterator<Item = A>) -> Answer {
    let mut weak = Weakness::Strong;
    for x in xs {
        match eval(m, Some(&x), weak) {
            PartialAnswer::Continue(w, l) => {
                m = l;
                weak = w
            }
            r => return finish(r),
        }
    }
    finish(PartialAnswer::Continue(weak, m))
}

pub mod re {
    use regex::{Captures, Regex};

    use super::*;

    /// True if the current position of the log stream matches `start`, and
    /// eventually it matches finish`, where `finish` receives the capture
    /// groups specified in `start`. Note that if the closing expression is
    /// never encountered, this formula never "terminates". The main
    /// consequence of this is that if you use an expression such as
    /// `always(re::ranged(Regex::new("foo"), Regex::new("bar")))`, then every
    /// "foo" encountered in the input will result in an additional formula
    /// scanning ahead for the closing bar, resulting in an open formulae for
    /// every unclosed foo. This can exhausted memory fairly quickly, which is
    /// why it's important to consider using `ranged_within_time` or
    /// `ranged_within_lines`.
    pub fn ranged<'a, A: AsRef<str> + std::fmt::Debug>(
        start: Regex,
        mut finish: impl FnMut(Captures<'_>) -> Regex + Send + Sync + 'a,
    ) -> Formula<'a, A> {
        examine(move |entry: &A| {
            if let Some(groups) = start.captures(entry.as_ref()) {
                let fin = finish(groups);
                next(eventually(examine(move |entry: &A| {
                    truth(fin.is_match(entry.as_ref()))
                })))
            } else {
                top()
            }
        })
    }

    /// Check that the current entry matches the first regular expression, and
    /// based on the captures there, the second occurs within N inputs. This
    /// requires that each input be paired with its offset.
    pub fn ranged_within_count<'a, A: AsRef<str> + std::fmt::Debug + 'a>(
        start: Regex,
        mut finish: impl FnMut(Captures<'_>) -> Regex + Send + Sync + 'a,
        mut proj: impl FnMut(&A) -> usize + Clone + Send + Sync + 'a,
        count: usize,
    ) -> Formula<'a, A> {
        examine(move |x: &A| {
            if let Some(groups) = start.captures(x.as_ref()) {
                next(until(
                    examine({
                        let xi = proj(x);
                        let mut proj = proj.clone();
                        move |y: &A| truth(proj(y) - xi < count)
                    }),
                    examine({
                        let fin = finish(groups);
                        move |y: &A| truth(fin.is_match(y.as_ref()))
                    }),
                ))
            } else {
                top()
            }
        })
    }

    use chrono::{DateTime, Duration, FixedOffset};

    /// Check that the current entry matches the first regular expression, and
    /// based on the captures there, the second occurs within the given time
    /// duration. This requires that input contain a time value; any that do
    /// not are simply skipped.
    pub fn ranged_within_time<'a, A: AsRef<str> + std::fmt::Debug>(
        start: Regex,
        mut finish: impl FnMut(Captures<'_>) -> Regex + Send + Sync + 'a,
        mut parse_time: impl FnMut(&str) -> Option<DateTime<FixedOffset>> + Clone + Send + Sync + 'a,
        duration: Duration,
    ) -> Formula<'a, A> {
        examine(move |entry: &A| {
            if let Some(groups) = start.captures(entry.as_ref()) {
                if let Some(begin) = parse_time(entry.as_ref()) {
                    let fin = finish(groups);
                    next(until(
                        examine({
                            let fin = fin.clone();
                            let mut parse_time = parse_time.clone();
                            move |entry: &A| {
                                if let Some(now) = parse_time(entry.as_ref()) {
                                    if now.signed_duration_since(begin) < duration {
                                        top()
                                    } else {
                                        bottom(&format!(
                                        "Failed to match {} within {} (actual time: {} - {} = {})",
                                        fin,
                                        duration,
                                        now,
                                        begin,
                                        now.signed_duration_since(begin)
                                    ))
                                    }
                                } else {
                                    top()
                                }
                            }
                        }),
                        examine({
                            let mut parse_time = parse_time.clone();
                            move |entry: &A| {
                                if let Some(now) = parse_time(entry.as_ref()) {
                                    if now.signed_duration_since(begin) < duration {
                                        truth(fin.is_match(entry.as_ref()))
                                    } else {
                                        bottom(&format!(
                                        "Failed to match {} within {} (actual time: {} - {} = {})",
                                        fin,
                                        duration,
                                        now,
                                        begin,
                                        now.signed_duration_since(begin)
                                    ))
                                    }
                                } else {
                                    truth(fin.is_match(entry.as_ref()))
                                }
                            }
                        }),
                    ))
                } else {
                    top()
                }
            } else {
                top()
            }
        })
    }
}

pub mod time {
    use chrono::DateTime;
    use chrono::Duration;
    use chrono::FixedOffset;

    use super::*;

    /// True if the current entry contains a time value, and `formula` holds
    /// true across all further entries up to `duration`, based on their time
    /// values.
    pub fn within<'a, A: Send + Sync + 'a>(
        mut parse_time: impl FnMut(&A) -> Option<DateTime<FixedOffset>> + Clone + Send + Sync + 'a,
        duration: Duration,
        formula: Formula<'a, A>,
    ) -> Formula<'a, A> {
        examine(move |entry: &A| {
            if let Some(begin) = parse_time(entry) {
                release(
                    formula.clone(),
                    examine({
                        let copy = formula.clone();
                        let mut parse_time = parse_time.clone();
                        move |entry: &A| {
                            if let Some(now) = parse_time(entry) {
                                if now.signed_duration_since(begin) < duration {
                                    top()
                                } else {
                                    bottom(&format!(
                                "Formula {:#?} failed to match within {} (actual time: {} - {} = {})",
                                copy, duration, now, begin, now.signed_duration_since(begin)
                            ))
                                }
                            } else {
                                top()
                            }
                        }
                    }),
                )
            } else {
                top()
            }
        })
    }
}

#[derive(Clone, Debug)]
pub struct Property<'fml, T> {
    label: String,
    answer: PartialAnswer<'fml, T>,
}

#[derive(Clone, Debug)]
pub struct Analyzer<'fml, T> {
    properties: Vec<Property<'fml, T>>,
}

impl<'fml, T> Default for Analyzer<'fml, T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'fml, T> Analyzer<'fml, T> {
    pub fn new() -> Self {
        Analyzer {
            properties: Vec::new(),
        }
    }

    pub fn add_property(mut self, lbl: &str, formula: Formula<'fml, T>) -> Self {
        self.properties.push(Property {
            label: String::from(lbl),
            answer: PartialAnswer::Continue(Weakness::Strong, formula),
        });
        self
    }

    /// Feeds one event to every property under observation. Returns `Ok(())` if
    /// no property under observation failed, otherwise it returns the list
    /// of failed property labels.
    pub fn observe_event(&mut self, event: &T) -> Result<(), Vec<String>> {
        let mut errs: Vec<String> = Vec::new();

        self.properties.iter_mut().for_each(|prop| {
            // Note that using iter_mut and wanting to step on the prop.answer value is not
            // possible, as prop.answer is of type &mut and step would "move out of it". The
            // solution is to use an auxiliary variable; exachange the value with a
            // placeholder then go on to step the state machine.
            let mut old_ans = PartialAnswer::Success;
            std::mem::swap(&mut prop.answer, &mut old_ans);
            match step(old_ans, event) {
                PartialAnswer::Failure(_) => errs.push(prop.label.clone()),
                x => prop.answer = x,
            }
        });

        if errs.is_empty() {
            Ok(())
        } else {
            Err(errs)
        }
    }
}
