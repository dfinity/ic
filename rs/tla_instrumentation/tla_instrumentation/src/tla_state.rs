use crate::tla_value::{TlaValue, ToTla};
use crate::{Diff, SourceLocation};
use candid::{CandidType, Deserialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fmt::{Display, Formatter},
};

#[derive(Clone, Debug, Default, Hash, PartialEq, Eq, PartialOrd, Ord, CandidType, Deserialize)]
pub struct VarAssignment(pub BTreeMap<String, TlaValue>);

impl VarAssignment {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    pub fn size(&self) -> u64 {
        self.0.len() as u64 + self.0.values().map(|x| x.size()).sum::<u64>()
    }

    pub fn update(&mut self, locals: Vec<(String, TlaValue)>) {
        self.0.extend(locals)
    }

    pub fn add(&self, name: &str, value: TlaValue) -> VarAssignment {
        let mut new_locals = self.clone();
        new_locals.push(name, value);
        new_locals
    }

    pub fn push(&mut self, name: &str, value: TlaValue) {
        self.0.insert(name.to_string(), value);
    }

    pub fn extend(&mut self, other: VarAssignment) {
        self.0.extend(other.0)
    }

    fn assert_no_name_intersection(&self, other: &VarAssignment) {
        let intersection: BTreeSet<_> = self
            .0
            .keys()
            .collect::<BTreeSet<_>>()
            .intersection(&other.0.keys().collect::<BTreeSet<_>>())
            .cloned()
            .collect();

        assert!(
            intersection.is_empty(),
            r#"The states have non-disjoint sets of keys:
{:?}
Possible causes:
1. A local variable is set both after the last await and in default_locals.
   This is the most likely cause if the stack trace includes tla_log_method_return.
2. A local variable of the same name is set in multiple functions in the call stack.
States are:
{:?}
and
{:?}"#,
            intersection,
            self,
            other
        );
    }

    pub fn merge(&self, other: VarAssignment) -> VarAssignment {
        self.assert_no_name_intersection(&other);
        let mut new_locals = self.0.clone();
        new_locals.extend(other.0);
        VarAssignment(new_locals)
    }
}

#[derive(Clone, Default, PartialEq, Eq, Hash, CandidType, Deserialize)]
pub struct GlobalState(pub VarAssignment);

impl GlobalState {
    pub fn new() -> Self {
        Self(VarAssignment::new())
    }

    pub fn size(&self) -> u64 {
        self.0.size()
    }

    pub fn merge(&self, other: GlobalState) -> GlobalState {
        GlobalState(self.0.merge(other.0))
    }

    pub fn extend(&mut self, other: GlobalState) {
        self.0.extend(other.0)
    }

    pub fn add(&mut self, name: &str, value: TlaValue) {
        self.0.push(name, value)
    }

    pub fn get(&self, name: &str) -> Option<&TlaValue> {
        self.0.0.get(name)
    }
}

impl std::fmt::Debug for GlobalState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GlobalState ")?;
        let mut debug_map = f.debug_map();
        for (key, value) in &self.0.0 {
            debug_map.entry(key, value);
        }
        debug_map.finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, CandidType)]
pub struct Label(String);

impl Label {
    pub fn new(name: &str) -> Self {
        Self(name.to_string())
    }

    pub fn merge(&self, other: &Label) -> Label {
        Label(format!("{}_{}", self.0, other.0))
    }
}

#[derive(Clone, Debug)]
pub struct LocalState {
    pub locals: VarAssignment,
    pub label: Label,
}

#[derive(Clone, Debug)]
pub struct Destination(String);

impl Display for Destination {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Destination {
    pub fn new(name: &str) -> Self {
        Self(name.to_string())
    }
}

#[derive(Debug)]
pub struct RequestBuffer {
    pub to: Destination,
    pub method: String,
    pub args: TlaValue,
}

#[derive(Clone, Debug)]
pub struct ResponseBuffer {
    pub from: Destination,
    pub message: TlaValue,
}

#[derive(Clone, Debug)]
pub struct StartState {
    pub global: GlobalState,
    pub local: LocalState,
    pub responses: Vec<ResponseBuffer>,
    pub source_location: SourceLocation,
}

#[derive(Debug)]
pub struct EndState {
    pub global: GlobalState,
    pub local: LocalState,
    pub requests: Vec<RequestBuffer>,
    pub source_location: SourceLocation,
}

#[derive(Debug)]
pub struct StatePair {
    pub start: StartState,
    pub end: EndState,
}

/// A pair of states with local variable names resolved to functions from the process ID
#[derive(Debug, Clone, CandidType, Deserialize)]
pub struct ResolvedStatePair {
    pub start: GlobalState,
    pub end: GlobalState,
    pub start_source_location: SourceLocation,
    pub end_source_location: SourceLocation,
}

impl ResolvedStatePair {
    /// Returns a list of fields that differ between the start and end states
    /// The difference is fine-grained, so if a field is a (potentially nested) record or a function,
    /// the difference lists just the fields that differ (respectively, the argument/value pairs that differ)
    pub fn diff(&self) -> Vec<(String, Diff)> {
        let mut diff = vec![];
        let start = &self.start.0;
        let end = &self.end.0;
        for (key, value) in start.0.iter() {
            if let Some(end_value) = end.0.get(key) {
                if let Some(d) = value.diff(end_value) {
                    diff.push((key.clone(), d));
                }
            } else {
                diff.push((key.clone(), Diff::Other(Some(value.clone()), None)));
            }
        }
        for (key, value) in end.0.iter() {
            if !start.0.contains_key(key) {
                diff.push((key.clone(), Diff::Other(None, Some(value.clone()))));
            }
        }
        diff
    }
}

fn resolve_local_variable(name: &str, value: &TlaValue, process_id: &str) -> VarAssignment {
    let mut assignment = VarAssignment::new();
    assignment.push(
        name,
        TlaValue::Function(BTreeMap::from([(
            TlaValue::Literal(process_id.to_string()),
            value.clone(),
        )])),
    );
    assignment
}

fn resolve_locals(locals: VarAssignment, process_id: &str) -> VarAssignment {
    let mut resolved_locals = VarAssignment::new();
    for (name, value) in locals.0 {
        resolved_locals.extend(resolve_local_variable(&name, &value, process_id));
    }
    resolved_locals
}

fn resolve_request_buffers(
    requests: Vec<RequestBuffer>,
    canister_name: &str,
    process_id: &str,
) -> VarAssignment {
    let mut resolved_request_buffers = VarAssignment::new();
    for request_buffer in requests {
        let buffer_global = format!("{}_to_{}", canister_name, request_buffer.to.0);
        let buffer_contents = TlaValue::Seq(vec![TlaValue::Record(BTreeMap::from([
            (
                "caller".to_string(),
                TlaValue::Literal(process_id.to_string()),
            ),
            (
                "method_and_args".to_string(),
                TlaValue::Variant {
                    tag: request_buffer.method,
                    value: Box::new(request_buffer.args.clone()),
                },
            ),
        ]))]);
        resolved_request_buffers.push(&buffer_global, buffer_contents);
    }
    resolved_request_buffers
}

fn resolve_response_buffers(
    responses: Vec<ResponseBuffer>,
    canister_name: &str,
    process_id: &str,
) -> VarAssignment {
    let mut resolved_response_buffers = VarAssignment::new();
    for response_buffer in responses {
        let buffer_global = format!("{}_to_{}", response_buffer.from.0, canister_name);
        let buffer_contents = TlaValue::Set(BTreeSet::from([TlaValue::Record(BTreeMap::from([
            ("caller".to_string(), process_id.to_tla_value()),
            ("response".to_string(), response_buffer.message.clone()),
        ]))]));
        resolved_response_buffers.push(&buffer_global, buffer_contents);
    }
    resolved_response_buffers
}

impl ResolvedStatePair {
    pub fn resolve(
        unresolved: StatePair,
        process_id: &str,
        canister_name: &str,
    ) -> ResolvedStatePair {
        let resolved_start_locals = resolve_locals(unresolved.start.local.locals, process_id);
        let start_pc = resolve_local_variable(
            "pc",
            &unresolved.start.local.label.0.to_tla_value(),
            process_id,
        );
        let resolved_end_locals = resolve_locals(unresolved.end.local.locals, process_id);
        let end_pc = resolve_local_variable(
            "pc",
            &unresolved.end.local.label.0.to_tla_value(),
            process_id,
        );
        // println!("Resolved start locals: {:?}", resolved_start_locals);
        // println!("Resolved end locals: {:?}", resolved_end_locals);
        let resolved_responses =
            resolve_response_buffers(unresolved.start.responses, canister_name, process_id);
        let resolved_requests =
            resolve_request_buffers(unresolved.end.requests, canister_name, process_id);
        ResolvedStatePair {
            start: GlobalState(
                unresolved
                    .start
                    .global
                    .0
                    .merge(resolved_start_locals)
                    .merge(resolved_responses)
                    .merge(start_pc),
            ),
            end: GlobalState(
                unresolved
                    .end
                    .global
                    .0
                    .merge(resolved_end_locals)
                    .merge(resolved_requests)
                    .merge(end_pc),
            ),
            start_source_location: unresolved.start.source_location,
            end_source_location: unresolved.end.source_location,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Write a test that checks that the `resolve_locals` function works correctly
    // by checking that the returned VarAssignment correctly interprets the local variables
    // as functions from the process ID to the local variable value
    #[test]
    fn test_resolve_local_variable() {
        let test_assignment = VarAssignment(BTreeMap::from([
            ("foo".to_string(), TlaValue::Literal("bar".to_string())),
            ("baz".to_string(), TlaValue::Literal("qux".to_string())),
        ]));

        let process_id = "pid";
        let expected_assignment = VarAssignment(BTreeMap::from([
            (
                "foo".to_string(),
                TlaValue::Function(BTreeMap::from([(
                    TlaValue::Literal(process_id.to_string()),
                    TlaValue::Literal("bar".to_string()),
                )])),
            ),
            (
                "baz".to_string(),
                TlaValue::Function(BTreeMap::from([(
                    TlaValue::Literal(process_id.to_string()),
                    TlaValue::Literal("qux".to_string()),
                )])),
            ),
        ]));

        assert_eq!(
            resolve_locals(test_assignment, process_id),
            expected_assignment
        );
    }
}
