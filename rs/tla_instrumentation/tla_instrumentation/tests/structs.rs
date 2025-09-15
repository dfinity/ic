use async_trait::async_trait;
use std::{
    collections::{BTreeMap, BTreeSet},
    ptr::addr_of_mut,
};
// Also possible to define a wrapper macro, in order to ensure that logging is only
// done when certain crate features are enabled
use tla_instrumentation::{
    Destination, InstrumentationState, tla_log_locals, tla_log_request, tla_log_response,
    tla_value::{TlaValue, ToTla},
};
use tla_instrumentation_proc_macros::{tla_update_method, with_tla_trace_check};

mod common;
use common::check_tla_trace;

// Example of how to separate as much of the instrumentation code as possible from the main code
#[macro_use]
mod tla_stuff {
    use crate::StructCanister;
    use std::collections::BTreeSet;

    use candid::Int;

    pub const PID: &str = "Counter";
    pub const CAN_NAME: &str = "mycan";

    use local_key::task_local;
    use std::sync::{Arc, Mutex};
    use std::{collections::BTreeMap, sync::RwLock};
    use tla_instrumentation::{
        GlobalState, InstrumentationState, Label, TlaConstantAssignment, TlaValue, ToTla,
        UnsafeSendPtr, Update, UpdateTrace, VarAssignment,
    };

    task_local! {
        pub static TLA_INSTRUMENTATION_STATE: InstrumentationState;
        pub static TLA_TRACES_LKEY: Arc<Mutex<Vec<UpdateTrace>>>;
    }

    pub static TLA_TRACES_MUTEX: Option<RwLock<Vec<UpdateTrace>>> = Some(RwLock::new(Vec::new()));

    pub fn tla_get_globals(p: &UnsafeSendPtr<StructCanister>) -> GlobalState {
        let mut state = GlobalState::new();
        let c = unsafe { &*(p.0) };
        state.add("counter", c.counter.to_tla_value());
        state.add("empty_fun", TlaValue::Function(BTreeMap::new()));
        state
    }

    // #[macro_export]
    macro_rules! tla_get_globals {
        ($self:expr_2021 $(, $_:expr_2021)*) => {{
            let raw_ptr = tla_instrumentation::UnsafeSendPtr($self as *const _);
            ::std::sync::Arc::new(::std::sync::Mutex::new(move || {
                tla_stuff::tla_get_globals(&raw_ptr)
            }))
        }};
    }

    pub fn my_f_desc() -> Update {
        Update {
            default_start_locals: VarAssignment::new().add("my_local", 0_u64.to_tla_value()),
            default_end_locals: VarAssignment::new(),
            start_label: Label::new("Start_Label"),
            end_label: Label::new("Done"),
            process_id: PID.to_string(),
            canister_name: CAN_NAME.to_string(),
            post_process: |trace| {
                let max_counter = trace
                    .iter()
                    .map(
                        |pair| match (pair.start.get("counter"), pair.end.get("counter")) {
                            (
                                Some(TlaValue::Int(start_counter)),
                                Some(TlaValue::Int(end_counter)),
                            ) => start_counter.max(end_counter).clone(),
                            _ => Int::from(0_u64),
                        },
                    )
                    .max();
                let constants = BTreeMap::from([
                    (
                        "MAX_COUNTER".to_string(),
                        max_counter.unwrap_or(Int::from(0_u64)).to_tla_value(),
                    ),
                    (
                        "My_Method_Process_Ids".to_string(),
                        BTreeSet::from([PID.to_string()]).to_tla_value(),
                    ),
                ]);
                let outgoing = format!("{}_to_{}", CAN_NAME, "othercan");
                let outgoing = outgoing.as_str();
                let incoming = format!("{}_to_{}", "othercan", CAN_NAME);
                let incoming = incoming.as_str();
                for pair in trace {
                    for s in [&mut pair.start, &mut pair.end] {
                        if !s.0.0.contains_key(outgoing) {
                            s.0.0.insert(
                                outgoing.to_string(),
                                Vec::<TlaValue>::new().to_tla_value(),
                            );
                        }
                        if !s.0.0.contains_key(incoming) {
                            s.0.0.insert(
                                incoming.to_string(),
                                BTreeSet::<TlaValue>::new().to_tla_value(),
                            );
                        }
                    }
                }
                TlaConstantAssignment { constants }
            },
        }
    }
}

use tla_stuff::{
    CAN_NAME, PID, TLA_INSTRUMENTATION_STATE, TLA_TRACES_LKEY, TLA_TRACES_MUTEX, my_f_desc,
};

struct StructCanister {
    pub counter: u64,
}

static mut GLOBAL: StructCanister = StructCanister { counter: 0 };

fn call_maker() {
    tla_log_request!(
        "WaitForResponse",
        Destination::new("othercan"),
        "Target_Method",
        2_u64
    );
    tla_log_response!(
        Destination::new("othercan"),
        TlaValue::Variant {
            tag: "Ok".to_string(),
            value: Box::new(3_u64.to_tla_value())
        }
    );
}

#[async_trait]
trait MyTrait {
    async fn my_method(&mut self, ignored_arg: u64);
}

#[async_trait]
impl MyTrait for StructCanister {
    #[tla_update_method(my_f_desc(), tla_get_globals!(), force_async_fn = true)]
    async fn my_method(&mut self, _ignored_arg: u64) {
        self.counter += 1;
        let mut my_local: u64 = self.counter;
        tla_log_locals! {my_local: my_local};
        call_maker();
        self.counter += 1;
        my_local = self.counter;
        // Note that this would not be necessary (and would be an error) if
        // we defined my_local in default_end_locals in my_f_desc
        tla_log_locals! {my_local: my_local};
    }
}

#[test]
fn struct_test() {
    unsafe {
        let canister = &mut *addr_of_mut!(GLOBAL);
        tokio_test::block_on(canister.my_method(1));
    }
    let trace = &TLA_TRACES_MUTEX.as_ref().unwrap().read().unwrap()[0];
    assert_eq!(
        trace.constants.to_map().get("MAX_COUNTER"),
        Some(&2_u64.to_string())
    );
    let pairs = &trace.state_pairs;
    println!("----------------");
    println!("State pairs:");
    for pair in pairs.iter() {
        println!("{:?}", pair.start);
        println!("{:?}", pair.end);
    }
    println!("----------------");
    assert_eq!(pairs.len(), 2);
    let first = &pairs[0];
    assert_eq!(first.start.get("counter"), Some(&0_u64.to_tla_value()));
    assert_eq!(first.end.get("counter"), Some(&1_u64.to_tla_value()));

    assert_eq!(
        first.start.get("my_local"),
        Some(BTreeMap::from([(PID, 0_u64)]).to_tla_value()).as_ref()
    );
    assert_eq!(
        first.end.get("my_local"),
        Some(BTreeMap::from([(PID, 1_u64)]).to_tla_value()).as_ref()
    );

    let outgoing = format!("{}_to_{}", CAN_NAME, "othercan");
    let outgoing = outgoing.as_str();
    let incoming = format!("{}_to_{}", "othercan", CAN_NAME);
    let incoming = incoming.as_str();

    assert_eq!(
        first.start.get(outgoing),
        Some(&Vec::<TlaValue>::new().to_tla_value())
    );
    assert_eq!(
        first.end.get(outgoing),
        Some(
            &vec![TlaValue::Record(BTreeMap::from([
                ("caller".to_string(), PID.to_tla_value()),
                (
                    "method_and_args".to_string(),
                    TlaValue::Variant {
                        tag: "Target_Method".to_string(),
                        value: Box::new(2_u64.to_tla_value())
                    }
                )
            ]))]
            .to_tla_value()
        )
    );

    assert_eq!(
        first.start.get(incoming),
        Some(&BTreeSet::<TlaValue>::new().to_tla_value())
    );
    assert_eq!(
        first.end.get(incoming),
        Some(&BTreeSet::<TlaValue>::new().to_tla_value())
    );

    let second = &pairs[1];

    assert_eq!(second.start.get("counter"), Some(&1_u64.to_tla_value()));
    assert_eq!(second.end.get("counter"), Some(&2_u64.to_tla_value()));

    assert_eq!(
        second.start.get("my_local"),
        Some(BTreeMap::from([(PID, 1_u64)]).to_tla_value()).as_ref()
    );
    assert_eq!(
        second.end.get("my_local"),
        Some(BTreeMap::from([(PID, 2_u64)]).to_tla_value()).as_ref()
    );

    assert_eq!(
        second.start.get(incoming),
        Some(
            &BTreeSet::from([TlaValue::Record(BTreeMap::from([
                ("caller".to_string(), PID.to_tla_value()),
                (
                    "response".to_string(),
                    TlaValue::Variant {
                        tag: "Ok".to_string(),
                        value: Box::new(3_u64.to_tla_value())
                    }
                )
            ]))])
            .to_tla_value()
        )
    );
    assert_eq!(
        second.end.get(incoming),
        Some(&BTreeSet::<TlaValue>::new().to_tla_value())
    );

    assert_eq!(
        second.start.get(outgoing),
        Some(&Vec::<TlaValue>::new().to_tla_value())
    );
    assert_eq!(
        second.end.get(outgoing),
        Some(&Vec::<TlaValue>::new().to_tla_value())
    );

    check_tla_trace(trace);
}

fn tla_check_traces() {
    let traces = TLA_TRACES_LKEY.get();
    let traces = traces
        .lock()
        .expect("Couldn't lock traces in tla_check_traces");
    for t in &*traces {
        check_tla_trace(t)
    }
}

#[test]
#[with_tla_trace_check]
fn annotated_test() {
    let canister = &mut StructCanister { counter: 0 };
    tokio_test::block_on(canister.my_method(2));
}
