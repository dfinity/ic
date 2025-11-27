use tla_instrumentation::{
    Destination, InstrumentationState, tla_log_label, tla_log_locals, tla_log_request,
    tla_log_response,
    tla_value::{TlaValue, ToTla},
};
use tla_instrumentation_proc_macros::{tla_function, tla_update_method};

mod common;
use common::check_tla_trace;

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::thread_local;

use async_trait::async_trait;
use std::thread::LocalKey;

thread_local! {
    pub static COUNTER: RefCell<u64> = const { RefCell::new(0) };
}

#[macro_use]
mod tla_stuff {
    use candid::Int;
    use local_key::task_local;
    use std::cell::RefCell;
    use std::collections::BTreeSet;
    use std::sync::Mutex;
    use std::thread::LocalKey;
    use std::{collections::BTreeMap, sync::RwLock};
    use tla_instrumentation::{
        GlobalState, InstrumentationState, Label, TlaConstantAssignment, TlaValue, ToTla,
        UnsafeSendPtr, Update, UpdateTrace, VarAssignment,
    };

    pub const PID: &str = "Multiple_Calls";
    pub const CAN_NAME: &str = "mycan";

    task_local! {
        pub static TLA_INSTRUMENTATION_STATE: InstrumentationState;
        pub static TLA_TRACES_LKEY: Mutex<Vec<UpdateTrace>>;
    }
    pub static TLA_TRACES_MUTEX: Option<RwLock<Vec<UpdateTrace>>> = Some(RwLock::new(Vec::new()));

    pub fn my_get_globals(p: &UnsafeSendPtr<LocalKey<RefCell<u64>>>) -> GlobalState {
        let mut state = GlobalState::new();
        let counter = unsafe { &*(p.0) };
        state.add("counter", counter.with_borrow(|c| c.to_tla_value()));
        state.add("empty_fun", TlaValue::Function(BTreeMap::new()));
        state
    }

    macro_rules! snapshotter {
        ($first_arg:expr_2021 $(, $_rest:tt)* ) => {{
            // Use a block to potentially shadow variables and contain the logic
            let raw_ptr = ::tla_instrumentation::UnsafeSendPtr($first_arg as *const _);
            ::std::sync::Arc::new(::std::sync::Mutex::new(move || my_get_globals(&raw_ptr)))
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
    my_get_globals,
};

struct CallMaker {}

#[async_trait]
trait CallMakerTrait {
    async fn call_maker(&self);
}

#[async_trait]
impl CallMakerTrait for CallMaker {
    #[tla_function(force_async_fn = true)]
    async fn call_maker(&self) {
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
}
#[tla_update_method(my_f_desc(), snapshotter!())]
pub async fn my_method(state: &'static LocalKey<RefCell<u64>>) {
    state.with_borrow_mut(|s| *s += 1);
    let call_maker = CallMaker {};
    let mut my_local: u64 = state.with_borrow(|s| *s);
    tla_log_locals! {my_local: my_local};
    tla_log_label!("Phase1");
    call_maker.call_maker().await;
    state.with_borrow_mut(|s| *s += 1);
    my_local = state.with_borrow(|s| *s);
    tla_log_locals! {my_local: my_local};
    tla_log_label!("Phase2");
    call_maker.call_maker().await;
    state.with_borrow_mut(|s| *s += 1);
    my_local = state.with_borrow(|s| *s);
    // Note that this would not be necessary (and would be an error) if
    // we defined my_local in default_end_locals in my_f_desc
    tla_log_locals! {my_local: my_local};
}

#[test]
fn multiple_calls_test() {
    tokio_test::block_on(my_method(&COUNTER));
    let trace = &TLA_TRACES_MUTEX.as_ref().unwrap().read().unwrap()[0];
    assert_eq!(
        trace.constants.to_map().get("MAX_COUNTER"),
        Some(&3_u64.to_string())
    );
    let pairs = &trace.state_pairs;
    println!("----------------");
    println!("State pairs:");
    for pair in pairs.iter() {
        println!("{:?}", pair.start);
        println!("{:?}", pair.end);
    }
    println!("----------------");
    assert_eq!(pairs.len(), 3);
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

    let third = &pairs[2];

    assert_eq!(third.start.get("counter"), Some(&2_u64.to_tla_value()));
    assert_eq!(third.end.get("counter"), Some(&3_u64.to_tla_value()));

    assert_eq!(
        third.start.get("my_local"),
        Some(BTreeMap::from([(PID, 2_u64)]).to_tla_value()).as_ref()
    );
    assert_eq!(
        third.end.get("my_local"),
        Some(BTreeMap::from([(PID, 3_u64)]).to_tla_value()).as_ref()
    );

    assert_eq!(
        third.start.get(incoming),
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
        third.end.get(incoming),
        Some(&BTreeSet::<TlaValue>::new().to_tla_value())
    );

    assert_eq!(
        third.start.get(outgoing),
        Some(&Vec::<TlaValue>::new().to_tla_value())
    );
    assert_eq!(
        third.end.get(outgoing),
        Some(&Vec::<TlaValue>::new().to_tla_value())
    );

    check_tla_trace(trace);
}
