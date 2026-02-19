use std::{
    cell::{Cell, RefCell},
    cmp::Ordering,
    collections::BinaryHeap,
    pin::Pin,
    time::Duration,
};

use slotmap::{SlotMap, new_key_type};

// To ensure that tasks are removable seamlessly, there are two separate concepts here:
// tasks, for the actual function being called, and timers, the scheduled execution of tasks.
// As this is an implementation detail, lib.rs exposes TaskId under the name TimerId.

thread_local! {
    pub(crate) static TIMER_COUNTER: Cell<u128> = const { Cell::new(0) };
    pub(crate) static TASKS: RefCell<SlotMap<TaskId, Task>> = RefCell::default();
    pub(crate) static TIMERS: RefCell<BinaryHeap<Timer>> = RefCell::default();
    static MOST_RECENT: Cell<Option<u64>> = const { Cell::new(None) };
    pub(crate) static ALL_CALLS: Cell<usize> = const { Cell::new(0) };
}

pub(crate) enum Task {
    Once(Pin<Box<dyn Future<Output = ()>>>),
    Repeated {
        func: Box<dyn FnMut() -> Pin<Box<dyn Future<Output = ()>>>>,
        interval: Duration,
        concurrent_calls: usize,
    },
    RepeatedSerial {
        func: Box<dyn SerialClosure>,
        interval: Duration,
    },
    RepeatedSerialBusy {
        interval: Duration,
    },
    Invalid,
}

pub(crate) trait SerialClosure {
    fn call<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = ()> + 'a>>;
}

impl<F: AsyncFnMut()> SerialClosure for F {
    fn call<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = ()> + 'a>> {
        Box::pin(self())
    }
}

new_key_type! {
    #[expect(missing_docs)] // documented in lib.rs
    pub struct TaskId;
}

#[derive(Debug)]
pub(crate) struct Timer {
    pub(crate) task: TaskId,
    pub(crate) time: u64,
    pub(crate) counter: u128,
}

// Timers are sorted first by time, then by insertion order to ensure deterministic ordering.
// The ordering is reversed (earlier timer > later) for use in BinaryHeap which is a max-heap.

impl Ord for Timer {
    fn cmp(&self, other: &Self) -> Ordering {
        self.time
            .cmp(&other.time)
            .then_with(|| self.counter.cmp(&other.counter))
            .reverse()
    }
}

impl PartialOrd for Timer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Timer {
    fn eq(&self, other: &Self) -> bool {
        self.time == other.time
    }
}

impl Eq for Timer {}

pub(crate) fn next_counter() -> u128 {
    TIMER_COUNTER.with(|c| {
        let v = c.get();
        c.set(v + 1);
        v
    })
}

/// Calls `ic0.global_timer_set` with the soonest timer in [`TIMERS`]. This is needed after inserting a timer, and after executing one.
pub(crate) fn update_ic0_timer() {
    TIMERS.with_borrow(|timers| {
        let soonest_timer = timers.peek().map(|timer| timer.time);
        let should_change = match (soonest_timer, MOST_RECENT.get()) {
            (Some(timer), Some(recent)) => timer < recent,
            (Some(_), None) => true,
            _ => false,
        };
        if should_change {
            ic0::global_timer_set(soonest_timer.unwrap());
            MOST_RECENT.set(soonest_timer);
        }
    });
}

/// Like [`update_ic0_timer`], but forces updating unconditionally. Should only be called from canister_global_timer.
pub(crate) fn update_ic0_timer_clean() {
    MOST_RECENT.set(None);
    update_ic0_timer();
}

impl Task {
    pub(crate) fn increment_concurrent(&mut self) {
        if let Task::Repeated {
            concurrent_calls, ..
        } = self
        {
            *concurrent_calls += 1;
        }
    }
    pub(crate) fn decrement_concurrent(&mut self) {
        if let Task::Repeated {
            concurrent_calls, ..
        } = self
        {
            if *concurrent_calls > 0 {
                *concurrent_calls -= 1;
            }
        }
    }
}

pub(crate) fn increment_all_calls() {
    ALL_CALLS.set(ALL_CALLS.get() + 1);
}

pub(crate) fn decrement_all_calls() {
    let current = ALL_CALLS.get();
    if current > 0 {
        ALL_CALLS.set(current - 1);
    }
}
