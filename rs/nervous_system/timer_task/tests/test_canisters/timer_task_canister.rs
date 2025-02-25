use async_trait::async_trait;
use ic_cdk::{init, query};
use ic_nervous_system_timer_task::{
    PeriodicAsyncTask, PeriodicSyncTask, RecurringAsyncTask, RecurringSyncTask,
};
use std::{cell::RefCell, collections::BTreeMap, time::Duration};

fn increase_counter(name: &'static str) {
    COUNTERS.with_borrow_mut(|counters| {
        let counter = counters.entry(name.to_string()).or_insert(0);
        *counter += 1;
    });
}

thread_local! {
    static COUNTERS : RefCell<BTreeMap<String, u64>> = RefCell::new(BTreeMap::new());
}

fn schedule(name: &str) {
    match name {
        SuccessRecurringSyncTask::NAME => SuccessRecurringSyncTask::default().schedule(),
        IncrementalDelayRecurringSyncTask::NAME => {
            IncrementalDelayRecurringSyncTask::default().schedule()
        }
        PanicRecurringSyncTask::NAME => PanicRecurringSyncTask::default().schedule(),
        OutOfInstructionsRecurringSyncTask::NAME => {
            OutOfInstructionsRecurringSyncTask::default().schedule()
        }
        SuccessRecurringAsyncTask::NAME => SuccessRecurringAsyncTask::default().schedule(),
        PanicRecurringAsyncTask::NAME => PanicRecurringAsyncTask::default().schedule(),
        OutOfInstructionsBeforeCallRecurringAsyncTask::NAME => {
            OutOfInstructionsBeforeCallRecurringAsyncTask::default().schedule()
        }
        OutOfInstructionsAfterCallRecurringAsyncTask::NAME => {
            OutOfInstructionsAfterCallRecurringAsyncTask::default().schedule()
        }
        SuccessPeriodicSyncTask::NAME => SuccessPeriodicSyncTask::default().schedule(),
        SuccessPeriodicAsyncTask::NAME => SuccessPeriodicAsyncTask::default().schedule(),
        PanicPeriodicAsyncTask::NAME => PanicPeriodicAsyncTask::default().schedule(),
        _ => panic!("Unknown task: {}", name),
    }
}

#[init]
fn canister_init(tasks: Vec<String>) {
    for task in tasks {
        schedule(&task);
    }
}

#[query]
fn get_counter(name: String) -> u64 {
    COUNTERS.with_borrow(|counters| *counters.get(&name).unwrap_or(&0))
}

#[query]
fn __self_call() {}

async fn invoke_self_call() {
    let () = ic_cdk::call(ic_cdk::api::id(), "__self_call", ())
        .await
        .unwrap();
}

fn main() {}

#[derive(Default)]
struct SuccessRecurringSyncTask {}

impl RecurringSyncTask for SuccessRecurringSyncTask {
    fn execute(self) -> (Duration, Self) {
        increase_counter(Self::NAME);
        (Duration::from_secs(1), self)
    }

    fn initial_delay(&self) -> Duration {
        Duration::from_secs(0)
    }

    const NAME: &'static str = "SuccessRecurringSyncTask";
}

#[derive(Default)]
struct IncrementalDelayRecurringSyncTask {
    counter: u64,
}

impl RecurringSyncTask for IncrementalDelayRecurringSyncTask {
    fn execute(self) -> (Duration, Self) {
        increase_counter(Self::NAME);
        let new_counter = self.counter + 1;
        let delay = Duration::from_secs(new_counter);
        (
            delay,
            Self {
                counter: new_counter,
            },
        )
    }

    fn initial_delay(&self) -> Duration {
        Duration::from_secs(0)
    }

    const NAME: &'static str = "IncrementalDelayRecurringSyncTask";
}

#[derive(Default)]
struct PanicRecurringSyncTask {}

impl RecurringSyncTask for PanicRecurringSyncTask {
    fn execute(self) -> (Duration, Self) {
        increase_counter(Self::NAME);
        panic!("This task always panics");
    }

    fn initial_delay(&self) -> Duration {
        Duration::from_secs(0)
    }

    const NAME: &'static str = "PanicRecurringSyncTask";
}

#[derive(Default)]
struct OutOfInstructionsRecurringSyncTask {}

impl RecurringSyncTask for OutOfInstructionsRecurringSyncTask {
    #[allow(unreachable_code)]
    fn execute(self) -> (Duration, Self) {
        increase_counter(Self::NAME);
        loop {
            ic_cdk::api::instruction_counter();
        }
        (Duration::from_secs(1), self)
    }

    fn initial_delay(&self) -> Duration {
        Duration::from_secs(0)
    }

    const NAME: &'static str = "OutOfInstructionsRecurringSyncTask";
}

#[derive(Default)]
struct SuccessRecurringAsyncTask {}

#[async_trait]
impl RecurringAsyncTask for SuccessRecurringAsyncTask {
    async fn execute(self) -> (Duration, Self) {
        invoke_self_call().await;

        increase_counter(Self::NAME);
        (Duration::from_secs(1), self)
    }

    fn initial_delay(&self) -> Duration {
        Duration::from_secs(0)
    }

    const NAME: &'static str = "SuccessRecurringAsyncTask";
}

#[derive(Default)]
struct PanicRecurringAsyncTask {}

#[async_trait]
impl RecurringAsyncTask for PanicRecurringAsyncTask {
    async fn execute(self) -> (Duration, Self) {
        increase_counter(Self::NAME);
        invoke_self_call().await;
        panic!("This task always panics");
    }

    fn initial_delay(&self) -> Duration {
        Duration::from_secs(0)
    }

    const NAME: &'static str = "PanicRecurringAsyncTask";
}

#[derive(Default)]
struct OutOfInstructionsBeforeCallRecurringAsyncTask {}

#[async_trait]
impl RecurringAsyncTask for OutOfInstructionsBeforeCallRecurringAsyncTask {
    #[allow(unreachable_code)]
    async fn execute(self) -> (Duration, Self) {
        increase_counter(Self::NAME);

        loop {
            ic_cdk::api::instruction_counter();
        }

        invoke_self_call().await;
        (Duration::from_secs(1), self)
    }

    fn initial_delay(&self) -> Duration {
        Duration::from_secs(0)
    }

    const NAME: &'static str = "OutOfInstructionsBeforeCallRecurringAsyncTask";
}

#[derive(Default)]
struct OutOfInstructionsAfterCallRecurringAsyncTask {}

#[async_trait]
impl RecurringAsyncTask for OutOfInstructionsAfterCallRecurringAsyncTask {
    #[allow(unreachable_code)]
    async fn execute(self) -> (Duration, Self) {
        increase_counter(Self::NAME);
        invoke_self_call().await;

        loop {
            ic_cdk::api::instruction_counter();
        }

        (Duration::from_secs(1), self)
    }

    fn initial_delay(&self) -> Duration {
        Duration::from_secs(0)
    }

    const NAME: &'static str = "OutOfInstructionsAfterCallRecurringAsyncTask";
}

#[derive(Default, Clone, Copy)]
struct SuccessPeriodicSyncTask {}

impl PeriodicSyncTask for SuccessPeriodicSyncTask {
    fn execute(self) {
        increase_counter(Self::NAME);
    }

    const NAME: &'static str = "SuccessPeriodicSyncTask";
    const INTERVAL: Duration = Duration::from_secs(1);
}

#[derive(Default, Clone, Copy)]
struct SuccessPeriodicAsyncTask {}

#[async_trait]
impl PeriodicAsyncTask for SuccessPeriodicAsyncTask {
    async fn execute(self) {
        increase_counter(Self::NAME);
    }

    const NAME: &'static str = "SuccessPeriodicAsyncTask";
    const INTERVAL: Duration = Duration::from_secs(1);
}

#[derive(Default, Clone, Copy)]
struct PanicPeriodicAsyncTask {}

#[async_trait]
impl PeriodicAsyncTask for PanicPeriodicAsyncTask {
    async fn execute(self) {
        increase_counter(Self::NAME);
        invoke_self_call().await;
        panic!("This task always panics");
    }

    const NAME: &'static str = "PanicPeriodicAsyncTask";
    const INTERVAL: Duration = Duration::from_secs(1);
}
