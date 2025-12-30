use crate::tasks::{TASKS, Task, TaskQueue, TaskType, pop_if_ready, run_task, schedule_now};
use crate::test_fixtures::mock::MockCanisterRuntime;
use proptest::{collection::vec as pvec, prop_assert_eq, proptest};
use std::time::Duration;

proptest! {
    #[test]
    fn should_hold_one_copy_of_each_task(
        timestamps in pvec(1_000_000_u64..1_000_000_000, 2..100),
    ) {
        let mut task_queue: TaskQueue = Default::default();
        for (i, ts) in timestamps.iter().enumerate() {
            task_queue.schedule_at(*ts, TaskType::ProcessLogic);
            prop_assert_eq!(task_queue.len(), 1, "queue: {:?}", task_queue);

            let task = task_queue.pop_if_ready(u64::MAX).unwrap();

            prop_assert_eq!(task_queue.len(), 0);

            prop_assert_eq!(&task, &Task{
                execute_at: timestamps[0..=i].iter().cloned().min().unwrap(),
                task_type: TaskType::ProcessLogic
            });
            task_queue.schedule_at(task.execute_at, task.task_type);

            prop_assert_eq!(task_queue.len(), 1);
        }
    }
}

#[tokio::test]
async fn should_reschedule_process_logic() {
    test_reschedule(
        TaskType::ProcessLogic,
        || crate::guard::TimerLogicGuard::new().unwrap(),
        Duration::from_secs(5),
    )
    .await;
}

#[tokio::test]
async fn should_reschedule_refresh_fees() {
    test_reschedule(
        TaskType::RefreshFeePercentiles,
        || crate::guard::TimerLogicGuard::new().unwrap(),
        Duration::from_secs(60 * 60),
    )
    .await;
}

async fn test_reschedule<T, G: FnOnce() -> T>(
    task_type: TaskType,
    guard: G,
    expected_deadline: Duration,
) {
    init_state();
    let mut runtime = MockCanisterRuntime::new();
    runtime.expect_time().return_const(0_u64);
    runtime.expect_global_timer_set().return_const(());
    runtime
        .expect_refresh_fee_percentiles_frequency()
        .return_const(Duration::from_secs(60 * 60));
    schedule_now(task_type.clone(), &runtime);

    let _guard_mocking_already_running_task = guard();
    let task = pop_if_ready(&runtime).unwrap();
    assert_eq!(
        task,
        Task {
            execute_at: 0,
            task_type: task_type.clone(),
        }
    );
    assert_eq!(task_deadline_from_state(&task_type), None);

    run_task(task, runtime).await;

    assert_eq!(
        task_deadline_from_state(&task_type),
        Some(expected_deadline.as_nanos() as u64)
    );
}

fn task_deadline_from_state(task: &TaskType) -> Option<u64> {
    TASKS.with(|t| t.borrow().deadline_by_task.get(task).cloned())
}

fn init_state() {
    crate::test_fixtures::init_state(crate::test_fixtures::init_args());
}
