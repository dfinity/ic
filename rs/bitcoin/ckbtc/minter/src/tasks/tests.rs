use crate::tasks::tests::mock::MockCanisterRuntime;
use crate::tasks::{pop_if_ready, run_task, schedule_now, Task, TaskType, TASKS};
use std::time::Duration;

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

#[tokio::test]
async fn should_reschedule_distribute_kyt_fee() {
    test_reschedule(
        TaskType::DistributeKytFee,
        || crate::guard::DistributeKytFeeGuard::new().unwrap(),
        Duration::from_secs(24 * 60 * 60),
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

mod mock {
    use crate::CanisterRuntime;
    use async_trait::async_trait;
    use mockall::mock;

    mock! {
        pub CanisterRuntime {}

        #[async_trait]
        impl CanisterRuntime for CanisterRuntime {
            fn time(&self) -> u64;
            fn global_timer_set(&self, timestamp: u64);
        }
    }
}
