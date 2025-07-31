use crate::metrics::MetricsRegistryRef;
use crate::RecurringAsyncTask;
use async_trait::async_trait;
use std::cell::RefCell;
use std::collections::VecDeque;

use std::thread::LocalKey;
use std::time::Duration;

#[derive(Debug, Default)]
pub struct JobQueue<T> {
    tasks: VecDeque<T>,
}

pub enum JobProcessorError<T: Send> {
    Requeue(T),
    TaskProcessingFailed(String),
}

pub fn add_to_queue<T: Send + 'static>(queue: &'static LocalKey<RefCell<JobQueue<T>>>, task: T) {
    queue.with_borrow_mut(|queue| queue.enqueue(task));
}

pub fn process_queue<T: Send + 'static, Processor: JobProcessor<T> + 'static>(
    queue: &'static LocalKey<RefCell<JobQueue<T>>>,
    initial_delay: Duration,
    reschedule_delay: Duration,
    processor: Processor,
    metrics_registry: MetricsRegistryRef,
) {
    JobWorker::new(queue, initial_delay, reschedule_delay, processor).schedule(metrics_registry)
}

#[async_trait]
pub trait JobProcessor<T: Send>: Send + 'static {
    async fn process(&self, task: T) -> Result<(), JobProcessorError<T>>;
    fn handle_failure(&self, error: JobProcessorError<T>);
}

struct JobWorker<T: 'static + Send, Processor: JobProcessor<T> + Send + 'static> {
    queue: &'static LocalKey<RefCell<JobQueue<T>>>,
    initial_delay: Duration,
    delay_between_runs: Duration,
    processor: Processor,
}

impl<T: Send + 'static, Processor: JobProcessor<T> + Send + 'static> JobWorker<T, Processor> {
    pub fn new(
        queue: &'static LocalKey<RefCell<JobQueue<T>>>,
        initial_delay: Duration,
        delay_between_runs: Duration,
        processor: Processor,
    ) -> Self {
        Self {
            queue,
            initial_delay,
            delay_between_runs,
            processor,
        }
    }

    fn next(&self) -> Option<T> {
        self.queue.with_borrow_mut(|queue| queue.dequeue())
    }

    fn queue_has_items(&self) -> bool {
        !self.queue.with_borrow(|queue| queue.is_empty())
    }

    fn add_task(&self, task: T) {
        self.queue.with_borrow_mut(|queue| queue.enqueue(task));
    }
}

#[async_trait]
impl<T: Send + 'static, Processor: JobProcessor<T> + Send + 'static> RecurringAsyncTask
    for JobWorker<T, Processor>
{
    async fn execute(self) -> (Option<Duration>, Self) {
        let work_item = match self.next() {
            Some(task) => task,
            // Don't reschedule if there are no tasks
            None => return (None, self),
        };

        match self.processor.process(work_item).await {
            Ok(_) => {
                // Successfully processed the task, return the next delay
                let next_delay = self.queue_has_items().then_some(self.delay_between_runs);

                (next_delay, self)
            }
            Err(JobProcessorError::Requeue(task)) => {
                // Requeue the task for later processing
                self.add_task(task);
                (Some(self.delay_between_runs), self)
            }
            Err(JobProcessorError::TaskProcessingFailed(err)) => {
                // Log the error and return the next delay
                eprintln!("Task processing failed: {}", err);
                (Some(self.delay_between_runs), self)
            }
        }
    }

    fn initial_delay(&self) -> Duration {
        self.initial_delay
    }

    const NAME: &'static str = "JobWorker_RecurringAsyncTask";
}

impl<T> JobQueue<T> {
    fn new() -> Self {
        Self {
            tasks: Default::default(),
        }
    }

    fn enqueue(&mut self, task: T) {
        self.tasks.push_back(task);
    }

    fn dequeue(&mut self) -> Option<T> {
        self.tasks.pop_front()
    }

    fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TimerTaskMetricsRegistry;
    use ic_nervous_system_timers::test::{
        existing_timer_ids, run_pending_timers_every_interval_for_count,
    };
    use std::cell::RefCell;
    use std::time::Duration;

    thread_local! {
        static TEST_QUEUE: RefCell<JobQueue<TestJob>> = RefCell::new(JobQueue::new());
        static PROCESSED_JOBS: RefCell<Vec<String>> = RefCell::new(Vec::new());
        static TEST_METRICS: RefCell<TimerTaskMetricsRegistry> = RefCell::new(TimerTaskMetricsRegistry::default());
        static PROCESS_CALL_COUNT: RefCell<u32> = RefCell::new(0);
    }

    #[derive(Debug, Clone, PartialEq)]
    struct TestJob {
        id: String,
        action: JobAction,
    }

    #[derive(Debug, Clone, PartialEq)]
    enum JobAction {
        Process,      // Process successfully
        Requeue(u32), // Requeue this many more times before processing
        Fail,         // Fail permanently
    }

    struct TestJobProcessor;

    #[async_trait]
    impl JobProcessor<TestJob> for TestJobProcessor {
        async fn process(&self, job: TestJob) -> Result<(), JobProcessorError<TestJob>> {
            // Increment the process call counter
            PROCESS_CALL_COUNT.with_borrow_mut(|count| *count += 1);

            match job.action {
                JobAction::Process => {
                    // Record successful processing
                    PROCESSED_JOBS.with_borrow_mut(|jobs| jobs.push(job.id));
                    Ok(())
                }
                JobAction::Requeue(remaining_requeues) => {
                    if remaining_requeues > 0 {
                        // Still need to requeue - decrement the count
                        let requeued_job = TestJob {
                            id: job.id,
                            action: JobAction::Requeue(remaining_requeues - 1),
                        };
                        Err(JobProcessorError::Requeue(requeued_job))
                    } else {
                        // Done re-queuing, now process
                        PROCESSED_JOBS.with_borrow_mut(|jobs| jobs.push(job.id));
                        Ok(())
                    }
                }
                JobAction::Fail => Err(JobProcessorError::TaskProcessingFailed(format!(
                    "Job {} failed",
                    job.id
                ))),
            }
        }

        fn handle_failure(&self, _error: JobProcessorError<TestJob>) {
            // Test implementation - just ignore failures
        }
    }

    fn clear_test_state() {
        TEST_QUEUE.with_borrow_mut(|queue| *queue = JobQueue::new());
        PROCESSED_JOBS.with_borrow_mut(|jobs| jobs.clear());
        PROCESS_CALL_COUNT.with_borrow_mut(|count| *count = 0);
    }

    #[tokio::test]
    async fn test_basic_job_processing() {
        clear_test_state();

        // Add some jobs to process
        add_to_queue(
            &TEST_QUEUE,
            TestJob {
                id: "job1".to_string(),
                action: JobAction::Process,
            },
        );
        add_to_queue(
            &TEST_QUEUE,
            TestJob {
                id: "job2".to_string(),
                action: JobAction::Process,
            },
        );

        // Create and start worker
        process_queue(
            &TEST_QUEUE,
            Duration::from_millis(10),
            Duration::from_millis(50),
            TestJobProcessor,
            &TEST_METRICS,
        );

        // Verify timer is running
        let timer_ids = existing_timer_ids();
        assert_eq!(timer_ids.len(), 1, "Should have exactly one timer running");

        // Advance time to allow processing
        run_pending_timers_every_interval_for_count(Duration::from_millis(100), 5);

        // Verify jobs were processed
        let processed = PROCESSED_JOBS.with_borrow(|jobs| jobs.clone());
        assert_eq!(processed, vec!["job1", "job2"]);

        // Verify process was called exactly twice (once per job)
        let call_count = PROCESS_CALL_COUNT.with_borrow(|count| *count);
        assert_eq!(call_count, 2, "Process should be called exactly twice");

        // Verify timer is no longer running (worker stopped due to empty queue)
        let timer_ids_after = existing_timer_ids();
        assert_eq!(
            timer_ids_after.len(),
            0,
            "Should have no timers running after queue is empty"
        );
    }

    #[tokio::test]
    async fn test_job_requeuing() {
        clear_test_state();

        // Add a job that will requeue twice before processing
        add_to_queue(
            &TEST_QUEUE,
            TestJob {
                id: "requeue_job".to_string(),
                action: JobAction::Requeue(2),
            },
        );

        process_queue(
            &TEST_QUEUE,
            Duration::from_millis(10),
            Duration::from_millis(50),
            TestJobProcessor,
            &TEST_METRICS,
        );

        // Verify timer is running
        let timer_ids = existing_timer_ids();
        assert_eq!(timer_ids.len(), 1, "Should have exactly one timer running");

        // Advance time to allow processing
        run_pending_timers_every_interval_for_count(Duration::from_millis(100), 5);

        // Verify job was eventually processed after requeuing
        let processed = PROCESSED_JOBS.with_borrow(|jobs| jobs.clone());
        assert_eq!(processed, vec!["requeue_job"]);

        // Verify process was called exactly 3 times (initial + 2 requeues)
        let call_count = PROCESS_CALL_COUNT.with_borrow(|count| *count);
        assert_eq!(
            call_count, 3,
            "Process should be called 3 times: initial attempt + 2 requeues"
        );

        // Verify timer is no longer running
        let timer_ids_after = existing_timer_ids();
        assert_eq!(
            timer_ids_after.len(),
            0,
            "Should have no timers running after queue is empty"
        );
    }

    #[tokio::test]
    async fn test_worker_stops_when_queue_empty() {
        clear_test_state();

        // Add one job
        add_to_queue(
            &TEST_QUEUE,
            TestJob {
                id: "single_job".to_string(),
                action: JobAction::Process,
            },
        );

        process_queue(
            &TEST_QUEUE,
            Duration::from_millis(10),
            Duration::from_millis(50),
            TestJobProcessor,
            &TEST_METRICS,
        );

        // Verify timer is running
        let timer_ids = existing_timer_ids();
        assert_eq!(timer_ids.len(), 1, "Should have exactly one timer running");

        // Advance time to allow processing
        run_pending_timers_every_interval_for_count(Duration::from_millis(100), 5);

        // Verify job was processed
        let processed = PROCESSED_JOBS.with_borrow(|jobs| jobs.clone());
        assert_eq!(processed, vec!["single_job"]);

        // Verify process was called exactly once
        let call_count = PROCESS_CALL_COUNT.with_borrow(|count| *count);
        assert_eq!(call_count, 1, "Process should be called exactly once");

        // Advance time to allow processing
        run_pending_timers_every_interval_for_count(Duration::from_millis(100), 5);

        // Should still only have the one job (worker stopped)
        let processed_after = PROCESSED_JOBS.with_borrow(|jobs| jobs.clone());
        assert_eq!(processed_after, vec!["single_job"]);
    }

    #[tokio::test]
    async fn test_multiple_workers_processing_different_jobs() {
        clear_test_state();

        // Add multiple jobs
        for i in 1..=5 {
            add_to_queue(
                &TEST_QUEUE,
                TestJob {
                    id: format!("job{}", i),
                    action: JobAction::Process,
                },
            );
        }

        // Start multiple workers
        process_queue(
            &TEST_QUEUE,
            Duration::from_millis(10),
            Duration::from_millis(30),
            TestJobProcessor,
            &TEST_METRICS,
        );
        process_queue(
            &TEST_QUEUE,
            Duration::from_millis(20),
            Duration::from_millis(30),
            TestJobProcessor,
            &TEST_METRICS,
        );

        // Verify timers are running
        let timer_ids = existing_timer_ids();
        assert_eq!(timer_ids.len(), 2, "Should have exactly two timers running");

        // Advance time to allow processing
        run_pending_timers_every_interval_for_count(Duration::from_millis(100), 5);

        // Verify all jobs were processed exactly once
        let mut processed = PROCESSED_JOBS.with_borrow(|jobs| jobs.clone());
        processed.sort();
        assert_eq!(processed, vec!["job1", "job2", "job3", "job4", "job5"]);

        // Verify process was called exactly 5 times (once per job)
        let call_count = PROCESS_CALL_COUNT.with_borrow(|count| *count);
        assert_eq!(call_count, 5, "Process should be called exactly 5 times");

        // Verify timers are no longer running
        let timer_ids_after = existing_timer_ids();
        assert_eq!(
            timer_ids_after.len(),
            0,
            "Should have no timers running after all queues are empty"
        );
    }

    #[tokio::test]
    async fn test_mixed_job_types_with_failures_and_requeues() {
        clear_test_state();

        // Add mixed job types
        add_to_queue(
            &TEST_QUEUE,
            TestJob {
                id: "process1".to_string(),
                action: JobAction::Process,
            },
        );
        add_to_queue(
            &TEST_QUEUE,
            TestJob {
                id: "requeue1".to_string(),
                action: JobAction::Requeue(1),
            },
        );
        add_to_queue(
            &TEST_QUEUE,
            TestJob {
                id: "fail1".to_string(),
                action: JobAction::Fail,
            },
        );
        add_to_queue(
            &TEST_QUEUE,
            TestJob {
                id: "process2".to_string(),
                action: JobAction::Process,
            },
        );

        process_queue(
            &TEST_QUEUE,
            Duration::from_millis(10),
            Duration::from_millis(50),
            TestJobProcessor,
            &TEST_METRICS,
        );

        // Verify timer is running
        let timer_ids = existing_timer_ids();
        assert_eq!(timer_ids.len(), 1, "Should have exactly one timer running");

        // Advance time to allow processing
        run_pending_timers_every_interval_for_count(Duration::from_millis(100), 5);

        // Verify successful jobs were processed (excluding failed ones)
        let mut processed = PROCESSED_JOBS.with_borrow(|jobs| jobs.clone());
        processed.sort();
        assert_eq!(processed, vec!["process1", "process2", "requeue1"]);

        // Verify process was called 5 times: process1(1) + requeue1(2) + fail1(1) + process2(1)
        let call_count = PROCESS_CALL_COUNT.with_borrow(|count| *count);
        assert_eq!(call_count, 5, "Process should be called 5 times: 2 immediate successes + 2 requeue attempts + 1 failure");

        // Verify timer is no longer running
        let timer_ids_after = existing_timer_ids();
        assert_eq!(
            timer_ids_after.len(),
            0,
            "Should have no timers running after queue is empty"
        );
    }
}
