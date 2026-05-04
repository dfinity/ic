use ic_cdk_timers::TimerId;
use slotmap::SlotMap;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::mem;
use std::pin::Pin;
use std::time::{Duration, SystemTime};

enum TimerTask {
    OneShot(OneShotTimerTask),
    Recurring(RecurringTimerTask),
}

impl Default for TimerTask {
    fn default() -> Self {
        TimerTask::OneShot(OneShotTimerTask::default())
    }
}

impl TimerTask {
    fn next_run(&self) -> Duration {
        match self {
            TimerTask::Recurring(task) => task.run_at_duration_after_epoch,
            TimerTask::OneShot(task) => task.run_at_duration_after_epoch,
        }
    }
}

trait RepeatedClosure {
    fn call_mut<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = ()> + 'a>>;
}

impl<F: AsyncFnMut()> RepeatedClosure for F {
    fn call_mut<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = ()> + 'a>> {
        Box::pin(self())
    }
}

struct RecurringTimerTask {
    pub interval: Duration,
    pub run_at_duration_after_epoch: Duration,
    pub func: Box<dyn RepeatedClosure>,
}

impl Default for RecurringTimerTask {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(u64::MAX),
            run_at_duration_after_epoch: Duration::default(),
            func: Box::new(async || {}),
        }
    }
}

struct OneShotTimerTask {
    pub run_at_duration_after_epoch: Duration,
    pub fut: Pin<Box<dyn Future<Output = ()>>>,
}

impl Default for OneShotTimerTask {
    fn default() -> Self {
        Self {
            run_at_duration_after_epoch: Duration::default(),
            fut: Box::pin(async {}),
        }
    }
}

thread_local! {
    // This could be improved to use some other kind of time that would be perhaps
    // common to all time-based functions in the system.  However, using systemtime
    // would make the tests slow, so that is not a good option.
    pub static CURRENT_TIME: RefCell<Duration> = RefCell::new(SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap());
    pub static TIMER_TASKS: RefCell<SlotMap<TimerId, TimerTask >> = RefCell::default();
}

pub fn set_timer(delay: Duration, fut: impl Future<Output = ()> + 'static) -> TimerId {
    let current_time = CURRENT_TIME.with(|current_time| *current_time.borrow());
    TIMER_TASKS.with(|timer_tasks| {
        timer_tasks
            .borrow_mut()
            .insert(TimerTask::OneShot(OneShotTimerTask {
                run_at_duration_after_epoch: current_time + delay,
                fut: Box::pin(fut),
            }))
    })
}

pub fn set_timer_interval(interval: Duration, func: impl AsyncFnMut() + 'static) -> TimerId {
    let current_time = CURRENT_TIME.with(|current_time| *current_time.borrow());
    TIMER_TASKS.with(|timer_tasks| {
        timer_tasks
            .borrow_mut()
            .insert(TimerTask::Recurring(RecurringTimerTask {
                interval,
                run_at_duration_after_epoch: current_time + interval,
                func: Box::new(func),
            }))
    })
}

pub fn clear_timer(id: TimerId) {
    TIMER_TASKS.with(|timer_intervals| {
        timer_intervals.borrow_mut().remove(id);
    });
}
// Set the time as seconds since unix epoch
pub fn set_time_for_timers(duration_since_epoch: Duration) {
    CURRENT_TIME.with(|current_time| {
        *current_time.borrow_mut() = duration_since_epoch;
    });
}

pub fn get_time_for_timers() -> Duration {
    CURRENT_TIME.with(|current_time| *current_time.borrow())
}

pub fn advance_time_for_timers(duration: Duration) {
    CURRENT_TIME.with(|current_time| {
        *current_time.borrow_mut() += duration;
    });
}

pub async fn run_pending_timers() {
    let current_time = CURRENT_TIME.with(|current_time| *current_time.borrow());

    let tasks: BTreeMap<TimerId, TimerTask> = TIMER_TASKS.with(|timer_tasks| {
        let mut timer_tasks = timer_tasks.borrow_mut();
        let mut runnable_ids = vec![];
        for (id, timer_task) in timer_tasks.iter_mut() {
            if current_time >= timer_task.next_run() {
                runnable_ids.push(id);
            }
        }
        runnable_ids
            .into_iter()
            .map(|id| (id, timer_tasks.get_mut(id).map(mem::take).unwrap()))
            .collect()
    });

    for (id, task) in tasks.into_iter() {
        match task {
            TimerTask::OneShot(task) => {
                task.fut.await;
                TIMER_TASKS.with(|timer_tasks| {
                    timer_tasks.borrow_mut().remove(id);
                });
            }
            TimerTask::Recurring(mut task) => {
                task.func.call_mut().await;
                task.run_at_duration_after_epoch += task.interval;
                TIMER_TASKS.with(|timer_tasks| {
                    if let Some(slot) = timer_tasks.borrow_mut().get_mut(id) {
                        *slot = TimerTask::Recurring(task)
                    };
                });
            }
        }
    }
}

pub async fn run_pending_timers_every_interval_for_count(interval: Duration, count: u64) {
    for _ in 0..count {
        advance_time_for_timers(interval);
        run_pending_timers().await;
    }
}

pub fn has_timer_task(timer_id: TimerId) -> bool {
    TIMER_TASKS.with(|timers| timers.borrow().contains_key(timer_id))
}

pub fn existing_timer_ids() -> Vec<TimerId> {
    TIMER_TASKS.with(|timers| timers.borrow().keys().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_timers_setting_running_and_clearing() {
        thread_local! {
            static TIMER_1_COUNT: RefCell<u64> = const { RefCell::new(0) };
            static TIMER_2_COUNT: RefCell<u64> = const { RefCell::new(0) };
        }

        let timer_1_id = set_timer(Duration::from_secs(10), async {
            TIMER_1_COUNT.with(|count| {
                *count.borrow_mut() += 1;
            });
        });
        let timer_2_id = set_timer_interval(Duration::from_secs(5), async || {
            TIMER_2_COUNT.with(|count| {
                *count.borrow_mut() += 1;
            });
        });
        assert!(has_timer_task(timer_1_id));
        assert!(has_timer_task(timer_2_id));

        let current_time = get_time_for_timers();

        // Run the timers
        run_pending_timers().await;

        // Check nothing ran yet
        TIMER_1_COUNT.with(|count| {
            assert_eq!(*count.borrow(), 0);
        });
        TIMER_2_COUNT.with(|count| {
            assert_eq!(*count.borrow(), 0);
        });

        // Advance time by 5 seconds
        set_time_for_timers(current_time + Duration::from_secs(1));
        advance_time_for_timers(Duration::from_secs(4));

        // Run the timers
        run_pending_timers().await;

        // Check that the second timer ran
        TIMER_1_COUNT.with(|count| {
            assert_eq!(*count.borrow(), 0);
        });
        TIMER_2_COUNT.with(|count| {
            assert_eq!(*count.borrow(), 1);
        });

        run_pending_timers_every_interval_for_count(Duration::from_secs(5), 2).await;

        // Check that the first timer ran
        TIMER_1_COUNT.with(|count| {
            assert_eq!(*count.borrow(), 1);
        });
        TIMER_2_COUNT.with(|count| {
            assert_eq!(*count.borrow(), 3);
        });

        // Timer 1 should no longer exist, but timer 2 is an interval.
        assert!(!has_timer_task(timer_1_id));
        assert!(has_timer_task(timer_2_id));

        clear_timer(timer_2_id);

        assert!(!has_timer_task(timer_2_id));

        run_pending_timers_every_interval_for_count(Duration::from_secs(5), 2).await;

        // Check that second timer is in fact not running
        TIMER_2_COUNT.with(|count| {
            assert_eq!(*count.borrow(), 3);
        });

        // Time internally advances as expected
        assert_eq!(
            get_time_for_timers(),
            current_time + Duration::from_secs(25)
        );
    }
}
