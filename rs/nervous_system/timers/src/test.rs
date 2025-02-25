use ic_cdk_timers::TimerId;
use slotmap::SlotMap;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::mem;
use std::time::{Duration, SystemTime};

pub enum TimerTask {
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

struct RecurringTimerTask {
    pub interval: Duration,
    pub run_at_duration_after_epoch: Duration,
    pub func: Box<dyn FnMut()>,
}

impl Default for RecurringTimerTask {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(u64::MAX),
            run_at_duration_after_epoch: Duration::default(),
            func: Box::new(|| {}),
        }
    }
}

struct OneShotTimerTask {
    pub run_at_duration_after_epoch: Duration,
    pub func: Box<dyn FnOnce()>,
}

impl Default for OneShotTimerTask {
    fn default() -> Self {
        Self {
            run_at_duration_after_epoch: Duration::default(),
            func: Box::new(|| {}),
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

pub fn set_timer(delay: Duration, func: impl FnOnce() + 'static) -> TimerId {
    let current_time = CURRENT_TIME.with(|current_time| *current_time.borrow());
    TIMER_TASKS.with(|timer_tasks| {
        timer_tasks
            .borrow_mut()
            .insert(TimerTask::OneShot(OneShotTimerTask {
                run_at_duration_after_epoch: current_time + delay,
                func: Box::new(func),
            }))
    })
}

pub fn set_timer_interval(interval: Duration, func: impl FnMut() + 'static) -> TimerId {
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

// TODO should we have this run intervals more than once if enough time has elapsed?
pub fn run_pending_timers() {
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
                (task.func)();
                TIMER_TASKS.with(|timer_tasks| {
                    timer_tasks.borrow_mut().remove(id);
                });
            }
            TimerTask::Recurring(mut task) => {
                (task.func)();
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

pub fn run_pending_timers_every_x_seconds(interval: Duration, count: u64) {
    for _ in 0..count {
        advance_time_for_timers(interval);
        run_pending_timers();
    }
}

pub fn has_timer_task(timer_id: TimerId) -> bool {
    TIMER_TASKS.with(|timers| timers.borrow().contains_key(timer_id))
}
