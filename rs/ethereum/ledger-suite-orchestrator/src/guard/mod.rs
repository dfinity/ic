use crate::scheduler::Task;
use crate::state::mutate_state;

#[derive(Eq, PartialEq, Debug)]
pub struct TimerGuard {
    task: Task,
}

impl TimerGuard {
    pub fn new(task: Task) -> Option<Self> {
        mutate_state(|s| {
            if !s.active_tasks.insert(task.clone()) {
                return None;
            }
            Some(Self { task })
        })
    }
}

impl Drop for TimerGuard {
    fn drop(&mut self) {
        mutate_state(|s| {
            s.active_tasks.remove(&self.task);
        });
    }
}
