#[rustfmt::skip]

use std::collections::BTreeSet;
use std::process::Command;

use crate::driver::new::{context::GroupContext, task::Task};

pub struct TaskExecutor {}

impl TaskExecutor {
    pub fn execute(ctx: &GroupContext, tasks: &mut BTreeSet<Task>) -> BTreeSet<Task> {
        let mut processed_tasks: BTreeSet<Task> = BTreeSet::new();
        // TODO: make this function communicate with a sub-process
        for task in tasks.iter() {
            let test_name = task.name();

            let mut child = Command::new(ctx.exec_path.clone())
                .arg("--working-dir")
                .arg(ctx.group_dir().as_os_str())
                .arg("spawn-child")
                .arg(test_name.as_str())
                .arg("ABC")
                .arg("XYZ")
                .spawn()
                .expect("failed to start child");

            let ecode = child.wait().expect("failed to wait on child");

            processed_tasks.insert(if ecode.success() {
                task.mk_passed()
            } else {
                task.mk_failed(format!("child exited with code {:?}", ecode))
            });
        }
        processed_tasks
    }
}
