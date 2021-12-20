use std::{panic::catch_unwind, time::Duration, time::Instant};

use crossbeam_channel::{bounded, Receiver, Sender};
use serde::Serialize;
use slog::{error, info, warn};

use super::bootstrap::{
    attach_config_disk_images, create_config_disk_images, init_ic, upload_config_disk_images,
};
use super::driver_setup::DriverContext;
use super::pot_dsl::{ExecutionMode, Pot, Suite, Test, TestPath, TestSet};
use super::resource::{allocate_resources, get_resource_request};
use super::test_setup::create_ic_handle;
use crate::ic_manager::IcHandle;
use crate::prod_tests::driver_setup::tee_logger;
use crate::prod_tests::farm::{FarmResult, GroupSpec};
use fondue::pot::Context;

pub const N_THREADS_PER_SUITE: usize = 6;
pub const N_THREADS_PER_POT: usize = 8;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TestResult {
    Passed,
    Failed,
    Skipped,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
/// A tree-like structure containing statistics on how much time it took to
/// complete a node and all its children, i.e. threads spawned from the node.
pub struct TestResultNode {
    pub name: String,
    #[serde(with = "serde_millis")]
    pub started_at: Instant,
    pub duration: Duration,
    pub result: TestResult,
    pub children: Vec<TestResultNode>,
}

impl Default for TestResultNode {
    fn default() -> Self {
        Self {
            name: String::default(),
            started_at: Instant::now(),
            duration: Duration::default(),
            result: TestResult::Skipped,
            children: vec![],
        }
    }
}

pub fn infer_result(tests: &[TestResultNode]) -> TestResult {
    if tests.iter().all(|t| t.result == TestResult::Skipped) {
        return TestResult::Skipped;
    }
    if tests.iter().any(|t| t.result == TestResult::Failed) {
        TestResult::Failed
    } else {
        TestResult::Passed
    }
}

pub fn evaluate(ctx: &DriverContext, ts: Suite) -> TestResultNode {
    let started_at = Instant::now();
    let pots: Vec<Pot> = ts
        .pots
        .into_iter()
        .filter(|p| p.execution_mode != ExecutionMode::Ignore)
        .collect();
    let pots_num = pots.len();

    let path = TestPath::new_with_root(ts.name.clone());
    let (sender, receiver) = bounded(pots.len());
    let chunks = chunk(pots, N_THREADS_PER_SUITE);

    let mut join_handles = vec![];
    for chunk in chunks {
        let s = sender.clone();

        let join_handle = std::thread::spawn({
            let t_path = path.clone();
            let t_ctx = ctx.clone();
            move || {
                for p in chunk {
                    evaluate_pot_and_propagate_result(&t_ctx, s.clone(), p, t_path.clone());
                }
            }
        });
        join_handles.push(join_handle);
    }

    for jh in join_handles {
        jh.join().expect("waiting for thread failed!");
    }

    let children = collect_n_children(receiver, pots_num);
    TestResultNode {
        name: ts.name,
        started_at,
        duration: started_at.elapsed(),
        result: infer_result(children.as_slice()),
        children,
    }
}

fn evaluate_pot_and_propagate_result(
    ctx: &DriverContext,
    parent: Sender<TestResultNode>,
    pot: Pot,
    path: TestPath,
) {
    let name = pot.name.clone();
    let result = evaluate_pot(ctx, pot, path).unwrap_or_else(|e| {
        error!(ctx.logger, "failed to execute pot {}: {}", &name, e);
        TestResultNode {
            name,
            ..TestResultNode::default()
        }
    });
    parent
        .send(result)
        .expect("failed to send result to parent node");
}

#[allow(clippy::mutex_atomic)]
fn evaluate_pot(ctx: &DriverContext, pot: Pot, path: TestPath) -> FarmResult<TestResultNode> {
    if pot.execution_mode == ExecutionMode::Skip {
        return Ok(TestResultNode {
            name: pot.name,
            ..TestResultNode::default()
        });
    }

    // set up the group
    let pot_path = path.join(&pot.name);
    let logger = ctx.logger();
    let group_name = format!("{}-{}", pot_path.url_string(), ctx.job_id)
        .replace(":", "_")
        .replace(".", "_");
    info!(logger, "creating group '{}'", group_name);
    let spec = GroupSpec {
        vm_allocation: pot.config.vm_allocation.clone(),
    };
    ctx.farm.create_group(&group_name, pot.time_limit, spec)?;
    let res = evaluate_pot_with_group(ctx, pot, pot_path, &group_name);
    if let Err(e) = ctx.farm.delete_group(&group_name) {
        warn!(ctx.logger, "Could not delete group {}: {:?}", group_name, e);
    }

    res
}

#[allow(clippy::mutex_atomic)]
fn evaluate_pot_with_group(
    ctx: &DriverContext,
    pot: Pot,
    pot_path: TestPath,
    group_name: &str,
) -> FarmResult<TestResultNode> {
    let logger = ctx.logger();
    let started_at = Instant::now();
    let (no_threads, all_tests) = match pot.testset {
        TestSet::Sequence(tests) => (1, tests),
        TestSet::Parallel(tests) => (N_THREADS_PER_POT, tests),
    };
    let tests: Vec<Test> = all_tests
        .into_iter()
        .filter(|t| t.execution_mode != ExecutionMode::Ignore)
        .collect();
    let tests_num = tests.len();

    let res_request = get_resource_request(ctx, &pot.config, group_name);
    let res_group = allocate_resources(ctx, &res_request)?;
    let temp_dir = tempfile::tempdir().expect("Could not create temp directory");
    let (init_ic, mal_beh, node_vms) = init_ic(ctx, temp_dir.path(), pot.config, &res_group);
    create_config_disk_images(ctx, group_name, &logger, &init_ic);
    let cfg_disk_image_ids = upload_config_disk_images(ctx, &init_ic, group_name)?;
    attach_config_disk_images(ctx, &res_group, cfg_disk_image_ids)?;
    let ic_handle = create_ic_handle(ctx, &init_ic, &node_vms, &mal_beh);
    info!(logger, "temp_dir: {:?}", temp_dir.path());

    let (sender, receiver) = bounded(tests_num);
    let chunks = chunk(tests, no_threads);

    let mut join_handles = vec![];

    for chunk in chunks {
        let s = sender.clone();
        let join_handle = std::thread::spawn({
            let t_path = pot_path.clone();
            let t_ctx = ctx.clone();
            let t_ic_handle = ic_handle.clone();
            move || {
                for t in chunk {
                    let t_path = t_path.clone();
                    let t_ic_handle = t_ic_handle.clone();
                    evaluate_test(&t_ctx, t_ic_handle, s.clone(), t, t_path.clone());
                }
            }
        });
        join_handles.push(join_handle);
    }
    for jh in join_handles {
        jh.join().expect("waiting for thread failed!");
    }
    let children = collect_n_children(receiver, tests_num);

    Ok(TestResultNode {
        name: pot.name.clone(),
        started_at,
        duration: started_at.elapsed(),
        result: infer_result(children.as_slice()),
        children,
    })
}

fn evaluate_test(
    ctx: &DriverContext,
    ic_handle: IcHandle,
    parent: Sender<TestResultNode>,
    t: Test,
    path: TestPath,
) {
    let mut result = TestResultNode {
        name: t.name.clone(),
        ..TestResultNode::default()
    };
    if t.execution_mode == ExecutionMode::Skip {
        parent
            .send(result)
            .expect("failed to send result to parent node");
        return;
    }

    let path = path.join(&t.name);
    let test_ctx = Context::new(ctx.rng.clone(), tee_logger(ctx, &path));
    info!(test_ctx.logger, "Starting test: {}", path);
    let t_res = catch_unwind(|| (t.f)(ic_handle, &test_ctx));
    if let Err(panic_res) = t_res {
        if let Some(s) = panic_res.downcast_ref::<String>() {
            warn!(test_ctx.logger, "{} FAILED: {}", path, s);
        } else {
            warn!(test_ctx.logger, "{} FAILED (): {:?}", path, panic_res);
        }
        result.result = TestResult::Failed;
    } else {
        info!(test_ctx.logger, "{} SUCCESS.", path);
        result.result = TestResult::Passed;
    }

    result.duration = result.started_at.elapsed();
    parent
        .send(result)
        .expect("failed to send result to parent node");
}

fn chunk<T>(items: Vec<T>, no_buckets: usize) -> Vec<Vec<T>> {
    let mut res: Vec<Vec<T>> = (0..no_buckets).map(|_| Vec::new()).collect();
    items
        .into_iter()
        .enumerate()
        .for_each(|(i, item)| res[i % no_buckets].push(item));
    res.retain(|i| !i.is_empty());
    res
}

pub fn collect_n_children(r: Receiver<TestResultNode>, n: usize) -> Vec<TestResultNode> {
    let mut ch = vec![];
    for _ in 0..n {
        let r = r.recv().expect("failed to fetch result from child");
        ch.push(r);
    }
    ch
}

#[cfg(test)]
mod tests {
    use super::chunk;
    use std::collections::HashSet;

    #[test]
    fn chunking_retains_all_elements() {
        for c in 1..11 {
            for n in 1..63 {
                let set: HashSet<_> = (0..n).collect();
                let chunks = chunk(set.iter().cloned().collect::<Vec<_>>(), c);
                assert_eq!(chunks.len().min(n), c.min(n));
                assert_eq!(chunks.concat().iter().cloned().collect::<HashSet<_>>(), set);
            }
        }
    }
}
