use std::time::Duration;
use std::{panic::catch_unwind, time::Instant};

use super::driver_setup::DriverContext;
use super::farm::{Farm, GroupSpec};
use super::pot_dsl::{ExecutionMode, Pot, Suite, Test, TestPath, TestSet};
use crate::driver::driver_setup::IcSetup;
use crate::driver::test_env::{HasTestPath, TestEnv, TestEnvAttribute};
use crate::driver::test_setup::PotSetup;
use anyhow::{bail, Result};
use crossbeam_channel::{bounded, Receiver, RecvTimeoutError, Sender};
use ic_fondue::result::*;
use slog::{error, info, warn, Logger};

pub const N_THREADS_PER_SUITE: usize = 8;
pub const N_THREADS_PER_POT: usize = 8;

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
        group_name: None,
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
            result: TestResult::Failed,
            ..TestResultNode::default()
        }
    });
    parent
        .send(result)
        .expect("failed to send result to parent node");
}

fn evaluate_pot(ctx: &DriverContext, mut pot: Pot, path: TestPath) -> Result<TestResultNode> {
    if pot.execution_mode == ExecutionMode::Skip {
        return Ok(TestResultNode {
            name: pot.name,
            ..TestResultNode::default()
        });
    }

    let pot_path = path.join(&pot.name);
    let group_name = format!("{}-{}", pot_path.url_string(), ctx.job_id)
        .replace(':', "_")
        .replace('.', "_");

    let pot_working_dir = ctx.working_dir.join(&pot.name).join("setup");
    let pot_env = ctx.env.fork(ctx.logger.clone(), pot_working_dir)?;

    pot_env
        .write_test_path(&pot_path)
        .expect("Could not write the pot test path");

    PotSetup {
        farm_group_name: group_name.clone(),
        pot_timeout: pot.pot_timeout.unwrap_or(ctx.pot_timeout),
        artifact_path: ctx.artifacts_path.clone(),
    }
    .write_attribute(&pot_env);

    create_group_for_pot(&pot_env, &pot, &ctx.logger)?;

    if let Err(e) = pot.setup.evaluate(pot_env.clone()) {
        if let Some(s) = e.downcast_ref::<String>() {
            bail!("Could not evaluate pot config: {}", s);
        } else if let Some(s) = e.downcast_ref::<&str>() {
            bail!("Could not evaluate pot config: {}", s);
        }
        bail!("Could not evaluate pot config: {:?}", e);
    };

    let res = evaluate_pot_with_group(ctx, pot, pot_path, &pot_env, &group_name);
    if let Err(e) = ctx.farm.delete_group(&group_name) {
        warn!(ctx.logger, "Could not delete group {}: {:?}", group_name, e);
    }
    res
}

fn create_group_for_pot(env: &TestEnv, pot: &Pot, logger: &Logger) -> Result<()> {
    let pot_setup = PotSetup::read_attribute(env);
    let ic_setup = IcSetup::read_attribute(env);
    let farm = Farm::new(ic_setup.farm_base_url, logger.clone());
    info!(logger, "creating group '{}'", &pot_setup.farm_group_name);
    Ok(farm.create_group(
        &pot_setup.farm_group_name,
        pot_setup.pot_timeout,
        GroupSpec {
            vm_allocation: pot.vm_allocation.clone(),
        },
    )?)
}

fn evaluate_pot_with_group(
    ctx: &DriverContext,
    pot: Pot,
    pot_path: TestPath,
    pot_env: &TestEnv,
    group_name: &str,
) -> Result<TestResultNode> {
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

    let (sender, receiver) = bounded(tests_num);
    let chunks = chunk(tests, no_threads);
    let mut join_handles = vec![];

    for chunk in chunks {
        let s = sender.clone();
        let join_handle = std::thread::spawn({
            let t_path = pot_path.clone();
            let t_pot_env = pot_env.clone();
            let t_ctx = ctx.clone();
            move || {
                for t in chunk {
                    // the pot env is in <pot>/setup. Hence, we take the parent,
                    // to create the path <pot>/tests/<test>
                    let t_env_dir = t_pot_env
                        .base_path()
                        .parent()
                        .expect("parent not set")
                        .to_owned()
                        .join("tests")
                        .join(&t.name);
                    let test_env = t_pot_env
                        .fork(t_ctx.logger.clone(), t_env_dir)
                        .expect("Could not create test env.");
                    evaluate_test(&t_ctx, test_env, s.clone(), t, t_path.clone());
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
        group_name: Some(group_name.to_string()),
        started_at,
        duration: started_at.elapsed(),
        result: infer_result(children.as_slice()),
        children,
    })
}

fn evaluate_test(
    ctx: &DriverContext,
    test_env: TestEnv,
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
    test_env
        .write_test_path(&path)
        .expect("Could not write test path");
    info!(ctx.logger, "Starting test: {}", path);

    let pot_setup = PotSetup::read_attribute(&test_env);
    // keep underlying group alive
    let (keep_alive_task, stop_sig_s) = keep_group_alive_task(
        ctx.logger.clone(),
        ctx.farm.clone(),
        &pot_setup.farm_group_name,
    );
    let task_handle = std::thread::spawn(keep_alive_task);
    let t_res = catch_unwind(|| (t.f)(test_env));
    if let Err(e) = stop_sig_s.send(()) {
        warn!(ctx.logger, "Could not send stop signal: {:?}", e);
    }
    std::mem::drop(stop_sig_s);
    task_handle.join().expect("could not join tickle handle");

    if let Err(panic_res) = t_res {
        if let Some(s) = panic_res.downcast_ref::<String>() {
            warn!(ctx.logger, "{} FAILED: {}", path, s);
        } else if let Some(s) = panic_res.downcast_ref::<&str>() {
            warn!(ctx.logger, "{} FAILED: {}", path, s);
        } else {
            warn!(ctx.logger, "{} FAILED (): {:?}", path, panic_res);
        }
        result.result = TestResult::Failed;
    } else {
        info!(ctx.logger, "{} SUCCESS.", path);
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

/// The goal of this choice of parameters is to
/// * not overload farm with repeated requests, ...
/// * while keeping the TTL as short as possible, and
/// * ensuring that setting the TTL is retried at least once in case of a failure.
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(15);
const GROUP_TTL: Duration = Duration::from_secs(50);

fn keep_group_alive_task(log: Logger, farm: Farm, group_name: &str) -> (impl FnMut(), Sender<()>) {
    let (stop_sig_s, stop_sig_r) = bounded::<()>(0);
    let group_name = group_name.to_string();
    let task = move || {
        while let Err(RecvTimeoutError::Timeout) = stop_sig_r.recv_timeout(KEEP_ALIVE_INTERVAL) {
            if let Err(e) = farm.set_group_ttl(&group_name, GROUP_TTL) {
                warn!(log, "Failed to set group ttl of {:?}: {:?}", group_name, e);
            }
        }
    };
    (task, stop_sig_s)
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
