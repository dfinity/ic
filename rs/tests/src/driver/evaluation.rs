use std::{panic::catch_unwind, thread::JoinHandle, time::Duration};

use crate::driver::{
    config,
    driver_setup::{DriverContext, IcSetup},
    farm::{Farm, GroupSpec},
    pot_dsl::{ExecutionMode, Pot, Suite, Test, TestPath, TestSet},
    test_env::{HasTestPath, TestEnv, TestEnvAttribute},
    test_setup::PotSetup,
};
use anyhow::{bail, Result};
use crossbeam_channel::{bounded, Receiver, RecvTimeoutError, Sender};
use crossbeam_utils::sync::WaitGroup;
use ic_fondue::result::*;
use rayon::{ScopeFifo, ThreadPoolBuilder};
use slog::{error, info, warn, Logger};

// This function has a `dry-run` execution concept for the test suite.
// Namely, it generates a test suite contract, where all tests, pots, and the suite itself are labeled
pub fn generate_suite_execution_contract(suite: &Suite) -> TestSuiteContract {
    let mut pot_results: Vec<TestSuiteContract> = Vec::new();
    for pot in suite
        .pots
        .iter()
        .filter(|p| p.execution_mode != ExecutionMode::Ignore)
    {
        let mut tests_results_for_pot: Vec<TestSuiteContract> = Vec::new();
        for test in pot.testset.iter() {
            if test.execution_mode != ExecutionMode::Ignore {
                tests_results_for_pot.push(TestSuiteContract {
                    name: test.name.clone(),
                    is_skipped: test.execution_mode == ExecutionMode::Skip,
                    alert_channels: vec![],
                    children: vec![],
                });
            }
        }
        pot_results.push(TestSuiteContract {
            name: pot.name.clone(),
            is_skipped: false,
            alert_channels: if pot.alert_channels.is_empty() {
                suite.alert_channels.clone()
            } else {
                pot.alert_channels.clone()
            },
            children: tests_results_for_pot,
        })
    }
    TestSuiteContract {
        name: suite.name.clone(),
        is_skipped: false,
        alert_channels: vec![],
        children: pot_results,
    }
}

pub fn evaluate(ctx: &DriverContext, ts: Suite) {
    let pots = ts.pots;
    let path = &TestPath::new_with_root(ts.name);
    let pool = ThreadPoolBuilder::new()
        .num_threads(config::N_THREADS_PER_SUITE)
        .build()
        .expect("Could not create threadpool");

    pool.scope_fifo(move |scope| {
        let pots = pots
            .into_iter()
            .filter(|p| p.execution_mode != ExecutionMode::Ignore);

        for p in pots {
            scope.spawn_fifo(move |_| {
                let pot_name = p.name.clone();
                evaluate_pot(ctx, p, path).unwrap_or_else(|e| {
                    error!(ctx.logger, "Failed to execute pot {}: {}.", pot_name, e);
                });
            })
        }
    })
}

fn evaluate_pot(ctx: &DriverContext, mut pot: Pot, path: &TestPath) -> Result<()> {
    let pot_path = path.join(&pot.name);
    let group_name = format!("{}-{}", pot_path.url_string(), ctx.job_id)
        .replace(':', "_")
        .replace('.', "_");

    let pot_working_dir = ctx.working_dir.join(&pot.name).join(config::POT_SETUP_DIR);
    let pot_env = ctx.env.fork(ctx.logger.clone(), pot_working_dir)?;

    pot_env
        .write_test_path(&pot_path)
        .expect("Could not write the pot test path");

    PotSetup {
        farm_group_name: group_name.clone(),
        pot_timeout: pot.pot_timeout.unwrap_or(ctx.pot_timeout),
        artifact_path: ctx.artifacts_path.clone(),
        default_vm_resources: pot.default_vm_resources,
    }
    .write_attribute(&pot_env);

    // create the group (and start the keep alive thread) and evaluate the pot
    // setup
    let (pot_setup_result, keep_alive_handle_and_signal) =
        match create_group_for_pot_and_spawn_keepalive_thread(&pot_env, &pot, &ctx.logger) {
            Ok(keep_alive_handle_and_signal) => {
                let res = if let Err(err) = pot.setup.evaluate(pot_env.clone()) {
                    if let Some(s) = err.downcast_ref::<String>() {
                        TestResult::failed_with_message(s.as_str())
                    } else if let Some(s) = err.downcast_ref::<&str>() {
                        TestResult::failed_with_message(s)
                    } else {
                        TestResult::failed_with_message(format!("{:?}", err).as_str())
                    }
                } else {
                    TestResult::Passed
                };
                (res, Some(keep_alive_handle_and_signal))
            }
            Err(err) => (
                TestResult::failed_with_message(format!("{:?}", err).as_str()),
                None,
            ),
        };

    // store away the pot result before the pot's tests are evaluated
    pot_env
        .write_json_object(config::POT_SETUP_RESULT_FILE, &pot_setup_result)
        .unwrap_or_else(|e| {
            error!(
                ctx.logger,
                "Couldn't save pot setup result {} file: {}.",
                config::POT_SETUP_RESULT_FILE,
                e
            );
        });

    // fail fast in case of a setup failure
    if let TestResult::Failed(err) = pot_setup_result {
        bail!("Could not evaluate pot setup: {}", err);
    }

    evaluate_pot_with_group(ctx, pot, &pot_path, &pot_env);

    // at this point we should be guaranteed to have a task_handle
    if let Some((task_handle, stop_sig_s)) = keep_alive_handle_and_signal {
        info!(ctx.logger, "Stopping keep alive task for pot: {}", pot_path);
        if let Err(e) = stop_sig_s.try_send(()) {
            warn!(ctx.logger, "Could not send stop signal: {:?}", e);
        }
        std::mem::drop(stop_sig_s);
        info!(ctx.logger, "Joining keep alive task for pot: {}", pot_path);
        task_handle
            .join()
            .expect("could not join keep alive handle");
    }

    if let Err(e) = ctx.farm.delete_group(&group_name) {
        warn!(ctx.logger, "Could not delete group {}: {:?}", group_name, e);
    }
    Ok(())
}

fn create_group_for_pot_and_spawn_keepalive_thread(
    env: &TestEnv,
    pot: &Pot,
    logger: &Logger,
) -> Result<(JoinHandle<()>, Sender<()>)> {
    let pot_setup = PotSetup::read_attribute(env);
    let ic_setup = IcSetup::read_attribute(env);
    let farm = Farm::new(ic_setup.farm_base_url, logger.clone());
    info!(logger, "creating group '{}'", &pot_setup.farm_group_name);
    farm.create_group(
        &pot_setup.farm_group_name,
        pot_setup.pot_timeout,
        GroupSpec {
            vm_allocation: pot.vm_allocation.clone(),
            required_host_features: pot.required_host_features.clone(),
            preferred_network: ic_setup
                .preferred_network
                .map(|ipv6| ipv6.to_string() + "/128"),
        },
    )?;

    // keep the group alive using a background thread
    let (keep_alive_task, stop_sig_s) =
        keep_group_alive_task(logger.clone(), farm, &pot_setup.farm_group_name);
    let task_handle = std::thread::spawn(keep_alive_task);

    Ok((task_handle, stop_sig_s))
}

fn evaluate_pot_with_group(ctx: &DriverContext, pot: Pot, pot_path: &TestPath, pot_env: &TestEnv) {
    let pool = ThreadPoolBuilder::new()
        .num_threads(config::N_THREADS_PER_POT)
        .build()
        .expect("Could not create threadpool");
    pool.scope_fifo(move |scope| {
        scope.spawn_fifo(move |scope| {
            evaluate_testset_with_group(ctx, scope, pot.testset, pot_path, pot_env)
        })
    })
}

fn evaluate_testset_with_group<'scope>(
    ctx: &'scope DriverContext,
    scope: &ScopeFifo<'scope>,
    testset: TestSet,
    pot_path: &'scope TestPath,
    pot_env: &'scope TestEnv,
) {
    match testset {
        TestSet::Single(test) => {
            if test.execution_mode != ExecutionMode::Ignore {
                evaluate_test(ctx, pot_env, test, pot_path)
            }
        }
        TestSet::Sequence(tests) => {
            for test in tests {
                evaluate_testset_with_group(ctx, scope, test, pot_path, pot_env)
            }
        }
        TestSet::Parallel(tests) => {
            let wg = WaitGroup::new();
            for test in tests {
                let wg = wg.clone();
                scope.spawn_fifo(move |scope| {
                    let _wg = wg;
                    evaluate_testset_with_group(ctx, scope, test, pot_path, pot_env)
                });
            }
            wg.wait();
        }
    }
}

fn evaluate_test(ctx: &DriverContext, pot_env: &TestEnv, t: Test, pot_path: &TestPath) {
    use slog::Drain;
    let discard_drain = slog::Discard;
    let logger = if ctx.propagate_test_logs {
        ctx.logger()
    } else {
        slog::Logger::root(discard_drain.fuse(), slog::o!())
    };

    // the pot env is in <pot>/setup. Hence, we take the parent,
    // to create the path <pot>/tests/<test>
    let t_env_dir = pot_env
        .base_path()
        .parent()
        .expect("parent not set")
        .to_owned()
        .join(config::TESTS_DIR)
        .join(&t.name);
    let test_env = pot_env
        .fork(logger, t_env_dir)
        .expect("Could not create test env.");

    let mut result = TestResultNode {
        name: t.name.clone(),
        ..TestResultNode::default()
    };

    if t.execution_mode == ExecutionMode::Skip {
        return;
    }

    let path = pot_path.join(&t.name);
    test_env
        .write_test_path(&path)
        .expect("Could not write test path");
    info!(ctx.logger, "Starting test: {}", path);
    let t_res = catch_unwind(|| (t.f)(test_env.clone()));

    if let Err(panic_res) = t_res {
        if let Some(s) = panic_res.downcast_ref::<String>() {
            warn!(ctx.logger, "{} FAILED: {}", path, s);
            result.result = TestResult::failed_with_message(s);
        } else if let Some(s) = panic_res.downcast_ref::<&str>() {
            warn!(ctx.logger, "{} FAILED: {}", path, s);
            result.result = TestResult::failed_with_message(s);
        } else {
            warn!(ctx.logger, "{} FAILED (): {:?}", path, panic_res);
            result.result = TestResult::failed_with_message(format!("{:?}", panic_res).as_str());
        }
    } else {
        info!(ctx.logger, "{} SUCCESS.", path);
        result.result = TestResult::Passed;
    }

    result.duration = result.started_at.elapsed();
    // Failure of an individual test should not cause panic of the pot execution.
    test_env
        .write_json_object(config::TEST_RESULT_FILE, &result)
        .unwrap_or_else(|e| {
            error!(
                ctx.logger,
                "Couldn't save test result {} file, err={}.",
                config::TEST_RESULT_FILE,
                e
            );
        })
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
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(30);
const GROUP_TTL: Duration = Duration::from_secs(90);

fn keep_group_alive_task(log: Logger, farm: Farm, group_name: &str) -> (impl FnMut(), Sender<()>) {
    // A non-empty channel guarantees that a signal can be sent at least once
    // without the sender being blocked.
    let (stop_sig_s, stop_sig_r) = bounded::<()>(1);
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
