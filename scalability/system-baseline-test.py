#!/usr/bin/env python3
import os
import sys
import time

import experiment
import gflags
import misc
import run_experiment_1

FLAGS = gflags.FLAGS

gflags.DEFINE_string("base_revision", "", "Git revision to measure pre-upgrade performance")
gflags.DEFINE_string("upgrade_revision", "", "Git revision to measure post-upgrade performance")
gflags.DEFINE_integer("target_query_load", 300, "Target query load in queries per second to issue.")
gflags.DEFINE_integer("target_update_load", 40, "Target update load in queries per second to issue.")
gflags.DEFINE_integer("iter_duration", 300, "Duration in seconds for which to execute workload in each round")

if __name__ == "__main__":
    experiment.parse_command_line_args()
    failures = 0
    result_file = "verification_results.txt"

    # 1. Measure system baseline performance on base version
    FLAGS.should_deploy_ic = True
    FLAGS.git_revision = FLAGS.base_revision
    os.environ["GIT_REVISION"] = FLAGS.base_revision

    # 1.1 Measure system baseline performance on base version with query calls
    FLAGS.use_updates = False
    FLAGS.load = FLAGS.target_query_load

    print(f"Performance test of {FLAGS.load} query calls on version {FLAGS.git_revision} starts now. ")
    base_query_datapoints = [FLAGS.target_query_load]
    base_query_start = int(time.time())
    (
        base_query_failure_rate,
        base_query_t_median,
        base_query_t_average,
        base_query_t_max,
        base_query_t_min,
        base_query_total_requests,
        base_query_num_success,
        base_query_num_failure,
    ) = run_experiment_1.Experiment1().run_iterations(base_query_datapoints)
    base_query_duration = int(time.time()) - base_query_start

    # 1.2 Measure system baseline performance on base version with update calls
    FLAGS.should_deploy_ic = False
    FLAGS.use_updates = True
    FLAGS.load = FLAGS.target_update_load

    print(f"Performance test of {FLAGS.load} update calls on version {FLAGS.git_revision} starts now. ")
    base_update_datapoints = [FLAGS.target_update_load]
    base_update_start = int(time.time())
    (
        base_update_failure_rate,
        base_update_t_median,
        base_update_t_average,
        base_update_t_max,
        base_update_t_min,
        base_update_total_requests,
        base_update_num_success,
        base_update_num_failure,
    ) = run_experiment_1.Experiment1().run_iterations(base_update_datapoints)
    base_update_duration = int(time.time()) - base_update_start

    # 1.3 Validate base version query and update results
    failures += misc.verify("Query failure rate", base_query_failure_rate, 0, 0, result_file)
    failures += misc.verify("Query median latency", base_query_t_median, 350, 0.01, result_file)
    failures += misc.verify(
        "Query throughput",
        base_query_total_requests / base_query_duration,
        FLAGS.target_query_load,
        -0.01,
        result_file,
    )
    failures += misc.verify("Update failure rate", base_update_failure_rate, 0, 0, result_file)
    failures += misc.verify("Update median latency", base_update_t_median, 2700, 0.01, result_file)
    failures += misc.verify(
        "Update throughput",
        base_update_total_requests / base_update_duration,
        FLAGS.target_update_load,
        -0.01,
        result_file,
    )

    # 2. Measure system baseline performance on new version
    FLAGS.should_deploy_ic = True
    FLAGS.git_revision = FLAGS.upgrade_revision
    os.environ["GIT_REVISION"] = FLAGS.upgrade_revision

    # 2.1 Measure system baseline performance on upgrade version with query calls
    FLAGS.use_updates = True
    FLAGS.load = FLAGS.target_query_load

    print(f"Performance test of {FLAGS.load} query calls on version {FLAGS.git_revision} starts now. ")
    upgrade_query_datapoints = [FLAGS.target_query_load]
    upgrade_query_start = int(time.time())
    (
        upgrade_query_failure_rate,
        upgrade_query_t_median,
        upgrade_query_t_average,
        upgrade_query_t_max,
        upgrade_query_t_min,
        upgrade_query_total_requests,
        upgrade_query_num_success,
        upgrade_query_num_failure,
    ) = run_experiment_1.Experiment1().run_iterations(upgrade_query_datapoints)
    upgrade_query_duration = int(time.time()) - upgrade_query_start

    # 2.2 Measure system baseline performance on upgrade version with update calls
    FLAGS.should_deploy_ic = False
    FLAGS.use_updates = True
    FLAGS.load = FLAGS.target_update_load

    print(f"Performance test of {FLAGS.load} update calls on version {FLAGS.git_revision} starts now. ")
    upgrade_update_datapoints = [FLAGS.target_update_load]
    upgrade_update_start = int(time.time())
    (
        upgrade_update_failure_rate,
        upgrade_update_t_median,
        upgrade_update_t_average,
        upgrade_update_t_max,
        upgrade_update_t_min,
        upgrade_update_total_requests,
        upgrade_update_num_success,
        upgrade_update_num_failure,
    ) = run_experiment_1.Experiment1().run_iterations(upgrade_update_datapoints)
    upgrade_update_duration = int(time.time()) - upgrade_update_start

    # 2.3 Validate upgrade version query and update results
    failures += misc.verify("Query failure rate", upgrade_query_failure_rate, 0, 0, result_file)
    failures += misc.verify("Query median latency", upgrade_query_t_median, 350, 0.01, result_file)
    failures += misc.verify(
        "Query throughput",
        upgrade_query_total_requests / upgrade_query_duration,
        FLAGS.target_query_load,
        -0.01,
        result_file,
    )
    failures += misc.verify("Update failure rate", upgrade_update_failure_rate, 0, 0, result_file)
    failures += misc.verify("Update median latency", upgrade_update_t_median, 2700, 0.01, result_file)
    failures += misc.verify(
        "Update throughput",
        upgrade_update_total_requests / upgrade_update_duration,
        FLAGS.target_update_load,
        -0.01,
        result_file,
    )

    # 3. Verify system baseline performance on new version does not degrade from base version
    failures += misc.verify(
        "Query failure rate", upgrade_query_failure_rate, base_query_failure_rate, 0.02, result_file
    )
    failures += misc.verify("Query median latency", upgrade_query_t_median, base_query_t_median, 0.02, result_file)
    failures += misc.verify(
        "Query throughput",
        upgrade_query_total_requests / upgrade_query_duration,
        base_query_total_requests / base_query_duration,
        -0.02,
        result_file,
    )
    failures += misc.verify(
        "Update failure rate", upgrade_update_failure_rate, base_update_failure_rate, 0.02, result_file
    )
    failures += misc.verify("Update median latency", upgrade_update_t_median, base_update_t_median, 0.02, result_file)
    failures += misc.verify(
        "Update throughput",
        upgrade_update_total_requests / upgrade_update_duration,
        base_update_total_requests / base_update_duration,
        -0.02,
        result_file,
    )

    if failures > 0:
        print(
            "❌ Performance did not meet expectation. Check verification_results.txt file for more detailed results. 😭😭😭"
        )
        sys.exit(1)

    print("✅ Performance verifications passed! 🎉🎉🎉")
