#!/usr/bin/env python3
import os
import sys
import time

import experiment
import gflags
import misc
import run_experiment_1
from elasticsearch import ElasticSearch

FLAGS = gflags.FLAGS

gflags.DEFINE_string(
    "base_revision",
    "",
    'Git revision hash to measure pre-upgrade performance. E.g. "391fd19f2154471f01068aaa771084eac010a099".',
)
gflags.DEFINE_string(
    "upgrade_revision",
    "",
    'Git revision hash to measure post-upgrade performance. E.g. "391fd19f2154471f01068aaa771084eac010a099".',
)
gflags.DEFINE_string(
    "base_branch", "", 'Git branch to measure pre-upgrade performance. E.g., "origin/rc--2021-12-31_18-31".'
)
gflags.DEFINE_string(
    "upgrade_branch", "", 'Git branch to measure post-upgrade performance. E.g. "origin/rc--2022-01-01_18-31".'
)
gflags.DEFINE_integer("target_query_load", 300, "Target query load in queries per second to issue.")
gflags.DEFINE_integer("target_update_load", 40, "Target update load in queries per second to issue.")
gflags.DEFINE_integer("iter_duration", 300, "Duration in seconds for which to execute workload in each round")


if __name__ == "__main__":
    experiment.parse_command_line_args()
    experiment_name = "System_Baseline_Nightly"

    query_median_latency_threshold = 75
    query_median_latency_delta_threshold = 0.1
    query_failure_rate_threshold = 0
    query_failure_rate_delta_threshold = 0
    query_throughput_threhold = FLAGS.target_query_load
    query_throughput_delta_threshold = -0.05
    update_median_latency_threshold = 2700
    update_median_latency_delta_threshold = 0.1
    update_failure_rate_threshold = 0
    update_failure_rate_delta_threshold = 0
    update_throughput_threhold = FLAGS.target_update_load
    update_throughput_delta_threshold = -0.05

    if FLAGS.base_revision == "" or FLAGS.upgrade_revision == "":
        print("base_revision and upgrade_revision are not set. Using base_branch and upgrade_branch to set revisions.")

        if FLAGS.base_branch == "" or FLAGS.upgrade_branch == "":
            print(
                "base_branch and upgrade_branch are not set. Could not retrieve revisions. Please either set base_revision and upgrade_revision pair, or base_branch and upgrade_branch pair, and try again. Exiting."
            )
            sys.exit(1)

        FLAGS.base_branch = FLAGS.base_branch.replace("origin/", "")
        FLAGS.upgrade_branch = FLAGS.upgrade_branch.replace("origin/", "")
        print(f"Branches to be compared: {FLAGS.base_branch} vs. {FLAGS.upgrade_branch}")

        FLAGS.base_revision = misc.get_latest_ic_version_on_branch(FLAGS.base_branch)
        FLAGS.upgrade_revision = misc.get_latest_ic_version_on_branch(FLAGS.upgrade_branch)

    print(f"Revisions to be compared: {FLAGS.base_revision} vs. {FLAGS.upgrade_revision}")

    experiment_dir = (
        f"{experiment_name}/{int(time.time())}/{FLAGS.testnet}-{FLAGS.base_revision}-vs-{FLAGS.upgrade_revision}"
    )
    if not os.path.exists(experiment_dir):
        os.makedirs(experiment_dir)
    FLAGS.experiment_dir = experiment_dir
    result_file = f"{experiment_dir}/verification_results.txt"

    query_perf_failures = 0
    update_perf_failures = 0

    # 1. Measure system baseline performance on base version
    misc.try_deploy_ic(FLAGS.testnet, FLAGS.base_revision, f"{experiment_dir}/{FLAGS.base_revision}")

    # 1.1 Measure system baseline performance on base version with query calls
    FLAGS.use_updates = False
    FLAGS.load = FLAGS.target_query_load

    print(f"Performance test of {FLAGS.load} query calls on version {FLAGS.base_revision} starts now. ")
    base_query_datapoints = [FLAGS.target_query_load]
    base_query_start = int(time.time())
    base_query_exp = run_experiment_1.Experiment1()
    (
        base_query_failure_rate,
        base_query_t_median,
        base_query_t_average,
        base_query_t_max,
        base_query_t_min,
        base_query_total_requests,
        base_query_num_success,
        base_query_num_failure,
        base_query_rps,
    ) = base_query_exp.run_iterations(base_query_datapoints)

    # 1.2 Measure system baseline performance on base version with update calls
    FLAGS.use_updates = True
    FLAGS.load = FLAGS.target_update_load

    print(f"Performance test of {FLAGS.load} update calls on version {FLAGS.base_revision} starts now. ")
    base_update_datapoints = [FLAGS.target_update_load]
    base_update_start = int(time.time())
    base_update_exp = run_experiment_1.Experiment1()
    (
        base_update_failure_rate,
        base_update_t_median,
        base_update_t_average,
        base_update_t_max,
        base_update_t_min,
        base_update_total_requests,
        base_update_num_success,
        base_update_num_failure,
        base_update_rps,
    ) = base_update_exp.run_iterations(base_update_datapoints)

    # 1.3 Validate base version query and update results
    query_perf_failures += misc.verify(
        "Query failure rate", base_query_failure_rate, query_failure_rate_threshold, 0, result_file
    )
    query_perf_failures += misc.verify(
        "Query median latency", base_query_t_median, query_median_latency_threshold, 0.01, result_file
    )
    update_perf_failures += misc.verify(
        "Update failure rate", base_update_failure_rate, update_failure_rate_threshold, 0, result_file
    )
    update_perf_failures += misc.verify(
        "Update median latency", base_update_t_median, update_median_latency_threshold, 0.01, result_file
    )

    # 2. Measure system baseline performance on new version
    misc.try_deploy_ic(FLAGS.testnet, FLAGS.upgrade_revision, f"{experiment_dir}/{FLAGS.upgrade_revision}")

    # 2.1 Measure system baseline performance on upgrade version with query calls
    FLAGS.use_updates = False
    FLAGS.load = FLAGS.target_query_load

    print(f"Performance test of {FLAGS.load} query calls on version {FLAGS.upgrade_revision} starts now. ")
    upgrade_query_datapoints = [FLAGS.target_query_load]
    upgrade_query_start = int(time.time())
    upgrade_query_exp = run_experiment_1.Experiment1()
    (
        upgrade_query_failure_rate,
        upgrade_query_t_median,
        upgrade_query_t_average,
        upgrade_query_t_max,
        upgrade_query_t_min,
        upgrade_query_total_requests,
        upgrade_query_num_success,
        upgrade_query_num_failure,
        upgrade_query_rps,
    ) = upgrade_query_exp.run_iterations(upgrade_query_datapoints)

    # 2.2 Measure system baseline performance on upgrade version with update calls
    FLAGS.use_updates = True
    FLAGS.load = FLAGS.target_update_load

    print(f"Performance test of {FLAGS.load} update calls on version {FLAGS.upgrade_revision} starts now. ")
    upgrade_update_datapoints = [FLAGS.target_update_load]
    upgrade_update_start = int(time.time())
    upgrade_update_exp = run_experiment_1.Experiment1()
    (
        upgrade_update_failure_rate,
        upgrade_update_t_median,
        upgrade_update_t_average,
        upgrade_update_t_max,
        upgrade_update_t_min,
        upgrade_update_total_requests,
        upgrade_update_num_success,
        upgrade_update_num_failure,
        upgrade_update_rps,
    ) = upgrade_update_exp.run_iterations(upgrade_update_datapoints)

    # 2.3 Validate upgrade version query and update results
    query_perf_failures += misc.verify(
        "Query failure rate", upgrade_query_failure_rate, query_failure_rate_threshold, 0, result_file
    )
    query_perf_failures += misc.verify(
        "Query median latency", upgrade_query_t_median, query_median_latency_threshold, 0.01, result_file
    )
    update_perf_failures += misc.verify(
        "Update failure rate", upgrade_update_failure_rate, update_failure_rate_threshold, 0, result_file
    )
    update_perf_failures += misc.verify(
        "Update median latency", upgrade_update_t_median, update_median_latency_threshold, 0.01, result_file
    )

    # 3. Verify system baseline performance on new version does not degrade from base version
    query_perf_failures += misc.verify(
        "Query failure rate",
        upgrade_query_failure_rate,
        base_query_failure_rate,
        query_failure_rate_delta_threshold,
        result_file,
    )
    query_perf_failures += misc.verify(
        "Query median latency",
        upgrade_query_t_median,
        base_query_t_median,
        query_median_latency_delta_threshold,
        result_file,
    )
    query_perf_failures += misc.verify(
        "Query throughput",
        upgrade_query_rps,
        base_query_rps,
        query_throughput_delta_threshold,
        result_file,
    )
    update_perf_failures += misc.verify(
        "Update failure rate",
        upgrade_update_failure_rate,
        base_update_failure_rate,
        update_failure_rate_delta_threshold,
        result_file,
    )
    update_perf_failures += misc.verify(
        "Update median latency",
        upgrade_update_t_median,
        base_update_t_median,
        update_median_latency_delta_threshold,
        result_file,
    )
    update_perf_failures += misc.verify(
        "Update throughput",
        upgrade_update_rps,
        base_update_rps,
        update_throughput_delta_threshold,
        result_file,
    )

    ElasticSearch.send_perf_compare(
        experiment_name,
        query_perf_failures <= 0,
        "Query",
        base_query_exp.git_hash,
        upgrade_query_exp.git_hash,
        FLAGS.base_branch,
        FLAGS.upgrade_branch,
        FLAGS.is_ci_job,
        (
            base_query_failure_rate,
            upgrade_query_failure_rate,
            query_failure_rate_threshold,
            query_failure_rate_delta_threshold,
            base_query_t_median,
            upgrade_query_t_median,
            query_median_latency_threshold,
            query_median_latency_delta_threshold,
            base_query_rps,
            upgrade_query_rps,
            query_throughput_threhold,
            query_throughput_delta_threshold,
        ),
    )

    ElasticSearch.send_perf_compare(
        experiment_name,
        update_perf_failures <= 0,
        "Update",
        base_query_exp.git_hash,
        upgrade_query_exp.git_hash,
        FLAGS.base_branch,
        FLAGS.upgrade_branch,
        FLAGS.is_ci_job,
        (
            base_update_failure_rate,
            upgrade_update_failure_rate,
            update_failure_rate_threshold,
            update_failure_rate_delta_threshold,
            base_update_t_median,
            upgrade_update_t_median,
            update_median_latency_threshold,
            update_median_latency_delta_threshold,
            base_update_rps,
            upgrade_update_rps,
            update_throughput_threhold,
            update_throughput_delta_threshold,
        ),
    )

    if query_perf_failures > 0 or update_perf_failures > 0:
        print(
            "❌ Performance did not meet expectation. Check verification_results.txt file for more detailed results. 😭😭😭"
        )
        sys.exit(1)

    print("✅ Performance verifications passed! 🎉🎉🎉")
