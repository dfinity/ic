#!/usr/bin/env python3
import experiment
import gflags
import misc
import run_experiment_2

FLAGS = gflags.FLAGS

# Flags for query mode
gflags.DEFINE_integer("initial_rps", 100, "Start rps and increment in query mode.")
gflags.DEFINE_integer("target_query_load", 450, "Target query load in queries per second to issue.")
gflags.DEFINE_integer("max_query_load", 40000, "Maximum query load in queries per second to issue.")
gflags.DEFINE_integer("query_rps_increment", 50, "Increment of requests per second per round for queries.")

# Flags for update mode
gflags.DEFINE_integer("target_update_load", 130, "Target update load in queries per second to issue.")
gflags.DEFINE_integer("update_initial_rps", 20, "Start rps and increment in update mode.")
gflags.DEFINE_integer("max_update_load", 1000, "Maximum update load in queries per second to issue.")
gflags.DEFINE_integer("update_rps_increment", 5, "Increment of requests per second per round for update calls.")

# Duration in seconds for which to execute workload in each round.
gflags.DEFINE_integer("iter_duration", 300, "Duration per iteration of the benchmark.")
# Size of payload for the memory test canister
gflags.DEFINE_integer("payload_size", 5000000, "Payload size to use.")

# Maximum failure rate and median query duration limit to consider
# for rps to choose as rps_max. If failure rate or latency is higher,
# continue running the benchmark, but do not consider this RPS
# for max capacity
gflags.DEFINE_float("max_failure_rate", 0.2, "Maximum failure rate at which to consider the iteration successful.")
gflags.DEFINE_integer("max_t_median", 5000, "Maximum median latency at which to consider the iteration successful.")

# Maximum failure rate and median query duration limit for when to
# stop the benchmark.
# Looks like the workload generator timeout is 30s, so we will never
# see anything higher than that on average.
gflags.DEFINE_float("stop_failure_rate", 0.95, "Maximum failure rate before aborting the benchmark.")
gflags.DEFINE_integer("stop_t_median", 25000, "Maximum median latency before aborting the benchmark.")

if __name__ == "__main__":
    experiment.parse_command_line_args()

    exp = run_experiment_2.Experiment2()
    exp.start_experiment()

    failure_rate = 0.0
    t_median = 0.0
    run = True
    rps = []

    rps_max = 0
    rps_max_in = None

    num_succ_per_iteration = []

    iteration = 0
    datapoints = (
        misc.get_datapoints(
            FLAGS.target_update_load, FLAGS.update_initial_rps, FLAGS.max_update_load, FLAGS.update_rps_increment, 1.5
        )
        if exp.use_updates
        else misc.get_datapoints(
            FLAGS.target_query_load, FLAGS.initial_rps, FLAGS.max_query_load, FLAGS.query_rps_increment, 1.5
        )
    )

    while run:

        load_total = datapoints[iteration]
        iteration += 1

        rps.append(load_total)
        print(f"🚀 Testing with load: {load_total} and updates={exp.use_updates}")

        failure_rate, t_median, _, _, _, _, num_succ, _ = exp.run_experiment(
            {
                "rps_total": load_total,
                "payload_size": FLAGS.payload_size,
                "duration": FLAGS.iter_duration,
            }
        )

        num_succ_per_iteration.append(num_succ)

        print(f"🚀  ... failure rate for {load_total} rps was {failure_rate} median latency is {t_median}")

        if failure_rate < FLAGS.max_failure_rate and t_median < FLAGS.max_t_median:
            if num_succ / exp.last_duration > rps_max:
                rps_max = num_succ / exp.last_duration
                rps_max_in = load_total

        run = failure_rate < FLAGS.stop_failure_rate and t_median < FLAGS.stop_t_median and iteration < len(datapoints)

        # Write summary file in each iteration including experiment specific data.
        rtype = "update" if exp.use_updates else "query"
        state = "running" if run else "done"
        exp.write_summary_file(
            "experiment_2",
            {
                "rps": rps,
                "rps_max": rps_max,
                "rps_max_in": rps_max_in,
                "num_succ_per_iteration": num_succ_per_iteration,
            },
            rps,
            "requests / s",
            rtype=rtype,
            state=state,
        )

        print(f"🚀  ... maximum capacity so far is {rps_max}")

    exp.end_experiment()
