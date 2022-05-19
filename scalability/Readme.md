# Benchmarking Suite for the IC

The benchmarking suite is structured as follows:

- An abstraction for experiments together with a set of experiments {1, 2, 3, .. ,n}
- An abstraction for metrics, with an implementation of flamegraph and prometheus metrics.
- A report generator that renders a human-friendly summary report from those experiments.
- A integration for sending performance data points to Grafana dashboard.
- A pattern for exercising scenario max capacity and a pattern for spot exercising and performance verification.

Currently, there is support for installing canisters, running the workload generator with different configurations and collecting statistics for it.

Maximum capacity experiments run in iterations, where each iteration typically increases stress on the system, until the benchmake suite considers system can no longer process more transactions.

Each experiment has an entry point.  `run_experiment_*.py` for a spot run, or `max_capacity_*.py` for a maximum capacity run. Worth noting that, maximum capacity runs internally call spot runs, in iteration.

When running benchmarks, the tool collects all measurements and metrics, most of them are collected for each iteration the benchmark is running, which will be used to generate summary report that includes iteration measurements. The reports are HTML reports, and they contain rich content (such as flamegraphs), but they also contain links to existing material such as existing Grafana dashboards.

Report generation (generate_report.py) is decoupled from the benchmark runs. It can be invoked by supplying the `base_dir` directory which is the root of previous experiment run artifacts are generated into, the `git_revision` of IC the experiment was executed on, and the `timestamp` the experiment is marked with. `results`, `git_revision` and `timestamp` will be concatenated to form the full artifact directory of the previous experiment run. An example of generating report command will look like:
```common/generate_report.py --base_dir "results/" --git_revision 9f8390a49caaf43b1bd5a9d3e566ec4837b687eb --timestamp 1651766562```
In this example, `generate_report.py` script will compile the report from artifacts in directory of `scalability/results/9f8390a49caaf43b1bd5a9d3e566ec4837b687eb/1651766562`.  Please note, always trigger your scripts from `scalability/` folder as the root.

The code is as follows:
- `metrics.py`: Abstraction for metrics. Can be started and stopped, which typically happens at the beginning and end of an iteration respectively. Currently supported are:
   - `flamegraphs.py`: Generation of flamegraphs on the target machine.
   - `prometheus.py`: Downloads metrics collected during benchmark execution on Prometheus.
- `ssh.py`: Helpers to execute commands remotely via SSH
- `experiment.py`: Base class for experiments. Implements common functionality like installing canisters or running the workload generator.
   - `workload_experiment.py`: Base class for workload generator based experiments. In addition to `experiment.py`, those experiments have built-in support for running the workload generator.
   - `run_*_experiment.py`: Each of those implement a single benchmark as descrobed in IC-562
   - `max_capacity_*.py`: Maximum capacity variants of the experiments - increases loads iteratively until the system starts to fail.
 - `report.py` and `generate_report.py`: Scripts to generate HTML reports out of collected measurements from experiment executions.
   - `templates/`: folder for storing templates to generate HTML reports. There is one main`experiment.html.hb` is the main experiment report template, with `experiment_*.html.hb` defining the template for the experiment-specific part of the report. The name of the template file has to match what's given as first argument to `write_summary_file`.


# Install dependencies

A clean way of managing dependencies for a python project, is via isolated virtual environment.
`pipenv` tool is handy for this purpose.

- Configure your local virtual environment and install the dependencies:
  ```
  $ cd ic/scalability
  ``` 
  ```
  $ pipenv --python 3
  ```
  ```
  $ pipenv install -r requirements.txt
  ```

# Deploy IC on the testnet

Experiments that don't require workload generators (directly inheriting from `experiment.py`) require *one* testnet: 
the testnet on which we install canisters to benchmark.
It should ideally be close to the hardware we are running in mainnet.
Currently, testnets `benchmarklarge`, `benchmarksmall01` and `benchmarksmall02` are good candidates.

Experiments using workload generators (based on `workload_experiment.py`) require *two* testnets in order to 
guarantee a consistent setup of the workload generator machines.
In those tests,
we deploy workload generator instances on the guest OS images in that second testnet.
That means, that we also initially deploy an IC there, even though we turn off replicas during experimentation so that
the workload generator can be started there instead.

The use of a second testnet has multiple advantages:

 1. We can easily run multiple workload generators, as we have enough machines to deploy to and run the workload generator from.
    This is very important for some of the experiments, as otherwise, the client side of the experiment could become the 
    bottleneck and not issue enough requests (or not issue those requests at a consistent rate).
 2. We get a uniform environment to run the workload generator from (in contrast to some people running it in data centers and others
    from their laptop)
 3. Testnet machines are scrape targets for Prometheus, so we can immediately monitor the client side without additional setup.

`--help` on the experiment file will inform you what the required arguments are 
(both `--testnet` and `--wg_testnet` or only the former).

Depending on your requirements, boot the testnets as usual.
  ```
  $ testnet/tools/icos_deploy.sh $TESTNET --git-revision $(./gitlab-ci/src/artifacts/newest_sha_with_disk_image.sh origin/master)
  $ testnet/tools/icos_deploy.sh $WG_TESTNET --git-revision $(./gitlab-ci/src/artifacts/newest_sha_with_disk_image.sh origin/master)
  ```

# Run the benchmark (experiment)

There is a collection of flags to instruct how to run an experiment. Common ones are:
* use_updates
* initial_rps
* increment_rps
* target_rps
* max_rps
* testnet
* ... 

You can add more flags for your experiment as needed. 

For the common workload setting flags (e.g. `initial_rps`, `increment_rps`, `target_rps`, `max_rps`), as their definition are shared between query experiments and update experiments, the default values are also shared between the two. So it is expected from experiment developer, to set sensible workload targets for the environment they run the experiment on. A typical way of doing it correctly, takes a couple of tries of different values, to find a sensible compilation of numbers, to set to the recurring pipeline.

Make sure you have *two* testnets reserved, then:

- Run the python script corresponding to your benchmark. A good starting point is the following, which benchmarks system overhead by stressing with query and update calls. Default are queries, use `--use_updates=True` for update calls:

  ```
  $  pipenv run experiments/max_capacity_system_baseline.py --testnet $TESTNET --wg_testnet $WG_TESTNET
  ```
- You can observe the benchmark on the following dashboard: https://grafana.dfinity.systems/d/u016YUeGz/workload-generator-metrics?orgId=1&refresh=5s - make sure to select the target subnetwork *as well as* the subnetwork with workload generators under "IC" and "IC workload generator" at the top respectively.
- Create the report `pipenv run generate_report.py --base_dir {your_artifacts_root_dir} --git_revision {IC_revision_your_experiment_ran_on} --timestamp {the_timestamp_marker_of_your_experiment}`. This is normally called from the suite automatically, so in many cases you won't to manually run it.

# Run against mainnet

Use `--testnet mercury`. Also need to specify `--mainnet_target_subnet_id` to determine machines to run against as well as `--canister`. 
The latter is a coma separated list of canister that have to be pre-installed on mainnet (since a wallet is needed, deploying canisters is different on mainnet and currently not supported by the suite).

There is also a flag `--no_instrument=True` to disable instrumenting the target machine (for which we don't have SSH access on mainnet). 
The suite will then not get a flamegraph and hardware information, but the benchmarks itself will work as usual.

# Stress-testing mainnet.

 1. Reserve all `large0x` testnets, possibly more. Each of those has 4 subnetworks. The number of subnetworks of all the machines you book has to be larger than the number of subnetworks you want to stress in mainnet (e.g. all for `large0x` subnets together have 16 subnetworks, which allows you to stress 16 subnetworks in mainnet concurrently).
 2. Boot (any) IC OS on all of those (just a usual deployment via `icos_deploy`).
 3. Update variable `testnets` in the constructor of `Mainnet` to reflect the subnetworks that you have booked. The workload generator will be ran from there.
 4. Open a tmux session (just type `tmux` on e.g. spm34).
 5. `cd` into you `scalability` in your IC checkout
 5. Configure the desired rate of updates/second per subnetwork by setting variable `LOAD_MAX`.
 5. Run `pipenv run run_mainnet.py`
 
 Observe the dashboards

# Adding new experiment

In order to add a new experiment:

 - Create a new file `run_experiment_foobar.py`
 - Create a class `ExperimentFoobar` with inherits from `Experiment` or `WorkloadExperiment` depending on whether you need to run workload generator to stress your system.
 - Implement method `init_experiment` which is being called exactly once when the experiment is first set up.
 - Implement method `run_experiment_internal` which implements the actual benchmark logic. It's typically configurable, so that the benchmark can be executed repeatedly with e.g. increasing load. `config` is a dict that can be used to pass on configuration arguments.
 - Implement `if __name__ == "__main__":` that initializes your experiment, calls `start_experiment` followed by (potentially a series of) `run_experiment` with a sensible configuration for your experiment.
 - Finally call `write_summary_file` and `end_experiment` to generate a report.
 - Add a template file for your experiment to add more details to the generated report in `templates/experiment_foobar.html.hb`. Have a look at existing ones for inspiration.  
  
Consider other experiments `run_experiment_*.py` for inspiration. Notable `run_system_baseline_experiment.py` for an example of a workload experiment as well as `run_xnet_experiment.py` for one that doesn't.

## Debugging

For debugging purposes, it is normally useful to instruct python to pop up a debugger on any exception.

```
pipenv run python3 -m pdb -c continue ./run_XXX_experiment.py
```

This way, if an exception occurs, the debugger will be opened and the program state can be displayed at the point at
which the exception has happened.
