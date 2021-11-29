# Benchmarking Suite for the IC

The benchmarking suite is structured as follows:

- An abstraction for experiments together with a set of experiments {1, 2, 3, .. ,n}
- An abstraction for metrics, with an implementation of flamegraph and prometheus metrics.
- A simple first report generator to render results from those experiments.

Currently, there is support for installing canisters, running the workload generator with different configurations and collecting statistics for it.

Experiments typically run in iterations, where each iteration typically increases stress on the system.

Each experiment has an entry point at `run_experiment_n.py`.
Some of them (currently only Experiment 1) have a maximum capacity script as well (`max-capacity-experiment-n.py`), where the load of the system is incrementally increased until failures occur.

When running benchmarks, the tool collects all measurements and quite a few metrics, most of them are collected for each iteration the benchmark is running.

A separate tool can be used to generate reports for previously collected benchmark runs (generate_report.py). 
Those are HTML reports. Later, we can introduce more reports, e.g. to monitor performance over time. 
Reports contain rich content (such as flamegraphs), but they also contain links to existing material such as existing Grafana dashboards.


The code is as follows:
- `metrics.py`: Abstraction for metrics. Can be started and stopped, which typically happens at the beginning and end of an iteration respectively. Currently supported are:
   - `flamegraphs.py`: Generation of flamegraphs on the target machine.
   - `prometheus.py`: Downloads metrics collected during benchmark execution on Prometheus.
- `ssh.py`: Helpers to execute commands remotely via SSH
- `experiment.py`: Base class for experiments. Implements common functionality like installing canisters or running the workload generator.
   - `run_experiment_{1,2,3}.py`: Implements the given experiments as described in the IC-562
   - `max-capacity-experiment-1.py`: Maximum capacity variants of the experiments - increases loads iteratively until the system starts to fail. Currently only experiment 1 is implemented.
 - `report.py` and `generate_report.py`: Scripts to generate HTML reports out of collected measurements from experiment executions.
   - `templates/`: folder for storing templates to generate HTML reports. There is one main`experiment.html.hb` is the main experiment report template, with `experiment_{1,2,3}.html.hb` defining the template for the experiment-specific part of the report.


# Install dependencies

A clean way of managing dependencies for a python project, is via isolated virtual environment.
`pipenv` tool is handy for this purpose.

- Configure your local virtual environment and install the dependencies:
  ```
  $ cd ic/scalability
  ``` 
  ```
  $ pipenv --python 3.8.10 # or some other python version
  ```
  ```
  $ pipenv shell # this will activate the environment
  ```
  ```
  $ pip install -r requirements.txt
  ```

# Deploy IC on the testnet
In order to properly run experiments here, you should book *two* testnets.

One of the testnets will be the one to run the experiments against. It should ideally be close to what we are running in mainnet.
Currently, testnets `benchmarklarge`, `benchmarksmall01` and `benchmarksmall02` are good candidates.

Experiments typically also need a second testnet. We deploy workload generator instances on the guest OS images in that testnet.
That means, that we also initially deploy an IC there, even though we turn off replicas there during experimentation so that
the workload generator can be started there instead.

This has multiple advantages:

 1. We can easily run multiple workload generators, as we have enough machines to deploy to and run the workload generator from.
    This is very important for some of the experiments, as otherwise, the client side of the experiment could become the 
    bottleneck and not issue enough requests.
 2. We get a uniform environment to run the workload generator from (in contrast to some people running it in data centers and others
    from their laptop)
 3. Testnet machines are scrape targets for Prometheus, so we can immediately monitor the client side without additional setup.

  ```
  $ testnet/tools/icos_deploy.sh $TESTNET --git-revision $(git rev-parse origin/master)
  $ testnet/tools/icos_deploy.sh $WG_TESTNET --git-revision $(git rev-parse origin/master)
  ```

# Run the benchmark (experiment)

As described above, make sure you have *two* testnets reserved, then:

- Run the python script corresponding to your benchmark (make sure you are within the `pipenv shell`). A good starting point is the following, which benchmarks system overhead by stressing with query and update calls (default are queries, use `--use_updates=True` for update calls):

  ```
  $  ./max-capacity-experiment-1.py --testnet $TESTNET --wg_testnet $WG_TESTNET
  ```
- You can observe the benchmark on the following dashboard: https://grafana.dfinity.systems/d/u016YUeGz/workload-generator-metrics?orgId=1&refresh=5s - make sure to select the target subnetwork *as well as* the subnetwork with workload generators under "IC" and "IC workload generator" at the top respectively.
- Create the report `python generate_report.py githash timestamp`. This is normally called from the suite automatically, so in many cases you won't to manually run it.

# Run against mainnet

Use `--testnet mercury`. Also need to specify `--target_subnet_id` to determine machines to run against as well as `--canister`. 
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
 5. Run `python3 run_mainnet.py`
 
 Observe the dashboards

# Adding new experiment

In order to add a new experiment:

 - Create a new file `run_experiment_n.py`
 - Create a class `ExperimentN` with inherits from `Experiment`
 - Implement method `init_experiment` which is being called exactly once when the experiment is first started 
 - Implement method `run_experiment_internal` which implements the actual benchmark logic. It's typically configurable, so that the benchmark can be executed repeatedly with e.g. increasing load. `config` is a dict that can be used to pass on configuration arguments.
  - Implement `if __name__ == "__main__":` that initializes your experiment, calls `start_experiment` followed by `run_experiment` with a sensible configuration for your experiment.
  - Finally call `write_summary_file` and `end_experiment` to generate a report.
 - Add a template file for your experiment to add more details to the generated report in `templates/experiment_n.html.hb`. Have a look at existing ones for inspiration.  
  
Consider other experiments `run_experiment_*.py` for inspiration.
