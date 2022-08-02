# Developing a benchmark with a .toml file

## Overview
This is an upgraded way of developing a maximum capacity workload benchmark, by declaring the workloads intended through a .toml configuration file. The toml file is then consumed by `run_mixed_workload_experiment.py` to generate iterations plan and workload distribution among the defined workloads for each iteration. 

## Defining the workload
The toml way of defining workloads supports multiple workloads, with multiple canisters and varied durations. Please check `workloads/template.toml` for the template of how to define an experiment with multiple workloads, and parameters accepted in current framework. 

## How to run the workload
```
experiments/run_mixed_workload_experiment.py \
    --testnet "{testnet_name_you_reserved_from_Slack_Dee_for_running_replicas}" \
    --wg_testnet "{testnet_name_you_reserved_from_Slack_Dee_for_running_workload_generators}" \
    --wg_subnet {the_subnet_index_where_the_workload_generator_should_be_installed_on} \
    --initial_rps={requests_per_second_the_initial_iteration_starts_with} \
    --increment_rps={requests_per_second_to_be_increased_in_between_each_iteration} \
    --target_rps={requests_per_second_the_experiment_target_at} \
    --max_rps={requests_per_second_the_experiment's_last_iteration_should_be_at} \
    --workload workloads/canister-http-benchmark.toml
```

## How to add a workload to GitLab pipeline
All existing benchmark experiments are in `gitlab-ci/config/60--benchmark-test-spwan-benchmark-pipeline.yml`. Find an example job in that file which uses `run_mixed_workload_experiment.py`, for example, the `maximum-capacity-canister-http` job. Copy the block of that job and paste it to the same file, and modify parts necessary to match the name of the new experiment.

## Finding the right arguments for regression checks
At the time of adding the experiment to GitLab config file, there are a list of argument values expected. For example: `initial_rps`, `incremental_rps`, `target_rps` and `max_rps`, etc. How do we know what are the relevant numbers to check in for future exercising? 

That takes experimenting with a few different combinations for parameters and observing the rough scenario capacity, with the targeted testnet. For example, for `maximum-capacity-canister-http` experiment, through testing we found out the scenario capacity is roughly at 250 rps (with multiple workload combined). System performs stably and predicatably till 200 rps, at which system started to show degrated finalization rate. Then at 250 rps, a minor failure rate starts to show up. As we continue raising workload, more failures, increase in latency and degradation in finalization are observed in an exponential manner. 

In this case, we set up our `target_rps` at 200 rps, as that's where things shift from stable to unstable. We set our `initial_rps` to 50 rps, and `increment_rps` to 50 rps, as we want to have a few samples before the healthy threshold, but no needed for dense sampling. However, we wanted to see a bit more dense exercising around 200 rps. We set out `max_rps` to 500 rps as our last iteration to be boundary where our experiment stops, so we can catch performance improvements that can potentially cover this workload, but doesn't waste exercise cycles for irrational workloads that the system cannot deal with currently.
