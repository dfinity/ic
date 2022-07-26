#!/bin/env python3
import os
import re
import subprocess

import pybars


def camel_to_snake(s: str):
    return re.sub(r"(?<!^)(?=[A-Z])", "_", s).lower()


def generate_cd_job(benchmark_name, benchmark_path, is_max_capacity_run):
    CD_JOB_FILE = "60--benchmark-test--spawn-benchmark-pipeline.yml"
    CD_JOB_DIR = "../gitlab-ci/config"
    compiler = pybars.Compiler()

    with open("templates/cd_job.yml.hb") as f:
        cd_job_template = f.read()
        template = compiler.compile(cd_job_template)
        with open(os.path.join(CD_JOB_DIR, CD_JOB_FILE), "a") as f:
            f.write(
                template(
                    {
                        "benchmark_path": benchmark_path,
                        "benchmark_name": benchmark_name,
                        "is_max_capacity_run": is_max_capacity_run,
                    }
                )
            )


def add_benchmark():

    compiler = pybars.Compiler()

    benchmark_name = input("Benchmark name (CamelCase): ")
    benchmark_fname = camel_to_snake(benchmark_name)
    is_workload_bench = input("Does the benchmark stress the IC from clients (e.g. workload generators) [y/n]") == "y"

    if is_workload_bench:
        use_workload_generators = input("Should the benchmark use workload generators to stress the IC [y/n]") == "y"
    else:
        use_workload_generators = False

    is_max_capacity_run = (
        input("Will your benchmark have a variant that determines maximum capacity (increase load until failure) [y/n]")
        == "y"
    )
    install_canister = input(
        "Provide canister to install. Leave empty otherwise. Workload experiments will use the counter canister in that case. "
    )
    if len(install_canister) < 1:
        install_canister = "counter"

    if is_workload_bench:
        with open("templates/workload_benchmark.py.hb") as f:
            benchmark_template = f.read()
        if is_max_capacity_run:
            with open("templates/max_capacity_workload_benchmark.py.hb") as f:
                max_capacity_template = f.read()
    else:
        raise Exception("Only workload benchmarks currently supported")

    output = {
        "bench": f"experiments/run_{benchmark_fname}.py",
        "template": f"templates/run_{benchmark_fname}.html.hb",
    }

    with open(output["bench"], "w") as f:
        template = compiler.compile(benchmark_template)
        f.write(
            template(
                {
                    "experiment_name": benchmark_name,
                    "experiment_fname": f"run_{benchmark_fname}",
                    "is_workload_bench": is_workload_bench,
                    "is_max_capacity_run": is_max_capacity_run,
                    "use_workload_generators": use_workload_generators,
                    "install_canister": len(install_canister) > 0,
                    "canister_name": install_canister,
                }
            )
        )

    if is_max_capacity_run:
        output["max_capacity"] = f"experiments/max_capacity_{benchmark_fname}.py"
        with open(output["max_capacity"], "w") as f:
            template = compiler.compile(max_capacity_template)
            f.write(
                template(
                    {
                        "benchmark_name": benchmark_name,
                        "benchmark_fname": f"run_{benchmark_fname}",
                    }
                )
            )

    with open(output["template"], "w") as f:
        f.write(f"<h1>{benchmark_name}</h1>")

    for _, path in output.items():
        subprocess.check_output(["git", "add", path])

    generate_cd_job(benchmark_fname, f"{benchmark_fname}.py", is_max_capacity_run)
    print("Done!")


if __name__ == "__main__":
    add_benchmark()
