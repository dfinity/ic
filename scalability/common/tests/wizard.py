import itertools
import os
import subprocess

is_workload_bench = ["y"]  # Currently only workload experiments supported
use_workload_generators = ["y", "n"]  # Only if is_workload_bench = true
is_max_capacity_run = ["y", "n"]
install_canister = ["", "memory"]

output = list(
    itertools.product(
        is_workload_bench,
        use_workload_generators,
        is_max_capacity_run,
        install_canister,
    )
)

output = [e for e in output if e[0] == "y"] + [(e[0], e[2], e[3]) for e in output if e[0] == "n"]
output = list(sorted(set(output)))

for test_idx, test_case in enumerate(output):
    input_str = "\n".join([f"Test_{test_idx}"] + list(test_case) + [""])
    print("Testing with:")
    print(str(input_str))
    p = subprocess.Popen(["pipenv", "run", "python3", "add_benchmark.py"], stdin=subprocess.PIPE)
    p.communicate(input=input_str.encode())
    rc = p.wait()
    assert rc == 0

    if test_case[0] == "y":
        (is_workload_bench, use_workload_generators, is_max_capacity_run, install_canister) = tuple(test_case)
    else:
        (is_workload_bench, is_max_capacity_run, install_canister) = tuple(test_case)
        use_workload_generators = "n"

    assert os.path.isfile(
        os.path.join("experiments", f"run_test_{test_idx}.py")
    ), "Experiment run file was not generated"
    if is_max_capacity_run == "y":
        # Max capacity benchmarks need a seperate file
        assert os.path.isfile(
            os.path.join("experiments", f"max_capacity_test_{test_idx}.py")
        ), "Experiment max capacity file was not generated"
    assert os.path.isfile(
        os.path.join("templates", f"run_test_{test_idx}.html.hb")
    ), "Experiment template was not generated"

    with open(os.path.join("experiments", f"run_test_{test_idx}.py")) as f:
        if len(install_canister) > 0:
            assert "install_canister" in f.read()
        else:
            assert "install_canister" not in f.read()

    with open(os.path.join("experiments", f"run_test_{test_idx}.py")) as f:
        if use_workload_generators == "y":
            assert "run_workload_generator" in f.read()
        else:
            assert "run_workload_generator" not in f.read()
