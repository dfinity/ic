import os
import re
from importlib.util import module_from_spec
from importlib.util import spec_from_file_location
from os.path import isdir
from os.path import isfile
from os.path import join
from typing import List

from monpoly.monpoly import AlertHandlerParams
from monpoly.monpoly import ErrorHandlerParams
from monpoly.monpoly import ExitHandlerParams
from monpoly.monpoly import Monpoly
from monpoly.monpoly import MonpolyException
from util import docker

EVENT_DELAY = 0.1  # seconds


def _compare(actual: str, expected: str) -> bool:
    if "*" in expected:
        # treat as a regex
        m = re.match(expected, actual)
        return not not m
    else:
        # treat literally
        return actual == expected


def assert_match(test: str, stream: str, actual: List[str], expected: List[str]) -> None:
    assert len(actual) == len(expected) and all(map(lambda pair: _compare(pair[0], pair[1]), zip(actual, expected))), (
        "Test {test} failed.\n"
        "Actual {stream} output did not match expected {stream} output:\n"
        " --- expected ({ex_lines} lines) ---\n{expected}\n"
        " --- actual ({ac_lines} lines) ---\n{actual}\n".format(
            test=test,
            stream=stream,
            expected="\n".join(map(lambda x: "`%s`" % x, expected)),
            actual="\n".join(map(lambda x: "`%s`" % x, actual)),
            ex_lines=len(expected),
            ac_lines=len(actual),
        )
    )


def run_tests(tests_dir: str, tests: List[str], local_sig_file=True) -> None:
    print("Preparing to run %d tests from %s" % (len(tests), str(tests_dir)), flush=True)
    for test in tests:
        print("=== Running Test %s ===" % test, flush=True)

        test_prefix = join(tests_dir, test)
        test_instances = [t for t in os.listdir(test_prefix) if isdir(join(test_prefix, t)) and t != "__pycache__"]

        if not test_instances:
            run_test(tests_dir, test, ".", local_sig_file)
        else:
            for instance in test_instances:
                run_test(tests_dir, test, instance, local_sig_file)

    print("All tests passed!", flush=True)


def run_test(prefix: str, test: str, instance: str, local_sig_file=True):

    test_dir = join(prefix, test, instance)
    log_file = str(join(test_dir, "input.log"))

    if not isfile(log_file):
        log_gen_file = str(join(test_dir, "input.py"))
        assert isfile(log_gen_file), f"cannot find input.log nor input.py in {str(test_dir)}"

        print(" Generating input.log using input.py ...", end="", flush=True)

        module_name = log_gen_file.replace(".py", "").replace("/", ".")
        spec = spec_from_file_location(module_name, log_gen_file)
        module = module_from_spec(spec)
        spec.loader.exec_module(module)
        module.gen(log_file)

        print(" done.")

    with open(log_file, "r") as log_file_text:
        logs = list(map(lambda x: x.strip("\n"), log_file_text.readlines()))

    with open(str(join(test_dir, "expected_stdout.txt")), "r") as expected_stdout_file:
        expected_stdout = list(map(lambda x: x.strip("\n"), expected_stdout_file.readlines()))

    with open(str(join(test_dir, "expected_stderr.txt")), "r") as expected_stderr_file:
        expected_stderr = list(map(lambda x: x.strip("\n"), expected_stderr_file.readlines()))

    expected_exit_code_file_path = str(join(test_dir, "expected_exit_code.txt"))
    with open(expected_exit_code_file_path, "r") as expected_exit_code_file:
        expected_exit_code = list(map(lambda x: x.strip("\n"), expected_exit_code_file.readlines()))

    assert len(expected_exit_code) == 1, "%s should contain exactly one line" % expected_exit_code_file_path

    expected_exit_code = expected_exit_code[-1]

    actual_stdout = []

    def alert_handler(arg: AlertHandlerParams) -> None:
        print("{{{ Alert service got [%s] %s }}}" % (arg.source, arg.message), flush=True)
        actual_stdout.append(arg.message)

    actual_stderr = []

    def error_handler(arg: ErrorHandlerParams) -> None:
        print("{{{ Experiencing Monpoly error [%s] %s }}}" % (arg.source, arg.message), flush=True)
        actual_stderr.append(arg.message)

    actual_exit_status = {"code": None}

    def exit_handler(arg: ExitHandlerParams) -> None:
        print("{{{ Monpoly exited with code %s }}}" % arg.exit_code, flush=True)
        actual_exit_status["code"] = arg.exit_code

    if local_sig_file:
        sig_file = join(test, "predicates.sig")
    else:
        sig_file = "predicates.sig"

    with Monpoly(
        name="test",
        workdir=str(join(prefix)),
        local_sig_file=sig_file,
        local_formula=str(join(test, "formula.mfotl")),
        alert_handler=alert_handler,
        error_handler=error_handler,
        exit_handler=exit_handler,
        docker=(not docker.is_inside_docker()),
        hard_timeout=6.0,
    ) as monpoly:

        try:
            for entry in logs:
                # sleep(EVENT_DELAY)
                monpoly.submit(entry)
                # monpoly.submit(Monpoly.SYNC_MARKER)
        except MonpolyException:
            print("Interaction stopped due to Monpoly exception", flush=True)

    # Monpoly has closed

    assert_match(join(test, instance), "STDOUT", actual=actual_stdout, expected=expected_stdout)
    assert_match(join(test, instance), "STDERR", actual=actual_stderr, expected=expected_stderr)
    assert expected_exit_code == actual_exit_status["code"], (
        f"actual exit code {actual_exit_status['code']} did not" f" match expected exit code {expected_exit_code}"
    )

    # Obtain the variable sequence,
    #  but only if monpoly is expected to succeed with -check
    if expected_exit_code == "0":
        var_seq = Monpoly.get_variables(
            workdir=str(join(prefix)),
            local_sig_file=sig_file,
            local_formula=str(join(test, "formula.mfotl")),
            docker=(not docker.is_inside_docker()),
            hard_timeout=5.0,
        )
        assert var_seq is not None, "could not obtain sequence of variables"
        print(f"obtained sequence of variables: {', '.join(var_seq)}")
    else:
        print("skipped obtaining sequence of variables for test with non-zero" " expected exit code")
