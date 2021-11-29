#!/usr/bin/env python3
"""Transform the cargo json output into the format which can be indexed by ElasticSearch."""
import argparse
import datetime
import json
import os
from typing import Any
from typing import Dict
from typing import TextIO

import junit_xml

JSONData = Dict[str, Any]

MAX_STDOUT_SIZE_BYTES = 64 * 1024


def text_limit_size(text, desc):
    if len(text) > MAX_STDOUT_SIZE_BYTES:
        print(f"{desc} len {len(text)} > {MAX_STDOUT_SIZE_BYTES} bytes, truncating")
        return (
            text[: MAX_STDOUT_SIZE_BYTES // 2] + "\n\n\n[***TRUNCATED***]\n\n\n" + text[-MAX_STDOUT_SIZE_BYTES // 2 :]
        )
    else:
        return text


def parse_file(in_file: TextIO) -> (dict, dict):
    """Parse the JSON data from Cargo and fix (potentially) broken or missing data."""
    suite = {
        "type": "suite",
        "passed": 0,
        "failed": 0,
        "ignored": 0,
    }
    tests = {}

    def cp_data_if_in_src(src_dict: dict, dest_dict: dict, fields: list):
        """Copy fields from src_dict to dest_dict, if they exist in src_dict."""
        for field in fields:
            if field in src_dict:
                dest_dict[field] = src_dict[field]

    for line in in_file:
        try:
            json_data = json.loads(line)
        except Exception:  # pylint: disable=W0703
            # Not a valid JSON line, continue.
            continue

        dtype = json_data.get("type")
        event = json_data.get("event")
        if dtype == "test":
            test_name = json_data.get("name", "")
            test = tests.get(test_name, {})
            cp_data_if_in_src(
                json_data,
                test,
                ["type", "name", "event", "exec_time", "stdout", "stderr", "reason"],
            )
            if event == "failed":
                suite["failed"] += 1
            elif event == "ok":
                suite["passed"] += 1
            elif event == "ignored":
                suite["ignored"] += 1
            test["event"] = event
            tests[test_name] = test
    return suite, tests


def generate_json(in_file: TextIO, out_file: TextIO):
    """Generate a JSON file with the JUnit tests data."""
    suite, tests = parse_file(in_file)

    test_count = suite["passed"] + suite["failed"] + suite["ignored"]
    suite_event = "failed" if suite["failed"] else "ok"
    out_file.write(json.dumps({"type": "suite", "event": "started", "test_count": test_count}) + "\n")
    for test_name, test in tests.items():
        record = {"type": "test", "event": "started", "name": test_name}
        out_file.write(json.dumps(record) + "\n")
        record["event"] = test["event"] if test["event"] in ("ok", "ignored") else "failed"
        record["exec_time"] = test.get("exec_time", "0.0s")
        if "stdout" in test:
            record["stdout"] = test["stdout"]
        if "stderr" in test:
            record["stderr"] = test["stderr"]
        out_file.write(json.dumps(record) + "\n")
    out_file.write(
        json.dumps(
            {
                "type": "suite",
                "event": suite_event,
                "passed": suite["passed"],
                "failed": suite["failed"],
                "allowed_fail": 0,
                "ignored": suite["ignored"],
                "measured": 0,
                "filtered_out": 0,
            }
        )
        + "\n"
    )


def generate_xml(in_file: TextIO, out_file: TextIO) -> JSONData:
    """Generate an XML file with the JUnit tests data."""
    _, tests = parse_file(in_file)

    test_cases = []
    for test_name, test in tests.items():
        class_name = test_name.split("::")[0]
        exec_time = test.get("exec_time", "0.0s")
        if isinstance(exec_time, str):
            try:
                if exec_time.endswith("ns"):
                    exec_time = float(exec_time[:-2]) / 10 ** 9
                elif exec_time.endswith("μs"):
                    exec_time = float(exec_time[:-2]) / 10 ** 6
                elif exec_time.endswith("ms"):
                    exec_time = float(exec_time[:-2]) / 10 ** 3
                elif exec_time.endswith("s"):
                    exec_time = float(exec_time[:-1])
                else:
                    raise ValueError
            except ValueError:
                print("ERROR: could not convert exec_time to float:", exec_time)
                exec_time = 0.0

        def mk_test_case(stdout=None, stderr=None):
            return junit_xml.TestCase(
                name=test_name,
                classname=class_name,
                elapsed_sec=exec_time,
                stdout=stdout,
                stderr=stderr,
            )

        fname_stdout = f"rs/1/{test_name}/stdout"
        test_stdout = test.get("stdout", "")
        if os.path.isfile(fname_stdout):
            test_stdout = open(fname_stdout).read()
        test_stdout = text_limit_size(test_stdout, desc="stdout")

        fname_stderr = f"rs/1/{test_name}/stderr"
        test_stderr = test.get("stderr", "")
        if os.path.isfile(fname_stderr):
            test_stderr = open(fname_stderr).read()
        test_stderr = text_limit_size(test_stderr, desc="stderr")

        test_reason = test.get("reason", "")

        output = "\n".join((test_stdout, test_stderr, test_reason))
        if test["event"] == "failed":
            case = mk_test_case()
            case.add_failure_info(message=test.get("reason"), output=output)
        elif test["event"] == "error":
            case = mk_test_case()
            case.add_error_info(message=test.get("reason"), output=output)
        elif test["event"] == "skipped":
            case = mk_test_case()
            case.add_skipped_info(message=test.get("reason"), output=output)
        else:
            case = mk_test_case(stdout=test.get("stdout"), stderr=test.get("stderr"))
        test_cases.append(case)

    ts = junit_xml.TestSuite(os.environ.get("CI_JOB_NAME") or "cargo test", test_cases)
    out_file.write(junit_xml.to_xml_report_string([ts]) + "\n")


def parse_data(in_file: TextIO) -> JSONData:
    """Parse the JSON data from Cargo to a more digestible format."""
    data = {"results": []}
    for line in in_file:
        try:
            json_data = json.loads(line)
        except Exception:  # pylint: disable=W0703
            # Not a valid JSON line, continue.
            continue

        dtype = json_data.get("type")
        event = json_data.get("event")
        if dtype == "suite" and event == "started":
            data["test_count"] = json_data["test_count"]
        elif dtype == "suite":
            data["passed"] = json_data["passed"]
            data["failed"] = json_data["failed"]
            data["ignored"] = json_data["ignored"]
        elif dtype == "test" and event != "started":
            test = {"name": json_data["name"], "event": event}
            if "exec_time" in json_data:
                test["exec_time"] = json_data["exec_time"]
            if event == "failed":
                if "stdout" in json_data:
                    test["stdout"] = json_data["stdout"]
                if "stderr" in json_data:
                    test["stderr"] = json_data["stderr"]
            data["results"].append(test)

    return data


def write_json_data(data: JSONData, out_file: TextIO):
    """Write `data` to a JSON file for the log_metrics script."""
    out_data = {
        "__index": "cargo-test-results-%s-%s" % (os.getenv("CI_JOB_NAME", "none"), datetime.date.today().year),
        "results": {},
    }
    for key in ["failed", "ignored", "passed", "test_count"]:
        if key in data:
            out_data[key] = data[key]

    for test in data["results"]:
        test_data = {"event": test["event"]}
        if "stdout" in test:
            test_data["stdout"] = text_limit_size(text=test["stdout"], desc="stdout")
        if "exec_time" in test:
            test_data["exec_time"] = test["exec_time"]
        out_data["results"][test["name"]] = test_data

    json.dump(out_data, out_file, indent=2, sort_keys=True)


def to_log_metrics(in_file: TextIO, out_file: TextIO) -> None:
    """Parse data and convert it into the format understood by ElasticSearch."""
    data = parse_data(in_file)

    write_json_data(data, out_file)

    print("Done.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-i",
        "--input",
        help="Read the input from the provided file (default is stdout)",
        type=argparse.FileType("r"),
        nargs="?",
        const="-",
        default="-",
    )

    parser.add_argument(
        "-o",
        "--out",
        help="Store the output in the provided file (default is stdout)",
        type=argparse.FileType("w"),
        nargs="?",
        const="-",
        default="-",
    )

    parser.add_argument(
        "--to-log-metrics",
        help="Convert data into the format understood by ElasticSearch",
        action="store_true",
    )

    parser.add_argument(
        "--generate-junit-json",
        help="Generate a properly formatted JUnit JSON file",
        action="store_true",
    )

    parser.add_argument(
        "--generate-junit-xml",
        help="Generate a properly formatted JUnit XML file",
        action="store_true",
    )

    args = parser.parse_args()

    if args.to_log_metrics:
        to_log_metrics(args.input, args.out)

    if args.generate_junit_json:
        generate_json(args.input, args.out)

    if args.generate_junit_xml:
        generate_xml(args.input, args.out)
