import os
import shutil
import tempfile
from pathlib import Path
from unittest import mock

import xmltodict
from freezegun import freeze_time

import cargo_test_json_parser


@mock.patch.dict(os.environ, {"CI_JOB_NAME": "job-name"})
@freeze_time("2020-12-10")
def test_to_log_metrics():
    tempdir = Path(tempfile.mkdtemp(prefix="python-tests-"))
    # Compare all the files in the test_data file with the output of the script.
    for filename in (Path(__file__).parent / "test_data").glob("*-log-metrics-*.json"):
        with open(filename) as f_in, open(tempdir / filename.name, "w") as f_out:
            cargo_test_json_parser.to_log_metrics(f_in, f_out)
        found = (tempdir / filename.name).read_text().strip()
        expected = filename.with_name(filename.name + ".expected").read_text().strip()
        assert found == expected
    shutil.rmtree(tempdir)


def test_generate_json():
    tempdir = Path(tempfile.mkdtemp(prefix="python-tests-"))
    # Compare all the files in the test_data file with the output of the script.
    for filename in (Path(__file__).parent / "test_data").glob("*-gen-json-*.json"):
        with open(filename) as f_in, open(tempdir / filename.name, "w") as f_out:
            cargo_test_json_parser.generate_json(f_in, f_out)
        found = (tempdir / filename.name).read_text().strip()
        expected = filename.with_name(filename.name + ".expected").read_text().strip()
        assert found == expected
    shutil.rmtree(tempdir)


def test_generate_xml():
    job_name_orig = os.environ.get("CI_JOB_NAME") or "python-tests"
    os.environ["CI_JOB_NAME"] = "cargo test"
    tempdir = Path(tempfile.mkdtemp(prefix="python-tests-"))
    # Compare all the files in the test_data file with the output of the script.
    for filename in (Path(__file__).parent / "test_data").glob("*.json"):
        print(filename)
        with open(filename) as f_in, open(tempdir / filename.name, "w") as f_out:
            cargo_test_json_parser.generate_xml(f_in, f_out)
        found = (tempdir / filename.name).read_text()
        found = xmltodict.parse(found)
        expected = filename.with_name(filename.name + ".expected-xml").read_text()
        expected = xmltodict.parse(expected)
        assert found == expected
    shutil.rmtree(tempdir)
    os.environ["CI_JOB_NAME"] = job_name_orig
