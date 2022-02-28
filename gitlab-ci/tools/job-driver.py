#!/usr/bin/env python3
import importlib
import logging
import os
import re
import sys
from typing import Any

import yaml

if len(sys.argv) < 2:
    print(
        f"Usage: {os.path.dirname(__file__)}/docker-run gitlab-ci/tools/job-driver.py <ci-job-name> [<job-arg-1> <...>]"
    )
    exit(1)

logging.basicConfig(level=logging.INFO)

im_not_gitlab = os.environ.get("CI_JOB_ID") is None

# path to the top level of the repo
ci_top = os.path.abspath(os.path.join(__file__, "../.."))

# sets the import scope of the CI job scripts to the gitlab-ci/src directory. this is required for things like relative imports to work
sys.path.insert(1, os.path.join(ci_top, "src"))

all_jobs = {}  # type: dict[str, dict[str, Any]]

# job resolution
for yml in os.listdir(os.path.join(ci_top, "config")):
    if not yml.endswith(".yml"):
        continue
    job_file = yaml.load(open(os.path.join(ci_top, "config", yml)), Loader=yaml.FullLoader)  # type: dict[str, Any]
    # python <= 3.8 dict merge
    all_jobs = {**all_jobs, **job_file}


def execute_job(job):
    job_data = all_jobs.get(job)
    if job_data is None:
        print(f"'{job}': unrecognized job")
        exit(1)
    if im_not_gitlab:
        for dep in job_data.get("needs", []):
            print(f"{job}: executing dependent job {dep}")
            execute_job(dep)

    try:
        job_mod = re.sub("-", "_", job)
        importlib.import_module(f"job_scripts.{job_mod}").run(*sys.argv[2:])
    except ImportError:
        print(f"{job}: no script for job")
        exit(1)


execute_job(sys.argv[1])
