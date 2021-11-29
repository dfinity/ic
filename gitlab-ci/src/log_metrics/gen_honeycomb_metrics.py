#!/usr/bin/env python3
"""
Prints Honeycomb buildevents compatible data from environment variables.

The data is shipped to Honeycomb.
"""
import os


def main():
    """Generate Honeycomb compatible data from the environment variables."""
    for varname in [
        "CD_ENV",
        "CI_COMMIT_AUTHOR",
        "CI_COMMIT_SHA",
        "CI_COMMIT_TAG",
        "CI_COMMIT_TIMESTAMP",
        "CI_CONCURRENT_ID",
        "CI_CONCURRENT_PROJECT_ID",
        "CI_ENVIRONMENT_NAME",
        "CI_ENVIRONMENT_SLUG",
        "CI_EXTERNAL_PULL_REQUEST_IID",
        "CI_EXTERNAL_PULL_REQUEST_SOURCE_BRANCH_NAME",
        "CI_EXTERNAL_PULL_REQUEST_SOURCE_BRANCH_SHA",
        "CI_JOB_ID",
        "CI_JOB_IMAGE",
        "CI_JOB_MANUAL",
        "CI_JOB_NAME",
        "CI_JOB_STAGE",
        "CI_JOB_STATUS",
        "CI_NODE_INDEX",
        "CI_NODE_TOTAL",
        "CI_PIPELINE_ID",
        "CI_PIPELINE_SOURCE",
        "CI_RUNNER_DESCRIPTION",
        "CI_RUNNER_ID",
        "CI_RUNNER_TAGS",
        "DEPLOY_FLAVOR",
        "USER_ID",
        "USER_LOGIN",
        "SCHEDULE_NAME",
        "TESTNET",
        "STEP_START",
        "PIPELINE_START_TIME",
        "job_status",
        "DISKIMG_BRANCH",
        "CI_MERGE_REQUEST_APPROVED",
        "CI_MERGE_REQUEST_ASSIGNEES",
        "CI_MERGE_REQUEST_ID",
        "CI_MERGE_REQUEST_IID",
        "CI_MERGE_REQUEST_LABELS",
        "CI_MERGE_REQUEST_MILESTONE",
        "CI_MERGE_REQUEST_PROJECT_ID",
        "CI_MERGE_REQUEST_PROJECT_PATH",
        "CI_MERGE_REQUEST_PROJECT_URL",
        "CI_MERGE_REQUEST_REF_PATH",
        "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME",
        "CI_MERGE_REQUEST_SOURCE_BRANCH_SHA",
        "CI_MERGE_REQUEST_SOURCE_PROJECT_ID",
        "CI_MERGE_REQUEST_SOURCE_PROJECT_PATH",
        "CI_MERGE_REQUEST_SOURCE_PROJECT_URL",
        "CI_MERGE_REQUEST_TARGET_BRANCH_NAME",
        "CI_MERGE_REQUEST_TARGET_BRANCH_SHA",
        "CI_MERGE_REQUEST_TITLE",
        "CI_MERGE_REQUEST_EVENT_TYPE",
        "CI_MERGE_REQUEST_DIFF_ID",
        "CI_MERGE_REQUEST_DIFF_BASE_SHA",
    ]:
        if os.environ.get(varname):
            # Wrap the values in quotes to prevent Honeycomb from splitting by
            # comma or space into multiple columns.
            print(f'gitlab.{varname}="{os.environ[varname]}"')


if __name__ == "__main__":
    main()
