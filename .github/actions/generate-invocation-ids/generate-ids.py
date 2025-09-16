#!/usr/bin/env python3
import json
import logging
import os
import sys
import uuid
from dataclasses import dataclass
from typing import List

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

logger = logging.getLogger(__name__)

BUILD_BUDDY_URL = "https://dash.idx.dfinity.network/invocation/"
GITHUB_OUTPUT = "GITHUB_OUTPUT"
GITHUB_STEP_SUMMARY = "GITHUB_STEP_SUMMARY"


@dataclass
class Target:
    name: str
    output_id: str


def die(*args, **kwargs):
    logger.error(*args, **kwargs)
    sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        die("Expected to receive one argument, but received: %d", len(sys.argv) - 1)

    maybe_json = sys.argv[1]

    logger.info("Received input:\n%s", maybe_json)

    try:
        parsed = json.loads(maybe_json)
        targets: List[Target] = [Target(**item) for item in parsed]
    except json.JSONDecodeError as e:
        die("Failed to parse JSON: %s", e)
    except Exception as e:
        die("Failed to cast object due to: %s", e)

    summary = """
### Bazel Invocation IDs

_These links may not be immediately available; invocation details will eventually populate once the build/test completes._

| Job name | Invocation ID | Link |
|----------|---------------|------|
"""

    output = {}
    for entry in parsed:
        invocation_id = uuid.uuid4()
        logger.info(
            "Generated invocation ID %s for target %s and will store it in %s"
            % (invocation_id, entry["name"], entry["output_id"])
        )

        output[entry["output_id"]] = invocation_id

        summary += "| {} | `{}` | [{}]({}) |\n".format(
            entry["name"],
            invocation_id,
            "BuildBuddy link for " + str(invocation_id),
            BUILD_BUDDY_URL + str(invocation_id),
        )

    encoded_output = json.dumps(output, default=str)

    # Print the output
    print("Summary:\n{}".format(summary))
    print("\nEncoded output: ", encoded_output)

    if GITHUB_OUTPUT in os.environ:
        path = os.environ.get(GITHUB_OUTPUT)
        logger.info("Will write output to %s", path)
        with open(path, "w") as f:
            f.write(f"output={encoded_output}")
    else:
        logger.warning("Didn't find %s in environment variables", GITHUB_OUTPUT)

    if GITHUB_STEP_SUMMARY in os.environ:
        path = os.environ.get(GITHUB_STEP_SUMMARY)
        logger.info("Will write summary to %s", path)
        with open(path, "w") as f:
            f.write(summary)
    else:
        logger.warning("Didn't find %s in environment variables", GITHUB_STEP_SUMMARY)
