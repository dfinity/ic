#!/usr/bin/env python3
import os
import subprocess
import sys


def main():
    workspace_dir = os.path.dirname(os.path.realpath(os.environ["WORKSPACE"]))
    if not os.path.isdir(workspace_dir):
        sys.exit("WORKSPACE path '{}' is not directory".format(workspace_dir))

    res = subprocess.run(
        os.environ["BUILDIFIER_CHECK_BIN"],
        env={
            "BUILD_WORKSPACE_DIRECTORY": workspace_dir,
        },
    )

    if res.returncode != 0:
        print("\n\n        Please auto-format your changes with `bazel run //:buildifier`\n\n")
    sys.exit(res.returncode)


if __name__ == "__main__":
    main()
