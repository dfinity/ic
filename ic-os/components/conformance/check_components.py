#!/usr/bin/env python3

import argparse
import atexit
import itertools
import os
import pathlib
import re
import subprocess
import sys
import tarfile
import tempfile

ALLOWED_UNDECLARED_DEPENDENCIES = {
    "ic-os/components/misc/fetch-property.sh": {
        # fetch-property.sh checks existence of metrics.sh
        "/opt/ic/bin/metrics.sh",
    }
}

# Check file patterns /opt/ic/...
COMPONENT_FILE_PATTERN = r"/opt/ic/[^\s'\"},)]+"
# Exclude patterns that include $ since we don't support substitution.
EXCLUDE_FILE_PATTERN = r".*[$].*"


def check_paths_in_source(source: str, partition_img_path: str) -> [str]:
    """
    Checks if `source` contains only file paths that are present in the image
    file.

    Args:
        source: Path to the file to be checked.
        partition_img_path: Path to the extracted partition file (partition.img)

    Returns a list of errors or empty list on no error.
    """

    print(f"Checking component {source}")

    if not os.path.isfile(source):
        return [f"File '{source}' is not a valid file."]

    errors = []
    allowlisted_unavailable_dependencies = ALLOWED_UNDECLARED_DEPENDENCIES.get(
        source, {})
    source_content = pathlib.Path(source).read_text()
    for dependency in allowlisted_unavailable_dependencies:
        if dependency not in source_content:
            errors.append(f"{dependency} is in the allowlist of {source} even "
                          f"though {source} does not contain any references to "
                          f"it. Remove it from ALLOWED_UNDECLARED_DEPENDENCIES")

    for line_number, line in enumerate(source_content.splitlines(), start=1):
        dependencies = re.findall(COMPONENT_FILE_PATTERN, line)
        for dependency in dependencies:
            if re.match(EXCLUDE_FILE_PATTERN, dependency):
                print(f"Skipping dependency {dependency} (unable to parse path)")
                continue
            if dependency in allowlisted_unavailable_dependencies:
                print(f"Skipping allowlisted dependency {dependency}")
                continue

            print(f"Checking dependency {dependency}")
            if not exists(dependency, partition_img_path):
                errors.append(
                    f"File '{source}' contains reference to "
                    f"unavailable file '{dependency}' on line {line_number}. "
                    f"Ensure that {dependency} is added to the image.")
    print()
    return errors


def exists(path, partition_img_path):
    """
    Returns whether the partition at `partition_img_path` contains a file at
    `path`.
    """
    debugfs_output = subprocess.run(
        ["/usr/sbin/debugfs", "-R", f"testi {path}", partition_img_path],
        check=True,
        capture_output=True).stdout
    return b"marked in use" in debugfs_output


def main():
    parser = argparse.ArgumentParser(
        description="Check files for allowed sources")
    parser.add_argument('-f', '--files', required=True,
                        help="Comma-separated list of files to check")
    parser.add_argument('-i', '--image', required=True,
                        help="Path to partition image")
    args = parser.parse_args()

    files = args.files.split(',')

    tmpdir = tempfile.mkdtemp(prefix="icosbuild")
    atexit.register(lambda: subprocess.run(["rm", "-rf", tmpdir], check=True))
    partition_tar_path = os.path.join(tmpdir, "partition.tar")
    subprocess.run(["zstd", "-q", "--threads=0", "-f", "-d", args.image, "-o",
                    partition_tar_path], check=True)

    with tarfile.open(partition_tar_path) as tar:
        partition_img = next(
            (item for item in tar if item.path == "partition.img"), None)
        if not partition_img:
            return "partition.img not found in input image"
        tar.extract(partition_img, path=tmpdir)

    partition_img_path = os.path.join(tmpdir, "partition.img")

    errors = list(itertools.chain.from_iterable(
        check_paths_in_source(source, partition_img_path) for source in files))
    if errors:
        return "\nThe following problems were found:\n" + "\n".join(errors)


if __name__ == '__main__':
    sys.exit(main())
