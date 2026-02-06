import json
import logging
import os
import pathlib

from scanner.process_executor import ProcessExecutor

PROJECT_ROOT = pathlib.Path(
    os.environ.get("CI_PROJECT_DIR", pathlib.Path(__file__).absolute().parent.parent.parent.parent.parent)
)


def main():
    logging.basicConfig(level=logging.DEBUG)

    # command = f"git clone https://github.com/dfinity/ic"
    # logging.info(f"Performing git clone")
    # _ = ProcessExecutor.execute_command(command, PROJECT_ROOT.resolve(), {})
    # path = PROJECT_ROOT / "ic"
    # _ = ProcessExecutor.execute_command("git reset --hard dc2d53146c26eb41c8ae40ecc0c1d89f32072d14", path.resolve(), {})

    path = PROJECT_ROOT
    if not path.is_dir():
        raise RuntimeError(f"path {path} is invalid")
    json_file_path = f"{path.resolve()}/ic-os/guestos/envs/prod/findings.json"
    hash_file_path = f"{path.resolve()}/ic-os/guestos/envs/prod/file-hashes.txt"
    # command = (
    #     f"ci/container/container-run.sh bazel run vuln-scan -- --output-path /ic/ic-os/guestos/envs/prod/findings.json --format json --hash-output-path /ic/ic-os/guestos/envs/prod/file-hashes.txt"
    # )
    command = (
        f"bazel run vuln-scan -- --output-path {json_file_path} --format json --hash-output-path {hash_file_path}"
    )
    trivy_output = ProcessExecutor.execute_command(command, path.resolve(), {})
    if os.path.exists(json_file_path):
        with open(json_file_path, "r") as file:
            if os.fstat(file.fileno()).st_size == 0:
                logging.error(f"trivy scan attempt failed (file size 0) with output:\n{trivy_output}")
            else:
                trivy_data = json.load(file)
                logging.info(trivy_data)
    else:
        logging.error(f"trivy scan attempt failed ({json_file_path} doesn't exists) with output:\n{trivy_output}")


if __name__ == "__main__":
    main()
