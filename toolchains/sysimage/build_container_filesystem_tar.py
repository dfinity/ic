#!/usr/bin/env python3
#
# Build a container image and extract the single flattened filesystem into a tar file.

import argparse
import os
import pathlib
import shutil
import subprocess


def arrange_component_files(context_dir, component_files):
    """Add component files into the context directory by copying them to their defined paths."""
    for component_file in component_files:
        source_file, install_target = component_file.split(":")
        if install_target[0] == "/":
            install_target = install_target[1:]
        install_target = os.path.join(context_dir, install_target)
        os.makedirs(os.path.dirname(install_target), exist_ok=True)
        pathlib.Path(install_target).unlink(missing_ok=True)
        shutil.copyfile(source_file, install_target)


def get_args():
    parser = argparse.ArgumentParser()

    parser.add_argument("-o", "--output", help="Target (tar) file to write to", type=str)

    parser.add_argument(
        "--component-file",
        dest="component_files",
        type=str,
        action="append",
        help="Files to include in rootfs; expects list of sourcefile:targetfile",
        required=True
    )

    parser.add_argument(
        "--base-image-tar-file",
        help="Override the base image used by 'podman build'. The 'FROM' line in the target Dockerfile will be ignored",
        default=None,
        type=str)

    return parser.parse_args()


def main():
    args = get_args()
    destination_tar_filename = os.path.abspath(args.output)
    component_files = args.component_files

    context_dir = os.getenv("ICOS_TMPDIR")
    if not context_dir:
        raise RuntimeError("ICOS_TMPDIR env variable not available, should be set in BUILD script.")

    container_dir = os.path.join(context_dir, "container")
    os.mkdir(container_dir)

    # Untar base image
    subprocess.run(["tar", "-xf", args.base_image_tar_file, "-C", container_dir], check=True)

    # Fill context with remaining component files from map
    arrange_component_files(container_dir, component_files)

    setup_sh_path = os.path.join(container_dir, "tmp", "setup_icos.sh")
    shutil.copy("/ic/ic-os/hostos/context/setup.sh", setup_sh_path)
    os.chmod(setup_sh_path, 755)

    subprocess.run(["sudo", "chroot", container_dir, "/usr/bin/env", "ROOT_PASSWORD=root",
                    "faketime", "-f", "1970-1-1 0:0:0", "/tmp/setup_icos.sh"], check=True)
    subprocess.run(["sudo", "chown", "ubuntu", "-R", container_dir], check=True)

    # Clean up
    os.system("rm -rf " + os.path.join(container_dir, "tmp/*"))
    os.system("rm -rf " + os.path.join(container_dir, "var/cache/*"))
    os.system("rm -rf " + os.path.join(container_dir, "var/log/*"))
    os.system("rm -rf " + os.path.join(container_dir, "var/lib/apt/lists/*"))

    subprocess.check_call(f"time tar --mtime='UTC 1970-01-01' -cf {destination_tar_filename} *", cwd=container_dir,
                          shell=True)


if __name__ == "__main__":
    main()
