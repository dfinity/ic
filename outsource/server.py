#!/usr/bin/env python3
"""
Run a remote command inside a Docker container.

This script is run on the remote builder when a developer sends a command. It
creates a few docker volumes and spins up a docker container inside which the
command is run.

For more information, see ./DESIGN.md.
"""
import argparse
import hashlib
import os
import pathlib
import random
import re
import string
import subprocess
import sys
import tempfile
import time

import shell_safe

UID = os.getuid()
GID = os.getgid()
HOME = pathlib.Path.home()
# Tests run in an environment where $USER is not set
USER: str = os.environ.get("USER", "nobody")
VERBOSE = False

# number of hours after which the user's volume may be removed
KEEPALIVE_HOURS = 8


def main():

    # Set up the arguments and log the config

    args = parse_args()
    global VERBOSE  # XXX ugly
    VERBOSE = args.verbose
    debug(f"verbose: {VERBOSE}")

    run_build(args.command, args.relative_path, wipe=args.wipe, stop=args.stop)


def run_build(wire_cmd: str, relative_path, wipe=False, stop=False):
    """Run the given command inside a container."""
    debug(f"relative path: {relative_path}")
    debug(f"cmd: {wire_cmd}")
    debug(f"wipe: {wipe}")
    debug(f"stop: {stop}")

    cmd: shell_safe.Command = shell_safe.decode(wire_cmd)
    debug(f"cmd(decoded): {cmd}")

    if wipe is True or stop is True:
        kill_containers()
    if wipe is True:
        rm_docker_volume()

    log("preparing environment")

    # Make sure users don't get bitten by strict host key checking
    # Must be done before any github access (i.e. nix-build)
    ensure_github_in_known_hosts()
    ensure_ssh_config()

    # some users have wonky file permissions which prevents the ubuntu user
    # inside the container from reading the files we can't do this within the
    # container because it's too late
    ensure_checkout_readable()

    # Build and docker-load the image (nix-build)
    image_full = build_docker_image()

    ensure_target_volume()

    ensure_keepalive_container()

    run_container(image_full, cmd, relative_path)


def build_docker_image():
    """
    Return docker-dfinity-env:<tag>.

    This ensures that the environment docker image is built according to the
    codebase, and that the image is docker-loaded.
    """
    # The log file, used only in case of build failure. The logs are left
    # behind if the build fails, and removed if the build succeeds.
    nix_logs, nix_logs_path = tempfile.mkstemp()

    # We pass the UID and the primary group ID of the logged user to make sure
    # that permissions within the container (i.e. the 'ubuntu' user) matches
    # that of the user on the host.
    docker_build_args = [
        "--build-arg",
        f"UID={UID}",
        "--build-arg",
        f"GID={GID}",
    ]

    image_full: str

    with open(HOME / "outsource-checkout" / "outsource" / "docker" / "Dockerfile", "rb") as dockerfile:
        # We hash the dockerfile content and the docker build arguments and use
        # that as the image tag. This ensures that the image is rebuilt if
        # either changes.
        # More over we use the same content that we feed to docker build
        # through stdin to avoid a concurrent sync modifying the Dockerfile,
        # which would cause the resulting image to be incorrectly tagged.

        image_hash = hashlib.sha256()
        image_hash.update(dockerfile.read())
        [image_hash.update(build_arg.encode("utf-8")) for build_arg in docker_build_args]
        image_hash = image_hash.hexdigest()

        image_full = f"docker-dfinity-env:{USER}-{image_hash[:10]}"

        if (
            subprocess.check_output(["docker", "images", "-q", image_full], stderr=subprocess.DEVNULL)
            .decode("utf-8")
            .rstrip()
        ):
            log(f"image exists {image_full}")
            return image_full

        log(f"building {image_full}")

        dockerfile.seek(0)

        debug(f"nix logs: {nix_logs_path}")

        try:
            subprocess.check_call(
                ["docker", "build", "--tag", image_full, "-"] + docker_build_args,
                stderr=nix_logs,
                stdin=dockerfile,
            )
            os.remove(nix_logs_path)
            debug("nix-build successful")
        except subprocess.CalledProcessError:
            log(f"docker image build failed, logs can be found on the remote at {nix_logs_path}")
            log("")
            subprocess.check_call(["tail", nix_logs_path])
            exit(1)

    return image_full


def parse_args():
    """Parse arguments."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument(
        "-v",
        "--verbose",
        help="prints all logs.",
        action="store_true",
    )

    parse_build_args(parser)

    return parser.parse_args()


def parse_build_args(parser):
    """Parse the arguments for the build command."""
    parser.add_argument(
        "--relative-path",
        help="Where to run the command from.",
    )
    parser.add_argument(
        "--command",
        help="The command to run, encoded as a base64-encoded JSON array.",
    )

    parser.add_argument(
        "--wipe",
        help="Wipe system first.",
        action="store_true",
    )
    parser.add_argument(
        "--stop",
        help="Stop containers first.",
        action="store_true",
    )


def mk_container_tag(cmd: shell_safe.Command) -> str:
    """
    Create a tag for the container running the command.

    For debugging purposes, the tag includes:
        * the current time (seconds since the epoch)
        * the command being run (sanitized as alphanum + underscore)
        * the username

    Moreover we add a (somewhat) unique string (because two containers cannot
    have the same name).
    """
    cmd_str: str
    if isinstance(cmd, str):
        cmd_str = cmd
    else:
        cmd_str = "-".join(cmd)

    cmd_sanitized = re.sub("[^0-9a-zA-Z]+", "-", cmd_str)

    date_secs = str(int(time.time()))

    cmd_unique = "".join(random.choice(string.ascii_lowercase) for _ in range(8))

    return "-".join([USER, cmd_sanitized[:20], date_secs, cmd_unique])


def ensure_ssh_config():
    """
    Make sure the correct user is used when SSH-ing.

    NOTE: Since ~/.ssh is mounted on the container, this ensures that SSH
    commands don't use "ubuntu" as their user. If the file already exists and
    has content, it is not touched.
    """
    content_v1 = f"Host *\n    User {USER}"

    ssh_config_path = HOME / ".ssh" / "config"

    with ssh_config_path.open("a+") as config:
        # 'a+' creates the file if it doesn't exist but places the
        # cursor at the end, so we rewind
        # (r+ doesn't create the file, and w+ truncates it)
        config.seek(0)

        content_actual = config.read()

        if content_actual == "":
            debug("Empty SSH config, writing content")
            config.write(content_v1)
        elif content_actual == content_v1:
            debug("SSH config already has content")
        else:
            warn(f"Unknown content in {ssh_config_path}")

    os.chmod(HOME / ".ssh" / "config", 0o600)


def ensure_github_in_known_hosts():
    """
    Perform an ssh keyscan for 'github.com'.

    It first checks that ~/.ssh/known_hosts does _not_ contain "github.com". If
    it does contain "github.com", the keyscan is skipped.
    """
    with (HOME / ".ssh" / "known_hosts").open("a+") as known_hosts:
        # 'a+' creates the file if it doesn't exist but places the
        # cursor at the end, so we rewind
        # (r+ doesn't create the file, and w+ truncates it)
        known_hosts.seek(0)

        if "github.com" in known_hosts.read():
            debug("known_hosts has github.com")
        else:
            debug("adding github.com to known_hosts")
            gh_key = (
                subprocess.check_output(["ssh-keyscan", "github.com"], stderr=subprocess.DEVNULL)
                .decode("utf-8")
                .rstrip()
            )
            known_hosts.write(f"{gh_key}\n")


def log(s):
    """
    Log a single line at a time to avoid cluttering the output.

    In verbose mode, print everything and never clear.

    """
    if VERBOSE:
        print(f"[outsource]: {s}")
    else:
        sys.stdout.write("\033[K")  # clear
        print(f"[outsource]: {s}", end="\r")  # reset the cursor to beginning of line with \r


def debug(s):
    if VERBOSE:
        log(s)


def warn(s):
    log(f" WARNING: {s}\n")


def create_docker_volume():
    """
    Try to create the user's volume.

    To avoid failing if several invocations of this script are run at the same
    time, we simply issue a warning if the creation failed.
    """
    volume_name = mk_volume_name()
    docker_volume_cmd = [
        "docker",
        "volume",
        "create",
        "--driver",
        "local",
    ]

    docker_volume_cmd += [volume_name]
    debug(f"creating volume {volume_name}: {docker_volume_cmd}")
    try:
        subprocess.check_output(docker_volume_cmd, stderr=subprocess.DEVNULL)

        # Make sure that the volume is owned by the user (by default Docker
        # makes it owned by root). Note that this is a Docker volume and hence
        # does not impact the host filesystem at all.
        subprocess.check_output(
            [
                "docker",
                "run",
                "-d",
                "--rm",
                "--name",
                keepalive_container_name(),
                "-v",
                f"{mk_volume_name()}:/persisted",
                "ubuntu",
                "/bin/bash",
                "-c",
                f"chown -R {UID}:{GID} /persisted",
            ]
        )

    except subprocess.CalledProcessError:
        warn(f"could not create docker volume {volume_name}, the volume may exist already")


def kill_containers():
    """Kill the user's containers."""
    out = (
        subprocess.check_output(["docker", "ps", "--quiet", "--all", f"--filter=name={USER}-*"])
        .decode("utf-8")
        .rstrip()
    )

    for container in out.splitlines():
        debug(f"found container: '{container}'")
        subprocess.check_call(["docker", "kill", container])
        debug(f"container '{container}' was killed")


def rm_docker_volume():
    """
    Try to remove the user's volume.

    To avoid failing if several invocations of this script are run at the same
    time, we simply issue a warning if the removal failed.
    """
    volume_name = mk_volume_name()
    debug(f"deleting volume {volume_name}")
    try:
        subprocess.check_output(["docker", "volume", "rm", volume_name], stderr=subprocess.DEVNULL)

    except subprocess.CalledProcessError:
        warn(f"could not remove docker volume {volume_name}, the volume may not exist, or may still be in use.")
        # show the user's containers
        subprocess.check_call(["docker", "ps", "--quiet", "--all", f"--filter=name={USER}-*"])


def mk_volume_name():
    """Return the name of the user's volume."""
    return f"{USER}-target"


def keepalive_container_name():
    """Return the name of the keepalive container."""
    return f"{USER}-keepalive"


def ensure_target_volume():
    """
    Ensure that the user has a volume.

    If not, the volume is created.

    NOTE: There is a slight race condition here between the volume creation and
    the GC. The GC might kick in after the volume was created, but before the
    volume is attached to the keepalive container. Since the container is
    created (milli-)seconds after the volume, and since the GC kicks in only once a
    week, it's extremely unlikely to happen, but this needs to be addressed
    nonetheless.
    """
    volume_name = mk_volume_name()

    debug(f"checking volume {volume_name}")

    if (
        subprocess.check_output(
            [
                "docker",
                "volume",
                "ls",
                "--quiet",
                "--filter",
                f"name={volume_name}",
            ],
            stderr=subprocess.DEVNULL,
        )
        .decode("utf-8")
        .rstrip()
    ):
        debug(f"volume {volume_name} exists")
    else:
        debug(f"volume {volume_name} does not exist, creating")
        create_docker_volume()


def ensure_keepalive_container():
    """
    Ensure that the user has a keepalive container running.

    The target volume is attached to the keepalive container, preventing the
    volume from being GCed.
    """
    keepalive_name = keepalive_container_name()
    keepalive_path = "/persisted/keepalive"

    if (
        not subprocess.check_output(
            [
                "docker",
                "ps",
                "--quiet",
                "--all",
                "--filter",
                f"name={keepalive_container_name()}",
            ],
            stderr=subprocess.DEVNULL,
        )
        .decode("utf-8")
        .rstrip()
    ):
        debug(f"keepalive container {keepalive_name} does not exist, creating")
        touch_keepalive = [
            f"mkdir -p $(dirname {keepalive_path}) && touch {keepalive_path}",
            f"while find {keepalive_path} -mmin -{KEEPALIVE_HOURS * 60} | grep . ",
            'do echo "file is recent enough, staying alive"',
            "sleep 1",
            "done",
        ]

        subprocess.check_output(
            [
                "docker",
                "run",
                "-d",
                "--rm",
                "--name",
                keepalive_container_name(),
                "--user",
                str(UID),
                "-v",
                f"{mk_volume_name()}:/persisted",
                "ubuntu",
                "/bin/bash",
                "-c",
                ";".join(touch_keepalive),
            ]
        )


def ensure_checkout_readable():
    """Ensure all files in the checkout are readable."""
    subprocess.check_call(
        [
            "chmod",
            "+rX",
            HOME / "outsource-checkout",
            "-R",
        ],
        stdout=subprocess.DEVNULL,
    )


def run_container(image_full, cmd: shell_safe.Command, relative_path):
    """
    Run the user command inside a container.

    This creates a container with the dev env and runs the user's command
    inside it.

    """
    # Get a unique, meaningful tag for the container
    container_tag = mk_container_tag(cmd)

    # Read the SSH_AUTH_SOCK that is set by SSH when the ssh-agent is
    # forwarded. If it is set, we forward it to the container.
    ssh_auth_sock = os.environ.get("SSH_AUTH_SOCK")

    debug(f"Creating container: {container_tag}")

    docker_volume_args = [
        "-v",
        f"/home/{USER}/outsource-checkout:/src:ro",
        "-v",
        f"{mk_volume_name()}:/persisted",  # the target volume
        "-v",
        "/nix/store:/nix/store:ro",  # the host store which gets populated by the nix-daemon on nix-builds
        "-v",
        "/nix/var/nix/daemon-socket/socket:/tmp/daemon-socket/socket",  # the socket through which to communicate with the nix-daemon
        "-v",
        f"/home/{USER}/.ssh:/home/ubuntu/.ssh",  # share the ssh dir, mostly for known_hosts
    ]

    # We mount the socket to the container if ssh-agent is forwarded
    if ssh_auth_sock:
        docker_volume_args += ["-v", f"{ssh_auth_sock}:{ssh_auth_sock}"]

    # We store the PID as a label.
    # We run a reaper process that kills containers who don't have an
    # associated process running because we have no way of killing the
    # containers if the "docker run" command exits.
    my_pid = os.getpid()

    docker_create_args = (
        [
            "--label",
            f"org.dfinity.outsource-server-py-pid={my_pid}",
            "--rm",
            "--tty",  # allocate TTY and make sure the container is interactive to get nice colors from cargo and make sure signals are (somewhat) propagated.
            "--interactive",
            "-e",
            f"USER={USER}",
            "--user",
            str(UID),
            "--name",
            container_tag,
        ]
        + docker_volume_args
        + [
            image_full,
        ]
    )

    # Commands executed as the user inside the container
    #
    # note about the rsync command:
    # We copy the source to a writable, persisted dir. We do this because we
    # cannot remove the protobuf generated files without tiping the target dir
    # as well (see https://dfinity.atlassian.net/browse/INF-1632). And because
    # we _do_ want to delete other files that are not present in the user's
    # local check out we specify --delete _but_ we use --filter to 'P'rotect
    # the generated files.

    # Environment variables
    env_cmds = (["echo 'remote: touching keepalive'"] if VERBOSE else []) + [
        "touch /persisted/keepalive",
        "SAVED_OPTS=$(set +o)",
        "set -euo pipefail",
        "export IN_NIX_SHELL=impure",  # XXX: this is needed by some tools to function properly.
        "export CARGO_HOME=/persisted/cargo-home",
        "export CARGO_TARGET_DIR=/persisted/cargo-target",
        "export RUSTC_WRAPPER=sccache",
        "export SCCACHE_DIR=/persisted/sccache",
        "export XDG_CACHE_HOME=/persisted/.cache",  # make sure the nix "cache" (not the binary cache, the other one) is saved for faster eval. Right now the shell invocation goes from 20s down to 7s.
        "export SCCACHE_CACHE_SIZE=100G",
        "export NIX_STATE_DIR=/tmp",
        "export NIX_LOG_DIR=/tmp",
        "export NIX_REMOTE=daemon",
        "export NIX_PROFILES='/nix/var/nix/profiles/default /home/ubuntu/.nix-profile'",
        "export NIX_SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt",
    ]

    if ssh_auth_sock:
        env_cmds += [f"export SSH_AUTH_SOCK={ssh_auth_sock}"]

    log("loading shell and running command")
    print("")
    # Load sorri and restore shell opts
    env_cmds += [
        "export SORRI_SILENT=1",
        "pushd /src/rs >/dev/null && . /src/nix/sorri && popd >/dev/null",
        'eval "$SAVED_OPTS"',
    ]

    # To make sure arguments and forwarded properly from the local to the host
    # to the container, we never touch them but let Bash deal with its own
    # idiosyncracies. In particular, we just pass them as arguments to
    # /bin/bash -c (the "$@") bit at the end.
    cmds = env_cmds + [
        f'rsync -a --delete --filter "protect **/gen/**" /src/. /persisted/build/ && cd /persisted/build/{relative_path}',
    ]

    docker_run = ["docker", "run"]
    docker_run += docker_create_args
    # if the command is a single string, run it directly as part of the docker
    # run command. If it has arguments, then run "$@" and feed the arguments.
    if isinstance(cmd, list):
        cmds += ['"$@"']
        # here we prepend the command with "bash" because "$@" does not include
        # "$0" (generally the executable name, though could be set to anything).
        docker_run += ["/bin/bash", "-eo", "pipefail", "-c", " && ".join(cmds)] + ["bash"] + cmd
    elif isinstance(cmd, str):
        cmds += [cmd]
        docker_run += ["/bin/bash", "-ec", " && ".join(cmds)]

    debug(f"executing command: {docker_run}")

    proc = subprocess.Popen(docker_run)

    sys.exit(proc.wait())


if __name__ == "__main__":
    main()
