#!/usr/bin/env python3
# vim ft=python
"""
Execute commands on a remote builder.

This will first sync your codebase to the
remote host and then run the specified command. The command will be run in the
appropriate directory on the remote host. With the following command, the
`cargo build` will be run in <checkout>/rs/phantom_newtype on the remote
builder:

$ cd rs/phantom_newtype && remote cargo build

Examples
--------
$ cd rs && remote -v cargo check
$ cd rs/phantom_newtype && remote --user johndoe -- cargo -v build
$ remote -h

"""
import argparse
import json
import os
import pathlib
import random
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from socket import timeout
from urllib.error import HTTPError
from urllib.error import URLError

import shell_safe

OUTSOURCE_HOSTS = ["zh1-spm23.zh1.dfinity.network"]
VERBOSE = False
HOME = pathlib.Path.home()
XDG_CACHE_HOME = os.environ.get("XDG_CACHE_HOME", HOME / ".cache")

# The cache directory used by the 'remote' script (mostly for the SSH Control
# socket)
CACHE_DIR = pathlib.Path(XDG_CACHE_HOME) / "dfinity-outsource"

# The SSH control socket path, suffixed with the hostname
SSH_CONTROL_PATH = CACHE_DIR / "remote-control-%h"


def pick_host(user):
    """
    Pick a host based on the username.

    This hashes the username and returns a (known) host. We do this to ensure
    that the workload is spread amongst all our remote builders.
    """
    random.seed(user)
    return random.choice(OUTSOURCE_HOSTS)


def sanitized_argv(cli_args=None):
    """
    Return a list of arguments where -- may have been inserted.

    By default argparse gets confused with commands like the following:
    $ remote foo --yay bar
    The '--yay' argument should be sent to the "foo" command, but argparse
    interprets it as a "remote" argument. So here we iterate over the
    arguments, and insert "--" as soon as we encounter the first non "-"
    argument.
    """
    cli_args = sys.argv[1:] if not cli_args else cli_args  # skip the exe name

    if "--" in cli_args:
        return cli_args

    args = []
    for arg in cli_args:
        if "--" not in args and not arg.startswith("-"):
            args.append("--")
        args.append(arg)
    return args


def push_data_to_elastic_search(data):
    """
    Post `data` to our ElasticSearch instance at `index_name`.

    This script was adapted from gitlab-ci/.
    The index name is hardcoded to a test index for the time being.

    The ingest goes through the "add_timestamp" pipeline which was created like
    so:
        > http PUT elasticsearch.dfinity.systems:9200/_ingest/pipeline/add_timestamp description="the pipeline" processors:='[{"set": {"field": "ingest_timestamp", "value": "{{_ingest.timestamp}}" } }]'

    in the future, the pipeline should be terraformed.

    Args:
    ----
        data: The JSON data to export.

    """
    index_name = "outsource-test"
    pipeline_name = "add_timestamp"
    req = urllib.request.Request(
        "http://elasticsearch.dfinity.systems:9200/%s/_doc?pipeline=%s" % (index_name, pipeline_name),
        # Always sort keys so output is comparable for tests.
        data=json.dumps(data, sort_keys=True).encode(),
        headers={"content-type": "application/json"},
    )

    try:
        urllib.request.urlopen(req, timeout=5)
    except (HTTPError, URLError) as error:
        print(f"[outsource]: WARNING: could not upload metrics: {error}")
    except timeout:
        print("[outsource]: WARNING: could not upload metrics: timed out")


def main():
    # Everything CLI related to read the host, user, verbosity and command

    metrics = {}

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument(
        "-v",
        "--verbose",
        help="prints all logs, can also be set with OUTSOURCE_DEBUG=1.",
        action="store_true",
    )
    parser.add_argument(
        "--wipe",
        help="Wipe system first (implies --stop).",
        action="store_true",
    )
    parser.add_argument(
        "--stop",
        help="stop running containers first.",
        action="store_true",
    )
    parser.add_argument(
        "--host",
        help="The default host to connect to, can also be set through the environment variable OUTSOURCE_HOST",
        default=os.environ.get("OUTSOURCE_HOST"),
    )
    parser.add_argument(
        "--user",
        help="The default host to connect to, can also be set through the environment variable OUTSOURCE_USER",
        default=os.environ.get("OUTSOURCE_USER") or os.environ.get("USER"),
    )
    parser.add_argument(
        "--no-multiplex",
        help="Disable SSH connection multiplexing, SSH connection multiplexing can also be disabled by setting OUTSOURCE_NO_MULTIPLEX=1.",
        action="store_true",
        default=os.environ.get("OUTSOURCE_NO_MULTIPLEX") is not None,
    )
    parser.add_argument("cmd", help="The command to run.", nargs="*")

    try:
        args = parser.parse_args(sanitized_argv())
    except SystemExit:
        print(
            "\nMake sure to check the FAQ: https://gitlab.com/dfinity-lab/core/ic/blob/master/outsource/README.md#faq"
        )
        exit(1)

    global VERBOSE  # XXX ugly
    VERBOSE = args.verbose
    user = args.user
    metrics["user"] = user
    host = args.host or pick_host(user)
    metrics["host"] = host
    cmd: shell_safe.Command
    if len(args.cmd) == 1:
        cmd = args.cmd[0]
    else:
        cmd = args.cmd
    metrics["cmd"] = cmd
    wipe = args.wipe
    metrics["wipe"] = wipe
    stop = args.stop
    metrics["stop"] = stop
    no_multiplex = args.no_multiplex
    metrics["no_multiplex"] = no_multiplex

    if wipe and os.path.isdir(CACHE_DIR):
        shutil.rmtree(CACHE_DIR)

    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    # Figure out in which directory the command should be run on the builder
    # We do this by looking up the checkout root (based on git) and the PWD, and
    # remote the root (prefix) from the PWD.

    here = os.getcwd()

    root = subprocess.check_output(["git", "rev-parse", "--show-toplevel"]).decode("utf-8").rstrip()

    # relative as a UNIX-friendly path
    relative = str(pathlib.Path(here).relative_to(root))

    metrics["relative"] = relative

    debug(f"verbose: {VERBOSE}")
    debug(f"host: {host}")
    debug(f"user: {user}")
    debug(f"cwd: {here}")
    debug(f"root: {root}")
    debug(f"relative: {relative}")
    debug(f"cmd: {cmd}")
    debug(f"wipe: {wipe}")
    debug(f"stop: {stop}")
    debug(f"no_multiplex: {no_multiplex} (multiplex: {not no_multiplex})")

    # rsync the local checkout to the builder, using --filter to skip all
    # non-staged files

    log(f"syncing files with {user}@{host}")

    ssh_opts = [
        "-A",  # forward the SSH agent (useful when e.g. checking out repos)
        "-t",  # Make sure SSH allocates a TTY so that signals are forwarded and so that the command is killed by sshd when the connection is closed.
        "-o",
        "LogLevel=QUIET",  # suppress some message after connection is closed
    ]

    if not no_multiplex:
        ssh_opts += [
            "-o",
            "ControlMaster=auto",  # Make sure that the command(s) multiplex by creating a control connection if it does not exist yet
            "-o",
            f"ControlPath={SSH_CONTROL_PATH}",
            "-o",
            "ControlPersist=3600",  # Persist the control connection for an hour (in seconds)
        ]

    log(f"syncing files to {host}")

    sync_start = time.time_ns()
    try:
        rsync_to_builder(
            source=root,
            target=f"{user}@{host}:/home/{user}/outsource-checkout",
            ssh_opts=ssh_opts,
        )
    except subprocess.CalledProcessError:
        print(f"cannot sync files to host {host}")
        print("Make sure the host is reachable or specify another host with '--host my.host.com' ")
        print(f"Known hosts: {', '.join(OUTSOURCE_HOSTS)}")
        print("If the problem persists, try disabling SSH multiplexing with 'remote --no-multiplex'")
        print(" or by setting the environment variable OUTSOURCE_NO_MULTIPLEX to 1.")
        exit(1)
    sync_stop = time.time_ns()
    metrics["sync_files_ns"] = sync_stop - sync_start

    # Finally, SSH in and run the command. The command is passed to `server`,
    # which spins up the container.

    remote_cmd = f"/home/{user}/outsource-checkout/outsource/server.py"

    if VERBOSE is True:
        remote_cmd = f"{remote_cmd} -v"
    if wipe is True:
        remote_cmd = f"{remote_cmd} --wipe"
    if stop is True:
        remote_cmd = f"{remote_cmd} --stop"

    remote_cmd = f"{remote_cmd} --relative-path {relative} --command {shell_safe.encode(cmd)}"

    ssh_cmd = (
        [
            "ssh",
        ]
        + ssh_opts
        + [
            f"{user}@{host}",
            # This starts a login shell on the remote machine and passes the command to
            # the `server` script
            f"bash -l -c '{remote_cmd}'",
        ]
    )

    debug(ssh_cmd)

    # NOTE: by default, Popen inherits the main process' `stdin`, so any input
    # entered on the local machine will be sent to the remote machine.
    proc = subprocess.Popen(ssh_cmd)

    ret = proc.wait()

    if ret != 0:
        log(f"command returned with {ret}, for a clean state re-run with 'remote --wipe'\n")

    metrics["status"] = ret
    log("sending metrics")
    print("")
    push_data_to_elastic_search(metrics)


def rsync_to_builder(source, target, ssh_opts=[]):
    """
    Sync relevant files to the remote builder.

    This syncs the relevant files:
    * files tracked in git
    * files untracked in git

    Basically, everything that is _not_ git ignored.
    Unfortunately --files-from + --delete doesn't work because old untracked files are not
    deleted. We use --include-from to specify the list of files to sync, and
    _remove everything else_ on the target (note however that generated files
    are kept on the _volume_).
    """
    source = source.rstrip("/")
    target = target.rstrip("/")

    git_files = subprocess.check_output(["git", "ls-files"], cwd=source).decode("utf-8").splitlines()

    untracked_files = (
        subprocess.check_output(["git", "ls-files", "--others", "--exclude-standard"], cwd=source)
        .decode("utf-8")
        .splitlines()
    )

    sync_files = git_files + untracked_files

    # --include-from needs the directories to be listed too, so we list them.
    # This is a bit slow but really nothing compared to actually syncing the
    # files.
    directories = set()
    for directory in sync_files:
        while directory != "":
            directory = os.path.dirname(directory)
            directories.add(directory + "/")

    sync_files += list(directories)

    debug("requesting sync for files:")

    [debug(f" '{f}'") for f in sync_files]

    with tempfile.NamedTemporaryFile() as filelist:

        filelist.write("\n".join(sync_files).encode("utf-8"))
        filelist.seek(0)

        rsync_args = (
            ["rsync"]
            + (["--verbose"] if VERBOSE else [])
            + (["--rsh", f"ssh {' '.join(ssh_opts)}"] if ssh_opts else [])
            + [
                f"--include-from={filelist.name}",
                "--exclude=*",
                "--delete-excluded",
                "-a",
                f"{source}/",  # the '/' is needed to write the contents directly and not inside a directory called "dirname".
                target,
            ]
        )

        debug(rsync_args)
        try:
            subprocess.check_call(rsync_args)
        except subprocess.CalledProcessError as e:
            print(f"Failed to connect with {rsync_args}")
            raise e


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


if __name__ == "__main__":
    main()
