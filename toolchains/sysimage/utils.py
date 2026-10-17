#!/usr/bin/env python3
#
# Common utilities
#

import os

# Freeze the clock at the epoch for reproducible timestamps by preloading
# libfaketime directly, with its shared memory disabled. Both the `faketime`
# wrapper and libfaketime itself create a semaphore and shared memory in
# /dev/shm named after the PID, to share a running clock between processes.
# Bazel sandboxes have separate PID namespaces but share /dev/shm, so
# concurrent sandboxed actions collide ("File exists"). A frozen absolute time
# needs no shared clock.
# Where distributions install libfaketime; the first one present is used. The
# dev container (Debian/Ubuntu, x86_64) has the first. Set LIBFAKETIME to
# override, e.g. when running these tools outside Bazel on another host.
LIBFAKETIME_PATHS = [
    "/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1",
    "/usr/lib/aarch64-linux-gnu/faketime/libfaketime.so.1",
    "/usr/lib64/faketime/libfaketime.so.1",
    "/usr/lib/faketime/libfaketime.so.1",
]
FAKETIME = "1970-1-1 0:0:0"


def find_libfaketime():
    """Return the path of libfaketime, or raise if it isn't installed."""
    # If the library is missing, ld.so only warns and the command runs with the
    # real clock, silently producing non-reproducible images. Fail instead.
    override = os.environ.get("LIBFAKETIME")
    candidates = [override] if override else LIBFAKETIME_PATHS
    for path in candidates:
        if os.path.isfile(path):
            return path
    raise FileNotFoundError(
        f"libfaketime not found at {', '.join(candidates)}: install libfaketime, "
        "set LIBFAKETIME to its path, or build in the dev container"
    )


def faketime_env(env=None):
    """Return a copy of env (default: os.environ) that runs commands with the clock frozen at the epoch."""
    libfaketime = find_libfaketime()
    env = dict(os.environ if env is None else env)
    env["LD_PRELOAD"] = libfaketime + (":" + env["LD_PRELOAD"] if env.get("LD_PRELOAD") else "")
    env["FAKETIME"] = FAKETIME
    env["FAKETIME_DISABLE_SHM"] = "1"
    return env


def parse_size(s):
    if s[-1] == "k" or s[-1] == "K":
        return 1024 * int(s[:-1])
    elif s[-1] == "m" or s[-1] == "M":
        return 1024 * 1024 * int(s[:-1])
    elif s[-1] == "g" or s[-1] == "G":
        return 1024 * 1024 * 1024 * int(s[:-1])
    else:
        return int(s)
