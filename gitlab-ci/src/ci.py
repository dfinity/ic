import binascii
import hashlib
import logging
import os
import pathlib
import platform
import shlex
import subprocess
import time
from contextlib import contextmanager
from os import getenv
from os import path
from typing import Iterable
from typing import List
from typing import Literal
from typing import Optional
from typing import overload
from typing import TypeVar

import beeline

_here = path.realpath(__file__)
_top = path.realpath(path.join(_here, "../../.."))


@overload
def sh(*popenargs, pipe_to: Optional[str] = None, capture: Literal[True], **kwargs) -> str:
    ...


@overload
def sh(*popenargs, pipe_to: Optional[str] = None, capture: bool = False, **kwargs):
    ...


def sh(
    *popenargs,
    pipe_to: Optional[str] = None,
    capture: bool = False,
    **kwargs,
):
    cmdline = list(popenargs)
    cmdline_extra = ""
    native_shell = kwargs.get("shell", False)

    if capture:
        assert pipe_to is None, "the `capture` and `pipe_to` arguments are mutually exclusive"
    if native_shell:
        assert pipe_to is None, "don't use `pipe_to` when shell=True, just use native pipe"
        assert len(cmdline) == 1, "don't pass multiple arguments when shell=True, they will not be preserved"

    if pipe_to is not None:
        kwargs["stdout"] = open(pipe_to, "w")
        cmdline_extra = f" > {pipe_to}"

    if native_shell:
        logging.info(f"$ {cmdline[0]}")
    else:
        logging.info(f"$ {shlex.join(cmdline)}{cmdline_extra}")

    if capture:
        return subprocess.run(cmdline, text=True, stdout=subprocess.PIPE, **kwargs).stdout.strip()
    else:
        subprocess.run(cmdline, **kwargs).check_returncode()


def mkdir_p(dir):
    logging.info(f"$ mkdir -p {dir}")
    pathlib.Path(dir).mkdir(parents=True, exist_ok=True)


T = TypeVar("T")
S = TypeVar("S")


def flatten(ls: Iterable[Iterable[T]]) -> List[T]:
    return [item for sublist in ls for item in sublist]


# set up honeycomb API
key = getenv("BUILDEVENT_APIKEY", "none")
dataset = getenv("BUILDEVENT_DATASET", "local")
beeline.init(writekey=key, debug=key == "none", dataset=dataset)


def buildevent(name):
    """Return a beeline context manager which is prefilled with the trace_id and parent_id set by GitLab."""
    root_pipeline_id = getenv("PARENT_PIPELINE_ID", "")
    if root_pipeline_id == "":
        root_pipeline_id = getenv("CI_PIPELINE_ID")
    return beeline.tracer(name, trace_id=root_pipeline_id, parent_id=getenv("CI_JOB_ID"))


@contextmanager
def log_section(header: str, name: Optional[str] = None, collapsed: bool = True):
    """
    Generate a collapsible GitLab CI log section. Only the section header, not the name,
    is displayed to the user, so a random hex string will be generated and used as the
    section name unless you want to specify a name yourself.
    """
    ts = int(time.time())
    name = binascii.b2a_hex(os.urandom(6)).decode("utf-8") if name is None else name
    collapse = "[collapsed=true]" if collapsed else ""
    print(f"\x1b[0Ksection_start:{ts}:{name}{collapse}\r\x1b[0K{header}", flush=True)
    try:
        yield
    finally:
        print(f"\x1b[0Ksection_end:{ts}:{name}\r\x1b[0K", flush=True)


def show_sccache_stats():
    wrapper = getenv("RUSTC_WRAPPER")
    if wrapper is not None:
        with log_section("Click here to see the sccache stats"):
            sh(wrapper, "--show-stats")


@contextmanager
def cwd(dir: str):
    """
    Execute some code with the current working directory of `dir`.

    * If you pass a relative path as `dir`, it will be interpreted relative to the top level of the source tree.
    * If you pass an absolute path, it will be used verbatim.

    Restores the previous working directory when the context ends.
    """
    stored = os.getcwd()
    logging.info(f"$ pushd {dir}")
    newpath = dir if path.isabs(dir) else path.join(ENV.top, dir)
    os.chdir(newpath)
    try:
        yield
    finally:
        logging.info("$ popd")
        os.chdir(stored)


def sha256(string: str) -> str:
    return hashlib.sha256(string.encode("utf-8")).hexdigest()


class Env:
    """Stores a bunch of useful globals."""

    def __init__(self) -> None:
        target = getenv("CARGO_BUILD_TARGET")
        if target is None:
            sys = platform.system()
            if sys == "Linux":
                target = "x86_64-unknown-linux-gnu"
            elif sys == "Darwin":
                target = "x86_64-apple-darwin"
            else:
                raise Exception("unable to guess rust host triple")
        self._cargo_build_target = target
        self._top = _top
        self._cargo_target_dir = getenv("CARGO_TARGET_DIR", path.join(self._top, "rs/target"))
        self._is_gitlab = getenv("CI_JOB_ID", "") != ""
        self._build_id = None

    @property
    def build_target(self):
        return self._cargo_build_target

    @property
    def target(self):
        return self.build_target

    @property
    def cargo_target_dir(self):
        return self._cargo_target_dir

    @property
    def target_dir(self):
        return self._cargo_target_dir

    @property
    def platform_target_dir(self):
        """Equivalent to path.join(target_dir, build_target)."""
        return path.join(self._cargo_target_dir, self._cargo_build_target)

    @property
    def top(self):
        """The top level directory (where .git is)."""
        return self._top

    @property
    def is_linux(self):
        return self.build_target == "x86_64-unknown-linux-gnu"

    @property
    def is_macos(self):
        return self.build_target == "x86_64-apple-darwin"

    @property
    def is_gitlab(self):
        return self._is_gitlab

    @property
    def is_local(self):
        return not self._is_gitlab

    @property
    def build_id(self):
        if self._build_id is None:
            if (
                # this condition is a hack to fix the broken hack of !2067
                getenv("CI_PARENT_PIPELINE_SOURCE", "") == "merge_request_event"
                and getenv("CI_COMMIT_REF_NAME", "") != "broken-blockmaker"
            ):
                buildidcmd = ["placebo", "-c", "build-id", "--inputs_hash"]
            else:
                buildidcmd = ["git", "rev-parse", "--verify", "HEAD"]

            self._build_id = sh(*buildidcmd, cwd=self._top, capture=True)
        return self._build_id


ENV = Env()
