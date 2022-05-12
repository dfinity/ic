import os
import subprocess
import sys
from datetime import datetime
from datetime import timedelta
from threading import Thread
from typing import Any
from typing import Callable
from typing import Dict
from typing import IO
from typing import List
from typing import Optional
from typing import Tuple

import psutil
from func_timeout import func_timeout
from func_timeout import FunctionTimedOut


class DebugMode:
    flag = False


# Inspired by https://stackoverflow.com/a/31614591/4342379
class PropagatingThread(Thread):
    def run(self):
        self.exc = None
        self.ret = None
        try:
            self.ret = self._target(*self._args, **self._kwargs)
        except BaseException as e:
            self.exc = e

    def join(self, timeout=None):
        super().join(timeout)
        if self.exc:
            raise self.exc
        return self.ret


class MonpolyException(Exception):
    def __init__(self, name: str, cmd: str, msg: str):
        super().__init__(msg)
        self.name = name
        self.cmd = cmd
        self.msg = msg


class MonpolyTimeout(MonpolyException):
    pass


class MonpolyIoClosed(MonpolyException):
    pass


class StreamHandlerFailure(MonpolyException):
    def __init__(self, name: str, cmd: str, exception: BaseException):
        super().__init__(name, cmd, msg=str(exception))


class StdoutHandlerFailure(StreamHandlerFailure):
    pass


class StderrHandlerFailure(StreamHandlerFailure):
    pass


class StreamHandlerParams:
    def __init__(self, session: "Monpoly", source: str, message: str):
        self.session = session
        self.source = source
        self.message = message


class AlertHandlerParams(StreamHandlerParams):
    pass


class ErrorHandlerParams(StreamHandlerParams):
    pass


class ExitHandlerParams:
    def __init__(self, session: "Monpoly", exit_code: str):
        self.session = session
        self.exit_code = exit_code


class Monpoly:

    # The endocing used in Monpoly I/O.
    ENCODING = "utf-8"

    # Which version of the Monpoly Docker image to use.
    VERSION = "1.4.1"

    # Sending this datum via [submit] enables I/O synchronization.
    SYNC_MARKER = ">get_pos<"

    # The absolute minumum of the output-stream-draining timeout in [finalize].
    MIN_DRAIN_TIMEOUT = 4.0  # seconds

    # After 1/LARGE_INPUT_FACTOR calls to [submit], the output-stream-draining
    #  timeout in [finalize] reaches its absolute maximum, [_hard_timeout].
    LARGE_INPUT_FACTOR = 1 / 10_000

    # Prefix used to identify final reports from running "time -v monpoly".
    RSS_STAT_MARKER = 'Command being timed: "monpoly '

    @staticmethod
    def is_rss_stat_marker(line: str) -> bool:
        return line.strip().startswith(Monpoly.RSS_STAT_MARKER)

    def print_dbg(self, msg):
        if DebugMode.flag:
            print(f"{self.name}.DBG >> {msg}", flush=True)

    def print(self, msg):
        print(f"{self.name} >> {msg}", flush=True)

    @staticmethod
    def _docker_base_cmd(
        workdir: Optional[str] = None, reprodir: Optional[str] = None, with_rss=False
    ) -> Tuple[str, ...]:

        mountpoints: List[str]
        mountpoints = []
        if workdir:
            mountpoints.append("-v")
            mountpoints.append(f"{workdir}:/work")
        if reprodir:
            mountpoints.append("-v")
            mountpoints.append(f"{reprodir}:/repro")

        res: Tuple[str, ...]
        if with_rss:
            res = (
                ("docker", "run", "-i")
                + tuple(mountpoints)
                + (
                    "--entrypoint=time",
                    f"infsec/monpoly:{Monpoly.VERSION}",
                    "-v",  # this is an argument for "time", not "docker"
                    "monpoly",  # explicitly call "monpoly"
                )
            )
        else:
            # "monpoly" is the default entrypoint
            res = ("docker", "run", "-i") + tuple(mountpoints) + (f"infsec/monpoly:{Monpoly.VERSION}",)

        return res

    def _cmd(
        self,
        with_rss: bool,
        use_local_paths=False,
        stop_at_first_viol=True,
        stop_at_out_of_order_ts=True,
        # no_rw: do not rewrite the policy, i.e.,
        #        do not push negation over conjunction etc.
        no_rw=True,
    ) -> Tuple[str, ...]:

        if self.docker or use_local_paths:
            signatures_file = self.local_sig_file
            formula_file = self.local_formula
        else:
            signatures_file = os.path.join(self.workdir, self.local_sig_file)
            formula_file = os.path.join(self.workdir, self.local_formula)

        monpoly_args: Tuple[str, ...]
        monpoly_args = (
            # '-verbose',
            "-sig",
            signatures_file,
            "-formula",
            formula_file,
        )
        if stop_at_first_viol:
            monpoly_args = monpoly_args + ("-stop_at_first_viol",)
        if stop_at_out_of_order_ts:
            monpoly_args = monpoly_args + ("-stop_at_out_of_order_ts",)
        if no_rw:
            monpoly_args = monpoly_args + ("-no_rw",)

        monpoly_args = monpoly_args + self._extra_options

        res: Tuple[str, ...]
        if self.docker:
            res = (
                Monpoly._docker_base_cmd(
                    self.workdir,
                    self.reprodir,
                    with_rss,
                )
                + monpoly_args
            )
        elif with_rss:
            res = (
                "time",
                "-v",
                "monpoly",
            ) + monpoly_args
        else:
            res = ("monpoly",) + monpoly_args

        return res

    def cmd_str(self) -> str:
        """
        Returns the string representation of the exact Monpoly command that
        is used in this Monpoly session.
        """
        return " ".join(self._cmd(with_rss=(self.stat is not None)))

    def cmd_wo_rss(self, enforce_no_docker=False) -> Tuple[str, ...]:
        """
        Returns the list representation of the Monpoly command that
         is used in this Monpoly session, ** modulo time -v **.
        The -stop_at_first_viol option is ** not included **, making
         this command more suitable for running repros in non-interactive mode.
        """
        if enforce_no_docker:
            tmp = self.docker
            self.docker = False
            res = self._cmd(with_rss=False, stop_at_first_viol=False, use_local_paths=True)
            self.docker = tmp
        else:
            res = self._cmd(with_rss=False, stop_at_first_viol=False)
        return res

    @staticmethod
    def decode(bs: bytes) -> str:
        text = bs.rstrip()
        decoded_text = text.decode(encoding=Monpoly.ENCODING)
        return decoded_text

    @staticmethod
    def install_docker_image():
        """Prints whether the Monpoly image was successfully installed."""
        cmd: Tuple[str]
        cmd = Monpoly._docker_base_cmd() + ("-version",)
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Check that STDOUT contains exactly the expected signature
        signature = "MonPoly (development build)"
        stdout = []
        for line in proc.stdout:
            line = Monpoly.decode(line)
            stdout.append(line)
        assert (
            len(stdout) == 1 and stdout[-1] == signature
        ), "Got unexpected STDOUT after attempting to check MonPoly version: \n" + "\n".join(stdout)

        # Check that nothing is printed into STDERR
        stderr = []
        for line in proc.stderr:
            line = Monpoly.decode(line)
            stderr.append(stderr)
        assert not stderr, "Got something in STDERR after attempting to check MonPoly version:\n" + "\n".join(stderr)

        print(f"{signature} installed successfully")

    @staticmethod
    def get_variables(
        workdir: str,
        local_sig_file: str,
        local_formula: str,
        docker=True,
        hard_timeout=7.0,
    ) -> Tuple[str, ...]:

        var_list: Optional[List[str]] = None
        marker = "The sequence of free variables is: "

        def alert_h(arg: AlertHandlerParams):
            sys.stderr.write(f"found unexpected text in STDOUT: {arg.message}")

        def error_h(arg: ErrorHandlerParams):
            nonlocal var_list
            if arg.message.startswith(marker):
                var_list = arg.message[len(marker) :][1:-1].split(",")

        def exit_h(arg: ExitHandlerParams):
            if arg.exit_code != "0":
                sys.stderr.write(f"non-zero exit code:\n{str(arg.__dict__)}\n")
            if var_list is None:
                sys.stderr.write(f"did not find marker '{marker}' in Monpoly output\n")

        with Monpoly(
            name="infer_variables",
            workdir=workdir,
            local_sig_file=local_sig_file,
            local_formula=local_formula,
            alert_handler=alert_h,
            error_handler=error_h,
            exit_handler=exit_h,
            docker=docker,
            hard_timeout=hard_timeout,
            extra_options=("-check",),
        ):
            pass

        assert var_list is not None, "could not obtain variable names from MonPoly"

        return tuple(var_list)

    docker: bool

    _outputs: List[str]
    _proc: Optional[Any]

    def __init__(
        self,
        name: str,
        workdir: str,
        local_sig_file: str,
        local_formula: str,
        alert_handler: Callable[[AlertHandlerParams], None],
        error_handler: Callable[[ErrorHandlerParams], None],
        exit_handler: Callable[[ExitHandlerParams], None],
        docker=True,
        hard_timeout=10.0,
        extra_options=(),
        stat: Optional[Dict[str, Any]] = None,
        reprodir: Optional[str] = None,
    ):
        """
        docker:
            If False, we assume that the `monpoly` command is installed.
            If True, we assume that `docker` is installed.

        hard_timeout:
            maximal number of seconds to wait for Monpoly to close STDOUT
            and STDERR after closing STDIN.
        """
        self.name = name
        self.workdir = workdir
        self.reprodir = reprodir
        self.local_sig_file = local_sig_file
        self.local_formula = local_formula

        assert Monpoly.MIN_DRAIN_TIMEOUT <= hard_timeout, f"hard_timeout must be ≥ {Monpoly.MIN_DRAIN_TIMEOUT}"
        self._hard_timeout = hard_timeout
        self._extra_options = extra_options

        self.__start_time = None
        self.__stop_time = None

        self._outputs = []  # contains only responses
        self._proc = None

        self._alert_handler = alert_handler
        self._stdout_listener_thread = PropagatingThread(target=self._stdout_listener)

        self._error_handler = error_handler
        self._stderr_listener_thread = PropagatingThread(target=self._stderr_listener)

        self._exit_handler = exit_handler

        self.docker = docker

        self._input_counter = 0
        self._stdout_counter = 0
        self._stderr_counter = 0

        self.stat = stat

    def _bump_stdout_counter(self) -> None:
        self._stdout_counter += 1

    def _bump_stderr_counter(self) -> None:
        self._stderr_counter += 1

    def _timeout(self, msg: str) -> MonpolyTimeout:
        return MonpolyTimeout(name=self.name, cmd=self.cmd_str(), msg=msg)

    def _io_error(self, msg: str) -> MonpolyIoClosed:
        return MonpolyIoClosed(name=self.name, cmd=self.cmd_str(), msg=msg)

    def _stdout_handler_failure(self, e: BaseException) -> StreamHandlerFailure:

        return StdoutHandlerFailure(name=self.name, cmd=self.cmd_str(), exception=e)

    def _stderr_handler_failure(self, e: BaseException) -> StreamHandlerFailure:

        return StderrHandlerFailure(name=self.name, cmd=self.cmd_str(), exception=e)

    @staticmethod
    def _read_stream(stream: IO[bytes], handler: Callable[[str], None]):
        while True:
            line = stream.readline()
            if not line:
                break
            decoded_line = Monpoly.decode(line)
            handler(decoded_line)

    def _stdout_listener(self):
        self.print("Starting Monpoly listener thread ...")

        def handler(line: str) -> None:
            try:
                self._alert_handler(
                    AlertHandlerParams(
                        session=self,
                        source="monpoly_stdout_listener",
                        message=line,
                    )
                )
            except BaseException as e:
                raise self._stdout_handler_failure(e)

            self._stdout_counter += 1

        try:
            self._read_stream(self._proc.stdout, handler)
        except ValueError:
            pass

        self.print("Finished Monpoly listener thread.")

    def read_rss_stats(self, line: str) -> None:
        assert self.stat is not None, "please initialize Monpoly.stats before calling read_rss_stats!"
        line = line.strip()
        key, value = line.split(": ")
        key = key.lower().replace(" ", "_")
        key = "".join(c for c in key if c.isalnum() or c == "_")
        if "perf_metrics" not in self.stat:
            self.stat["perf_metrics"] = dict()
        self.stat["perf_metrics"][key] = value.strip()

    def _stderr_listener(self):
        self.print("Starting Monpoly error listener thread ...")

        found_rss_stat_marker = False

        def handler(line: str) -> None:
            nonlocal found_rss_stat_marker
            if self.stat is not None and not found_rss_stat_marker and Monpoly.is_rss_stat_marker(line):
                # Handle final statistics reported by "time -v"
                # Assume the rest of STDOUT is RSS stats
                found_rss_stat_marker = True
            elif self.stat is not None and found_rss_stat_marker:
                self.read_rss_stats(line)
            else:
                # Treat this line as Monpoly output
                try:
                    self._error_handler(
                        ErrorHandlerParams(
                            session=self,
                            source="monpoly_stderr_listener",
                            message=line,
                        )
                    )
                except BaseException as e:
                    raise self._stderr_handler_failure(e)

                self._stderr_counter += 1

        try:
            self._read_stream(self._proc.stderr, handler)
        except ValueError:
            pass

        self.print("Finished Monpoly error listener thread.")

    def __str__(self):
        """Returns a serialized representation of this Monpoly session"""
        return self.cmd_str() + "\n" + "\n".join(self._outputs)

    def __enter__(self):
        """Starts a new Monpoly session"""
        self.print("Preparing Monpoly process ...")

        self.__start_time = datetime.now()

        cmd = self._cmd(with_rss=(self.stat is not None))
        self.print(f"Starting Monpoly via command: {' '.join(cmd)}")

        self._proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        self._stdout_listener_thread.start()
        self._stderr_listener_thread.start()

        self.print("Preparing Monpoly done.")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Gracefully finalizes the Monpoly session"""
        self.print("Finalizing Monpoly process ...")
        self.__stop_time = datetime.now()
        exit_code = self.finalize()
        self._exit_handler(
            ExitHandlerParams(
                session=self,
                exit_code=str(exit_code),
            )
        )
        duration = self.duration()
        self.print(
            f"Finalizing Monpoly done.\n"
            f"  Session duration: {str(duration)}\n"
            f"  Input data: {self._input_counter}\n"
            f"  STDOUT counter: {self._stdout_counter}\n"
            f"  STDERR counter: {self._stderr_counter}\n"
            f"  Exit code: {exit_code}"
        )
        if self.stat is not None:
            self.stat["process_duration_seconds"] = duration.total_seconds()
            self.stat["num_events"] = self._input_counter
            self.stat["num_violations_reported"] = self._stdout_counter
            self.stat["num_errors"] = self._stderr_counter
            self.stat["exit_code"] = exit_code

    def duration(self) -> timedelta:
        assert self.__start_time, "Monpoly did not start"
        if self.__stop_time:
            end_time = self.__stop_time
        else:
            end_time = datetime.now()
        return end_time - self.__start_time

    @staticmethod
    def _kill(pid):
        process = psutil.Process(pid)
        for proc in process.children(recursive=True):
            proc.kill()
        process.kill()

    def _drain_output_streams(self, timeout: float) -> None:
        first_start = datetime.now()
        self._stdout_listener_thread.join(timeout=timeout)
        new_timeout = timeout - (datetime.now() - first_start).total_seconds()
        self._stderr_listener_thread.join(timeout=new_timeout)

    def finalize(self, term_timeout=5.0) -> Optional[int]:

        assert self._proc is not None, "finalized called but self._proc is None"

        # 1. Tell Monpoly to stop
        try:
            self._proc.stdin.close()
        except BrokenPipeError:
            # the process may have already closed STDIN
            pass

        # 2. Drain the output streams
        event_timeout = self._hard_timeout * Monpoly.LARGE_INPUT_FACTOR
        drain_timeout = self._input_counter * event_timeout - self.duration().total_seconds()
        drain_timeout = max(drain_timeout, Monpoly.MIN_DRAIN_TIMEOUT)
        drain_timeout = min(drain_timeout, self._hard_timeout)
        self._drain_output_streams(drain_timeout)

        # 3. Try graceful process shutdown. If it times out, terminate by PID
        returncode = None
        try:
            returncode = func_timeout(term_timeout, self._proc.wait)
        except FunctionTimedOut:
            timeout = drain_timeout + term_timeout
            self.print(f"Monpoly did not finish within {timeout} seconds after " f"closing STDIN.")
            self.print("Killing process by PID ...")
            try:
                self._kill(self._proc.pid)
            except BrokenPipeError:
                pass

        return returncode

    def _submit(self, datum: str) -> None:
        assert self._proc is not None, "finalized called but self._proc is None"

        msg = (f"{datum}\n").encode(Monpoly.ENCODING)

        self._proc.stdin.write(msg)

        try:
            self._proc.stdin.flush()
        except BrokenPipeError:
            raise MonpolyIoClosed(
                name=self.name, cmd=self.cmd_str(), msg="Monpoly has closed the session; cannot submit new queries"
            )

        self.print_dbg(f"Added {datum}")

        self._input_counter += 1

    def submit(self, datum: str, timeout=30.0) -> None:
        try:
            func_timeout(timeout, self._submit, args=(datum,))
        except FunctionTimedOut:
            msg = f"Monpoly is blocking STDIN for more than {timeout} seconds."
            self.print(msg)
            raise self._timeout(msg)
