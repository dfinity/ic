import time
from pathlib import Path
from typing import Callable
from typing import List
from typing import Optional

from util.print import eprint
from util.threads import PropagatingThread

from .monpoly import Monpoly
from .monpoly import MonpolyException


class MultiMonitor:

    BUFFER_SIZE = 10_000

    def __init__(
        self,
        single_formula_monitors: List[Monpoly],
        exception_handlers: Callable[[MonpolyException], None],
        event_stream_file: Optional[Path],
        hard_timeout: Optional[float] = None,
    ):
        self._monitors = single_formula_monitors
        self._exception_handlers = exception_handlers
        self.event_stream_file = event_stream_file
        self._buf: List[str] = []
        self._hard_timeout = hard_timeout
        self._start_time = time.monotonic()
        self._timeout_exception = None

        def check_timeout():
            """
            If elapsed time is beyond self._hard_timeout, checks whether there are any Monpoly threads still running.
            - If so, sets self._timeout_exception to an instance of MonpolyGlobalTimeout.
            - Otherwise, return.
            """
            if not self._hard_timeout:
                return
            while True:
                time.sleep(0.1)
                elapsed = time.monotonic() - self._start_time
                if elapsed < self._hard_timeout:
                    # timeout not reached yet
                    continue
                detected_timeout = False
                for mon in self._monitors:
                    if mon.still_running():
                        detected_timeout = True  # found a running Monpoly thread
                        mon.terminate()
                if detected_timeout:
                    self._timeout_exception = mon.global_timeout(
                        f"hard timeout reached after {self._hard_timeout} seconds"
                    )
                else:
                    # no more running Monpoly threads -- return
                    return

        self._timeout_thread = PropagatingThread(
            name="MultiMonitorTimeoutThread",
            target=check_timeout,
        )

    def __enter__(self):
        """Prepare the requied Monpoly sessions"""
        for mon in self._monitors:
            mon.__enter__()
        self._timeout_thread.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Gracefully finalizes the Monpoly sessions and flush the buffer"""
        if self.event_stream_file:
            self._flush()
            eprint(f"Saved event stream into '{self.event_stream_file.absolute()}'")

        exit_threads = []
        for mon in self._monitors:

            def exit_f():
                mon.__exit__(exc_type, exc_val, exc_tb)

            th = PropagatingThread(
                name=f"MultiMonitorThread_{mon.name}",
                target=exit_f,
            )
            th.start()
            exit_threads.append(th)

        for th in exit_threads:
            th.join()  # the timeouts are determined by the monpoly instances

        self._timeout_thread.join()

    def _flush(self) -> None:
        assert self.event_stream_file, "event_stream_file is not specified"
        with open(self.event_stream_file, "a") as fout:
            fout.writelines(self._buf)
        self._buf = []

    def _forward_to_file(self, datum: str) -> None:
        self._buf.append(datum)
        if len(self._buf) >= self.BUFFER_SIZE:
            self._flush()

    def _query_timeout(self) -> float:
        if not self._hard_timeout:
            return 60.0
        elapsed = time.monotonic() - self._start_time
        return max(60.0, self._hard_timeout - elapsed)

    def submit(self, datum: str) -> None:
        # Propagate timeout exceptions
        if self._timeout_exception:
            raise self._timeout_exception

        if self.event_stream_file:
            self._forward_to_file(datum)

        for mon in self._monitors:
            try:
                mon.submit(datum, timeout=self._query_timeout())
            except MonpolyException as e:
                self._exception_handlers(e)
