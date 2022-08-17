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
    ):
        self._monitors = single_formula_monitors
        self._exception_handlers = exception_handlers
        self.event_stream_file = event_stream_file
        self._buf: List[str] = []

    def __enter__(self):
        """Prepare the requied Monpoly sessions"""
        for mon in self._monitors:
            mon.__enter__()
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

    def _flush(self) -> None:
        assert self.event_stream_file, "event_stream_file is not specified"
        with open(self.event_stream_file, "a") as fout:
            fout.writelines(self._buf)
        self._buf = []
        eprint("Flush!")  # TODO: remove

    def _forward_to_file(self, datum: str) -> None:
        self._buf.append(datum)
        if len(self._buf) >= self.BUFFER_SIZE:
            self._flush()

    def submit(self, datum: str) -> None:
        if self.event_stream_file:
            self._forward_to_file(datum)

        for mon in self._monitors:
            try:
                mon.submit(datum)
            except MonpolyException as e:
                self._exception_handlers(e)
