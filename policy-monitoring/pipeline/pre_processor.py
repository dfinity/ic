import functools
import pprint
import time
from abc import abstractmethod
from pathlib import Path
from typing import Any
from typing import Dict
from typing import FrozenSet
from typing import Iterable
from typing import List
from typing import Optional
from typing import Set
from typing import Type
from typing import TypedDict
from typing import Union

from util.print import assert_with_trace
from util.print import eprint

from .es_doc import EsDoc
from .event import ConsensusFinalizedEvent
from .event import ControlePlaneSpawnAcceptTaskTlsServerHandshakeFailedEvent
from .event import CupShareProposedEvent
from .event import DeliverBatchEvent
from .event import Event
from .event import FinalEvent
from .event import FinalizedEvent
from .event import GenericLogEvent
from .event import InfraEvent
from .event import MoveBlockProposalEvent
from .event import NodeAddedEvent
from .event import NodeRemovedEvent
from .event import OriginallyInIcPreambleEvent
from .event import OriginallyInSubnetPreambleEvent
from .event import OriginalSubnetTypePreambleEvent
from .event import RebootEvent
from .event import RebootIntentEvent
from .event import RegistryNodeAddedToIcEvent
from .event import RegistryNodeAddedToSubnetEvent
from .event import RegistryNodesRemovedFromIcEvent
from .event import RegistryNodesRemovedFromSubnetEvent
from .event import RegistrySubnetCreatedEvent
from .event import RegistrySubnetUpdatedEvent
from .event import ReplicaDivergedEvent
from .event import ValidatedBlockProposalAddedEvent
from .event import ValidatedBlockProposalMovedEvent
from .global_infra import GlobalInfra


class Timed:
    @staticmethod
    def default() -> Dict[str, float]:
        return {
            "wall_clock_time_seconds": 0.0,
            "process_time_seconds": 0.0,
            "perf_counter_seconds": 0.0,
        }

    def __init__(self, accumulator: Dict[str, str]):
        self.accumulator = accumulator
        self.wlclock_time_start = None
        self.process_time_start = None
        self.perf_counter_start = None

    def __enter__(self):
        """Starts the timers"""
        self.wlclock_time_start = time.time()
        self.process_time_start = time.process_time()
        self.perf_counter_start = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Accumulates the elapsed time"""
        self.accumulator["wall_clock_time_seconds"] += time.time() - self.wlclock_time_start

        self.accumulator["process_time_seconds"] += time.process_time() - self.process_time_start

        self.accumulator["perf_counter_seconds"] += time.perf_counter() - self.perf_counter_start


class OutcomeHandler:
    def __init__(self, exit_code: int, should_crash: bool, should_be_violated: bool):
        self.exit_code = exit_code
        self.should_crash = should_crash
        self.should_be_violated = should_be_violated


NORMAL = OutcomeHandler(0, False, False)


class PreProcessor:

    K = 10_000  # One progress indication per K logs processed
    BUFFER_SIZE = 10_000

    stat: Dict[str, Any]

    def __init__(self, name: str, raw_logs_file: Optional[Path]):
        self.name = name
        self.raw_logs_file = raw_logs_file
        self._ever_flushed = False
        self._pp = pprint.PrettyPrinter(indent=2)
        self._buf: List[str] = []
        self.stat = {
            "test_runtime_milliseconds": 0.0,
            "pre_processing": Timed.default(),
        }
        self._elapsed_time = 0.0
        self._counter = 0

    @abstractmethod
    def get_formulas(self) -> Dict[str, OutcomeHandler]:
        """
        Returns a dict of (name: OutcomeHandler) pairs for the MFOTL formulas that
        depend on this pre-processor.

        See https://gitlab.com/ic-monitoring/mfotl-policies
        """
        ...

    @abstractmethod
    def process_log_entry(self, doc: EsDoc) -> Iterable[str]:
        """
        Returns a generator of events (in string representation) corresponding
         to this ES document.
        - Theoretically, each ES document may yield multiple events.
        - Typically, an ES document yields a unique event.
        """
        ...

    def indicate_progress(self) -> None:
        """
        Print . to STDERR (once every K invocations).
        This function should be invoked once per process_log_entry.
        """
        self._counter += 1
        if self._counter % self.K == 0:
            eprint(".", end="", flush=True)

    def process_preamble(self) -> Iterable[str]:
        """
        Returns a generator of synthetic preamble events added at the very
        beginning of the testnet run. For example, this is used for passing
        the information about original subnet membership of nodes to Monpoly.
        """
        return []

    def _flush(self, is_final=False) -> None:
        assert self.raw_logs_file, "raw_logs_file is not specified"
        with open(self.raw_logs_file, "a") as fout:
            if not self._ever_flushed:
                fout.write(
                    "["
                )  # the entire output should respresent a syntactically correct python object, e.g., a list
                self._ever_flushed = True
            fout.writelines(self._buf)
            self._buf = []
            if is_final:
                fout.write("]")

    def _forward_to_file(self, doc: EsDoc) -> None:
        datum = self._pp.pformat(doc).strip()  # avoid the \n after the comma
        self._buf.append(f"{datum},\n")
        if len(self._buf) >= self.BUFFER_SIZE:
            self._flush()

    def run(self, logs: Iterable[EsDoc]) -> Iterable[str]:
        """Returns a generator of events corresponding to [logs]"""
        eprint(f"Running pre-processor {self.name} ...")

        timestamp = 0
        first_timestamp = None

        # Synthetic events added at the very beginning of the testnet run
        eprint(" Generating preamble relations ...", end="", flush=True)
        with Timed(self.stat["pre_processing"]):
            yield from self.process_preamble()
        eprint(" done", flush=True)

        eprint(f" Processing logs (. = {self.K} events) ", end="", flush=True)

        for doc in logs:
            timestamp = doc.unix_ts()
            if not first_timestamp:
                first_timestamp = timestamp

            with Timed(self.stat["pre_processing"]):
                if self.raw_logs_file:
                    self._forward_to_file(doc)
                yield from self.process_log_entry(doc)

        # In case we were forwarding the consumer stream of raw logs to a file,
        #  the buffer needs to be flushed one last time.
        if self.raw_logs_file:
            self._flush(is_final=True)
            eprint(f"Raw logs saved into '{self.raw_logs_file.absolute()}'")

        # synthetic event added as the very last event of the testnet run
        with Timed(self.stat["pre_processing"]):
            yield from FinalEvent(timestamp).compile()

        eprint(" done", flush=True)

        # report test runtime statistics
        if first_timestamp:
            self.stat["test_runtime_milliseconds"] = timestamp - first_timestamp
        else:
            self.stat["test_runtime_milliseconds"] = 0.0

        eprint(f"Pre-processor {self.name} completed.")


class DeclarativePreProcessor(PreProcessor):
    class UnknownPredicateError(Exception):
        """Predicate name is unknown"""

        def __init__(self, unknown_pred: str):
            super().__init__(unknown_pred)

    class UnknownPreambleEventNameError(Exception):
        """Preamble event name is unknown"""

        def __init__(self, unknown_pred: str):
            super().__init__(unknown_pred)

    _infra: Optional[GlobalInfra]

    EventSpec = TypedDict(
        "EventSpec",
        {
            # The event class.
            "type": Type[Union[Event, InfraEvent]],
            # Indicates whether this event is synthetic.
            "is_preamble": bool,
            # Indicates whether it make sense to monitor a policy that depends on this event only if debug-level logs are enabled.
            "is_dbg_level": bool,
            # Indicates whether constructing this event requires information from the IC registry.
            "need_global_infra": bool,
        },
    )

    EVENTS: Dict[str, EventSpec] = {
        "original_subnet_type": {
            "type": OriginalSubnetTypePreambleEvent,
            "is_preamble": True,
            "is_dbg_level": False,
            "need_global_infra": True,
        },
        "originally_in_ic": {
            "type": OriginallyInIcPreambleEvent,
            "is_preamble": True,
            "is_dbg_level": False,
            "need_global_infra": True,
        },
        "originally_in_subnet": {
            "type": OriginallyInSubnetPreambleEvent,
            "is_preamble": True,
            "is_dbg_level": False,
            "need_global_infra": True,
        },
        "log": {
            "type": GenericLogEvent,
            "is_preamble": False,
            "is_dbg_level": False,
            "need_global_infra": False,
        },
        "reboot": {
            "type": RebootEvent,
            "is_preamble": False,
            "is_dbg_level": False,
            "need_global_infra": False,
        },
        "reboot_intent": {
            "type": RebootIntentEvent,
            "is_preamble": False,
            "is_dbg_level": False,
            "need_global_infra": False,
        },
        "p2p__node_added": {
            "type": NodeAddedEvent,
            "is_preamble": False,
            "is_dbg_level": False,
            "need_global_infra": False,
        },
        "p2p__node_removed": {
            "type": NodeRemovedEvent,
            "is_preamble": False,
            "is_dbg_level": False,
            "need_global_infra": False,
        },
        "validated_BlockProposal_Added": {
            "type": ValidatedBlockProposalAddedEvent,
            "is_preamble": False,
            "is_dbg_level": True,
            "need_global_infra": False,
        },
        "validated_BlockProposal_Moved": {
            "type": ValidatedBlockProposalMovedEvent,
            "is_preamble": False,
            "is_dbg_level": True,
            "need_global_infra": False,
        },
        "deliver_batch": {
            "type": DeliverBatchEvent,
            "is_preamble": False,
            "is_dbg_level": True,
            "need_global_infra": False,
        },
        "consensus_finalized": {
            "type": ConsensusFinalizedEvent,
            "is_preamble": False,
            "is_dbg_level": True,
            "need_global_infra": False,
        },
        "move_block_proposal": {
            "type": MoveBlockProposalEvent,
            "is_preamble": False,
            "is_dbg_level": True,
            "need_global_infra": False,
        },
        "ControlPlane__spawn_accept_task__tls_server_handshake_failed": {
            "type": ControlePlaneSpawnAcceptTaskTlsServerHandshakeFailedEvent,
            "is_preamble": False,
            "is_dbg_level": False,
            "need_global_infra": False,
        },
        "registry__node_added_to_ic": {
            "type": RegistryNodeAddedToIcEvent,
            "is_preamble": False,
            "is_dbg_level": False,
            "need_global_infra": True,
        },
        "registry__node_removed_from_ic": {
            "type": RegistryNodesRemovedFromIcEvent,
            "is_preamble": False,
            "is_dbg_level": False,
            "need_global_infra": True,
        },
        "registry__subnet_created": {
            "type": RegistrySubnetCreatedEvent,
            "is_preamble": False,
            "is_dbg_level": False,
            "need_global_infra": False,
        },
        "registry__subnet_updated": {
            "type": RegistrySubnetUpdatedEvent,
            "is_preamble": False,
            "is_dbg_level": False,
            "need_global_infra": False,
        },
        "registry__node_added_to_subnet": {
            "type": RegistryNodeAddedToSubnetEvent,
            "is_preamble": False,
            "is_dbg_level": False,
            "need_global_infra": True,
        },
        "registry__node_removed_from_subnet": {
            "type": RegistryNodesRemovedFromSubnetEvent,
            "is_preamble": False,
            "is_dbg_level": False,
            "need_global_infra": True,
        },
        "replica_diverged": {
            "type": ReplicaDivergedEvent,
            "is_preamble": False,
            "is_dbg_level": False,
            "need_global_infra": False,
        },
        "CUP_share_proposed": {
            "type": CupShareProposedEvent,
            "is_preamble": False,
            "is_dbg_level": True,
            "need_global_infra": False,
        },
        "finalized": {
            "type": FinalizedEvent,
            "is_preamble": False,
            "is_dbg_level": True,
            "need_global_infra": False,
        },
    }

    @classmethod
    def is_event_dbg_level(Self, event_name: str) -> Optional[bool]:
        if event_name not in Self.EVENTS:
            return None
        return Self.EVENTS[event_name]["is_dbg_level"]

    def get_event_stream_builder(self, p_name: str, doc: Optional[EsDoc] = None) -> Event:
        if p_name not in self.EVENTS:
            raise self.UnknownPredicateError(p_name)
        event_spec = self.EVENTS[p_name]
        event_builder = event_spec["type"]
        event = object.__new__(event_builder)
        # check that we have what we need
        if event_spec["need_global_infra"]:
            assert self._infra is not None, f"{p_name} event requires global infra"
        if not event_spec["is_preamble"]:
            assert doc is not None, f"{p_name} event cannot be constructed out of thin air"

        if event_spec["need_global_infra"] and not event_spec["is_preamble"]:
            # Case A: non-preamble events that require Global Infra
            event.__init__(doc=doc, infra=self._infra)  # type: ignore
        elif event_spec["need_global_infra"]:
            # Case B: preamble (synthetic) events, i.e., not based on actual logs
            event.__init__(infra=self._infra)  # type: ignore
        elif not event_spec["need_global_infra"] and not event_spec["is_preamble"]:
            # Case C: regular (non-synthetic) event -- no global infra required
            event.__init__(doc=doc)  # type: ignore
        else:
            # Case D: hypothetical case; added for completeness
            event.__init__()  # type: ignore
        return event

    def __init__(
        self,
        name: str,
        raw_logs_file: Optional[Path],
        required_regular_events: FrozenSet[str],
        infra: Optional[GlobalInfra],
        required_preamble_events: FrozenSet[str] = frozenset(),
    ):
        super().__init__(name=name, raw_logs_file=raw_logs_file)
        self.required_predicates = required_regular_events
        self.required_preamble_events = required_preamble_events
        self._infra = infra

    def process_preamble(self) -> Iterable[str]:
        for p_name in self.required_preamble_events:
            event: Event = self.get_event_stream_builder(p_name)
            yield from event.compile()

    def process_log_entry(self, doc: EsDoc) -> Iterable[str]:
        self.indicate_progress()
        for p_name in self.required_predicates:
            event: Event = self.get_event_stream_builder(p_name, doc)
            yield from event.compile()


class UniversalPreProcessor(DeclarativePreProcessor):
    """Pre-processor that requires only the events needed for specifiec policies"""

    PolicySpec = TypedDict(
        "PolicySpec",
        {
            "enabled": bool,
            "preamble_dependencies": FrozenSet[str],
            "regular_dependencies": FrozenSet[str],
            "needs_end_event": bool,
        },
    )

    _POLICIES: Dict[str, PolicySpec]
    _POLICIES = {
        "artifact_pool_latency": {
            "enabled": False,  # Disabled because violations are not actionable
            "preamble_dependencies": frozenset(
                [
                    # "originally_in_ic" -- TODO
                    "original_subnet_type",
                    "originally_in_subnet",
                ]
            ),
            "regular_dependencies": frozenset(
                [
                    # "registry__node_removed_from_ic", -- TODO
                    # "registry__node_added_to_ic", -- TODO
                    "registry__node_removed_from_subnet",
                    "registry__node_added_to_subnet",
                    "registry__subnet_created",
                    "registry__subnet_updated",
                    "validated_BlockProposal_Added",
                    "validated_BlockProposal_Moved",
                ]
            ),
            "needs_end_event": False,
        },
        "catching_up_period": {
            "enabled": False,
            "preamble_dependencies": frozenset(
                [
                    # "originally_in_ic" -- TODO
                    "originally_in_subnet",
                ]
            ),
            "regular_dependencies": frozenset(
                [
                    # "registry__node_removed_from_ic", -- TODO
                    # "registry__node_added_to_ic", -- TODO
                    "registry__node_added_to_subnet",
                    "registry__node_removed_from_subnet",
                    "p2p__node_added",
                    "p2p__node_removed",
                    "consensus_finalized",
                ]
            ),
            "needs_end_event": False,
        },
        "proposal_fairness": {
            "enabled": False,
            "preamble_dependencies": frozenset(
                [
                    # "originally_in_ic" -- TODO
                    "originally_in_subnet",
                ]
            ),
            "regular_dependencies": frozenset(
                [
                    # "registry__node_removed_from_ic", -- TODO
                    # "registry__node_added_to_ic", -- TODO
                    "registry__node_added_to_subnet",
                    "registry__node_removed_from_subnet",
                    "p2p__node_added",
                    "p2p__node_removed",
                    "move_block_proposal",
                    "deliver_batch",
                ]
            ),
            "needs_end_event": False,
        },
        "replica_divergence": {
            "enabled": False,
            "preamble_dependencies": frozenset(
                [
                    # "originally_in_ic" -- TODO
                    "originally_in_subnet",
                ]
            ),
            "regular_dependencies": frozenset(
                [
                    # "registry__node_removed_from_ic", -- TODO
                    # "registry__node_added_to_ic", -- TODO
                    "registry__node_added_to_subnet",
                    "registry__node_removed_from_subnet",
                    "p2p__node_added",
                    "p2p__node_removed",
                    "replica_diverged",
                    "CUP_share_proposed",
                ]
            ),
            "needs_end_event": True,
        },
        "unauthorized_connections": {
            "enabled": True,
            "preamble_dependencies": frozenset(
                [
                    # "originally_in_ic" -- TODO
                    "originally_in_subnet",
                ]
            ),
            "regular_dependencies": frozenset(
                [
                    # "registry__node_removed_from_ic", -- TODO
                    # "registry__node_added_to_ic", -- TODO
                    "ControlPlane__spawn_accept_task__tls_server_handshake_failed",
                    "registry__node_added_to_subnet",
                    "registry__node_removed_from_subnet",
                ]
            ),
            "needs_end_event": False,
        },
        "reboot_count": {
            "enabled": True,
            "preamble_dependencies": frozenset(
                [
                    "originally_in_ic",
                ]
            ),
            "regular_dependencies": frozenset(
                [
                    "registry__node_removed_from_ic",
                    "registry__node_added_to_ic",
                    "reboot",
                    "reboot_intent",
                ]
            ),
            "needs_end_event": False,
        },
        "finalization_consistency": {
            "enabled": False,
            "preamble_dependencies": frozenset(
                [
                    # "originally_in_ic" -- TODO
                ]
            ),
            "regular_dependencies": frozenset(
                [
                    # "registry__node_removed_from_ic", -- TODO
                    # "registry__node_added_to_ic", -- TODO
                    "finalized",
                ]
            ),
            "needs_end_event": False,
        },
        "finalized_height": {
            "enabled": False,
            "preamble_dependencies": frozenset(
                [
                    # "originally_in_ic" -- TODO
                    "originally_in_subnet"
                ]
            ),
            "regular_dependencies": frozenset(
                [
                    # "registry__node_removed_from_ic", -- TODO
                    # "registry__node_added_to_ic", -- TODO
                    "registry__node_added_to_subnet",
                    "registry__node_removed_from_subnet",
                    "p2p__node_added",
                    "p2p__node_removed",
                    "finalized",
                ]
            ),
            "needs_end_event": False,
        },
        "clean_logs": {
            "enabled": True,
            "preamble_dependencies": frozenset([]),
            "regular_dependencies": frozenset(["log"]),
            "needs_end_event": False,
        },
    }

    @staticmethod
    def _preambles(formula: str) -> FrozenSet[str]:
        return UniversalPreProcessor._POLICIES[formula]["preamble_dependencies"]

    @staticmethod
    def _regulars(formula: str) -> FrozenSet[str]:
        return UniversalPreProcessor._POLICIES[formula]["regular_dependencies"]

    @classmethod
    def is_global_infra_event(Self, event_name: str) -> bool:
        return Self.EVENTS[event_name]["need_global_infra"]

    @classmethod
    def is_global_infra_required(Self, formula_names: Optional[Set[str]]) -> bool:
        if formula_names is None:
            # All formulas are enabled
            return True
        preds = frozenset(
            [p_name for formula in formula_names for p_name in Self._regulars(formula).union(Self._preambles(formula))]
        )
        return any(map(lambda p_name: Self.EVENTS[p_name]["need_global_infra"], preds))

    @classmethod
    def is_dbg_log_level_required(Self, formula: str) -> bool:
        return any(
            map(
                lambda event_name: Self.is_event_dbg_level(event_name),
                UniversalPreProcessor._regulars(formula).union(UniversalPreProcessor._preambles(formula)),
            )
        )

    @classmethod
    def is_preamble_required(Self, formula: str) -> bool:
        return len(Self._preambles(formula)) > 0

    @classmethod
    def is_end_event_required(Self, formula: str) -> bool:
        return Self._POLICIES[formula]["needs_end_event"]

    @classmethod
    def is_formula_enabled(Self, formula: str) -> bool:
        return Self._POLICIES[formula]["enabled"]

    formulas: Dict[str, OutcomeHandler]

    def get_formulas(self) -> Dict[str, OutcomeHandler]:
        return self.formulas

    @staticmethod
    def get_supported_formulas() -> List[str]:
        """Returns list of all the formulas supported by this pre-processor"""
        return sorted(list(UniversalPreProcessor._POLICIES.keys()))

    @staticmethod
    def get_enabled_formulas() -> List[str]:
        return sorted(
            list(map(lambda p: p[0], filter(lambda p: p[1]["enabled"], UniversalPreProcessor._POLICIES.items())))
        )

    @staticmethod
    def get_formulas_wo_global_infra() -> List[str]:
        return list(
            filter(
                lambda f: not UniversalPreProcessor.is_global_infra_required(set([f])),
                UniversalPreProcessor.get_enabled_formulas(),
            )
        )

    @classmethod
    def get_supported_events(Self) -> List[str]:
        unit: FrozenSet[str] = frozenset()
        res = functools.reduce(
            lambda val, elem: val.union(elem),
            [frozenset(d["preamble_dependencies"].union(d["regular_dependencies"])) for d in Self._POLICIES.values()],
            unit,
        )
        return sorted(list(res))

    @classmethod
    def get_supported_preamble_events(Self) -> List[str]:
        unit: FrozenSet[str] = frozenset()
        res = functools.reduce(
            lambda val, elem: val.union(elem), [d["preamble_dependencies"] for d in Self._POLICIES.values()], unit
        )
        return sorted(list(res))

    def __init__(
        self, infra: Optional[GlobalInfra], raw_logs_file: Optional[Path] = None, formulas: Optional[Set[str]] = None
    ):

        all_formulas = UniversalPreProcessor.get_enabled_formulas()

        if formulas is None:
            formulas = set(UniversalPreProcessor.get_enabled_formulas())
        else:
            assert_with_trace(formulas.issubset(all_formulas), "unexpected formulas")

        unit: FrozenSet[str] = frozenset()
        required_preamble_events = functools.reduce(
            lambda val, elem: val.union(elem), [UniversalPreProcessor._preambles(f) for f in formulas], unit
        )
        required_regular_events = functools.reduce(
            lambda val, elem: val.union(elem), [UniversalPreProcessor._regulars(f) for f in formulas], unit
        )
        assert all(map(lambda x: UniversalPreProcessor.EVENTS[x]["is_preamble"], required_preamble_events))
        assert all(map(lambda x: not UniversalPreProcessor.EVENTS[x]["is_preamble"], required_regular_events))

        eprint(f"Creating UniversalPreProcessor supporting formulas: {', '.join(formulas)}")

        super().__init__(
            name="unipol",
            raw_logs_file=raw_logs_file,
            infra=infra,
            required_preamble_events=required_preamble_events,
            required_regular_events=required_regular_events,
        )

        self.formulas = {f: NORMAL for f in formulas}
