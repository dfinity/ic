import functools
import sys
import time
from typing import Any
from typing import Dict
from typing import FrozenSet
from typing import Iterable
from typing import List
from typing import Optional
from typing import Set

from .es_doc import EsDoc
from .event import ConsensusFinalizedEvent
from .event import ControlePlaneAcceptAbortedEvent
from .event import ControlePlaneAcceptErrorEvent
from .event import ControlePlaneSpawnAcceptTaskEvent
from .event import ControlePlaneTlsServerHandshakeFailedEvent
from .event import CupShareProposedEvent
from .event import DeliverBatchEvent
from .event import Event
from .event import FinalEvent
from .event import FinalizedEvent
from .event import MoveBlockProposalEvent
from .event import NodeMembershipEvent
from .event import OriginallyInSubnetPreambleEvent
from .event import OriginalSubnetTypePreambleEvent
from .event import RebootEvent
from .event import RegistryNodeAddedEvent
from .event import RegistryNodeRemovedEvent
from .event import RegistrySubnetCreatedEvent
from .event import RegistrySubnetUpdatedEvent
from .event import ReplicaDivergedEvent
from .event import UnusualLogEvent
from .event import ValidatedBlockProposalEvent
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

    stat: Dict[str, Any]

    def __init__(self, name: str):
        self.name = name
        self.stat = {
            "test_runtime_milliseconds": 0.0,
            "pre_processing": Timed.default(),
        }
        self._elapsed_time = 0.0

    def get_formulas(self) -> Dict[str, OutcomeHandler]:
        """
        Returns a dict of (name: OutcomeHandler) pairs for the MFOTL formulas that
        depend on this pre-processor.

        See https://gitlab.com/ic-monitoring/mfotl-policies
        """
        ...

    def process_log_entry(self, doc: EsDoc) -> Iterable[str]:
        """
        Returns a generator of events (in string representation) corresponding
         to this ES document.
        - Theoretically, each ES document may yield multiple events.
        - Typically, an ES document yields a unique event.
        """
        ...

    def preamble(self) -> Iterable[str]:
        """
        Returns a generator of synthetic preamble events added at the very
        beginning of the testnet run. For example, this is used for passing
        the information about original subnet membership of nodes to Monpoly.
        """
        return []

    def run(self, logs: Iterable[EsDoc]) -> Iterable[str]:
        """Returns a generator of events corresponding to [logs]"""
        sys.stderr.write("Running pre-processor %s ...\n" % self.name)

        timestamp = 0
        first_timestamp = None

        # Synthetic events added at the very beginning of the testnet run
        sys.stderr.write(" Generating preamble relations ...")
        with Timed(self.stat["pre_processing"]):
            yield from self.preamble()
        sys.stderr.write(" done.\n")

        sys.stderr.write(" Processing logs ...")

        for doc in logs:
            timestamp = doc.unix_ts()
            if not first_timestamp:
                first_timestamp = timestamp

            for event in self.process_log_entry(doc):
                with Timed(self.stat["pre_processing"]):
                    yield event

        # synthetic event added as the very last event of the testnet run
        with Timed(self.stat["pre_processing"]):
            yield from FinalEvent(timestamp).compile()

        sys.stderr.write(" done.\n")

        # report test runtime statistics
        if first_timestamp:
            self.stat["test_runtime_milliseconds"] = timestamp - first_timestamp
        else:
            self.stat["test_runtime_milliseconds"] = 0.0

        sys.stderr.write("Pre-processor %s completed.\n" % self.name)


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

    def get_event_stream_builder(self, pred: str, doc: EsDoc) -> Event:
        if pred == "log":
            return UnusualLogEvent(doc)
        if pred == "reboot":
            assert self._infra is not None, f"{pred} event requires global infra"
            return RebootEvent(doc, self._infra)
        if pred == "p2p__node_added":
            return NodeMembershipEvent(doc, verb="added")
        if pred == "p2p__node_removed":
            return NodeMembershipEvent(doc, verb="removed")
        if pred == "validated_BlockProposal_Added":
            return ValidatedBlockProposalEvent(doc, verb="Added")
        if pred == "validated_BlockProposal_Moved":
            return ValidatedBlockProposalEvent(doc, verb="Moved")
        if pred == "deliver_batch":
            return DeliverBatchEvent(doc)
        if pred == "consensus_finalized":
            return ConsensusFinalizedEvent(doc)
        if pred == "move_block_proposal":
            return MoveBlockProposalEvent(doc)
        if pred == "ControlPlane_accept_error":
            return ControlePlaneAcceptErrorEvent(doc)
        if pred == "ControlPlane_spawn_accept_task":
            return ControlePlaneSpawnAcceptTaskEvent(doc)
        if pred == "ControlPlane_accept_aborted":
            return ControlePlaneAcceptAbortedEvent(doc)
        if pred == "ControlPlane_tls_server_handshake_failed":
            return ControlePlaneTlsServerHandshakeFailedEvent(doc)
        if pred == "registry__subnet_created":
            return RegistrySubnetCreatedEvent(doc)
        if pred == "registry__subnet_updated":
            return RegistrySubnetUpdatedEvent(doc)
        if pred == "registry__node_added_to_subnet":
            assert self._infra is not None, f"{pred} event requires global infra"
            return RegistryNodeAddedEvent(doc, self._infra)
        if pred == "registry__node_removed_from_subnet":
            assert self._infra is not None, f"{pred} event requires global infra"
            return RegistryNodeRemovedEvent(doc, self._infra)
        if pred == "replica_diverged":
            return ReplicaDivergedEvent(doc)
        if pred == "CUP_share_proposed":
            return CupShareProposedEvent(doc)
        if pred == "finalized":
            return FinalizedEvent(doc)

        raise DeclarativePreProcessor.UnknownPredicateError(pred)

    def preamble_builder(self, pred: str) -> Event:
        if pred == "p2p__original_subnet_type":
            assert self._infra is not None, f"{pred} preamble event requires global infra"
            return OriginalSubnetTypePreambleEvent(self._infra)
        if pred == "p2p__originally_in_subnet":
            assert self._infra is not None, f"{pred} preamble event requires global infra"
            return OriginallyInSubnetPreambleEvent(self._infra)
        if pred == "p2p__originally_unassigned":
            assert self._infra is not None, f"{pred} preamble event requires global infra"
            # TODO -- support class OriginallyUnassignedPreambleEvent(InfraEvent)
            raise DeclarativePreProcessor.UnknownPreambleEventNameError(pred)

        raise DeclarativePreProcessor.UnknownPreambleEventNameError(pred)

    GLOBAL_INFRA_BASED_EVENTS = frozenset(
        [
            "reboot",
            "p2p__original_subnet_type",
            "p2p__originally_unassigned",
            "p2p__originally_in_subnet",
            "registry__node_added_to_subnet",
            "registry__node_removed_from_subnet",
        ]
    )

    def __init__(
        self,
        name: str,
        required_predicates: FrozenSet[str],
        infra: Optional[GlobalInfra],
        required_preamble_events: FrozenSet[str] = frozenset(),
    ):
        super().__init__(name)
        self.required_predicates = required_predicates
        self.required_preamble_events = required_preamble_events
        self._infra = infra

    def preamble(self) -> Iterable[str]:
        for p_name in self.required_preamble_events:
            event: Event = self.preamble_builder(p_name)
            yield from event.compile()

    def process_log_entry(self, doc: EsDoc) -> Iterable[str]:
        for pred in self.required_predicates:
            event: Event = self.get_event_stream_builder(pred, doc)
            yield from event.compile()


class UniversalPreProcessor(DeclarativePreProcessor):

    _PREDS = frozenset(
        [
            "log",
            "reboot",
            "p2p__node_added",
            "p2p__node_removed",
            "deliver_batch",
            "consensus_finalized",
            "move_block_proposal",
            "ControlPlane_accept_error",
            "ControlPlane_accept_aborted",
            "ControlPlane_spawn_accept_task",
            "ControlPlane_tls_server_handshake_failed",
            "registry__node_added_to_subnet",
            "registry__node_removed_from_subnet",
            "CUP_share_proposed",
            "replica_diverged",
            "finalized",
        ]
    )

    # The values stored in this map can be used in the future to encode
    # policies that are *expected* to generate outputs. _NORMAL == no outputs.
    _FORMULAS = {
        # 'dummy': {
        #     'exit_code': 0,
        #     'should_crash': False,
        #     'should_be_violated': True,
        # },
        "artifact_pool_latency": NORMAL,
        "unauthorized_connections": NORMAL,  # Demo 2: fails, needs adjustment (node did not use updated registry version yet)
        "reboot_count": NORMAL,
        "finalization_consistency": NORMAL,  # Demo 1: succeeds
        "finalized_height": NORMAL,
        "clean_logs": NORMAL,
    }

    _PREAMBLES: Dict[str, FrozenSet[str]]
    _PREAMBLES = {
        "artifact_pool_latency": frozenset(
            [
                "p2p__original_subnet_type",
            ]
        ),
        "unauthorized_connections": frozenset(
            [
                "p2p__originally_in_subnet",
            ]
        ),
        "reboot_count": frozenset(),
        "finalization_consistency": frozenset(),
        "finalized_height": frozenset(),
        "clean_logs": frozenset(),
    }

    _DEPENDENCIES = {
        "artifact_pool_latency": frozenset(
            [
                "p2p__node_added",
                "p2p__node_removed",
                "registry__subnet_created",
                "registry__subnet_updated",
                "validated_BlockProposal_Added",
                "validated_BlockProposal_Moved",
            ]
        ),
        "unauthorized_connections": frozenset(
            [
                "ControlPlane_accept_error",
                "ControlPlane_accept_aborted",
                "ControlPlane_spawn_accept_task",
                "ControlPlane_tls_server_handshake_failed",
                "registry__node_added_to_subnet",
                "registry__node_removed_from_subnet",
            ]
        ),
        "reboot_count": frozenset(
            [
                "reboot",
            ]
        ),
        "finalization_consistency": frozenset(
            [
                "finalized",
            ]
        ),
        "finalized_height": frozenset(
            [
                "finalized",
            ]
        ),
        "clean_logs": frozenset(["log"]),
    }

    @staticmethod
    def is_global_infra_required(formula_names: Optional[Set[str]] = None) -> bool:

        if formula_names is None:
            # All formulas are enabled
            return True

        preds = frozenset(
            [
                pred
                for formula in formula_names
                for pred in UniversalPreProcessor._DEPENDENCIES[formula].union(
                    UniversalPreProcessor._PREAMBLES[formula]
                )
            ]
        )
        return len(preds.intersection(DeclarativePreProcessor.GLOBAL_INFRA_BASED_EVENTS)) > 0

    formulas: Dict[str, OutcomeHandler]

    def get_formulas(self) -> Dict[str, OutcomeHandler]:
        return self.formulas

    @staticmethod
    def get_supported_formulas() -> List[str]:
        """Returns list of all the formulas supported by this pre-processor"""
        return sorted(list(UniversalPreProcessor._FORMULAS.keys()))

    def __init__(self, infra: Optional[GlobalInfra], formulas: Optional[Set[str]] = None):

        if formulas is None:
            formulas = set(UniversalPreProcessor._DEPENDENCIES.keys())
            assert formulas == set(
                UniversalPreProcessor._PREAMBLES.keys()
            ), "unsynched _DEPENDENCIES / _PREAMBLES in UniversalPreProcessor"

        unit: FrozenSet[str] = frozenset()
        preambles = UniversalPreProcessor._PREAMBLES
        required_preamble_events = functools.reduce(
            lambda val, elem: val.union(elem), [preambles[f] for f in preambles if f in formulas], unit
        )
        deps = UniversalPreProcessor._DEPENDENCIES
        required_predicates = functools.reduce(
            lambda val, elem: val.union(elem), [deps[f] for f in deps if f in formulas], unit
        )

        super().__init__(
            name="unipol",
            infra=infra,
            required_preamble_events=required_preamble_events,
            required_predicates=required_predicates,
        )

        if formulas is None:
            self.formulas = self._FORMULAS
        else:
            self.formulas = {f: NORMAL for f in formulas}
