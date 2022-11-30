import codecs
import json
import os
import sys
import threading
import time
import uuid
from typing import List
from typing import NamedTuple

from common import misc
from common import ssh


WORKLOAD_DEFAULT_DURATION = 300


class BytesEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            return obj.decode("utf-8")
        return json.JSONEncoder.default(self, obj)


class WorkloadDescription(NamedTuple):
    canister_ids: list
    method: str
    call_method: str
    rps: float
    duration: int
    raw_payload: bytes
    json_payload: str
    arguments: list
    start_delay: int
    rps_ratio: float
    subnet: int


def workload_description_from_dict(values: list, canister_ids: dict):
    """
    Build workload description from toml dict representation.

    Use dictionary canister_ids to lookup canister IDs for given canister names.
    """
    workloads = [
        WorkloadDescription(
            canister_ids=canister_ids.get(value["canister"]),
            method=value.get("method", None),
            call_method=value.get("call_method", None),
            rps=float(value.get("rps", -1)),
            duration=int(value.get("duration", WORKLOAD_DEFAULT_DURATION)),
            raw_payload=value["raw_payload"].encode("utf-8") if "raw_payload" in value else None,
            json_payload=value.get("json_payload", None),
            arguments=value.get("arguments", []),
            start_delay=int(value.get("start_delay", 0)),
            rps_ratio=float(value.get("rps_ratio", 1)),
            subnet=int(value.get("subnet", -1)),
        )
        for value in values["workload"]
    ]
    return workloads


class Workload(threading.Thread):
    """
    Threaded abstraction around workload generator execution.

    Workload generators executed via SSH on remote machines. Workload
    generator output can be copied back using fetch_results.

    The benefit of implementing a threaded abstraction is that
    we can execute multiple workloads in parallel easily.

    """

    def __init__(
        self,
        load_generators: [str],
        target_machines: [str],
        workload: WorkloadDescription,
        workload_idx: int,
        outdir: str,
        f_stdout: str,
        f_stderr: str,
    ):
        """Initialize workload."""
        threading.Thread.__init__(self)

        self.load_generators = load_generators
        self.target_machines = target_machines
        self.workload = workload
        self.workload_idx = workload_idx
        self.outdir = outdir
        self.f_stdout = f_stdout
        self.f_stderr = f_stderr

        self.query_timeout_secs = 30
        self.ingress_timeout_secs = 6 * 60
        self.uuids = [uuid.uuid4() for i in range(len(self.load_generators))]

        if not isinstance(self.workload.canister_ids, list):
            raise Exception(
                f"canister_ids has to be a list of canister IDs represented as string: is {self.workload.canister_ids}"
            )
        if len(self.workload.canister_ids) < 1:
            raise Exception("List of canister  IDs is empty")

    def get_commands(self) -> List[str]:
        """Build a list of command line arguments to use for workload generation."""
        num_load_generators = len(self.load_generators)
        if num_load_generators <= 0:
            raise Exception("No workload generators registered for the current workload")

        # No command for machines that don't end up getting any workload assigned.
        # That's iff num(machines) > rps
        rps_per_machine = list(
            filter(lambda x: x != 0, misc.distribute_load_to_n(self.workload.rps, num_load_generators))
        )
        if len(rps_per_machine) < 0:
            raise Exception("Not using any workload generators, aborting")

        target_list = ",".join(f"http://[{target}]:8080" for target in self.target_machines)
        cmd = f'./ic-workload-generator "{target_list}"' f" -n {self.workload.duration} --no-status-check "
        cmd += " " + " ".join(self.workload.arguments)
        cmd += " --query-timeout-secs " + str(self.query_timeout_secs)
        cmd += " --ingress-timeout-secs " + str(self.ingress_timeout_secs)

        # Dump worklod generator command in output directory.
        if self.workload.raw_payload is not None:
            cmd += " --payload '{}'".format(self.workload.raw_payload.decode("utf-8"))
        if self.workload.json_payload is not None:
            cmd += " --payload '{}'".format(
                codecs.encode(self.workload.json_payload.encode("utf-8"), "hex").decode("utf-8")
            )
        if self.workload.method is not None:
            cmd += " -m {}".format(self.workload.method)
        if self.workload.call_method is not None:
            cmd += ' --call-method "{}"'.format(self.workload.call_method)

        # Sanity check the number of requests per machine
        # Later, we might have multiple workloads per iteration, so we should then probably also
        # check the sum of all requests from all workloads, but this should be good enough for now.
        for _rps in rps_per_machine:
            assert _rps < 8000, f"Not enough workload generator machines: {num_load_generators} which {_rps} rps each"

        # Each workload generator instance can target only a single canister ID currently.
        # In the case of multiple canisters, select a different canister for each machine.
        canister_ids = [
            self.workload.canister_ids[i % len(self.workload.canister_ids)] for i in range(num_load_generators)
        ]
        commands = [
            "{} --canister-id {} -r {rps} --summary-file wg_summary_{wg_summary} ".format(
                cmd, canister_id, rps=rps, wg_summary=self.uuids[i]
            )
            for i, (canister_id, rps) in enumerate(zip(canister_ids, rps_per_machine))
        ]
        self.__write_commands_to_file(commands)

        return commands

    def __write_commands_to_file(self, commands: List[str]):
        assert len(commands) == len(self.uuids) == len(self.load_generators)
        for idx, uid in enumerate(self.uuids):
            try:
                filename = os.path.join(self.outdir, f"workload-generator-cmd-{uid}")
                # Try to open file in exclusive mode
                with open(filename, "x") as cmd_file:
                    cmd_file.write(commands[idx] + "\n")
                break
            except FileExistsError:
                continue

    def __update_summary_map_file(self, destinations):
        summary_file_dir = os.path.join(self.outdir, "workload_command_summary_map.json")

        workload_command_summary_map = {}
        if os.path.exists(summary_file_dir):
            with open(summary_file_dir, "r") as map_file:
                # dictionary of type: dict[str] = (workload.Workload, str)
                workload_command_summary_map = json.loads(map_file.read())

        commands = self.get_commands()
        assert len(commands) == len(destinations)

        workload_command_summary_map[self.workload_idx] = {
            "workload_description": json.dumps(self.workload, cls=BytesEncoder, indent=4),
            "load_generators": [
                {
                    "command": command,
                    "summary_file": destination,
                }
                for command, destination in zip(commands, destinations)
            ],
        }

        with open(summary_file_dir, "w") as map_file:
            map_file.write(json.dumps(workload_command_summary_map, cls=BytesEncoder, indent=4))

    def run(self):
        """Start running the given workloads as a thread."""
        time.sleep(self.workload.start_delay)
        commands = self.get_commands()
        rc = ssh.run_all_ssh_in_parallel(self.load_generators, commands, self.f_stdout, self.f_stderr)
        # Note: error code 255 indicates an issue with SSH rather than the workload generator
        print("Return codes of workload generators are: ", rc, list(zip(self.load_generators, rc)))

    def fetch_results(self):
        """Fetch results from workload generators."""
        sources = ["admin@[{}]:wg_summary_{}".format(m, self.uuids[i]) for i, m in enumerate(self.load_generators)]

        assert len(self.uuids) == len(self.load_generators)
        destinations = [
            "{}/summary_workload_{}_{}_machine_{}".format(
                self.outdir, self.workload_idx, idx, load_generator.replace(":", "_")
            )
            for idx, load_generator in enumerate(self.load_generators)
        ]

        rc = ssh.scp_in_parallel(sources, destinations)

        # If workload generators fail, the result of the experiment is invalid anyway.
        # Just abort in such a case.
        if rc != [0 for _ in range(len(destinations))]:
            print("Failed to copy all summary files from workload generators: ", list(zip(self.load_generators, rc)))
            sys.exit(1)

        self.__update_summary_map_file(destinations)

        return destinations
