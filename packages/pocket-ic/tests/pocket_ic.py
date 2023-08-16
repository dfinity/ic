import base64
import os
import subprocess
import time
from typing import Any, List, Optional

import ic
import requests
from ic.candid import Types

POCKET_IC_BIN_PATH = "../../../target/debug/pocket-ic-backend"


class PocketIC:
    def __init__(self) -> None:
        backend = PocketICBackend()
        self.instance_id = backend.request_client.post(
            f"{backend.daemon_url}instance"
        ).text
        self.instance_url = f"{backend.daemon_url}instance/{self.instance_id}"
        self.request_client = requests.session()
        self.backend = backend

    def send_request(self, payload: Any) -> Any:
        result = self.request_client.post(self.instance_url, json=payload)
        if result.status_code != 200:
            raise ConnectionError(f"IC request retured with status code {result.status_code}")
        return result.json()

    def get_root_key(self) -> List[int]:
        return self.send_request("RootKey")

    def get_time(self) -> dict:
        return self.send_request("Time")

    def tick(self) -> None:
        return self.send_request("Tick")

    def set_time(self, time_nanosec: int) -> None:
        payload = {
            "SetTime": {
                "secs_since_epoch": time_nanosec // 1_000_000_000,
                "nanos_since_epoch": time_nanosec % 1_000_000_000,
            }
        }
        return self.send_request(payload)

    def advance_time(self, nanosecs: int) -> None:
        payload = {
            "AdvanceTime": {
                "secs": nanosecs // 1_000_000_000,
                "nanos": nanosecs % 1_000_000_000,
            }
        }
        return self.send_request(payload)

    def add_cycles(self, canister_id: ic.Principal, amount: int) -> int:
        payload = {
            "AddCycles": {
                "canister_id": base64.b64encode(canister_id.bytes).decode(),
                "amount": amount,
            }
        }
        return self.send_request(payload)

    def canister_update_call(self, sender: Optional[ic.Principal], canister_id: Optional[ic.Principal], method: str, arg: dict):
        sender = sender if sender else ic.Principal.anonymous()
        canister_id = canister_id if canister_id else ic.Principal.management_canister()
        payload = {
            "CanisterUpdateCall": {
                "sender": base64.b64encode(sender.bytes).decode(),
                "canister_id": base64.b64encode(canister_id.bytes).decode(),
                "method": method,
                "arg": base64.b64encode(ic.encode(arg)).decode()
            }
        }
        return self.send_request(payload)

    def create_canister(self, sender: ic.Principal) -> ic.Principal:
        record = Types.Record({'settings': Types.Opt(Types.Record(
                    {
                        'controllers': Types.Opt(Types.Vec(Types.Principal)),
                        'compute_allocation': Types.Opt(Types.Nat),
                        'memory_allocation': Types.Opt(Types.Nat),
                        'freezing_threshold': Types.Opt(Types.Nat),
                    }
                )
            )
        })
        arg = [{'type': record, 'value': {
            'settings': []
        }}]

        request_result = self.canister_update_call(sender, None, "create_canister", arg)
        ok_reply = request_result['Ok']['Reply']
        candid = ic.decode(bytes(ok_reply), Types.Record({'canister_id': Types.Principal}))
        canister_id = candid[0]['value']['canister_id']
        return canister_id

    def install_canister(self, sender: ic.Principal, canister_id: ic.Principal, wasm_module: bytes) -> list:
        install_code_argument = Types.Record({
            'wasm_module': Types.Vec(Types.Nat8),
            'canister_id': Types.Principal,
            'arg': Types.Vec(Types.Nat8),
            'mode': Types.Variant({'install': Types.Null, 'reinstall': Types.Null, 'upgrade': Types.Null}),
        })

        arg = [{'type': install_code_argument, 'value': {
                'wasm_module': wasm_module,
                'arg': [],
                'canister_id': canister_id.bytes,
                'mode': {'install': None}
            }
        }]

        request_result = self.canister_update_call(sender, None, "install_code", arg)
        ok_reply = request_result['Ok']['Reply']
        candid = ic.decode(bytes(ok_reply))
        return candid


class PocketICBackend:
    def __init__(self) -> None:
        # attempt to start the PocketIC backend if it's not already running
        pid = os.getpid()
        subprocess.Popen([POCKET_IC_BIN_PATH, "--pid", f"{pid}"])
        daemon_url = self.get_daemon_url(pid)
        print(f'PocketIC running under "{daemon_url}"')

        self.request_client = requests.session()
        self.daemon_url = daemon_url

    def get_daemon_url(self, pid: int) -> str:
        ready_file_path = f"/tmp/pocket_ic_{pid}.ready"
        port_file_path = f"/tmp/pocket_ic_{pid}.port"

        now = time.time()
        stop_at = now + 10  # wait for the ready file for 10 seconds
        while not os.path.exists(ready_file_path):
            if time.time() < stop_at:
                time.sleep(20 / 1000)
            else:
                raise TimeoutError("PocketIC failed to start")

        port = None
        if os.path.isfile(ready_file_path):
            with open(port_file_path) as port_file:
                port = port_file.readline().strip()
        else:
            raise ValueError(f"{ready_file_path} is not a file!")

        return f"http://127.0.0.1:{port}/"

    def list_instances(self) -> List[str]:
        return self.request_client.get(f"{self.daemon_url}instance").text.split(", ")
