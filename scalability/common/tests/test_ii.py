import asyncio
import json
import os
import re
import subprocess
import sys
import time

import gflags
from ic.agent import Agent
from ic.canister import Canister
from ic.client import Client
from ic.identity import DelegateIdentity
from ic.identity import Identity

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from common import misc  # noqa

FLAGS = gflags.FLAGS

gflags.DEFINE_string("targets", None, "Version of the guest OS to boot")
gflags.MarkFlagAsRequired("targets")

if "CI_PIPELINE_ID" in os.environ:
    print("Not running this test on the pipeline just yet.")
    sys.exit(0)


def install_ii_canister(hostname: str):
    """
    Install the NNS canister on the given host.

    Write the canister ID to a file, which can re-read on next try for re-use.
    """
    output = subprocess.run(
        ["dfx", "deploy", "--network", hostname],
        cwd="ii/",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    ).stdout.decode()
    for line in output.split("\n"):
        print("OUTPUT: ", line)
        m = re.match(r"Installing code for canister internet_identity, with canister ID ([0-9a-z\-]*)", line)
        if m:
            canister_id = m.groups()[0]
            with open("ii/canister_id", "w") as f:
                f.write(canister_id)
            return canister_id
    raise Exception("Could not find canister ID in output")


misc.parse_command_line_args()
host_url = f"http://[{FLAGS.targets}]:8080"

identity = Identity()
new_public_key = identity.der_pubkey
save_iden = identity.privkey + identity.pubkey

client = Client(url=host_url)
agent = Agent(identity, client)

with open("ii/identity.did", "r") as f:
    identity_canister_did = f.read()

ii_canister_id = "not-available"  # any invalid canister ID should do here.
if os.path.exists("ii/canister_id"):
    with open("ii/canister_id", "r") as f:
        ii_canister_id = f.read()

challenge = None
try:
    identityCanister = Canister(agent=agent, canister_id=ii_canister_id, candid=identity_canister_did)
    challenge = identityCanister.create_challenge()
    print(challenge)
except Exception:
    print("Getting a challenge from the II canister failed. Trying to reinstall")

# Attempted call against previous canister ID failed
if challenge is None:
    ii_canister_id = install_ii_canister(host_url)
    identityCanister = Canister(agent=agent, canister_id=ii_canister_id, candid=identity_canister_did)
    challenge = identityCanister.create_challenge()

# Call still failed after reinstalling
if challenge is None:
    raise Exception(
        (
            "Failed to get a challenge from II. Check if the II canister has "
            f"been installed correctly under {ii_canister_id}"
        )
    )

registration = identityCanister.register(
    {
        "pubkey": identity.der_pubkey,
        "alias": "foobar",
        "purpose": {"authentication": None},
        "key_type": {"platform": None},
        "credential_id": [[]],
        "protection": {"unprotected": None},
    },
    {"key": challenge[0]["challenge_key"], "chars": "a"},
)
print(registration)

prepare_delegation = identityCanister.prepare_delegation(
    registration[0]["registered"]["user_number"],
    host_url,
    identity.der_pubkey,
    [604800000000000],
)
print(prepare_delegation)

get_delegation = identityCanister.get_delegation(
    registration[0]["registered"]["user_number"], host_url, identity.der_pubkey, prepare_delegation[1]
)
print(get_delegation)


ic_delegation = {}
ic_delegation["delegations"] = [get_delegation[0]["signed_delegation"]]
ic_delegation["publicKey"] = prepare_delegation[0]
ic_identity = [new_public_key.hex(), save_iden]

ic_delegation["delegations"][0]["signature"] = bytes(ic_delegation["delegations"][0]["signature"]).hex()
ic_delegation["delegations"][0]["delegation"]["pubkey"] = bytes(
    ic_delegation["delegations"][0]["delegation"]["pubkey"]
).hex()
ic_delegation["delegations"][0]["delegation"]["expiration"] = hex(
    ic_delegation["delegations"][0]["delegation"]["expiration"]
)
ic_delegation["publicKey"] = bytes(ic_delegation["publicKey"]).hex()

delegated_client = Client(url=host_url)
delegated_identity = DelegateIdentity.from_json(json.dumps(ic_identity), json.dumps(ic_delegation))

delegated_agent = Agent(delegated_identity, delegated_client)
delegatedIdentityCanister = Canister(agent=delegated_agent, canister_id=ii_canister_id, candid=identity_canister_did)
challenge = delegatedIdentityCanister.create_challenge()
print("CALL WITH DELEGATION")
print(challenge)

print("QUERY counter canister")

cid = None
workload_generator_path = "../artifacts/release/ic-workload-generator"
cmd = [workload_generator_path, host_url, "-n", "1", "-r", "0"]
p = subprocess.run(
    cmd,
    check=True,
    capture_output=True,
)
wg_output = p.stdout.decode("utf-8").strip()
for line in wg_output.split("\n"):
    canister_id = re.findall(r"Successfully created canister at URL [^ ]*. ID: [^ ]*", line)
    if len(canister_id):
        cid = canister_id[0].split()[7]

if cid is None:
    raise Exception("Failed to install counter canister")


print("query")
print(delegated_agent.query_raw(cid, "read", []))

NUM_REQUESTS = 5
NUM_CLIENTS = 10


async def single_update(t_start):
    for i in range(NUM_REQUESTS):
        result = await delegated_agent.update_raw_async(cid, "write", [])
        print(f"Finished {i+1}/{NUM_REQUESTS} at: ", (time.time() - t_start), " - result:", result)


async def updates(t_start, num):
    print("update")
    f = []
    for i in range(num):
        f.append(delegated_agent.update_raw_async(cid, "write", []))
    for future in f:
        print("Finished at: ", (time.time() - t_start), " - result:", await future)


async def wait_all(t_start):
    calls = [single_update(t_start) for _ in range(NUM_CLIENTS)]
    await asyncio.gather(*calls)


t_start = time.time()
asyncio.run(wait_all(t_start))

duration = time.time() - t_start
NUM = NUM_CLIENTS * NUM_REQUESTS
print("Updates: {} - time: {} - per second: {}".format(NUM, duration, NUM / duration))

print("query")
print(delegated_agent.query_raw(cid, "read", []))
