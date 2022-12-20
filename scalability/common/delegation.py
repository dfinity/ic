import json
import logging
import os
import re
import subprocess

from ic.agent import Agent
from ic.canister import Canister
from ic.client import Client
from ic.identity import DelegateIdentity
from ic.identity import Identity


logging.basicConfig(level=logging.INFO)


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


def get_delegation(host_url):
    """
    Get delegation from the Internet Identity canister.

    Install development version of the canister if it isn't installed already.
    """
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
            ii_canister_id = f.read().strip()

    challenge = None
    try:
        identityCanister = Canister(agent=agent, canister_id=ii_canister_id, candid=identity_canister_did)
        logging.info("II: Creating challenge .. ")
        challenge = identityCanister.create_challenge()
        logging.debug(challenge)
    except Exception:
        logging.debug("Getting a challenge from the II canister failed. Trying to reinstall")

    # Attempted call against previous canister ID failed
    if challenge is None:
        ii_canister_id = install_ii_canister(host_url)
        identityCanister = Canister(agent=agent, canister_id=ii_canister_id, candid=identity_canister_did)
        logging.info("II: Creating challenge .. ")
        challenge = identityCanister.create_challenge()

    # Call still failed after reinstalling
    if challenge is None:
        raise Exception(
            (
                "Failed to get a challenge from II. Check if the II canister has "
                f"been installed correctly under {ii_canister_id}"
            )
        )

    logging.info("II: Registering .. ")
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
    logging.debug(registration)

    logging.info("II: Preparing delegation .. ")
    prepare_delegation = identityCanister.prepare_delegation(
        registration[0]["registered"]["user_number"],
        host_url,
        identity.der_pubkey,
        [604800000000000],
    )
    logging.debug(prepare_delegation)

    logging.info("II: Getting delegation .. ")
    get_delegation = identityCanister.get_delegation(
        registration[0]["registered"]["user_number"], host_url, identity.der_pubkey, prepare_delegation[1]
    )
    logging.debug(get_delegation)

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

    delegated_identity = DelegateIdentity.from_json(json.dumps(ic_identity), json.dumps(ic_delegation))
    return (delegated_identity, ii_canister_id, identity_canister_did)
