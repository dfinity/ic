#!/usr/bin/env python3
"""Benchmark the SNS."""
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import traceback

import gflags
import requests
from ic.candid import encode
from ic.candid import Types
from termcolor import colored

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common import misc  # noqa
from common import base_experiment  # noqa

FLAGS = gflags.FLAGS
gflags.DEFINE_boolean("interactive", False, "Confirm some steps before continuing the script")
gflags.DEFINE_boolean("deploy", True, "Should the NNS be deployed")

TMPDIR = "/tmp"
DFX_VERSION = "0.11.0"
SNS_REF = "origin/main"
IC_COMMIT = ""  # empty to use latest on public github


def sns_except_hook(exctype, value, tb_in):
    tb = "".join(traceback.format_tb(tb_in))
    tb = "\n".join([line[2:] for line in tb.split("\n")])
    tb_formatted = f"```\n{tb}\n```"
    blocks = {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "❌ SNS Deployment failed: " + str(exctype),
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "plain_text",
                    "text": str(value),
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": tb_formatted,
                },
            },
        ]
    }
    env = os.environ.copy()
    if "CI_JOB_ID" in env:
        job_id = env["CI_JOB_ID"]
        blocks["blocks"].append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"<https://https://gitlab.com/dfinity-lab/public/ic/-/jobs/{job_id}|View CI job>",
                },
            },
        )
    send_slack(blocks)
    sys.__excepthook__(exctype, value, tb)


sys.excepthook = sns_except_hook


def send_slack(message: dict):
    print("Not sending Slack messages at the moment .. ")
    # if "SLACK_WEBHOOK" in os.environ.copy():
    #    print("Sending Slack message .. ")
    #    subprocess.check_output(
    #        [
    #            "curl",
    #            "-X",
    #            "POST",
    #            "-H",
    #            "Content-type: application/json",
    #            "--data",
    #            json.dumps(message),
    #            os.environ["SLACK_WEBHOOK"],
    #        ]
    #    )


def send_slackmessage(mst: str):
    send_slack({"text": mst})


class SnsExperiment(base_experiment.BaseExperiment):
    """Logic for experiment 2."""

    def __init__(self):
        super().__init__()
        # Following https://www.notion.so/SNS-demo-deployment-notes-a3b88d71effa4ac380bd65020aca9cbf
        # as close as possible
        self.dfx_network = FLAGS.testnet
        self.testnet = FLAGS.testnet
        self.ic_commit = SnsExperiment.find_latest_commit_in_public_repo()
        self.ic_download = self.ic_commit
        self.nd_commit = SNS_REF
        self.nns_dapp_dir = os.path.join(TMPDIR, "nns-dapp")

    def find_latest_commit_in_public_repo():
        if len(IC_COMMIT) > 0:
            return IC_COMMIT
        path = os.path.join(TMPDIR, "public_ic")
        if not os.path.exists(path):
            subprocess.check_output(
                ["git", "clone", "https://github.com/dfinity/ic.git", "public_ic"],
                cwd=TMPDIR,
            )
        subprocess.check_output(["git", "fetch"], cwd=path)

        # Find the latest commit on that repo
        output = subprocess.check_output(["git", "rev-parse", "origin/master"], cwd=path)
        commit = output.decode().replace("\n", "")

        # Search for a commit with IC OS and artifacts from there backwards
        output = subprocess.check_output(["./gitlab-ci/src/artifacts/newest_sha_with_disk_image.sh", commit], cwd=path)
        commit = output.decode().replace("\n", "")
        return commit

    def get_canister_ids(self):
        with open(os.path.join(self.nns_dapp_dir, "canister_ids.json")) as f:
            return {key: value[FLAGS.testnet] for key, value in json.loads(f.read()).items()}

    def ensure_install_dfx(self):
        current_version = subprocess.check_output(["dfx", "--version"]).decode().split()
        if len(current_version) == 2 and current_version[1] == DFX_VERSION:
            return
        subprocess.check_output(
            f'DFX_VERSION={DFX_VERSION} sh -ci "$(curl -fsSL https://smartcontracts.org/install.sh)"', shell=True
        )

    def get_idl2json(self):
        self.idl2json_dir = os.path.join(TMPDIR, "idl2json")
        if not os.path.exists(self.idl2json_dir):
            subprocess.check_output(
                ["git", "clone", "https://github.com/dfinity/idl2json.git", self.idl2json_dir],
                cwd=TMPDIR,
            )
            subprocess.check_output(
                shlex.split("cargo build --release"),
                cwd=self.idl2json_dir,
            )

    def ensure_checkout_nns_dapp(self):
        if not os.path.exists(self.nns_dapp_dir):
            print("NNS dapp not checked out yet, checking out")
            subprocess.check_output(
                ["git", "clone", "https://github.com/dfinity/nns-dapp/", self.nns_dapp_dir],
                cwd=TMPDIR,
            )
            subprocess.check_output(
                ["git", "reset", "--hard", SNS_REF],
                cwd=self.nns_dapp_dir,
            )

    def __run_in_sns_dir(self, cmd=None, args=None):
        sns_env = os.environ.copy()
        sns_env["PATH"] = str(
            ":".join(
                [
                    os.path.abspath(self.artifacts_path),
                    os.path.join(os.path.abspath(self.idl2json_dir), "target/release/"),
                    sns_env["PATH"],
                ]
            )
        )
        # gitlab docker images might have the cargo target redirected. Make sure this isn't the case.
        if "CARGO_TARGET_DIR" in sns_env:
            del sns_env["CARGO_TARGET_DIR"]

        assert cmd is not None or args is not None
        if cmd is not None:
            command = shlex.split(cmd)
        elif args is not None:
            command = args

        return subprocess.check_output(command, cwd=self.nns_dapp_dir, env=sns_env).decode()

    def deploy(self, what: str):
        args = ["./deploy.sh", f"--{what}", self.dfx_network]
        print(colored("deploy.sh ", "blue"), args[1:])
        self.__run_in_sns_dir(args=args)

    def cleanup(self):
        print(colored("Remove canister IDs for that testnet from canister_ids.json", "blue"))
        self.deploy("delete")

    def deploy_ii(self):
        print(colored("Deploying II", "blue"))
        self.__run_in_sns_dir(f"git reset --hard {self.nd_commit}")
        self.generate_dfx_json(self.dfx_network, self._get_nns_url())
        self.deploy("ii")

    def deploy_sns_wasm(self):
        print(colored("Deploying SNS wasm", "blue"))
        # Get wasm files
        self.__run_in_sns_dir("e2e-tests/scripts/nns-canister-download")
        # Copy required did files
        did_files = [
            "rs/nns/governance/canister/governance.did",
            "rs/rosetta-api/ledger.did",
            "rs/rosetta-api/ledger_canister/ledger.did",
            "rs/rosetta-api/icrc1/ledger/icrc1.did",
            "rs/nns/gtc/canister/gtc.did",
            "rs/nns/cmc/cmc.did",
            "rs/nns/sns-wasm/canister/sns-wasm.did",
            "rs/sns/swap/canister/swap.did",
            "rs/sns/root/canister/root.did",
            "rs/sns/governance/canister/governance.did",
        ]
        for f in did_files:
            f_name = f.split("/")[-1]
            shutil.copyfile(os.path.join("../", f), os.path.join(self.nns_dapp_dir, "target/ic", f_name))

        # Deploy SNS wasm
        self.deploy("sns-wasm")

    def __propose(self, what):
        self.__run_in_sns_dir(f"./scripts/propose --jfdi --to {what} --dfx-network {self.dfx_network}")

    def setup_nns(self):
        print(colored("Deploying SNS", "blue"))

        self.__propose("set-authorized-subnetworks")
        self.__propose("propose-xdr-icp-conversion-rate")

        # Get dfx account ID
        self.__run_in_sns_dir(f"dfx ledger --network {self.dfx_network} account-id")

        # Check balance
        # On first use this will provide 100Tcycles, which is enough to deploy an SNS so later steps are not needed
        self.__run_in_sns_dir(f"dfx wallet --network {self.dfx_network} balance")
        self.__run_in_sns_dir(f"dfx ledger --network {self.dfx_network} balance")

    def deploy_sns(self):
        self.deploy("sns")

    def deploy_nns_dapp(self):
        # Deploy NNS dapp
        print(colored("Deploying NNS dapp", "blue"))
        self.add_canister_id(FLAGS.testnet, "nns-governance", "rwlgt-iiaaa-aaaaa-aaaaa-cai")
        # self.__run_in_sns_dir(f"git reset --hard {self.nd_commit}")
        # self.generate_dfx_json(self.dfx_network, self._get_nns_url())

        self.deploy("nns-dapp")

        # Needs Firefox or another browser
        #        self.__run_in_sns_dir(f"./deploy.sh --populate {self.dfx_network}")
        # Needs Firefox or another browser
        #        self.__run_in_sns_dir(f"./deploy.sh --populate {self.dfx_network}")

    def generate_dfx_json(self, testnet, nns_url):

        dfx_json_file = os.path.join(self.nns_dapp_dir, "dfx.json")
        print(f"Reading existing dfx.json file from {dfx_json_file}")

        old_dfx_json = {}
        with open(dfx_json_file) as dfx_file:
            old_dfx_json = json.loads(dfx_file.read())
            if testnet not in old_dfx_json["networks"]:
                old_dfx_json["networks"][testnet] = {
                    "config": {
                        "BUILD": "dev",
                        "FETCH_ROOT_KEY": True,
                        "REDIRECT_TO_LEGACY": "both",
                        "ENABLE_NEW_SPAWN_FEATURE": True,
                        "ENABLE_SNS_NEURONS": True,
                        "HOST": f"https://{testnet}.dfinity.network",
                        "IDENTITY_SERVICE_URL": f"https://qjdve-lqaaa-aaaaa-aaaeq-cai.{testnet}.dfinity.network",
                    },
                    "providers": [nns_url],
                    "type": "persistent",
                }
            old_dfx_json["defaults"]["build"]["config"]["IC_COMMIT"] = str(self.ic_commit)
            print("Generated new content for dfx.json file")

        with open(dfx_json_file, "w") as dfx_file:
            dfx_file.write(json.dumps(old_dfx_json, indent=2))
            print("Wrote new content for dfx.json file")

        # Sanity check
        print(subprocess.check_output(["git", "diff"], cwd=self.nns_dapp_dir).decode())

        if FLAGS.interactive:
            input("Confirm content of dfx json file .. ")
            print("")

    def add_canister_id(self, testnet, canister_name, canister_id):

        canister_ids_json_file = os.path.join(self.nns_dapp_dir, "canister_ids.json")
        print(f"Reading existing dfx.json file from {canister_ids_json_file}")

        old_canister_ids_json = {}
        with open(canister_ids_json_file) as json_file:
            old_canister_ids_json = json.loads(json_file.read())
            old_canister_ids_json[canister_name] = {testnet: canister_id}
            print("Generated new content for dfx.json file")

        with open(canister_ids_json_file, "w") as json_file:
            json_file.write(json.dumps(old_canister_ids_json, indent=2))
            print("Wrote new content for dfx.json file")

    def run_experiment_internal(self, config):
        raise Exception("Not yet implemented")

    def run_iterations(self, iterations=None):
        raise Exception("Not yet implemented")

    def check_root_canister(self, nns_url):
        canister_id = self.get_canister_ids()["sns_root"]
        print(f"Canister ID of root caniter is: {canister_id}")
        agent = misc.get_anonymous_agent(self._get_nns_ip())
        params = [
            {"type": Types.Vec(Types.Principal), "value": []},
        ]
        response = agent.update_raw(canister_id, "canister_status", encode(params))
        print("Response is:", response)

    def check_canisters_installed(self, nns_url, canister_name, fn_name):
        found = False
        num_lines_left = 0
        for line in requests.get(nns_url).text.split("\n"):
            if re.match(f".*summary.*{canister_name}.*", line):
                num_lines_left = 20
            if num_lines_left > 0:
                num_lines_left -= 1
                if re.match(f".*ExportedFunctions.*{fn_name}.*", line):
                    print(line)
                    found = True
        return found

    def check_canister_call_contains(self, canister: str, method: str, payload: str, match: str):
        cmd = ["dfx", "canister", "--network", FLAGS.testnet, "call", canister, method, payload]
        print("Calling", cmd)
        out = self.__run_in_sns_dir(args=cmd)
        print("Result", out, " - looking for", match)
        result = match in out
        if result:
            print(f"✅ Checking {method} with {payload} containes {match}")
        else:
            print(f"❌ Checking {method} with {payload} does not contain {match}")
        return result

    def check_correctness(self, canisters):
        all_correct = self.check_canister_call_contains(
            "wasm_canister", "list_deployed_snses", "( record { } )", canisters["sns_root"]
        )

        all_correct &= self.check_canister_call_contains(
            "sns_swap", "get_state", "( record { } )", "sns_root_canister_id"
        )

        return all_correct


if __name__ == "__main__":
    exp = SnsExperiment()
    nns_url = exp._get_nns_url()
    sns_subnet = exp.get_subnets()[1]
    print(f"SNS subnet ID is: {sns_subnet}")

    exp.ensure_checkout_nns_dapp()
    if FLAGS.deploy:
        print(exp.get_subnets())
        res = subprocess.check_output(
            [exp._get_ic_admin_path(), "--nns-url", nns_url, "get-subnet", exp.get_subnets()[0]],
            encoding="utf-8",
        )

        nns_subnet_json = json.loads(res)["records"][0]["value"]
        res = subprocess.check_output(
            [
                exp._get_ic_admin_path(),
                "--nns-url",
                nns_url,
                "propose-to-update-subnet",
                "--subnet",
                sns_subnet,
                "--test-neuron-proposer",
                "--initial-notary-delay-millis",
                str(nns_subnet_json["initial_notary_delay_mills"]),
                "--unit-delay-millis",
                str(nns_subnet_json["unit_delay_millis"]),
                "--max-ingress-bytes-per-message",
                str(nns_subnet_json["max_ingress_bytes_per_message"]),
                "--dkg-interval-length",
                str(nns_subnet_json["dkg_interval_length"]),
            ],
            encoding="utf-8",
        )
        print(f"Result of ic-admin call to update subnet: {res}")

        exp.get_idl2json()
        exp.ensure_install_dfx()
        exp.generate_dfx_json(FLAGS.testnet, nns_url)
        exp.cleanup()
        exp.setup_nns()
        exp.deploy_ii()
        exp.deploy_nns_dapp()
        exp.deploy_sns_wasm()
        exp.deploy_sns()

    exp.check_root_canister(nns_url)  # Doesn't work yet ..
    assert exp.check_canisters_installed(nns_url, exp.get_canister_ids()["sns_root"], "get_sns_canisters_summary")
    assert exp.check_canisters_installed(nns_url, exp.get_canister_ids()["sns_governance"], "get_root_canister_status")
    assert exp.check_correctness(exp.get_canister_ids())
    print(f"Done, check if canisters are installed at: {nns_url}")
    send_slackmessage("✅ SNS deployment succeeded")
