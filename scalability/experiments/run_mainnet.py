#!/usr/bin/env python3
import subprocess
import sys
import time
from typing import List

import gflags

FLAGS = gflags.FLAGS
gflags.DEFINE_bool("use_updates", False, "Issue update calls instead of query calls")


class Mainnet:
    """Wrapper to run against subnetworks in mainnet concurrently."""

    def __init__(self):
        """Initialize."""
        if FLAGS.testnet == "mercury" and FLAGS.target_subnet_id is None:
            raise Exception("--target_subnet_id has to be set when running against mainnet")

        # Testnets you have booked and the number of subnetworks each (including NNS)
        self.testnets = {
            "large01": 5,
            # "large02": 5,
            "large03": 5,
            "large04": 5,
            "large05": 5,
            # "medium01": 2,
            # "medium03": 2,
            "medium04": 2,
            # "medium06": 2,
            # "medium07": 2,
            # "medium08": 2,
            # "medium09": 2,
        }

        # All subnets with the ID of the counter canister.
        # Uncomment if you want to run against that subnetwork.
        # sum(self.testnets.items()) has to be larger than the number of subnets uncommented here.
        self.load_targets = {
            # --- pjljw has a lot of traffic, so perhaps avoid
            # "pjljw-kztyl-46ud4-ofrj6-nzkhm-3n4nt-wi3jt-ypmav-ijqkt-gjf66-uae": "ifkln-viaaa-aaaah-qccva-cai",
            "ejbmu-grnam-gk6ol-6irwa-htwoj-7ihfl-goimw-hlnvh-abms4-47v2e-zqe": "nffi3-byaaa-aaaae-qaava-cai",
            # # 404 - [MessageId(...)]: Update returned non-202: 404
            "gmq5v-hbozq-uui6y-o55wc-ihop3-562wb-3qspg-nnijg-npqp5-he3cj-3ae": "phin2-eyaaa-aaaak-qaaca-cai",
            "opn46-zyspe-hhmyp-4zu6u-7sbrh-dok77-m7dch-im62f-vyimr-a3n2c-4ae": "psp4x-fqaaa-aaaak-qaabq-cai",
            # # normal
            "w4asl-4nmyj-qnr7c-6cqq4-tkwmt-o26di-iupkq-vx4kt-asbrx-jzuxh-4ae": "wrd4y-xiaaa-aaaac-qaaaq-cai",
            "lspz2-jx4pu-k3e7p-znm7j-q4yum-ork6e-6w4q6-pijwq-znehu-4jabe-kqe": "m4dvk-faaaa-aaaag-aaaba-cai",
            "k44fs-gm4pv-afozh-rs7zw-cg32n-u7xov-xqyx3-2pw5q-eucnu-cosd4-uqe": "cst46-ryaaa-aaaak-aaaha-cai",
            "lhg73-sax6z-2zank-6oer2-575lz-zgbxx-ptudx-5korm-fy7we-kh4hl-pqe": "anvl4-jaaaa-aaaag-qaaca-cai",
            "brlsh-zidhj-3yy3e-6vqbz-7xnih-xeq2l-as5oc-g32c4-i5pdn-2wwof-oae": "qnlji-3yaaa-aaaai-aa2aq-cai",
            "mpubz-g52jc-grhjo-5oze5-qcj74-sex34-omprz-ivnsm-qvvhr-rfzpv-vae": "2zwmb-wyaaa-aaaai-qa2vq-cai",
            "qdvhd-os4o2-zzrdw-xrcv4-gljou-eztdp-bj326-e6jgr-tkhuc-ql6v2-yqe": "ivomh-taaaa-aaaaj-aac2a-cai",
            "jtdsg-3h6gi-hs7o5-z2soi-43w3z-soyl3-ajnp3-ekni5-sw553-5kw67-nqe": "tiezx-5yaaa-aaaaj-qagya-cai",
            "io67a-2jmkw-zup3h-snbwi-g6a5n-rm5dn-b6png-lvdpl-nqnto-yih6l-gqe": "ftuvq-daaaa-aaaad-aaaqa-cai",
            "5kdm2-62fc6-fwnja-hutkz-ycsnm-4z33i-woh43-4cenu-ev7mi-gii6t-4ae": "iqjyz-jqaaa-aaaad-qayoa-cai",
            "4zbus-z2bmt-ilreg-xakz4-6tyre-hsqj4-slb4g-zjwqo-snjcc-iqphi-3qe": "2oxpg-ayaaa-aaaac-aaacq-cai",
            "qxesv-zoxpm-vc64m-zxguk-5sj74-35vrb-tbgwg-pcird-5gr26-62oxl-cae": "htg4w-ziaaa-aaaab-aabaa-cai",
            "shefu-t3kr5-t5q3w-mqmdq-jabyv-vyvtf-cyyey-3kmo4-toyln-emubw-4qe": "2vzmb-ayaaa-aaaae-aaf3q-cai",
            "csyj4-zmann-ys6ge-3kzi6-onexi-obayx-2fvak-zersm-euci4-6pslt-lae": "cozrd-caaaa-aaaaf-qaeua-cai",
            "eq6en-6jqla-fbu5s-daskr-h6hx2-376n5-iqabl-qgrng-gfqmv-n3yjr-mqe": "34i5c-taaaa-aaaaf-aaa2q-cai",
            "snjp4-xlbw4-mnbog-ddwy6-6ckfd-2w5a2-eipqo-7l436-pxqkh-l6fuv-vae": "3muos-6yaaa-aaaaa-qaaua-cai",
            "pae4o-o6dxf-xki7q-ezclx-znyd6-fnk6w-vkv5z-5lfwh-xym2i-otrrw-fqe": "r7fsz-diaaa-aaaab-qadxa-cai",
        }

        # Next subnetwork to use for workload generators
        self.next_subnet = {key: 0 for key in self.testnets.keys()}
        total_subnetworks = sum(self.testnets.values())
        total_targets = len(self.load_targets)
        missing = total_targets - total_subnetworks
        if total_targets > total_subnetworks:
            print(
                (
                    f"Insufficient testnets for load generation (have {total_subnetworks}, "
                    f"but {total_targets} load targets, {missing} more missing"
                )
            )
            exit(1)

        self.start_time = int(time.time())

    def get_window_name(self, subnet):
        """Get window name from subnet."""
        return subnet.split("-")[0]

    def get_query_command(self, canister, subnet, wg_testnet, wg_subnet, subnet_prefix):
        """Return query command."""
        return [
            "./max_capacity_system_baseline.py",
            "--testnet",
            "mercury",
            "--canister",
            canister,
            "--target_subnet_id",
            subnet,
            "--wg_testnet",
            wg_testnet,
            "--wg_subnet",
            str(wg_subnet),
            "--no_instrument=True",
            "--top_level_out_dir",
            "mainnet-{}".format(self.start_time),
            "--second_level_out_dir",
            subnet_prefix,
            "--num_workload_generators",
            str(4),
            "--query_initial_rps",
            str(500),
            "--max_query_load",
            str(500),
            "--skip_generate_report=True",
            "--target_query_load",
            str(440),
            "--query_rps_increment",
            str(40),
            "--target_all=True",
        ]

    def get_update_command(self, canister, subnet, wg_testnet, wg_subnet, subnet_prefix):
        """Retrun update command."""
        return [
            "./max_capacity_system_baseline.py",
            "--testnet",
            "mercury",
            "--canister",
            canister,
            "--target_subnet_id",
            subnet,
            "--wg_testnet",
            wg_testnet,
            "--wg_subnet",
            str(wg_subnet),
            "--no_instrument=True",
            "--max_update_load",
            str(600),
            "--top_level_out_dir",
            "mainnet-{}".format(self.start_time),
            "--second_level_out_dir",
            subnet_prefix,
            "--num_workload_generators",
            str(4),
            "--target_update_load",
            str(600),
            "--update_rps_increment",
            str(4),
            "--update_initial_rps",
            str(600),
            "--skip_generate_report=True",
            "--target_update_load",
            str(600),
            "--use_updates=True",
            "--iter_duration={}".format(300),
        ]

    def get_commands(self, do_updates=True):
        """Get commands to run based on the list of subnets and canister IDs."""
        r = []
        for subnet, canister in self.load_targets.items():

            wg_testnet = None
            for testnet, num_subnets in self.testnets.items():
                if num_subnets > 0:
                    wg_testnet = testnet
                    break

            self.testnets[wg_testnet] -= 1

            wg_subnet = self.next_subnet[wg_testnet]
            self.next_subnet[wg_testnet] += 1

            subnet_prefix = self.get_window_name(subnet)

            r.append(
                (
                    subnet_prefix,
                    self.get_update_command(canister, subnet, wg_testnet, wg_subnet, subnet_prefix)
                    if do_updates
                    else self.get_query_command(canister, subnet, wg_testnet, wg_subnet, subnet_prefix),
                )
            )

        return r

    def run_in_session(self, name: str, command: List[str]):
        """Run the given command in a tmux session."""
        assert len(name) > 0
        subprocess.run(
            [
                "tmux",
                "new-window",
                "-n",
                name,
                " ".join(command) + '; echo "Check failure rate + hit enter to terminate"; read',
            ],
            check=True,
        )

    def start(self, do_updates):
        """Start the benchmark."""
        print(f"Starting workload with do_updates={do_updates}")
        for name, command in self.get_commands(do_updates):
            self.run_in_session(name, command)

    def tmux_window_list(self) -> List[str]:
        """Get the current tmux window list."""
        r = []
        for line in subprocess.check_output(["tmux", "list-windows"], encoding="utf-8").split("\n"):
            e = line.split(" ")
            if len(e) > 1:
                r.append(e[1])
        return r

    def wait(self):
        """Wait for all benchmarks to terminate."""
        time.sleep(30)
        for name in self.load_targets.keys():
            print(f"Waiting for {name}")
            while self.get_window_name(name) in self.tmux_window_list():
                time.sleep(10)


FLAGS(sys.argv)

mainnet = Mainnet()
mainnet.start(FLAGS.use_updates)

# Need to sleep a bit in order to ensure that all windows are coming up
mainnet.wait()

print("All terminated, done")
