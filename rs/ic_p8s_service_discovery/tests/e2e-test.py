#!/usr/bin/env python3
"""E2E-test for ic-titanium-p8s-daemon."""
import json
import os
import shlex
import subprocess
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path
from shutil import which
from subprocess import Popen
from unittest import TestCase

IC_BINARY_NAME = "ic-p8s-sd"
# Don't start scraping mainnet
DEFAULT_ARGUMENTS = "--no-poll"

# the following are the targets addresses of the root subnet of mainnet at
# registry version 0x6dc1. as we provide --no-poll to the daemon, the registry
# is *not* updated during the test and thus the addresses returned by the daemon
# do not change.
TDB26_TARGET_ADDRS = [
    "[2a00:fa0:3:0:5000:5aff:fe89:b5fc]",
    "[2604:7e00:50:0:5000:20ff:fea7:efee]",
    "[2604:3fc0:3002:0:5000:acff:fe31:12e8]",
    "[2401:3f00:1000:24:5000:deff:fed6:1d7]",
    "[2604:3fc0:2001:0:5000:b0ff:fe7b:ff55]",
    "[2001:920:401a:1708:5000:4fff:fe92:48f1]",
    "[2001:920:401a:1710:5000:28ff:fe36:512b]",
    "[2a00:fa0:3:0:5000:68ff:fece:922e]",
    "[2a01:138:900a:0:5000:2aff:fef4:c47e]",
    "[2a0f:cd00:2:1:5000:3fff:fe36:cab8]",
    "[2a0f:cd00:2:1:5000:87ff:fe58:ceba]",
    "[2001:920:401a:1710:5000:d7ff:fe6f:fde7]",
    "[2001:920:401a:1706:5000:87ff:fe11:a9a0]",
    "[2001:920:401a:1708:5000:5fff:fec1:9ddb]",
    "[2a04:9dc0:0:108:5000:7cff:fece:97d]",
    "[2401:3f00:1000:22:5000:c3ff:fe44:36f4]",
    "[2a00:fb01:400:100:5000:61ff:fe2c:14ac]",
    "[2a00:fb01:400:100:5000:5bff:fe6b:75c6]",
    "[2a00:fb01:400:100:5000:ceff:fea2:bb0]",
    "[2607:f758:c300:0:5000:72ff:fe35:3797]",
    "[2607:f758:c300:0:5000:8eff:fe8b:d68]",
    "[2600:c02:b002:15:5000:53ff:fef7:d3c0]",
    "[2600:c02:b002:15:5000:ceff:fecc:d5cd]",
    "[2600:c02:b002:15:5000:22ff:fe65:e916]",
    "[2607:f758:1220:0:5000:3aff:fe16:7aec]",
    "[2607:f758:c300:0:5000:3eff:fe6d:af08]",
    "[2607:f758:1220:0:5000:bfff:feb9:6794]",
    "[2a04:9dc0:0:108:5000:96ff:fe4a:be10]",
    "[2a04:9dc0:0:108:5000:6bff:fe08:5f57]",
    "[2607:f758:1220:0:5000:12ff:fe0c:8a57]",
    "[2600:3004:1200:1200:5000:59ff:fe54:4c4b]",
    "[2600:3006:1400:1500:5000:95ff:fe94:c948]",
    "[2600:3000:6100:200:5000:c4ff:fe43:3d8a]",
    "[2607:f1d0:10:1:5000:a7ff:fe91:44e]",
    "[2a01:138:900a:0:5000:5aff:fece:cf05]",
    "[2401:3f00:1000:23:5000:80ff:fe84:91ad]",
    "[2600:2c01:21:0:5000:27ff:fe23:4839]",
]


class IcP8sDaemonTest(TestCase):
    """Tests for ic-titanium-p8s-daemon."""

    def setUp(self):
        """Set up tests."""
        self.scraping_dir = tempfile.TemporaryDirectory()
        self.daemon = start_daemon(Path(self.scraping_dir.name))
        retry_with_timeout(lambda: get_request("replica"))

    def test_mainnet_targets_expose(self):
        """test_mainnet_targets_expose."""

        def get_tdb26_targets(path: str) -> list:
            resp = json.loads(get_request(path))
            return set(
                item["targets"][0]
                for item in filter(
                    lambda item: item["labels"].get("ic_subnet", "").startswith("tdb26"),
                    resp,
                )
            )

        def assert_port_matches(targets, port):
            expected_targets = set("{}:{}".format(item, port) for item in TDB26_TARGET_ADDRS)
            self.assertEqual(targets, expected_targets)

        assert_port_matches(get_tdb26_targets("replica"), 9090)
        assert_port_matches(get_tdb26_targets("orchestrator"), 9091)
        assert_port_matches(get_tdb26_targets("host_node_exporter"), 9100)
        assert_port_matches(get_tdb26_targets("node_exporter"), 9100)

    def tearDown(self):
        """Tear down resources."""
        self.scraping_dir.cleanup()
        self.daemon.kill()
        self.daemon.wait()


def in_ci_env() -> bool:
    """Return true iff the process is running on CI (based on env variables)."""
    return "CI_JOB_ID" in os.environ


def start_daemon(targets_dir: Path) -> Popen:
    """Start the discovery daemon, either by invoking 'cargo run'."""
    args = "{} --targets-dir {}".format(DEFAULT_ARGUMENTS, targets_dir)
    if in_ci_env():
        # On CI, we assume that someone else cleanups after us.
        tmpdir = tempfile.mkdtemp()
        target_bin = f"{tmpdir}/{IC_BINARY_NAME}"

        def sh(c):
            subprocess.run(c, shell=True, check=True)

        sh(f'gunzip -c -d "${{CI_PROJECT_DIR}}/artifacts/release/ic-p8s-sd.gz" >"{target_bin}"')
        sh(f"chmod +x {target_bin}")
        args = "{} {}".format(target_bin, args)
    else:
        bin_path = which("cargo")
        args = "{} run --bin {} -- {}".format(bin_path, IC_BINARY_NAME, args)

    p = Popen(shlex.split(args))
    time.sleep(1)
    r = p.poll()
    if r is not None:
        raise Exception("{} stopped. Return code: {}".format(IC_BINARY_NAME, r))
    return p


def retry_with_timeout(f):
    """Retry f with timeout."""
    start = time.time()
    while True:
        try:
            return get_request("replica")
        except Exception:
            if time.time() - start > 90:
                raise


def get_request(path: str) -> bytes:
    """Get request using given path."""
    with urllib.request.urlopen("http://localhost:11235/{}".format(path)) as response:
        return response.read()


if __name__ == "__main__":
    unittest.main()
