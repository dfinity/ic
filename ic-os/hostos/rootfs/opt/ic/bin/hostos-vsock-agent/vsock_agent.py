"""
Attaches the HSM to the guest VM domains, when they request HSM access.

The script periodically scans the attached HSMs and the guest VM domains.
* If an "attach-hsm" message comes from a guest VM domain (A) and the HSM is not already attached
  to any guest, the HSM will immediately be attached to the requesting VM.
* The HSM is detached from the guest VM after HSM_ATTACH_SECONDS, and will be immediately attached
  to other guest VM domain if there is a pending request.
* Every RESET_AFTER_SECONDS, if the HSM has been attached to any VM domain, the HSM will be
  detached from all guest VM domains, and the struct will be reinitialized (reset).
  This is done to address some libvirt (or qemu/kvm) issues where the HSM stays half-attached to
  the guest VM, but the HSM isn't usable within the VM.
"""
import asyncio
import hashlib
import logging
import os
import subprocess
import tempfile
import textwrap
import threading
import time
from threading import Timer

import libvirt_domains
import requests

HSM_VENDOR = "20a0"
HSM_PRODUCT = "4230"
HSM_ATTACH_SECONDS = 10  # Period after which the HSM is passed to another domain, if there are requests.
RESET_AFTER_SECONDS = 60  # After this many seconds, reset the object (and detach the HSM from all domains)


class VsockAgent:
    """Manages running functions on the server side of the VSOCK communication."""

    def __init__(self, libvirt_handler=None, with_timer=True):
        """Init the VSOCK agent class."""
        threading.excepthook = threading_exception_hook
        if libvirt_handler:
            self.lv = libvirt_handler
        else:
            self.lv = libvirt_domains.CidLibvirtDomain()
        self.hsm_dev_xml_desc = tempfile.mkstemp()[1]
        self.with_timer = with_timer  # Allows more controlled testing
        if self.with_timer:
            self.timer = Timer(HSM_ATTACH_SECONDS, self._periodic_checks)
            self.timer.start()
        else:
            self.timer = None
        self.lock = threading.Lock()
        self._reset()

    def _reset(self):
        logging.debug("HSM agent: Initializing")
        self.hsm_attach_reqs = {}
        self.hsm_detach_reqs = {}
        self.attached_cid = None
        self.attached_timestamp = None
        self.resets_enable = False  # resets are enabled if there were any attach requests
        self.reset_counter = RESET_AFTER_SECONDS / HSM_ATTACH_SECONDS
        self.lsusb_hsm_dev = None
        self._lsusb_parse_hsm_dev()
        self._remove_hsm_from_all_domains()

    def _periodic_checks(self):
        logging.debug("HSM agent: Running periodic checks")
        with self.lock:
            if self.reset_counter > 0 and self.lv.list_cids():
                # If there are active VM domains, run the reset counter
                self.reset_counter -= 1
            if self.resets_enable and self.reset_counter <= 0:
                self._reset()
            else:
                self._lsusb_parse_hsm_dev()
                self.lv.refresh_domains()
                self._detach_hsm_if_needed()
                self._process_detach_requests()
                self._process_one_attach_request()
            if self.with_timer:
                self.timer = Timer(HSM_ATTACH_SECONDS, self._periodic_checks)
                self.timer.start()

    def terminate(self):
        """Cleanup the temp files and stop the timer."""
        if self.attached_cid:
            logging.info("Removing HSM from domain %s", self.lv.cid_to_domain(self.attached_cid))
            self._detach_hsm()
        if self.hsm_dev_xml_desc:
            logging.info("Removing temp file %s", self.hsm_dev_xml_desc)
            os.unlink(self.hsm_dev_xml_desc)
            self.hsm_dev_xml_desc = None
        if self.timer:
            logging.info("Stopping the timer")
            self.timer.cancel()
            self.timer = None

    def __del__(self):
        """Cleanup before deleting the object."""
        self.terminate()

    def _remove_hsm_from_all_domains(self):
        for cid in self.lv.list_cids():
            logging.info(
                "Ensuring HSM is not in domain %s",
                self.lv.cid_to_domain(cid),
            )
            self._detach_hsm_unchecked(cid)

    def _lsusb_parse_hsm_dev(self):
        lsusb_lines = subprocess.check_output(["lsusb"]).strip().decode("utf8").splitlines()
        lsusb_hsm = [_ for _ in lsusb_lines if f"{HSM_VENDOR}:{HSM_PRODUCT}" in _]
        if len(lsusb_hsm) < 1:
            logging.info("No HSM devices detected")
            self.lsusb_hsm_dev = None
            return
        elif len(lsusb_hsm) > 1:
            logging.info("More than one HSM devices detected, will use the first one")
        lsusb_hsm = sorted(lsusb_hsm)[0].split()
        if self.lsusb_hsm_dev != lsusb_hsm:
            self.lsusb_hsm_dev = lsusb_hsm
            self._prepare_libvirt_hsm_dev_xml()

    def _prepare_libvirt_hsm_dev_xml(self):
        # Runs the following steps:
        # 1. run lsusb
        # 2. extract lines with desired VENDOR:PRODUCT
        # 3. take the first HSM device
        # 4. prepare the XML file with the HSM device description
        if not self.lsusb_hsm_dev:
            logging.debug("No HSM dev found. Can't prepare the HSM dev XML description.")
            return
        hsm_bus = int(self.lsusb_hsm_dev[1])
        hsm_device = int(self.lsusb_hsm_dev[3].replace(":", ""))
        with open(self.hsm_dev_xml_desc, "w") as f:
            f.write(
                textwrap.dedent(
                    f"""
            <hostdev mode='subsystem' type='usb' managed='yes'>
                <source>
                    <vendor id='0x{HSM_VENDOR}'/>
                    <product id='0x{HSM_PRODUCT}'/>
                    <address bus='{hsm_bus}' port='1' device='{hsm_device}'/>
                </source>
                <address type='usb' bus='0' port='2'/>
            </hostdev>
            """
                )
            )
        print("HSM device XML description for LibVirt:")
        print(open(self.hsm_dev_xml_desc).read())

    def _detach_hsm_unchecked(self, guest_cid):
        """Try to detach the HSM device from the guest, but don't check for success."""
        domain = self.lv.cid_to_domain(guest_cid)
        logging.debug("Trying to detach the HSM device from domain %s", domain)
        cmd = ["virsh", "detach-device", domain, "--file", self.hsm_dev_xml_desc]
        subprocess.call(cmd)

    def _detach_hsm(self):
        """Detach the HSM device from the currently attached guest, and check for success."""
        domain = self.lv.cid_to_domain(self.attached_cid)
        logging.info(
            "Detaching the HSM device from domain %s (cid %s)",
            domain,
            self.attached_cid,
        )
        cmd = ["virsh", "detach-device", domain, "--file", self.hsm_dev_xml_desc]
        subprocess.check_call(cmd)
        self.attached_cid = None
        self.attached_timestamp = None

    def _detach_hsm_if_needed(self):
        if self.attached_cid:
            if not self.lsusb_hsm_dev:
                logging.debug(
                    "HSM attached to CID %s but detached on the host. Detaching from the guest.",
                    self.attached_cid,
                )
                self._detach_hsm()
                return
            if not self.lv.cid_to_domain(self.attached_cid):
                logging.debug(
                    "HSM attached to CID %s which does not exist anymore. Marking as detached.",
                    self.attached_cid,
                )
                self.attached_cid = None
                self.attached_timestamp = None
                return
        if self.attached_cid and self.attached_timestamp:
            # HSM is attached to the domain guest
            if time.time() - self.attached_timestamp < HSM_ATTACH_SECONDS:
                # but for a short time
                logging.debug(
                    "HSM attached to domain %s and the timer didn't expire",
                    self.attached_cid,
                )
                return
            else:
                logging.debug(
                    "HSM attached to domain %s and the timer expired",
                    self.attached_cid,
                )
                self._detach_hsm()

    def _attach_hsm(self, guest_cid):
        if not self.lsusb_hsm_dev:
            logging.debug("HSM not present on the host. Cannot attach to the guest.")
            return
        domain = self.lv.cid_to_domain(guest_cid)
        logging.info("Attaching the HSM device to domain %s (cid %s)", domain, guest_cid)
        cmd = ["virsh", "attach-device", domain, "--file", self.hsm_dev_xml_desc]
        subprocess.check_call(cmd)
        self.attached_cid = guest_cid
        self.attached_timestamp = time.time()

    def _process_one_attach_request(self):
        """
        Attach the HSM to a domain, if there are pending requests.

        The HSM gets attached to a domain when the domain requests it.
        If the HSM is already attached to another domain, then the new request is queued up.
        """
        self._detach_hsm_if_needed()
        if self.attached_cid:
            # HSM is still attached to a domain.
            # The current request will be processed later, in self._periodic_checks()
            logging.info(
                "HSM currently attached to: %s (%s)",
                self.lv.cid_to_domain(self.attached_cid),
                self.attached_cid,
            )
            return
        if self.hsm_attach_reqs:
            logging.info("HSM attach reqs: %s", self.hsm_attach_reqs)
            guest_cid = self.hsm_attach_reqs.popitem()[0]
            self._attach_hsm(guest_cid)

    def _process_detach_requests(self):
        """
        Detach the HSM from a domain, if there are such requests.

        The HSM is detached from a domain when the domain either:
            a) explicitly requests that the HSM is detached, or
            b) when the timeout of HSM_ATTACH_SECONDS expires.
        However, if no other domain requests the HSM to be attached,
        the HSM will not be detached immediately.
        """
        # The HSM is kept attached if other guest do not needs the HSM
        if not self.hsm_attach_reqs:
            return
        for cid, _ts in self.hsm_detach_reqs.copy().items():
            logging.info("Processing the HSM detach request from: %s", cid)
            if cid == self.attached_cid:
                self._detach_hsm()
            else:
                self._detach_hsm_unchecked(cid)
            if cid in self.hsm_detach_reqs:
                del self.hsm_detach_reqs[cid]
        if self.attached_cid is None:
            self._process_one_attach_request()

    def _upgrade(self, info):
        """
        Upgrade this machine.

        Use `info` to apply upgrade image to alternate install partitions (A or
        B).
        """
        UPGRADE_PATH = "/tmp/upgrade.tar.gz"
        logging.info("Downloading image: " + info.url)
        r = requests.get(info.url)
        with open(UPGRADE_PATH, "wb") as f:
            f.write(r.content)
            f.truncate()

        logging.info("Checking image hash against: " + info.target_hash)
        hasher = hashlib.sha256()
        BUFF_SIZE = 65536
        with open(UPGRADE_PATH, "rb") as f:
            # Chunk up the hashing
            while True:
                data = f.read(BUFF_SIZE)
                if not data:
                    break
                hasher.update(data)
        download_hash = hasher.hexdigest()

        if download_hash != info.target_hash:
            logging.debug("Download failed, incorrect hash.")
            return

        logging.info("Applying update.")
        cmd = ["sudo", "/opt/ic/bin/install-upgrade.sh", UPGRADE_PATH]
        subprocess.check_call(cmd)

        logging.info("Update applied, going down for reboot.")
        cmd = ["sudo", "reboot"]
        subprocess.check_call(cmd)

    def handle_attach_request(self, sender_cid):
        """Handle the HSM attach request from the sender_cid."""
        logging.info("Registering the HSM attach request from: %s", sender_cid)
        with self.lock:
            if sender_cid not in self.hsm_attach_reqs and sender_cid != self.attached_cid:
                self.hsm_attach_reqs[sender_cid] = time.time()
            self.resets_enable = True
            self._process_one_attach_request()

    def handle_detach_request(self, sender_cid):
        """Handle the HSM detach request from the sender_cid."""
        logging.info("Registering the HSM detach request from: %s", sender_cid)
        with self.lock:
            self.hsm_detach_reqs[sender_cid] = time.time()
            self._process_detach_requests()

    def set_node_id(self, sender_cid, node_id):
        """Set node ID from guest-os."""
        logging.info("Setting node ID, from: %s", sender_cid)
        with open("/boot/config/node-id", "w") as f:
            f.write(node_id)
        cmd = ["sudo", "/opt/ic/bin/setup-hostname.sh", "--type=host"]
        subprocess.check_call(cmd)

    def handle_join_success(self, sender_cid):
        """Notify of a successful join request."""

        async def alert():
            with open("/dev/tty1", "w") as tty:
                for _ in range(20):
                    tty.write("Join request successful!\n")
                    tty.write("You may now safely remove the HSM\n\n")
                    await asyncio.sleep(2)

        logging.info("Notifying a successful join from: %s", sender_cid)
        return alert()

    def handle_upgrade_request(self, sender_cid, info):
        """Handle an upgrade request from the sender_cid."""
        logging.info("Upgrade hostOS on request of: %s", sender_cid)
        self._upgrade(info)


def threading_exception_hook(args):
    logging.exception("Caught an exception in a thread, exiting")
    # Exit the process with status n, without calling cleanup handlers, flushing stdio buffers, etc.
    # https://docs.python.org/3/library/os.html#os._exit
    os._exit(1)
