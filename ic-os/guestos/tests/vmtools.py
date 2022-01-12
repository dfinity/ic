#!/usr/bin/env python3
"""
Tools for working with virtual machines.

This module provides tools to set up and control virtual machines.
The API is structured to allow allocation of machines from a
'pool' of available machines, like this:

    machines = vmtools.pool().request_machines(
        [
            {"name": "node0", "ram": "6G", "disk": "100G", "cores": 1},
            {"name": "node1", "ram": "6G", "disk": "100G", "cores": 1},
        ],
    )

And then started like this:

    vmtools.start_machines(
        [
            (machines[0], system_disk_image, config_disk_image[0]),
            (machines[1], system_disk_image, config_disk_image[1]),
        ],
        start_ssh_log_streaming=True,
    )

All virtual machines will automatically be killed when the script
terminates.
"""
import atexit
import fcntl
import json
import os
import subprocess
import sys

import gflags

FLAGS = gflags.FLAGS

gflags.DEFINE_string("log_directory", "/tmp", "Directory where log files are stored")
gflags.DEFINE_string("vmtoolscfg", "/etc/vmtoolscfg.json", "Configuration file for vmtools")
gflags.DEFINE_bool(
    "is_upgrade_test",
    False,
    "Enable for upgrade tests. Will make sure we collect logs after reboot",
)


class MachineTemplate(object):
    """
    'Slot' in which a virtual machine can be spawned.

    This represents an "available VM slot" in which a user
    can spawn a specific VM instance. Each template has unique
    per-slot information associated with it such that multiple
    VMs spawned on the target do not collide.

    Each MachineTemplate instance must be used by at most
    one Machine instance.
    """

    def __init__(self, name, ipv6, ipv6_gateway, mac1, mac2):
        """Initialize a new Machine with various configurations."""
        self.name = name
        self.ipv6 = ipv6
        self.ipv6_gateway = ipv6_gateway
        self.mac1 = mac1
        self.mac2 = mac2

    def get_ipv6(self):
        """Return machine's ipv6 address."""
        return self.ipv6.split("/")[0]


class Machine(object):
    """
    Configuration of virtual machine instance.

    Holds the actual configuration of the machine. This
    amends the information held in MachineTemplate above
    with "dynamic" configuration, such as requested amount
    of RAM and disk size.
    """

    def __init__(self, template, ram, disk):
        """Initialize a new Machine with various configurations."""
        self.template = template
        self.ram = ram
        self.disk = disk
        self.process = None

    def execute(self, command, check=True):
        """Execute the given command on the given machine via SSH."""
        command_line = [
            "ssh",
            "-o",
            "ConnectTimeout=1",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ServerAliveCountMax=3",
            "-o",
            "ServerAliveInterval=1",
            "-o",
            "PasswordAuthentication=false",
            "root@%s" % self.get_ipv6(),
            command,
        ]
        subprocess.run(command_line, check=check)

    def reboot(self):
        """Hard-reboot this machine."""
        self.execute("reboot -ff", False)

    def get_ips(self, family):
        """
        Return IP addresses for family.

        The "family" parameter must be either 4 or 6 (for IPv4 or IPv6).

        Return the list of addresses associated with then machine
        for given family. The list could be empty if there are no
        addresses of the family. Each entry will be a dictionary
        of the form:
        {
            "address": <string>,
            "mask_length": <integer>,
            "gateway": <string>
        }
        """
        addrs = []
        for nic in self.template["nics"]:
            for nic_addr in nic["addresses"]:
                if nic_addr["family"] == family:
                    addrs.append(nic_addr)
        return addrs

    def get_ipv6(self):
        """Return machine's ipv6 address."""
        return self.get_ips(6)[0]["address"]

    def get_ram_mb(self):
        """Return the machine's RAM in MB."""
        return self.ram // (1024 * 1024)

    def get_disk_gb(self):
        """Return the machine's disk in GB."""
        return self.disk // (1024 * 1024 * 1024)

    def get_name(self):
        """Return name of the virtual machine."""
        return self.template["name"]

    def stop(self):
        """Stop the virtual machine."""
        if self.process:
            self.process.terminate()
            try:
                self.process.poll(1)
                self.process = None
                return
            except Exception:
                pass
            self.process.kill()
            self.process.wait()
            self.process = None
            return


class QEMUConfig(object):
    """
    Auxiliary object for QEMU config.

    Represent configuration for launching qemu command.
    """

    def __init__(self, name, ram="2G"):
        """Create baseline qemu configuration."""
        self.name = name
        self.ram = ram
        self.primary_hd_img = None
        self.usb_hd_imgs = []
        self.netdevs = []

    def set_primary_hd_image(self, path):
        """Set disk image for primary hard disk."""
        self.primary_hd_img = path

    def add_usb_hd_image(self, path):
        """Set disk image for additional USB hard disk."""
        self.usb_hd_imgs.append(path)

    def add_netdev(self, netdev, mac):
        """Add a network device."""
        self.netdevs.append((netdev, mac))

    def _build_base_cmdline(self):
        return [
            "qemu-system-x86_64",
            "-machine",
            "type=q35,accel=kvm",
            "-enable-kvm",
            "-nographic",
            "-display",
            "none",
            "-serial",
            "mon:stdio",
            "-m",
            self.ram,
            "-bios",
            "/usr/share/OVMF/OVMF_CODE.fd",
            # We need a USB controller in order to be able to
            # dynamically attach either removable media or HSMs
            "-device",
            "qemu-xhci,bus=pcie.0,addr=2.0",
        ]

    def _build_primary_hd_cmdline(self):
        return (
            [
                "-device",
                "virtio-blk-pci,drive=drive0,bus=pcie.0,addr=3.0",
                "-drive",
                "file=%s,format=raw,id=drive0,if=none" % self.primary_hd_img,
            ]
            if self.primary_hd_img is not None
            else []
        )

    def _build_usb_hds_cmdline(self):
        cmdline = []
        for usb_hd_img in self.usb_hd_imgs:
            cmdline += [
                "-device",
                "usb-storage,drive=removable,removable=true",
                "-drive",
                "file=%s,format=raw,id=removable,if=none" % usb_hd_img,
            ]
        return cmdline

    def _build_netdevs_cmdline(self):
        cmdline = []
        for n in range(len(self.netdevs)):
            index = n + 1
            netdev, mac = self.netdevs[n]
            name = "enp%ds0" % index
            cmdline += [
                "-device",
                "pcie-root-port,id=pcie.%d,chassis=%d" % (index, index),
                "-netdev",
                "%s,id=%s" % (netdev, name),
                "-device",
                "virtio-net-pci,netdev=%s,bus=pcie.%d,addr=0.0,mac=%s" % (name, index, mac),
            ]
        return cmdline

    def build_cmdline(self):
        """Build command line for QEMU process launch."""
        return (
            self._build_base_cmdline()
            + self._build_primary_hd_cmdline()
            + self._build_usb_hds_cmdline()
            + self._build_netdevs_cmdline()
        )


def start_machine_local(machine, disk_image, config_image, interactive=False):
    name = machine.get_name()
    disk_image = disk_image.get_local_filename()
    machine_disk = "/tmp/disk-%s.img" % name
    disk_size = machine.get_disk_gb()

    subprocess.run(["cp", "--sparse=always", disk_image, machine_disk], check=True)
    subprocess.run(["truncate", "--size", "%dG" % disk_size, machine_disk], check=True)

    qemu_config = QEMUConfig(name=machine.get_name(), ram="%dM" % machine.get_ram_mb())
    qemu_config.set_primary_hd_image(machine_disk)
    qemu_config.add_usb_hd_image(config_image)
    for nic in machine.template["nics"]:
        mac = nic["mac"]
        netdev = nic["netdev"]
        if netdev["mode"] == "tap":
            qemu_netdev = "tap,ifname=%s,script=no,downscript=no" % netdev["ifname"]
        elif netdev["mode"] == "bridge":
            qemu_netdev = "bridge,br=%s" % netdev["bridge"]
        qemu_config.add_netdev(qemu_netdev, mac)

    qemu_cmdline = qemu_config.build_cmdline()
    if interactive:
        stdin, stdout, stderr = None, None, None
    else:
        f_out = os.path.join(FLAGS.log_directory, "%s.serial.log" % machine.get_name())
        f_err = os.path.join(FLAGS.log_directory, "%s.stderr.log" % machine.get_name())
        stdin = subprocess.DEVNULL
        stdout = open(f_out, "wb")
        stderr = open(f_err, "wb")
    process = machine.process = subprocess.Popen(
        qemu_cmdline,
        stdin=stdin,
        stdout=stdout,
        stderr=stderr,
    )

    if interactive:
        process.wait()
    else:
        atexit.register(lambda machine=machine: machine.stop())


def start_log_streamer(machine):
    f_journal = os.path.join(FLAGS.log_directory, "%s.journal.log" % machine.get_name())
    f_ssh = os.path.join(FLAGS.log_directory, "%s.log_streamer_ssh.log" % machine.get_name())
    cmdline = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "log-streamer.py"),
        "root@%s" % machine.get_ipv6(),
        "2" if FLAGS.is_upgrade_test else "1",
    ]
    log_process = subprocess.Popen(
        cmdline,
        stdin=subprocess.DEVNULL,
        stdout=open(f_journal, "wb"),
        stderr=open(f_ssh, "wb"),
    )
    atexit.register(lambda log_process=log_process: log_process.kill())


def start_machines(items, start_ssh_log_streaming=True):
    for machine, disk_image, config_image in items:
        start_machine_local(machine, disk_image, config_image)
        if start_ssh_log_streaming:
            start_log_streamer(machine)


class SystemImage(object):
    """Represent a system disk image."""

    def __init__(self, local_path):
        """Initialize system image with the provided image path."""
        self.local_path = local_path

    @classmethod
    def open_local(cls, local_path):
        """Create a local system image."""
        return SystemImage(local_path)

    def get_local_filename(self):
        """Return the system image's local filepath."""
        return self.local_path


class StaticNamePool(object):
    """
    A pool of names that can be locked by user.

    Provide a pool of names where multiple users (in multiple processes) can
    acquire a number of individual names. This pool simply uses a static
    in-process list of names.

    Names are acquired using the acquire_name method. They are released either
    explicitly through the release_name method, or implicitly on process exit.
    """

    def __init__(self, names):
        """Initialize name pool for given set of names."""
        self.names = tuple(names)
        self.index = 0

    def acquire_name(self):
        """
        Locks an available name.

        Returns the next availabel name from the pool.
        """
        if self.index < len(self.names):
            name = self.names[self.index]
            self.index += 1
            return name
        else:
            return None
        assert False, "abstract method"

    def release_name(self, name):
        """
        Release a previously locked name.

        Does nothing (as this is simply an in-memory pool.
        """
        pass


class LockFileNamePool(object):
    """
    A pool of names that can be locked by user.

    Provide a pool of names where multiple users (in multiple processes) can
    acquire a number of individual names. The locking mechanism uses lockfiles
    stored in a specified directory.

    Names are acquired using the acquire_name method. They are released either
    explicitly through the release_name method, or implicitly on process exit.
    """

    def __init__(self, base_dir, names):
        """
        Initialize the lock file pool.

        Initialize the pool of lock files. Files will be stored in the given
        base_dir (which must be at least group-writable by everyone who is
        entitled to work with this pool). The list of available names is
        given the the "names" variable.
        """
        self.base_dir = base_dir
        self.tier_index = 0
        self.name_index = 0
        self.name_tiers = [[], [], []]
        self.locked = {}

        owned = set()
        other_owned = set()

        uid = os.getuid()
        for name in os.listdir(base_dir):
            st = os.stat(os.path.join(base_dir, name))
            if st.st_uid == uid:
                owned.add(name)
            else:
                other_owned.add(name)
        for name in names:
            if name in owned:
                self.name_tiers[0].append(name)
            elif name in other_owned:
                self.name_tiers[2].append(name)
            else:
                self.name_tiers[1].append(name)

    def acquire_name(self):
        """
        Locks an available name.

        Searches for an available name and locks it. Returns the acquired
        name if successful, or None if no name is available at present.

        When looking for an available name, the search tries in this order:
        - a name that was previously reserved to the same user
        - a name that was never reserved by any user
        - a name that was reserved by another user

        This strategy has the effect that a user performing interactive tests
        will mostly work with "stable" assignment: Two calls reserving the
        same number of names in short succession will result in the same
        names.
        """
        while self.tier_index < 3:
            names = self.name_tiers[self.tier_index]
            while self.name_index < len(names):
                name = names[self.name_index]
                fd = self._try_lock(name)
                if fd is not None:
                    self.locked[name] = fd
                    return name
                self.name_index += 1
            self.tier_index += 1
            self.name_index = 0
        return None

    def release_name(self, name):
        """
        Release a previously locked name.

        Releases a name that was locked previously. Note that any locked name
        will be released when the process exits, so it is not absolutely
        necessary to explicitly release locked names.

        Precondition: The given name was previously returned from "acquire_name"
        and it was not passed to "release_name" yet.
        """
        fd = self.locked[name]
        del self.locked[name]
        os.close(fd)

    def _try_lock(self, name):
        """
        Try to obtain named lock file.

        Tries to get exclusive lock for specified name
        in pool. Returns descriptor of opened file if
        successful. Retuns None if file is locked already.

        Post-condition:
        - named file exists
        - named file is owned by calling user
        - returned file handle corresponds to named file
        - there is an exclusive lock on returned file handle
        """
        while True:
            # Open (and maybe create) lock file.
            p = os.path.join(self.base_dir, name)
            fd = os.open(p, os.O_RDWR | os.O_CREAT, 0o666)
            try:
                os.fchmod(fd, 0o666)
            except PermissionError:
                pass

            # Try to obtain lock.
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                os.close(fd)
                return None

            # Now that file is locked, verify that obtained
            # handle matches file on fs. This closes a race
            # between us opening the file and someone else
            # removing it underneath.
            st_fs = os.stat(p)
            st = os.fstat(fd)
            if st_fs.st_ino != st.st_ino:
                os.close(fd)
                continue
            break

        # At this point we have opened the file that is linked
        # on fs, and we own an exclusive lock to it. The last
        # thing to do is to check ownership -- if this file
        # is owned by us, then we are done.
        if st.st_uid == os.getuid():
            return fd

        # Create a replacement file, and also lock it instantly.
        replacement_file = os.path.join(self.base_dir, "." + name)
        # Remove possibly existing stale replacement file.
        try:
            os.unlink(replacement_file)
        except FileNotFoundError:
            pass
        new_fd = os.open(replacement_file, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o666)
        os.fchmod(new_fd, 0o666)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.rename(replacement_file, p)
        os.close(fd)

        return new_fd


class MachinePool(object):
    """
    Pool of machines available to user.

    Represent the pool of virtual machines that can be used.
    A test run can request a certain number of machines that
    will then be reserved for duration of the test.

    Depending on configuration, this will be either a "system-wide"
    pool of machines, or some in-process construct representing
    a static set of machines for isolated environments (e.g. CI).
    """

    def __init__(self, vmtoolcfg_json):
        """
        Initialize machine pool.

        Initializes machine pool from the given configuration
        description.
        """
        machine_templates = vmtoolcfg_json["machine_templates"]
        names = [tpl["name"] for tpl in machine_templates]
        self.machine_templates = {tpl["name"]: tpl for tpl in machine_templates}

        machine_lock_dir = vmtoolcfg_json["machine_lock_directory"]
        if machine_lock_dir:
            self.name_pool = LockFileNamePool(machine_lock_dir, names)
        else:
            self.name_pool = StaticNamePool(names)

    @classmethod
    def _format_machine_template(cls, tpl):
        addrs = [addr["address"] for nic in tpl["nics"] for addr in nic["addresses"]]
        return "%s (%s)" % (tpl["name"], " ".join(addrs))

    @classmethod
    def _int_from_unit(cls, value):
        if value[-1] == "G":
            return int(value[:-1]) * 1024 * 1024 * 1024
        elif value[-1] == "M":
            return int(value[:-1]) * 1024 * 1024
        elif value[-1] == "K":
            return int(value[:-1]) * 1024
        else:
            return int(value)

    def request_machine(self, name=None, ram="2G", disk="100G", cores=1):
        """Request a single machine."""
        name = self.name_pool.acquire_name()
        assert name is not None, "No machine available"
        tpl = self.machine_templates[name]
        sys.stderr.write("Reserved VM %s\n" % self._format_machine_template(tpl))
        sys.stderr.flush()
        return Machine(tpl, self._int_from_unit(ram), self._int_from_unit(disk))

    def request_machines(self, machine_descriptions):
        """Request multiple machines."""
        return [self.request_machine(**d) for d in machine_descriptions]


# This is the configuration using a "fake" machine pool when specified
# to run with --vmtoolscfg=internal. This is used in CI tests for now where
# no other setup is available.
BUILTIN_VMTOOLSCFG = """
{
    "machine_lock_directory": null,
    "machine_templates": [
        {
            "name": "node0",
            "nics": [
                {
                    "mac": "52:54:00:e8:3c:db",
                    "netdev": {
                        "mode": "tap",
                        "ifname": "ipv6_ic_node0"
                    },
                    "addresses": [
                        {"family": 6, "address": "fd00:2:1:1:1::11", "mask_length": 64, "gateway": "fd00:2:1:1:1::1"}
                    ]
                }
            ]
        },
        {
            "name": "node1",
            "nics": [
                {
                    "mac": "52:54:00:33:b2:41",
                    "netdev": {
                        "mode": "tap",
                        "ifname": "ipv6_ic_node1"
                    },
                    "addresses": [
                        {"family": 6, "address": "fd00:2:1:1:1::12", "mask_length": 64, "gateway": "fd00:2:1:1:1::1"}
                    ]
                }
            ]
        }
    ]
}
"""


def _create_default_pool():
    """Create default machine pool."""
    if FLAGS.vmtoolscfg == "internal":
        return MachinePool(json.loads(BUILTIN_VMTOOLSCFG))
    else:
        with open(FLAGS.vmtoolscfg) as file:
            return MachinePool(json.loads(file.read()))


def pool():
    """Return pool of available machines (singleton)."""
    global _machine_pool
    if not _machine_pool:
        _machine_pool = _create_default_pool()
    return _machine_pool


_machine_pool = None
