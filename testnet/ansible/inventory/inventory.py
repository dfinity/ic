#!/usr/bin/env python3
#
# This script will generate the deployment inventory dynamically, based on the contents of:
# 1. /testnet/env/shared-config.yml
# 2. /testnet/env/<deployment>/hosts.ini
#
# To change the deployment config (inventory), you likely want to edit only
# /testnet/env/<deployment>/hosts.ini
#
# The contents of ../shared-config.yml are common (shared) for all deployments
# and part of that config may be overridden in /testnet/env/<deployment>/hosts.ini
#
# The 'hosts.ini' part of the deployment inventory can be overridden by setting an environment
# variable HOSTS_INI_FILENAME. E.g. `export HOSTS_INI_FILENAME=hosts_large_subnet.ini`
#
# The 'nodes' in the deployment inventory can be filtered (whitelisted) by setting an environment
# variable NODES_FILTER_INCLUDE. E.g. `export NODES_FILTER_INCLUDE='nns=root'`
# or also as a regular expression: `export NODES_FILTER_INCLUDE='nns=(parent|child)'`
#
import argparse
import io
import ipaddress
import json
import logging
import os
import pathlib
import re
import socket
import sys
import textwrap
from random import Random

import yaml
from ansible.inventory.manager import InventoryManager
from ansible.parsing.dataloader import DataLoader

# The assumption is that the script is located at <something>/testnet/ansible/inventory/inventory.py
# Then BASE_DIR becomes <something>/testnet
BASE_DIR = pathlib.PosixPath(__file__).absolute().parent.parent.parent
SERIAL_NUMBER_VARNAME = "system_serial_number"


class IcDeploymentInventory:
    """Dynamic inventory for the deployment."""

    def __init__(self, deployment_name):
        """Initialize the class object."""
        self._inventory = {}
        self.deployment_name = deployment_name

        self.common_config = None
        self.data_centers = None
        self.phy_serial_numbers_filename = None
        self.phy_serial_numbers = {}
        self.boundary_datacenters = None
        self._all_nodes_hosts = []
        self._nodes_filter_include = {}
        self._all_nns_hosts = set()
        self._all_boundary_hosts = set()
        self._all_aux_hosts = set()
        self._all_physical_hosts = {}
        self._phy_short_mapping = {}
        self._parent = {}  # link up from a child group/host to the parent group
        self.ic_hosts = {}
        self._load_baseline_config()
        self._load_hosts()

    def _load_baseline_config(self):
        """Load the config shared by all deployments."""
        cfg = BASE_DIR / "env/shared-config.yml"
        self.common_config = yaml.load(open(cfg), Loader=yaml.FullLoader)
        self.data_centers = self.common_config.get("data_centers")
        if not self.data_centers:
            logging.error("No data centers defined in %s", cfg)
        self._inventory = {"_meta": {"hostvars": {}}}
        for key, val in self.common_config.items():
            if not isinstance(val, dict):
                continue
            inv = {}
            if "hosts" in val:
                inv["hosts"] = val["hosts"]
            if "vars" in val:
                inv["vars"] = val["vars"]
            if "children" in val:
                inv["children"] = val["children"]
            if inv:
                self._inventory[key] = inv
        # Load a complete list of physical hosts and a unique string per host to generate a unique IPv6 address
        self.phy_serial_numbers_filename = BASE_DIR / "env/host-unique-string.yml"
        self.phy_serial_numbers = yaml.load(open(self.phy_serial_numbers_filename), Loader=yaml.FullLoader)

    def _load_hosts(self):
        # inventory hosts file can be comma separated
        hosts_ini_filename = os.environ.get("HOSTS_INI_FILENAME", "hosts.ini")
        inventory_filename = str(BASE_DIR / f"env/{self.deployment_name}/{hosts_ini_filename}")
        inventory_dir = os.path.dirname(inventory_filename)
        # Include only the nodes for which certain variables are set, e.g. `nns=parent`
        filter_include = os.environ.get("NODES_FILTER_INCLUDE", "")
        if filter_include:
            if "=" in filter_include:
                key, value = filter_include.split("=", 1)
                self._nodes_filter_include[key] = value.split(",")  # ',' is the AND operator, '|' is the OR operator
            else:
                logging.warning(
                    "Ignoring invalid filter_include (does not contain '='): %s",
                    filter_include,
                )
        # Loader takes care of finding and reading yaml, json and ini files
        loader = DataLoader()
        inventory = InventoryManager(loader=loader, sources=inventory_filename)
        # filter the inventory nodes based on the NODES_FILTER_INCLUDE environment variable
        inventory = self._filter_hosts(inventory)

        if "physical_hosts" not in inventory.groups:
            group = inventory.add_group("physical_hosts")
        for host in self.phy_serial_numbers.keys():
            inventory.add_host(host, group="physical_hosts")

        for group in inventory.groups.values():
            # get hosts from the common config and override if needed
            group_name = str(group.name)
            cur_inv_group = self._inventory.get(group_name, {})

            # Merge the "hosts" with the shared-config.yml contents
            hosts = set(cur_inv_group.get("hosts", []))
            hosts.update([h.name for h in group.hosts])
            if hosts:
                cur_inv_group["hosts"] = sorted(hosts)
                for host in cur_inv_group["hosts"]:
                    self._parent[host] = group_name

            # Merge "vars" with the shared-config.yml contents
            group_vars = cur_inv_group.get("vars", {})
            group_vars.update(group.vars)
            if group_vars:
                cur_inv_group["vars"] = group_vars

            # Merge the "children" with the shared-config.yml contents
            children = set(cur_inv_group.get("children", []))
            children.update([c.name for c in group.child_groups])
            if group_name == "all":
                children.add("physical_hosts")
            if children:
                cur_inv_group["children"] = sorted(children)
                for child in cur_inv_group["children"]:
                    self._parent[child] = group_name

            if cur_inv_group:
                self._inventory[group.name] = cur_inv_group

        # Populate the potentially missing variables for hosts
        for host in inventory.get_hosts():
            self._inventory["_meta"]["hostvars"][host.name] = host.vars
        for host in self.phy_serial_numbers.keys():
            self._inventory["_meta"]["hostvars"][host] = {
                "inventory_file": inventory_filename,
                "inventory_dir": inventory_dir,
                SERIAL_NUMBER_VARNAME: self.phy_serial_numbers[host],
            }

        # Update a list of all "nodes" in the deployment
        self._update_all_nodes_hosts(inventory)
        self._update_nns_nodes(inventory)
        self._update_boundary_nodes(inventory)
        self._update_aux_nodes(inventory)
        self._update_all_physical_nodes_hosts(inventory)

        # Check and if necessary fix/set missing node_index
        self._inventory_patch_node_index(inventory)
        self._inventory_patch_external_nodes(inventory)

        # Populate the potentially missing variables for hosts
        for host in inventory.get_hosts():
            if host.name in self._all_nodes_hosts:
                host = self._host_patch_ipv6(host)

        # Check and if necessary fix/set missing subnet_index
        self._inventory_patch_subnet_index(inventory)

    def _host_patch_ipv6(self, host):
        """Set the node IPv6 address, MAC address, guest hostname, and related."""
        ansible_host = host.vars.get("ansible_host")
        if "ipv6" not in host.vars:
            ipv6 = self._ipv6_resolve(host.name)
            ansible_host = host.vars.get("ansible_host")
            if not ipv6 and ansible_host:
                # ipv6 is not defined by ansible_host is.
                # Let's try to build "ipv6" from ansible_host
                ipv6 = self._ipv6_resolve(ansible_host)
            if not ipv6:
                # That didn't work, try to build IPv6 from the MAC address
                ic_host = host.vars.get("ic_host")
                if ic_host:
                    ipv6_prefix = self._get_ipv6_prefix_for_ic_host(ic_host)
                    ipv6_subnet = self._get_ipv6_subnet_for_ic_host(ic_host)
                    # For the mainnet deployments, the MAC address is calculated based on the number of guests on
                    # the physical host, so we need to enumerate and count the guests on each physical host.
                    phy_fqdn = self._phy_short_mapping[ic_host]
                    phy_vars = self._inventory["_meta"]["hostvars"][phy_fqdn]
                    # Assign a unique ID to each physical host. This will be a serial number if
                    # available, or fallback to the hostname.
                    phy_system_serial_number = phy_vars.get(SERIAL_NUMBER_VARNAME)
                    if not phy_system_serial_number:
                        logging.error(
                            "Physical host does not have a valid serial number: %s",
                            phy_fqdn,
                        )
                        env_hosts_path = self.phy_serial_numbers_filename.parent / self.deployment_name / "hosts.ini"
                        logging.error(
                            "ansible -i %s physical_hosts -m shell --become -a 'dmidecode -s system-serial-number'",
                            env_hosts_path,
                        )
                        logging.error(
                            "And update the serial numbers in %s",
                            self.phy_serial_numbers_filename.absolute(),
                        )
                        sys.exit(1)
                    # Each guest on a host (per deployment) gets a unique number 1..N
                    # used to generate a unique MAC address.
                    guest_number = phy_vars["ic_guests"].index(host.name) + 1
                    host.vars["guest_number"] = guest_number
                    guest_hostname = f"{host.name.rsplit('.', 1)[0]}-{guest_number}"
                    host.vars["guest_hostname"] = re.sub(r"\W+", "-", guest_hostname)
                    mac_address = mac_address_mainnet(phy_system_serial_number, self.deployment_name, guest_number)
                    host.vars["mac_address"] = mac_address
                    ipv6 = ipv6_address_calculate_slaac(ipv6_prefix, ipv6_subnet, mac_address)
            if ipv6:
                # Normalize the IPv6 address before using it elsewhere
                ipv6 = ipaddress.ip_address(ipv6)
                host.vars["ipv6"] = str(ipv6)
                if not ansible_host:
                    host.vars["ansible_host"] = str(ipv6)
        return host

    def _inventory_patch_external_nodes(self, inventory):
        """Set an 'external' tag for nodes not operated by DFINITY."""
        for hostname in self._all_nodes_hosts:
            host_vars = self._inventory["_meta"]["hostvars"][hostname]
            node_type = host_vars.get("node_type")
            if node_type:
                node_type_tags = set(node_type.split(","))
                ic_host = host_vars.get("ic_host")
                phy_fqdn = self._phy_short_mapping[ic_host]
                phy_vars = self._inventory["_meta"]["hostvars"][phy_fqdn]
                if "external" in node_type_tags:
                    phy_vars["external"] = True
                else:
                    phy_vars["external"] = False

    def _inventory_patch_node_index(self, inventory):
        """Set node_index for all hosts if any are missing."""
        # Check if any node_index appears twice, possibly due to a copy&paste bug
        found_node_idx = set()
        for hostname in self._all_nodes_hosts:
            # Check if any node doesn't have node_index set
            host_vars = self._inventory["_meta"]["hostvars"][hostname]
            if "node_index" not in host_vars:
                # check if the node name ends with ".<number>" ==> take the number as the node_index
                m = re.match(r".+\.(\d+)$", hostname)
                if m:
                    # Example: if a host is named "small-a.anything.100", set the node_index to "100"
                    host_vars["node_index"] = int(m.group(1))
                else:
                    raise ValueError("Missing node_index for host %s" % hostname)

            node_index = host_vars.get("node_index")

            if node_index:
                if node_index in found_node_idx:
                    logging.error("Duplicate node_index '%s' for host %s", node_index, host_vars)
                    raise ValueError("Duplicate node_index")
                else:
                    found_node_idx.add(node_index)

    def _inventory_patch_subnet_index(self, inventory):
        """Set subnet_index for all hosts if any are missing."""
        # For all subnet_X groups, copy all variables to the child hosts
        for group in inventory.groups.values():
            group_name = str(group.name).strip()
            m = re.match(r"subnet_(\d+)", group_name)
            if m:
                subnet_index = int(m.group(1))
                for host in group.hosts:
                    host_vars = self._inventory["_meta"]["hostvars"][str(host)]
                    if "subnet_index" not in host_vars:
                        host_vars["subnet_index"] = subnet_index
            # For groups "subnet_unassigned" or any starting with "onboarding_" ==> no need to set the subnet index
            elif group_name == "subnet_unassigned" or group_name.startswith("onboarding_"):
                for host in group.hosts:
                    host_vars = self._inventory["_meta"]["hostvars"][str(host)]
                    if "subnet_index" not in host_vars:
                        host_vars["subnet_index"] = "x"
            elif group_name == "nns":
                # For NNS group, set the subnet_index to 0 (hard-coded)
                for host in group.hosts:
                    host_vars = self._inventory["_meta"]["hostvars"][str(host)]
                    if "subnet_index" not in host_vars:
                        host_vars["subnet_index"] = 0
            elif group_name == "boundary":
                for host in group.hosts:
                    host_vars = self._inventory["_meta"]["hostvars"][str(host)]
                    host_vars["subnet_index"] = "boundary"
            elif group_name == "aux":
                for host in group.hosts:
                    host_vars = self._inventory["_meta"]["hostvars"][str(host)]
                    host_vars["subnet_index"] = "aux"

        for hostname in self._all_nodes_hosts:
            host_vars = self._inventory["_meta"]["hostvars"][hostname]
            # check if a host is named "<deployment_name>.<subnet_index>.<node_index>"
            m = re.match(r".+\.(\d+)\.\d+$", hostname)
            if m:
                # if a host is named e.g. "small-a.1.2", set the subnet_index to "1"
                subnet_index = int(m.group(1))
                if "subnet_index" in host_vars:
                    if subnet_index != host_vars["subnet_index"]:
                        raise ValueError("Mismatch subnet_index for host %s and its group name" % hostname)
                else:
                    host_vars["subnet_index"] = int(m.group(1))
            else:
                if "subnet_index" not in host_vars:
                    raise ValueError("Missing subnet_index for host %s" % hostname)

    def _filter_hosts(self, inventory):
        if not self._nodes_filter_include:
            return inventory
        root_group = inventory.groups.get("nodes")

        sub_groups_to_visit = set(root_group.child_groups)
        while sub_groups_to_visit:
            child = str(sub_groups_to_visit.pop())
            sub_group = inventory.groups.get(child)
            # For the other groups apply the filter
            subgroup_hosts = list(sub_group.hosts or [])
            for host in subgroup_hosts:
                for key, pattern_list in self._nodes_filter_include.items():
                    # Prepare a list of the required tags for this host
                    missing_tags = set(pattern_list)
                    for pattern in pattern_list:
                        # Ensure that a complete tag is matched, not only the beginning.
                        pattern_word = pattern
                        if not pattern_word.endswith("$"):
                            pattern_word += "$"
                        for host_tag in host.vars.get(key, "").split(","):
                            if re.match(pattern_word, host_tag):
                                missing_tags.remove(pattern)
                                break
                        else:
                            break
                    if missing_tags:
                        sub_group.remove_host(host)
                        logging.debug(
                            "Host removed %s since %s=%s does not match the required filter '%s'",
                            host.name,
                            key,
                            host.vars.get(key),
                            pattern_list,
                        )
                    else:
                        logging.debug(
                            "Host %s (%s) satisfies matches the required filter '%s'",
                            host.name,
                            host.vars.get(key),
                            pattern_list,
                        )

            sub_groups_to_visit.update(sub_group.child_groups or [])
        return inventory

    def _get_all_group_hosts(self, inventory, root_group_name):
        root_group = inventory.groups.get(root_group_name)
        if not root_group:
            if root_group_name == "boundary":
                logging.debug("Optional '%s' group not found", root_group_name)
                return []
            elif root_group_name == "physical_hosts":
                logging.debug("Group '%s' not found", root_group_name)
                return sorted(self.phy_serial_numbers.keys())
            else:
                logging.error("Required '%s' group not found", root_group_name)
                return []

        children = set(root_group.child_groups)
        nodes = set(root_group.hosts)
        while children:
            child = str(children.pop())
            sub_group = inventory.groups.get(child)
            nodes.update(sub_group.hosts or [])
            children.update(sub_group.child_groups or [])
        return sorted([str(_) for _ in nodes])

    def _update_all_nodes_hosts(self, inventory):
        """Return a sorted list of all hosts under the "nodes" group."""
        self._all_nodes_hosts = self._get_all_group_hosts(inventory, "nodes")

    def _update_nns_nodes(self, inventory):
        """Return a sorted list of all hosts under the "nns" group."""
        self._all_nns_hosts = set(self._get_all_group_hosts(inventory, "nns"))

    def _update_boundary_nodes(self, inventory):
        """Return a sorted list of all hosts under the boundary group."""
        self._all_boundary_hosts = set(self._get_all_group_hosts(inventory, "boundary"))

    def _update_aux_nodes(self, inventory):
        """Return a sorted list of all hosts under the aux group."""
        self._all_aux_hosts = set(self._get_all_group_hosts(inventory, "aux"))

    def _update_all_physical_nodes_hosts(self, inventory):
        # make a complete list of physical hosts and the nodes assigned to them
        for phy_fqdn in self._get_all_group_hosts(inventory, "physical_hosts"):
            self._all_physical_hosts[phy_fqdn] = []

        # make a complete list of all physical nodes, with their short hostname
        self._phy_short_mapping = {}
        for phy in self._all_physical_hosts.keys():
            phy_short = phy.split(".")[0]
            self._phy_short_mapping[phy_short] = phy

        # For every physical host make a list of all nodes (VM guests) running on it
        for node in self._all_nodes_hosts:
            node_vars = self._inventory["_meta"]["hostvars"][node]
            phy_short = node_vars.get("ic_host")
            phy_fqdn = self._phy_short_mapping[phy_short]
            if phy_short not in self._phy_short_mapping:
                logging.error(
                    "Host %s not found in the list of physical hosts, check the contents of %s"
                    % (phy_short, self.phy_serial_numbers_filename.absolute())
                )
                sys.exit(1)
            self._all_physical_hosts[phy_fqdn].append(node)

        phy_hosts = set(self._inventory["physical_hosts"]["hosts"])
        for phy_fqdn, nodes in self._all_physical_hosts.items():
            phy_serial_number = self.phy_serial_numbers.get(phy_fqdn)
            phy_vars = self._inventory["_meta"]["hostvars"][phy_fqdn]
            if phy_serial_number:
                phy_vars[SERIAL_NUMBER_VARNAME] = phy_serial_number
            if nodes:
                phy_vars["ic_guests"] = nodes
            elif os.environ.get("INCLUDE_ALL_PHYSICAL_HOSTS"):
                logging.debug("Physical host %s does not have any guests", phy_fqdn)
            else:
                # there are no nodes (VM guests) running on this physical host
                phy_hosts.remove(phy_fqdn)
                del self._inventory["_meta"]["hostvars"][phy_fqdn]
        self._inventory["physical_hosts"]["hosts"] = sorted(phy_hosts)
        self._inventory["all"]["vars"]["ic_deployment_name"] = self.deployment_name

    def _ipv6_resolve(self, hostname):
        if not (hostname.endswith(".dfinity.network") or hostname.endswith(".dfinity.systems")):
            return
        try:
            return socket.getaddrinfo(hostname, None, socket.AF_INET6)[0][4][0]
        except (OSError, KeyError):
            pass

    def _get_ipv6_prefix_for_ic_host(self, ic_host):
        dc = self._get_dc_config_for_ic_host(ic_host)
        return dc.get("vars", {}).get("ipv6_prefix")

    def _get_ipv6_subnet_for_ic_host(self, ic_host):
        dc = self._get_dc_config_for_ic_host(ic_host)
        return dc.get("vars", {}).get("ipv6_subnet")

    def _get_dc_config_for_ic_host(self, ic_host):
        hostname_short = ic_host.split(".")[0]
        dc = hostname_short.split("-")[0]
        return self.data_centers.get(dc, {})

    @property
    def inventory(self):
        """Return the complete (read-only) inventory."""
        # https://docs.ansible.com/ansible/latest/dev_guide/developing_inventory.html#inventory-script-conventions
        return self._inventory

    def hostvars(self, hostname=None):
        """Print either an empty JSON hash/dictionary, or a hash/dictionary of variables."""
        if hostname:
            inventory_vars = self._inventory["_meta"]["hostvars"]
            if hostname in inventory_vars:
                return inventory_vars[hostname]
        else:
            return self._inventory["all"].get("vars", {})
        return {}

    def _search_in_host_vars_and_in_parents(self, hostname, var_name):
        """Search for a variable defined either in the host vars, or parent's vars, its parents vars, etc."""
        # NOTE: unused at the moment, but may be useful
        if hostname not in self._inventory["_meta"]["hostvars"]:
            return
        host_vars = self._inventory["_meta"]["hostvars"][hostname]
        if var_name in host_vars:
            return host_vars[var_name]
        parent = self._parent[hostname]
        if not parent:
            raise ValueError("Host must have at least one parent")
        for _ in range(100):
            # Search up to 100 parents
            parent_vars = self._inventory[parent].get("vars", {})
            if var_name in parent_vars:
                return parent_vars[var_name]
            parent = self._parent.get(parent)
            if not parent:
                # We reached the top-level parent of the host
                return
        raise ValueError("Reached the parent-search limit")

    @property
    def media_config(self):
        """Config data for preparing the USB media for network deployment."""
        result = {
            "deployment": self.deployment_name,
            "name_servers": ["2606:4700:4700::1111", "2606:4700:4700::1001"],
            "name_servers_fallback": ["2001:4860:4860::8888", "2001:4860:4860::8844"],
            "datacenters": [],
        }

        nodes_vars = self._inventory["nodes"].get("vars", {})
        journalbeat_hosts = nodes_vars.get("journalbeat_hosts", [])
        result["journalbeat_hosts"] = journalbeat_hosts
        journalbeat_index = nodes_vars.get("journalbeat_index", "")
        result["journalbeat_index"] = journalbeat_index
        journalbeat_tags = nodes_vars.get("journalbeat_tags", [])
        result["journalbeat_tags"] = journalbeat_tags

        deployment_dcs = set()
        ic_nodes_by_dc = {}
        for node in self._all_nodes_hosts:
            node_vars = self.hostvars(node)
            ic_host = node_vars.get("ic_host")
            if not ic_host:
                logging.error("No host (ic_host) defined for %s", node)
                continue
            # Create a list of all DCs used by this deployment
            hostname_short = ic_host.split(".")[0]
            dc_name = hostname_short.split("-")[0]
            deployment_dcs.add(dc_name)

            # Create a list of nodes sorted by DC
            if dc_name not in ic_nodes_by_dc:
                ic_nodes_by_dc[dc_name] = []
            ic_nodes_by_dc[dc_name].append(node)

        for dc_name in sorted(deployment_dcs):
            dc_vars = self.data_centers[dc_name]["vars"]
            dc_config = {
                "name": dc_name,
                "ipv6_prefix": dc_vars["ipv6_prefix"],
                "ipv6_subnet": dc_vars["ipv6_subnet"],
                "nodes": [],
                "boundary_nodes": [],
                "aux_nodes": [],
            }

            for node_name in ic_nodes_by_dc[dc_name]:
                node_config = {}

                node_vars = self.hostvars(node_name)
                node_config["hostname"] = node_vars["guest_hostname"]
                node_config["node_idx"] = node_vars["node_index"]
                node_config["subnet_idx"] = node_vars["subnet_index"]

                if node_name in self._all_nns_hosts:
                    node_config["subnet_type"] = "root_subnet"
                elif node_name in self._all_boundary_hosts:
                    node_config["subnet_type"] = "boundary_subnet"
                elif node_name in self._all_aux_hosts:
                    node_config["subnet_type"] = "aux_subnet"
                else:
                    node_config["subnet_type"] = "app_subnet"

                node_config["ipv6_address"] = node_vars["ipv6"]
                use_hsm = node_vars.get("use_hsm")
                if use_hsm:
                    node_config["use_hsm"] = use_hsm

                if node_name in self._all_boundary_hosts:
                    dc_config["boundary_nodes"].append(node_config)
                elif node_name in self._all_aux_hosts:
                    dc_config["aux_nodes"].append(node_config)
                else:
                    dc_config["nodes"].append(node_config)

            result["datacenters"].append(dc_config)

        return result

    @property
    def ssh_config(self):
        """SSH configuration for the testnet hosts."""
        with io.StringIO() as f:
            for node in self._all_nodes_hosts:
                node_vars = self.hostvars(node)
                ipv6 = node_vars["ipv6"]
                f.write("Host %s.testnet\n" % node)
                f.write("  Hostname %s\n\n" % ipv6)

            return f.getvalue()

    @property
    def ipv6_addresses(self):
        """Return a string with the IPv6 addresses for all deployment nodes."""
        with io.StringIO() as f:
            for node in self._all_nodes_hosts:
                node_vars = self.hostvars(node)
                f.write("%s\n" % node_vars["ipv6"])

            return f.getvalue()

    @property
    def nodes(self):
        """Return a YAML string with all nodes and their IPv6 addresses."""
        with io.StringIO() as f:
            nodes = {}
            for node in self._all_nodes_hosts:
                node_vars = self.hostvars(node)
                nodes[node] = node_vars["ipv6"]

            yaml.dump(nodes, f)
            return f.getvalue()

    @property
    def nns_nodes(self):
        """Return a YAML string with all NNS nodes and their IPv6 addresses."""
        with io.StringIO() as f:
            nodes = {}
            for node in self._all_nns_hosts:
                node_vars = self.hostvars(node)
                nodes[node] = node_vars["ipv6"]

            yaml.dump(nodes, f)
            return f.getvalue()


# This function code is copied directly from ansible
# https://github.com/ansible-collections/community.general/blob/main/plugins/filter/random_mac.py
# note that we provide a seed value when we call this from mac_address_testnets and mac_address_mainnet
# so we get determisitic results.
def ansible_random_mac(value: str, seed: str):
    """Take string prefix, and return it completed with random bytes to get a complete 6 bytes MAC address."""
    if not isinstance(value, str):
        raise ValueError("Invalid value type (%s) for random_mac (%s)" % (type(value), value))

    value = value.lower()
    mac_items = value.split(":")

    if len(mac_items) > 5:
        raise ValueError("Invalid value (%s) for random_mac: 5 colon(:) separated" " items max" % value)

    err = ""
    for mac in mac_items:
        if not mac:
            err += ",empty item"
            continue
        if not re.match("[a-f0-9]{2}", mac):
            err += ",%s not hexa byte" % mac
    err = err.strip(",")

    if err:
        raise ValueError("Invalid value (%s) for random_mac: %s" % (value, err))

    r = Random(seed)
    # Generate random int between x1000000000 and xFFFFFFFFFF
    v = r.randint(68719476736, 1099511627775)
    # Select first n chars to complement input prefix
    remain = 2 * (6 - len(mac_items))
    rnd = ("%x" % v)[:remain]
    return value + re.sub(r"(..)", r":\1", rnd)


def mac2eui64(mac, prefix=None):
    """Convert a MAC address to a EUI64 address or, with prefix provided, a full IPv6 address."""
    # http://tools.ietf.org/html/rfc4291#section-2.5.1
    eui64 = re.sub(r"[.:-]", "", mac).lower()
    eui64 = eui64[0:6] + "fffe" + eui64[6:]
    eui64 = hex(int(eui64[0:2], 16) ^ 2)[2:].zfill(2) + eui64[2:]

    if prefix is None:
        return ":".join(re.findall(r".{4}", eui64))
    else:
        try:
            net = ipaddress.ip_network(prefix, strict=False)
            euil = int("0x{0}".format(eui64), 16)
            return str(net[euil])
        except ValueError:  # pylint: disable=bare-except
            return


def mac_address_testnets(deployment_name: str, node_index: str):
    """Calculate the MAC address for a host in a testnet."""
    return ansible_random_mac("52:00", f"{deployment_name} {node_index}")


def mac_address_mainnet(phy_system_serial_number: str, deployment_name: str, guest_number: int):
    """Calculate the MAC address for a host in the mainnet."""
    mac_seed = f"{phy_system_serial_number} {deployment_name} {guest_number}"
    return ansible_random_mac("52:00", mac_seed)


def ipv6_address_calculate_slaac(ipv6_prefix: str, ipv6_subnet: str, mac_address: str):
    """Calculate the same IPv6 address as SLAAC does, based on the interface MAC address."""
    return mac2eui64(mac_address, f"{ipv6_prefix.strip()}::{ipv6_subnet.strip()}")


def main():
    """Parse and process CLI arguments."""
    parser = argparse.ArgumentParser()

    parser.add_argument("--list", action="store_true")
    parser.add_argument("--host", action="store", nargs="?")

    parser.add_argument(
        "--deployment",
        action="store",
        help="Deployment name.",
    )

    parser.add_argument(
        "--media-json",
        action="store_true",
        help="Dump the deployment JSON config for the USB media generation.",
    )

    parser.add_argument(
        "--original-inventory-path",
        action="store",
        help="Original path by which the inventory was invoked. Allows the user to avoid having to specify"
        " the DEPLOYMENT environment variable.",
    )

    parser.add_argument(
        "--ssh-config",
        action="store_true",
        help="Configure local ssh client to access testnet hosts.",
    )

    parser.add_argument(
        "--ipv6",
        action="store_true",
        help="List of IPv6 addresses for all nodes.",
    )

    parser.add_argument(
        "--nodes",
        action="store_true",
        help="List of nodes with their IPv6 addresses.",
    )

    parser.add_argument(
        "--nns-nodes",
        action="store_true",
        help="List of NNS nodes with their IPv6 addresses.",
    )

    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose mode")

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    deployment_name = args.deployment or os.environ.get("DEPLOYMENT")
    if not deployment_name:
        if args.original_inventory_path:
            exe_path = args.original_inventory_path
        else:
            exe_path = pathlib.PosixPath(sys.argv[0]).absolute()
        deployment_name = re.search(r"/env/(.+?)/hosts", str(exe_path))
        if deployment_name:
            deployment_name = deployment_name.group(1)
            logging.debug(
                "Setting the deployment_name based on the subdirectory: %s",
                deployment_name,
            )
    if not deployment_name:
        logging.error("--deployment is not set. Cannot continue.")
        parser.print_help()
        sys.exit(1)

    deployment_inventory = IcDeploymentInventory(deployment_name=deployment_name)

    inventory = {}
    if args.media_json:
        inventory = deployment_inventory.media_config
    elif args.ipv6:
        sys.stdout.write(deployment_inventory.ipv6_addresses)
        sys.exit(0)
    elif args.nodes:
        sys.stdout.write(deployment_inventory.nodes)
        sys.exit(0)
    elif args.nns_nodes:
        sys.stdout.write(deployment_inventory.nns_nodes)
        sys.exit(0)
    elif args.ssh_config:
        cfg_path = pathlib.PosixPath().home() / ".ssh"
        should_patch = True
        with (cfg_path / "config").open("a+") as f:
            f.seek(0)
            cfg = f.read()
            for line in cfg.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Decide what to do based on the first non-empty line.
                if line == "Include ~/.ssh/config.d/*":
                    should_patch = False
                break
        if should_patch:
            print("Injecting the 'Include' directive in ~/.ssh/config")
            f.close()
            with (cfg_path / "config").open("w+") as f:
                f.write(
                    textwrap.dedent(
                        """
                        Include ~/.ssh/config.d/*

                        Host *.testnet
                            StrictHostKeyChecking no
                            UserKnownHostsFile=/dev/null
                            LogLevel ERROR
                            User admin

                        """
                    )
                )
                f.write(cfg)
            # This more is required by the ssh client
            (cfg_path / "config").chmod(mode=0o600)
        cfg_path.mkdir(mode=0o700, exist_ok=True)
        cfg_path = cfg_path / "config.d"
        cfg_path.mkdir(mode=0o700, exist_ok=True)
        cfg_path = (cfg_path / deployment_inventory.deployment_name).with_suffix(".testnet")
        cfg_path.touch(mode=0o600)
        with cfg_path.open(mode="w") as f:
            f.write(deployment_inventory.ssh_config)
        print("SSH config written to", cfg_path)

        autocomplete = textwrap.dedent(
            """
            _ssh()
            {
                local cur prev opts
                COMPREPLY=()
                cur="${COMP_WORDS[COMP_CWORD]}"
                prev="${COMP_WORDS[COMP_CWORD-1]}"
                opts=$(grep '^Host' ~/.ssh/config ~/.ssh/config.d/* 2>/dev/null | grep -v '[?*]' | cut -d ' ' -f 2-)

                COMPREPLY=( $(compgen -W "$opts" -- ${cur}) )
                return 0
            }
            complete -F _ssh ssh
            """
        )
        if "bash" in os.environ.get("SHELL"):
            cfg_path = pathlib.PosixPath().home() / ".config"
            cfg_path.mkdir(exist_ok=True)
            cfg_path = cfg_path / "bash-autocomplete-ic-testnets"
            with cfg_path.open("w+") as f:
                f.write(autocomplete)
            with (pathlib.PosixPath().home() / ".bashrc").open("r+") as f:
                autocomplete_line = f". {cfg_path}"
                should_patch = True
                for line in f.readlines():
                    if line.strip() == autocomplete_line:
                        print("Autocomplete support already enabled")
                        should_patch = False
                        break
                if should_patch:
                    f.write("\n%s\n\n" % autocomplete_line)
                    print("Autocomplete support added. Please logout and login to take effect.")
                    print("or run to take effect in your current shell:")
                    print(autocomplete_line)
        else:
            print("Only bash is supported for autocomplete at the moment.")
            print("Please reach out to us on #eng-idx to add autocomplete support for your shell.")
        print("\nAll done.")
        print(
            "You should now be able to ssh into `{0}` testnet nodes with e.g. `ssh {0}.0.0.testnet`".format(
                deployment_inventory.deployment_name
            )
        )

        sys.exit(0)
    else:
        if args.list:
            # Invoked with `--list`.
            inventory = deployment_inventory.inventory
        elif args.host:
            # Invoked with `--host [hostname]`.
            inventory = deployment_inventory.hostvars(args.host)
        else:
            # Return hostvars for "all".
            inventory = deployment_inventory.hostvars()

    print(json.dumps(inventory, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
