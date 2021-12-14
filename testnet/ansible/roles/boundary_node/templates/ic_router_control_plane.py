#!/usr/bin/env python3
import argparse
import base64
import datetime
import glob
import json
import os
import re
import sys
from shutil import copyfile

BACKUPS_TO_KEEP = 20


def patch_subnet_export(out):
    """
    Fix router table export names.

    KLUDGE: the ic_router_table.js has export names derived
    from network names. This export naming scheme runs into issues as
    network names do not follow JS export naming conventions.

    Following function named exports of the from
    export main-net, export dash-board etc
    to
    export subnet;

    This temporary function can be nuked once all boundary nodes are upgraded.

    Keyword Arguments:
    -----------------
    out -- a list of strings representation of JS code that need to patched

    """
    out[0] = "let subnet_table = {\n"
    out[len(out) - 1] = "export default subnet_table;\n"


def replace_demarcated_section(lines, out, section, prefix):
    """
    Replace section demarcated by magic start and end markers.

    Keyword Arguments:
    -----------------
    lines -- List of strings that may contain start and end markers.
    section: Section to be replaced with.
    out -- Result of the replacement.
    prefix --custom prefix to be placed before the start end marker.

    Example Transformation:
    lines = ["DontReplace",
    "MAINTAINED BY ic_router_control_plane.py DO NOT EDIT BY HAND"
    "{OldSection}"
    "END MAINTAINED BY ic_router_control_plane.py DO NOT EDIT BY HAND"
    "DontReplace"]

    is converted to
     out = ["DontReplace",
    "MAINTAINED BY ic_router_control_plane.py DO NOT EDIT BY HAND"
    "{NewSection}"
    "END MAINTAINED BY ic_router_control_plane.py DO NOT EDIT BY HAND"
    "DontReplace"]


    NOTE: start and end are MAGIC strings for now. Changing them will
    break boundary node upgrades.

    """
    start = prefix + "MAINTAINED BY ic_router_control_plane.py DO NOT EDIT BY HAND"
    end = prefix + "END MAINTAINED BY ic_router_control_plane.py DO NOT EDIT BY HAND"
    section.insert(0, start + "\n")
    section.append(end + "\n")
    skip = False
    for line in lines:
        if line.startswith(start):
            skip = True
            out.extend(section)
        elif line.startswith(end):
            skip = False
            continue
        if not skip:
            out.append(line)


def canister_id_to_hex(id):
    id = id.replace("-", "") + "="
    return base64.b32decode(id, casefold=True)[4:].hex()


def str2bool(v):
    if isinstance(v, bool):
        return v
    if v.lower() in ("yes", "true", "t", "y", "1"):
        return True
    elif v.lower() in ("no", "false", "f", "n", "0"):
        return False
    else:
        raise argparse.ArgumentTypeError("Boolean value expected.")


argparser = argparse.ArgumentParser(description="Configure NGINX for IC routing.")
argparser.add_argument(
    "routes_dir",
    metavar="ROUTE_DIR",
    type=str,
    nargs=1,
    help="a directory containing *.routes JSON files",
)
argparser.add_argument("nginx_file", metavar="NGINX_FILE", type=str, nargs=1, help="pathname of nginx.conf")
argparser.add_argument(
    "njs_file",
    metavar="NJS_FILE",
    type=str,
    nargs=1,
    help="pathname of ic_router.js",
)
argparser.add_argument(
    "trusted_certs_file",
    metavar="CERTS_FILE",
    type=str,
    nargs=1,
    help="pathname of trusted_certs.pem",
)
argparser.add_argument(
    "--allow_node_socket_addrs",
    metavar="NODE_ADDR,NODE_ADDR,...",
    type=str,
    nargs=1,
    default=None,
    help="a list of node socket addrs (e.g. [123:23]:8080) to allow, all others are not allowed",
)
argparser.add_argument(
    "--deny_node_socket_addrs",
    metavar="NODE_ADDR,NODE_ADDR,...",
    type=str,
    nargs=1,
    default=None,
    help="a list of socket addrs (e.g. [123:23]:8080) to deny, all others are allowed",
)
argparser.add_argument(
    "--generate_upstream_declarations",
    metavar="true/false",
    type=str2bool,
    nargs=1,
    default=[True],
    help="whether or not upstream declarations should be generated (false for rosetta front end)",
)

args = argparser.parse_args(sys.argv[1:])
routes_dir = args.routes_dir[0]
nginx_conf_file = args.nginx_file[0]
ic_router_file = args.njs_file[0]
trusted_certs_file = args.trusted_certs_file[0]

allow_node_socket_addrs = args.allow_node_socket_addrs
if allow_node_socket_addrs:
    allow_node_socket_addrs = [x for y in allow_node_socket_addrs for x in y.split(",")]
deny_node_socket_addrs = args.deny_node_socket_addrs
if deny_node_socket_addrs:
    deny_node_socket_addrs = [x for y in deny_node_socket_addrs for x in y.split(",")]
generate_upstream_declarations = args.generate_upstream_declarations[0]


def permit_node_addr(node_socket_addr):
    if allow_node_socket_addrs is not None:
        return node_socket_addr in allow_node_socket_addrs
    else:
        if deny_node_socket_addrs is not None:
            return node_socket_addr not in deny_node_socket_addrs
        else:
            return True


# find highest registery version *.routes file
routes_file = None
routes_files = sorted(os.listdir(routes_dir), reverse=True)
for f in routes_files:
    if re.match("^\\d+.routes$", f):
        routes_file = f
        break
if not routes_file:
    print("no *.routes file found")
    sys.exit(1)

print("routes_file", routes_file)
with open(os.path.join(sys.argv[1], routes_file)) as f:
    data = json.load(f)


class obj(object):
    """Class to Convert JSON to objects."""

    def __init__(self, d):
        """Convert JSON to objects."""
        for a, b in d.items():
            if isinstance(b, (list, tuple)):
                setattr(self, a, [obj(x) if isinstance(x, dict) else x for x in b])
            else:
                setattr(self, a, obj(b) if isinstance(b, dict) else b)


data = obj(data)

nginx_out = []
ic_router_out = []
trusted_certs_out = []

nns_node_ids = set([n.node_id for s in data.subnets if s.subnet_id == data.nns_subnet_id for n in s.nodes])

nodes = [n for s in data.subnets for n in s.nodes]
upstreams_section = []
for node in nodes:

    def print_upstream(suffix, max_conns):
        upstreams_section.append("upstream %s%s {\n" % (node.node_id, suffix))
        sockaddrary = node.socket_addr.split(":")
        port = sockaddrary.pop()
        if node.socket_addr[0] != "[" and len(sockaddrary) > 1:
            # add brackets for IPv6
            socket_addr = "[%s]:%s" % (":".join(sockaddrary), port)
        else:
            socket_addr = node.socket_addr
        upstreams_section.append("  server %s %s;\n" % (socket_addr, max_conns))
        upstreams_section.append("}\n")

    if generate_upstream_declarations:
        # The default is rate limited in nginx conf, not by max_conns
        print_upstream("", "")
        # Query calls are rate limited by max_conns
        max_conns = "max_conns=%d" % (50 if (node.node_id in nns_node_ids) else 100)
        print_upstream("-query", max_conns)
    trusted_certs_out.append(node.tls_certificate_pem)

nginx_lines = []
with open(nginx_conf_file, "r") as default_file:
    nginx_lines = default_file.readlines()
replace_demarcated_section(nginx_lines, nginx_out, upstreams_section, "# ")

ic_router_section = []

canister_range_starts = []
canister_range_ends = []
canister_subnets = []
canister_subnet_ids = []
for canister_route in sorted(data.canister_routes, key=lambda r: canister_id_to_hex(r.start_canister_id)):
    canister_range_starts.append("  '%s',\n" % canister_id_to_hex(canister_route.start_canister_id))
    canister_range_ends.append("  '%s',\n" % canister_id_to_hex(canister_route.end_canister_id))
    canister_subnets.append("  '%s',\n" % canister_route.subnet_id)
    canister_subnet_ids.append(canister_route.subnet_id)
ic_router_section.append("canister_range_starts: [\n")
ic_router_section.extend(canister_range_starts)
ic_router_section.append("],\n")
ic_router_section.append("canister_range_ends: [\n")
ic_router_section.extend(canister_range_ends)
ic_router_section.append("],\n")
ic_router_section.append("canister_subnets: [\n")
ic_router_section.extend(canister_subnets)
ic_router_section.append("],\n")
nns_subnet_index = canister_subnet_ids.index(data.nns_subnet_id)
ic_router_section.append("nns_subnet_index: %s,\n" % nns_subnet_index)

subnet_node_ids = []
subnet_nodes = []
for subnet in sorted(data.subnets, key=lambda s: canister_subnet_ids.index(s.subnet_id)):
    subnet_node_ids.append("  [\n")
    subnet_nodes.append("  [\n")
    for node in subnet.nodes:
        if not permit_node_addr(node.socket_addr):
            continue
        subnet_node_ids.append("    '%s',\n" % node.node_id)
        subnet_nodes.append("    '%s',\n" % node.socket_addr)
    subnet_node_ids.append("  ],\n")
    subnet_nodes.append("  ],\n")
ic_router_section.append("subnet_node_ids: [\n")
ic_router_section.extend(subnet_node_ids)
ic_router_section.append("],\n")
ic_router_section.append("subnet_nodes: [\n")
ic_router_section.extend(subnet_nodes)
ic_router_section.append("],\n")

ic_router_lines = []
with open(ic_router_file, "r") as default_file:
    ic_router_lines = default_file.readlines()
replace_demarcated_section(ic_router_lines, ic_router_out, ic_router_section, "// ")
patch_subnet_export(ic_router_out)

backup_time = datetime.datetime.now().strftime("%Y_%m_%d-%H:%M:%S")

ic_router_file_backup = ic_router_file + "." + backup_time
print("backing up %s to %s" % (ic_router_file, ic_router_file_backup))
copyfile(ic_router_file, ic_router_file_backup)
with open(ic_router_file, "w") as f:
    f.writelines(ic_router_out)

# do not create an empty file as this will cause NGINX to fail
if trusted_certs_out:
    trusted_certs_file_backup = trusted_certs_file + "." + backup_time
    print("backing up %s to %s" % (trusted_certs_file, trusted_certs_file_backup))
    if os.path.exists(trusted_certs_file):
        copyfile(trusted_certs_file, trusted_certs_file_backup)
    with open(trusted_certs_file, "w") as f:
        f.writelines(trusted_certs_out)

nginx_conf_file_backup = nginx_conf_file + "." + backup_time
print("backing up %s to %s" % (nginx_conf_file, nginx_conf_file_backup))
copyfile(nginx_conf_file, nginx_conf_file_backup)
with open(nginx_conf_file, "w") as f:
    f.writelines(nginx_out)

# cleanup backups


def cleanup_backups(fn):
    files = sorted(glob.glob(fn + ".*"))
    # largest (newest) first
    files.reverse()
    if len(files) > BACKUPS_TO_KEEP:
        files = files[BACKUPS_TO_KEEP:]
        for f in files:
            os.remove(f)


cleanup_backups(ic_router_file)
cleanup_backups(nginx_conf_file)
if trusted_certs_out:
    cleanup_backups(trusted_certs_file)
