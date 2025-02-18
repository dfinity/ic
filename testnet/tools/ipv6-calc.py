#!/usr/bin/env python3
#
# This script will calculate the guests' SLAAC IPv6 addresses for a given
# datacenter in production like deployments.
#
# The SLAAC IPv6 address is generated based on the following input:
# - IPv6 prefix (e.g. "2607:f1d0:10:1")
# - Serial (e.g. "59HBR53")
# - Deployment name (e.g. "mercury")
#
# Example for "mercury" guests running on hosts in NY1. The --serials input
# is a file containing a new line separated list of serial numbers.
#
# ./ipv6-calc.py --prefix "2607:f1d0:10:1" --deployment "mercury" --serials ./serials.txt
#
import argparse
import ipaddress
import logging
import re
import sys
from random import Random


# TODO: find a way to import directly from ansible
# https://github.com/ansible-collections/community.general/blob/main/plugins/filter/random_mac.py
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


def calc_mac_address(serial: str, deployment_name: str, node_index: str):
    return ansible_random_mac("52:00", f"{serial} {deployment_name} {node_index}")


def ipv6_address_calculate_slaac(ipv6_prefix: str, ipv6_subnet: str, mac_address: str):
    """Calculate the same IPv6 address as SLAAC does, based on the interface MAC address."""
    return mac2eui64(mac_address, f"{ipv6_prefix.strip()}::{ipv6_subnet.strip()}")


def ipv6_address_compressed(ipv6_address: str):
    return ipaddress.IPv6Address(ipv6_address).compressed


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--prefix",
        action="store",
        help='IPv6 data center prefix (e.g. "2607:f1d0:10:1")',
    )

    parser.add_argument(
        "--deployment-name",
        action="store",
        help='Deployment name (e.g. "mercury")',
    )

    parser.add_argument(
        "--serials",
        action="store",
        help="File containing new line separated list of serial numbers",
    )

    parser.add_argument(
        "--mac-address",
        action="store",
        help="Calculate IPv6 using SLAAC, based on this MAC address.",
    )

    parser.add_argument(
        "--addr-to-compressed",
        action="store",
        help="Return the compressed format of the IPv6 address.",
    )

    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose mode")

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    if args.addr_to_compressed:
        print(ipv6_address_compressed(args.addr_to_compressed))
    elif args.prefix:
        if args.mac_address:
            print(ipv6_address_calculate_slaac(args.prefix, "/64", args.mac_address))
        elif args.serials:
            for serial in open(args.serials).read().split():
                mac_address = ansible_random_mac("52:00", f"{serial} {args.deployment_name} 1")
                print(ipv6_address_calculate_slaac(args.prefix, "/64", mac_address))
        else:
            print("ERROR: either --mac-address or --serials argument is required in addition to --prefix.")
            parser.print_usage()
            sys.exit(1)
    else:
        parser.print_usage()
        sys.exit(1)


if __name__ == "__main__":
    main()
