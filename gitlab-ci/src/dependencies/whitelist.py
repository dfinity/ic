from __future__ import annotations

import argparse
import datetime
import json
import logging
import pathlib
import sys
import typing

import inventory


class WhitelistManager(object):
    def __init__(self) -> None:
        self.external = inventory.Inventory(inventory.Cargo())
        self.expiry = 30

    def get_inventory_file(self) -> pathlib.Path:
        return self.external.package_manager.get_inventory_file()

    def get_whitelist_file(self) -> pathlib.Path:
        return self.external.package_manager.get_whitelist_file()

    def check_inventory_sanity(self) -> bool:
        try:
            with open(self.get_inventory_file(), "r") as inv_file:
                _ = json.load(inv_file)
            return True
        except BaseException as err:
            logging.error("External inventory can't be parsed " + err)
            return False

    def check_whitelist_sanity(self) -> bool:
        try:
            with open(self.get_whitelist_file(), "r") as whitelist_file:
                whitelist_data = json.load(whitelist_file)
            # Check if each entry has all 5 fields
            whitelist_keys = ["name", "version", "date_added", "date_updated", "expiry_days"]
            for whitelisted_crate in whitelist_data:
                if list(whitelisted_crate.keys()) != whitelist_keys:
                    return False

            # each entry must have a value
            for whitelisted_crate in whitelist_data:
                if not all(whitelisted_crate.values()):
                    return False

            # Each name:version should have only one whitelist entry
            whitelist_crates = [crate["name"] + ":" + crate["version"] for crate in whitelist_data]
            if len(whitelist_crates) != len(set(whitelist_crates)):
                return False

            # always date_added < date_expiry
            for whitelisted_crate in whitelist_data:
                if datetime.datetime.strptime(whitelisted_crate["date_added"], "%d/%m/%Y") > datetime.datetime.strptime(
                    whitelisted_crate["date_updated"], "%d/%m/%Y"
                ):
                    return False

            return True

        except BaseException as err:
            logging.error("External inventory can't be parsed " + err)
            return False

    def create_inventory(self):
        # this method takes around 50mins to run on a macbook i7.
        external_inventory = self.external.package_manager.create_external_inventory()

        with open(self.get_inventory_file(), "w+") as inv_file:
            json.dump(external_inventory, inv_file, indent=4, default=str)

    # update_inventory must ensure inventory is always consistent.
    # Current blockers -> What happens, if we run this after cargo audit or cargo update
    # *.toml files aren't modified but Cargo.lock will be modified.
    # This creates inconsistencies which are hard to detect.

    def update_inventory(self):
        if self.check_inventory_sanity():
            package_diffs = self.external.package_manager.get_package_diff()
            with open(self.get_inventory_file(), "r") as inv_file:
                dependency_inventory = json.load(inv_file)

            if package_diffs:
                for internal_crate, diff in package_diffs.items():
                    for dep in diff.added_direct_deps:
                        dep_index = next(
                            (
                                index
                                for index, crate in enumerate(dependency_inventory)
                                if dep.name + ":" + dep.version == crate["name"] + ":" + crate["version"]
                            ),
                            -1,
                        )
                        if dep_index == -1:
                            dependency_inventory.append(
                                {
                                    "name": dep.name,
                                    "version": dep.version,
                                    "internal_crates": [internal_crate],
                                    "count": 1,
                                }
                            )
                        else:
                            dependency_inventory[dep_index]["internal_crates"].append(internal_crate)
                            dependency_inventory[dep_index]["count"] = len(
                                dependency_inventory[dep_index]["internal_crates"]
                            )

                    for dep in diff.removed_direct_deps:
                        dep_index = next(
                            (
                                index
                                for index, crate in enumerate(dependency_inventory)
                                if dep.name + ":" + dep.version == crate["name"] + ":" + crate["version"]
                            ),
                            -1,
                        )
                        if dep_index == -1:
                            logging.error(
                                "Inventory in a malformed state "
                                + dep.name
                                + ":"
                                + dep.version
                                + " should exist in inventory"
                            )
                        else:
                            if dependency_inventory[dep_index]["count"] == 1:
                                del dependency_inventory[dep_index]
                            else:
                                dependency_inventory[dep_index]["internal_crates"].remove(internal_crate)
                                dependency_inventory[dep_index]["count"] = len(
                                    dependency_inventory[dep_index]["internal_crates"]
                                )

            with open(self.get_inventory_file(), "w+") as inv_file:
                json.dump(
                    sorted(dependency_inventory, key=lambda crate: crate["count"], reverse=True),
                    inv_file,
                    indent=4,
                    default=str,
                )

    def update_whitelist(self, whitelist_crates: typing.List) -> None:

        if self.check_whitelist_sanity():

            with open(self.get_whitelist_file(), "r") as whitelist_file:
                whitelist = json.load(whitelist_file)

            for each in whitelist_crates:
                match_index = next(
                    (whitelist.index(crate) for crate in whitelist if each == crate["name"] + ":" + crate["version"]),
                    -1,
                )

                if match_index == -1:
                    whitelist.append(
                        {
                            "name": each.split(":")[0],
                            "version": each.split(":")[1],
                            "date_added": datetime.date.today().strftime("%d/%m/%Y"),
                            "date_updated": datetime.date.today().strftime("%d/%m/%Y"),
                            "expiry_days": self.expiry,
                        }
                    )
                else:
                    # first time or date_updated is not added
                    match = whitelist[match_index]
                    if not match["date_updated"]:
                        expiry_date = datetime.datetime.strptime(match["date_added"], "%d/%m/%Y") + datetime.timedelta(
                            days=int(match["expiry_days"])
                        )
                    else:
                        expiry_date = datetime.datetime.strptime(
                            match["date_updated"], "%d/%m/%Y"
                        ) + datetime.timedelta(days=int(match["expiry_days"]))

                    if expiry_date.date() < datetime.date.today():
                        whitelist[match_index]["date_updated"] = datetime.date.today().strftime("%d/%m/%Y")
                        whitelist[match_index]["expiry_days"] = self.expiry

            with open(self.get_whitelist_file(), "w+") as whitelist_file:
                # We want to sorted based on crate which is going to expire first.
                sorted_whitelist = sorted(
                    whitelist,
                    key=lambda whitelist_crate: (
                        datetime.datetime.strptime(whitelist_crate["date_added"], "%d/%m/%Y")
                        + datetime.timedelta(days=int(whitelist_crate["expiry_days"])),
                        whitelist_crate["name"],
                    ),
                )
                json.dump(sorted_whitelist, whitelist_file, indent=4, default=str)

    def validate_whitelist(self, vulnerable_crates: typing.List) -> tuple[typing.List, bool]:
        fail_job = False
        whitelist_status: typing.List = []

        if self.check_whitelist_sanity():

            with open(self.get_whitelist_file(), "r") as whitelist_file:
                whitelist = json.load(whitelist_file)

            for each in vulnerable_crates:
                match = next((crate for crate in whitelist if each == crate["name"] + ":" + crate["version"]), None)
                if not match:
                    whitelist_status.append(each + " is not fixed and not present in the Whitelist")
                    fail_job = True
                else:
                    # first time or date_updated is not added
                    if not match["date_updated"]:
                        expiry_date = datetime.datetime.strptime(match["date_added"], "%d/%m/%Y") + datetime.timedelta(
                            days=int(match["expiry_days"])
                        )
                    else:
                        expiry_date = datetime.datetime.strptime(
                            match["date_updated"], "%d/%m/%Y"
                        ) + datetime.timedelta(days=int(match["expiry_days"]))

                    if expiry_date.date() < datetime.date.today():
                        whitelist_status.append(
                            each
                            + " is present in the Whitelist but the entry expired on "
                            + expiry_date.strftime("%d/%m/%Y")
                        )
                        fail_job = True
                    else:
                        whitelist_status.append(
                            each
                            + " is present in the Whitelist with a valid expiry until "
                            + expiry_date.strftime("%d/%m/%Y")
                        )
        return whitelist_status, fail_job

    def validate_inventory(self, external_new_deps: typing.List[typing.Dict]) -> tuple[typing.Dict, bool]:
        fail_job = False
        inventory_status: typing.List = []

        if self.check_inventory_sanity():

            with open(self.get_inventory_file(), "r") as inv_file:
                dependency_inventory = json.load(inv_file)

            if external_new_deps:
                for package in external_new_deps:
                    dependency_index = next(
                        (
                            index
                            for index, crate in enumerate(dependency_inventory)
                            if package["name"] + ":" + package["version"] == crate["name"] + ":" + crate["version"]
                        ),
                        -1,
                    )
                    if dependency_index == -1:
                        inventory_status.append(
                            package["name"] + ":" + package["version"] + " is not present in the inventory file"
                        )
                        fail_job = True
                    else:
                        diff = list(
                            set(package["internal_crates"])
                            - set(dependency_inventory[dependency_index]["internal_crates"])
                        )
                        if diff:
                            inventory_status.append(
                                package["name"]
                                + ":"
                                + package["version"]
                                + " is present in the inventory file but internal crates "
                                + " ".join([x for x in diff])
                                + " are not present"
                            )
                            fail_job = True
                        else:
                            inventory_status.append(
                                package["name"]
                                + ":"
                                + package["version"]
                                + " is present in the inventory file and internal crates "
                                + " ".join([x for x in package["internal_crates"]])
                                + " are present"
                            )
        return inventory_status, fail_job


if __name__ == "__main__":
    dep = WhitelistManager()

    parser = argparse.ArgumentParser(description="Utility script to maintain the dependency inventory and whitelist")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-i", "--update", help="Update the external inventory", action="store_true")
    group.add_argument("-c", "--create", help="Create the external inventory from scratch", action="store_true")
    group.add_argument(
        "-a",
        "--add",
        help="Add vulnerable crates to whitelist",
        type=lambda crates: [crate for crate in crates.split(",")],
    )

    args = parser.parse_args()

    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(1)

    if args.update:
        dep.update_inventory()

    if args.create:
        dep.create_inventory()

    if args.add:
        dep.update_whitelist(args.add)
