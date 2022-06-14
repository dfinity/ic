import argparse
import json
import logging
import sys

import inventory
import jira_helper
import whitelist

"""
MERGE_HOOK - This is the main process script for handling vulnerable dependencies in a merge request.

The script will flag the MR for a ProdSec review incase of the following instances.
    - A vulnerable dependency is found

Job failing conditions :
    - Vulnerable dependencies (direct and indirect) are not updated to fixed versions or not in the whitelist

    Whitelist structure :
    [{
            "name" : # package name,
            "version" : # package version,
            "date_added" : # dd/mm/yyyy,
            "date_updated" : # dd/mm/yyyy,
            "expiry_days" : # days until whitlelist expires.
    },]

    Whitelist file : .dependencies/vulnerable_crates_whitelist.json

To pass the CI job, the vulnerable crate needs to approved by Product Security for Whitelisting and needs be included
in the Whitelist with a valid expiry. The whitelist file is owned by product security and would require their approval
for changes.

A JIRA ticket will be created with all the relevant information and full delta as an attachment. Incremental runs will
update the ticket with comment history."""

USE_LOCAL = False
USE_VERBOSE = False


def main():

    result = {}
    fail_job = False

    # Initialize the inventory
    curr = inventory.Inventory(inventory.Cargo())
    dep_manager = whitelist.WhitelistManager()

    # Get the modified crates for the current MR
    delta = curr.package_manager.get_modified_crates()
    if delta:
        result["modified_crates"] = list(delta)

        # Perform the vulnerability scan for the modified crates
        vulnerable_scan = curr.package_manager.get_vulnerable_dependencies(crates=list(delta))
        result["vulnerable_crates"] = vulnerable_scan["metadata"]
        del vulnerable_scan["metadata"]
        result["vulnerability_scan"] = vulnerable_scan

        if result["vulnerable_crates"] or result["vulnerability_scan"]:

            # Check vulnerability scan against whitelist.
            (result["whitelist_status"], fail_job) = dep_manager.validate_whitelist(result["vulnerable_crates"])

            # Get the cargo.toml diffs for finding external packages
            # and collect metadata on them.
            # metadata = {}
            # external_new_deps = curr.package_manager.get_external_direct_deps()

            # Thresholds for failing an external dependency?
            # For now, we can fail by default.
            # But we would require some threshold to fail this job
            # and the thresholds need to be documented properly.
            # (result["inventory_status"], fail_job) = dep_manager.validate_inventory(external_new_deps)

            # # Collect external metadata on the new crates.
            # if external_new_deps :
            #     for package in external_new_deps :
            #         cwd = os.path.abspath(os.path.join(curr.package_manager.root, "rs"))
            #         crate_path = os.path.abspath(os.path.join(curr.package_manager.root, "gitlab-ci/src/dependencies/crates"))
            #         command = "{crate_path} {external_dep}".format(crate_path = crate_path, external_dep = package["name"] + ":" + package["version"])
            #         environment = {}
            #         data = inventory.ProcessExecutor.execute_command(command, cwd, environment)

            #         # affinity fix
            #         while data[0] != "{":
            #             _, data = data.split("\n", 1)
            #         metadata[package["name"] + ":" + package["version"]] = json.loads(data)

            # result["external_crates"] = metadata

            if USE_LOCAL:
                # TODO : For now, it temporarily prints everything.
                # Need more nuanced reporting.
                if USE_VERBOSE:
                    print(json.dumps(result, indent=4, default=str))
                else:
                    print(jira_helper.create_description(data=result))

            else:
                if fail_job:
                    try:
                        if jira_helper.check_ticket_exists():
                            jira_helper.update_ticket(data=result)
                        else:
                            url = jira_helper.create_ticket(data=result)
                            if url:
                                curr.comment_on_gitlab(url)
                    except Exception as err:
                        logging.error("Error in JIRA API " + str(err))
                    finally:
                        sys.exit(1)
        else:
            print("No vulnerablility found in the modified crates")
    else:
        print("No crates were modified. Dependency test will not run.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Dependency management for IC codebase")
    parser.add_argument("-l", "--local", action="store_true")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()
    USE_LOCAL = args.local
    USE_VERBOSE = args.verbose
    if USE_VERBOSE:
        logging.basicConfig(level=logging.INFO)
    main()
