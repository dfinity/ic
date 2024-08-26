import argparse
import glob
import json
import logging
from collections import Counter, defaultdict
from functools import reduce
from operator import add
from string import Formatter
from typing import List, Optional

import input
import requests


class Colors:
    RED = "\x1b[31m"
    GREEN = "\x1b[32m"
    NC = "\x1b[0m"


NODE_LOGS = "/app/kibana#/discover?_g=(time:(from:now-1y,to:now))&_a=(columns:!(_source),index:c8cf8e20-593f-11ec-9f11-0fb8445c6897,interval:auto,query:(language:kuery,query:'tags:%22{}%22'),sort:!(!('@timestamp',desc)))"
KIBANA_BASE_URL = "https://kibana.testnet.dfinity.network"
TAB_SIZE = 2
MAX_DISPLAY_ERROR_SIZE = 300


def colored(text: str, color: str) -> str:
    """Turn text string into colored string."""
    return f"{color}{text}{Colors.NC}"


def format_error(s: str) -> str:
    return s if len(s) < MAX_DISPLAY_ERROR_SIZE else s[:MAX_DISPLAY_ERROR_SIZE] + " ..."


def try_get_pot_setup_failure_msg(
    pot_name: str, pot_setup_result_file: str, all_pots_setup_result_files: List[str]
) -> Optional[str]:
    try:
        # Normally, pot_setup_result_file should be always present.
        # If file is absent, the reason of the pot failure is unknown.
        search_idx = [pot_name in s for s in all_pots_setup_result_files].index(True)
    except ValueError:
        return f"file {pot_setup_result_file} not found"
    except Exception:
        return ""
    filename = all_pots_setup_result_files[search_idx]
    with open(filename) as file:
        data = json.load(file)
    if "Failed" in data:
        return data["Failed"]
    return None


def summarize(root, working_dir: str, pot_setup_file: str, pot_setup_result_file: str, verbose: bool):
    """Print an execution summary for a given test results tree."""
    print_statistics(root)
    pots = root.children
    # Perform files search once here.
    all_pots_setup_files = glob.glob(f"{working_dir}/**/{pot_setup_file}", recursive=True)
    all_pots_setup_result_files = glob.glob(f"{working_dir}/**/{pot_setup_result_file}", recursive=True)
    for p in pots:
        pot_setup_failure_msg = try_get_pot_setup_failure_msg(
            p.name, pot_setup_result_file, all_pots_setup_result_files
        )
        pot_result, _ = input.format_node_result(p.result)
        group_name = ""
        try:
            search_idx = [p.name in s for s in all_pots_setup_files].index(True)
            group_name_file = all_pots_setup_files[search_idx]
            with open(group_name_file) as file:
                data = json.load(file)
                group_name = data["infra_group_name"]
        except Exception:
            print(f"Couldn't establish `group_name` of the pot {p.name}.")
        if verbose or pot_result == "Failed":
            pot_summary(p, group_name, pot_setup_failure_msg)


def pot_summary(p, group_name: str, pot_setup_failure_msg: Optional[str]):
    pot_result, _ = input.format_node_result(p.result)
    result_to_color = {"Failed": Colors.RED, "Passed": Colors.GREEN, "Skipped": Colors.NC}
    print(
        colored(
            "Pot '{}' (duration: {}s) contains {} test(s):".format(p.name, p.duration.secs, len(p.children)),
            result_to_color[pot_result],
        )
    )
    if pot_setup_failure_msg is not None:
        # Pot setup failed, thus tests within this pot didn't even start.
        print(
            colored(
                f"\t* Pot setup failed with error: '{format_error(pot_setup_failure_msg)}'".expandtabs(TAB_SIZE),
                Colors.RED,
            )
        )
    else:
        print(colored("\t* Pot setup succeeded".expandtabs(TAB_SIZE), Colors.GREEN))
        for t in p.children:
            test_result, test_result_msg = input.format_node_result(t.result)
            print(
                colored(
                    f"\t* {t.name} (duration: {t.duration.secs}s) {test_result}".expandtabs(2 * TAB_SIZE),
                    result_to_color[test_result],
                )
            )
            if test_result == "Failed":
                print(
                    colored(
                        f"\t* Test failed with error: '{format_error(test_result_msg)}'".expandtabs(3 * TAB_SIZE),
                        result_to_color[test_result],
                    )
                )
        if group_name:
            print(colored(f"\tNode logs: {create_link(group_name)}".expandtabs(TAB_SIZE), result_to_color[pot_result]))
    # Separate pot results with a newline.
    print()


def create_link(group_name):
    url = NODE_LOGS.format(group_name)
    try:
        # Shorten a link pointing to replica logs corresponding to a given pot.
        resp = requests.post(
            KIBANA_BASE_URL + "/api/shorten_url", headers={"kbn-xsrf": "true"}, json={"url": url}
        ).json()
        if "urlId" in resp:
            return "{}/goto/{}".format(KIBANA_BASE_URL, resp["urlId"])
    except Exception as e:
        logging.error("Error while sending a request to Kibana: {}".format(e))
    # Fall back to using a long url, if the shorten_url service fails.
    return KIBANA_BASE_URL + url


def print_statistics(root):
    pots = root.children
    tests = reduce(add, map(lambda p: p.children, pots), [])
    print(
        "Suite '{}' contains {} pots ".format(root.name, len(pots))
        + summarize_results(pots)
        + " with a total of {} tests ".format(len(tests))
        + summarize_results(tests)
        + " and terminated after {}s\n".format(root.duration.secs)
    )


def summarize_results(results):
    d = defaultdict(int, Counter(map(lambda r: input.format_node_result(r.result)[0], results)))
    return Formatter().vformat("({Passed} passed, {Skipped} skipped, {Failed} failed)", (), d)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--test_results",
        type=str,
        help="Path to a file containing results of a test suite.",
    )
    parser.add_argument(
        "--working_dir",
        type=str,
        help="Path to the working directory of the test suite.",
    )
    parser.add_argument(
        "--pot_setup_file",
        type=str,
        help="Name of the pot setup file.",
    )
    parser.add_argument(
        "--pot_setup_result_file",
        type=str,
        help="Name of the pot setup result file.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="If true, list all pots contained in a test suite, instead of only failing ones.",
    )
    args = parser.parse_args()

    results = input.read_test_results(args.test_results)
    summarize(results, args.working_dir, args.pot_setup_file, args.pot_setup_result_file, args.verbose)


if __name__ == "__main__":
    main()
