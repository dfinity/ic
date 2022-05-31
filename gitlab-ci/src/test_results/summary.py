import argparse
import glob
import json
import logging
from collections import Counter
from collections import defaultdict
from functools import reduce
from operator import add
from string import Formatter

import input
import requests
from termcolor import colored

NODE_LOGS = "/app/kibana#/discover?_g=(time:(from:now-1y,to:now))&_a=(columns:!(_source),index:c8cf8e20-593f-11ec-9f11-0fb8445c6897,interval:auto,query:(language:kuery,query:'tags:%22{}%22'),sort:!(!('@timestamp',desc)))"
KIBANA_BASE_URL = "https://kibana.testnet.dfinity.systems"


def summarize(root, working_dir, pot_setup_file, verbose, message):
    """Print an execution summary for a given test results tree."""
    print_statistics(root)
    pots = root.children
    all_pots_setup_files = glob.glob(f"{working_dir}/**/{pot_setup_file}", recursive=True)
    for p in pots:
        pot_result, _ = input.format_node_result(p.result)
        group_name = ""
        try:
            search_idx = [p.name in s for s in all_pots_setup_files].index(True)
            group_name_file = all_pots_setup_files[search_idx]
            with open(group_name_file) as file:
                data = json.load(file)
                group_name = data["farm_group_name"]
        except Exception:
            print(f"Couldn't establish `group_name` of the pot {p.name}.")
        if verbose or pot_result == "Failed":
            pot_summary(p, group_name)
            if message:
                import notify_slack

                notify_slack.send_message(
                    message=message.format(p.name),
                    channel="#test-failure-alerts",
                )


def pot_summary(p, group_name):
    pot_result, _ = input.format_node_result(p.result)
    result_to_color = {"Failed": "red", "Passed": "green", "Skipped": "white"}
    print(
        colored(
            "Pot '{}' (duration: {}s) contains {} test(s):".format(p.name, p.duration.secs, len(p.children)),
            result_to_color[pot_result],
        )
    )
    for t in p.children:
        test_result, _ = input.format_node_result(t.result)
        print(colored("* {} (duration: {}s)".format(t.name, t.duration.secs), result_to_color[test_result]))
    if group_name:
        print(colored("Node logs: {}\n".format(create_link(group_name)), result_to_color[pot_result]))


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
        "--verbose",
        action="store_true",
        help="If true, list all pots contained in a test suite, instead of only failing ones.",
    )
    parser.add_argument(
        "--slack_message",
        type=str,
        help="If set, message to push to a slack channel, in form of a notification, for failed pots.",
    )
    args = parser.parse_args()

    results = input.read_test_results(args.test_results)
    summarize(results, args.working_dir, args.pot_setup_file, args.verbose, args.slack_message)


if __name__ == "__main__":
    main()
