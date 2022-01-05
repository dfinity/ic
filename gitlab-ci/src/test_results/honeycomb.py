import argparse
import datetime
import os
import secrets
import sys

import input
import libhoney


def create_and_export_spans(node, trace_id, parent_id, service_name):
    """Create spans for all tests and organize them into a tree mirroring the structure of a test suite."""
    parent_span_id = push_span(node, trace_id, parent_id, service_name)
    for ch in node.children:
        create_and_export_spans(ch, trace_id, parent_span_id, service_name)


def push_span(node, trace_id, parent_id, service_name):
    """Pushes to Honeycomb a span corresponding to a given test result object and returns its randomly generated ID."""
    span_id = secrets.token_hex(16)
    ev = libhoney.new_event()
    ev.add_field("service_name", service_name)
    ev.add_field("name", node.name)
    ev.created_at = datetime.datetime.fromtimestamp(node.started_at // 1000)
    ev.add_field(
        "duration_ms",
        to_millis(node.duration.secs, node.duration.nanos),
    )
    ev.add_field("trace.parent_id", parent_id)
    ev.add_field("trace.span_id", span_id)
    ev.add_field("trace.trace_id", trace_id)
    ev.add_field("ci_provider", "GitLab-CI")
    ev.add_field("execution_result", node.result)
    ev.send()
    return span_id


def to_millis(secs, nanos):
    """Combine seconds and nanoseconds and convert them to milliseconds."""
    return 1000 * secs + nanos / 1000000


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--test_results",
        type=str,
        help="Path to a file containing test results.",
    )
    parser.add_argument(
        "--trace_id",
        type=str,
        help="Id of a trace containing the tests.",
    )
    parser.add_argument(
        "--parent_id",
        type=str,
        help="Id of a parent span to which all top-level spans will be linked to.",
    )
    parser.add_argument(
        "--type",
        type=str,
        help="Type of a tests suite that spans relate to.",
    )
    args = parser.parse_args()

    api_token = os.getenv("HONEYCOMB_API_TOKEN")
    if not api_token:
        sys.exit("No Honeycomb token specified in HONEYCOMB_API_TOKEN env var.")

    libhoney.init(writekey=api_token, dataset="gitlab-ci-dfinity", debug=False)
    root = input.read_test_results(args.test_results)
    create_and_export_spans(root, args.type, args.trace_id, args.parent_id)
    libhoney.close()


if __name__ == "__main__":
    main()
