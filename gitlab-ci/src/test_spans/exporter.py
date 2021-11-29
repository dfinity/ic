import argparse
import datetime
import json
import os
import secrets
import sys

import libhoney


def create_and_export_spans(node, service_name, trace_id, parent_id):
    """Create spans for all tests and organize them as a tree mirroring the structure of a test suite."""
    parent_span = Span.from_dict(node)
    parent_span.service_name = service_name
    parent_span_id = parent_span.push(trace_id, parent_id)

    for ch in node.get("children"):
        create_and_export_spans(ch, service_name, trace_id, parent_span_id)


def read_runtime_stats(stats_filepath):
    """Read from a file runtime statistics used for generating spans."""
    with open(stats_filepath) as json_file:
        return json.load(json_file)


def to_millis(secs, nanos):
    """Combine seconds and nanoseconds and convert them to milliseconds."""
    return 1000 * secs + nanos / 1000000


class Span:
    """Span represents a single pushable Honeycomb span."""

    def __init__(self, started_at, duration, name, succeeded, service_name="cmd"):
        """Create a Span instance."""
        self.started_at = started_at
        self.duration = duration
        self.name = name
        self.succeeded = succeeded
        self.service_name = service_name

    @classmethod
    def from_dict(cls, d):
        """Create a Span instance from a dictionary."""
        return cls(d.get("started_at"), d.get("duration"), d.get("name"), d.get("succeeded"))

    def push(self, trace_id, parent_id):
        """Pushes a span to Honeycomb and returns its ID, randomly generated on the fly within the function."""
        span_id = secrets.token_hex(16)
        ev = libhoney.new_event()
        ev.add_field("service_name", self.service_name)
        ev.add_field("name", self.name)
        ev.created_at = datetime.datetime.fromtimestamp(self.started_at // 1000)
        ev.add_field(
            "duration_ms",
            to_millis(self.duration.get("secs"), self.duration.get("nanos")),
        )
        ev.add_field("trace.parent_id", parent_id)
        ev.add_field("trace.span_id", span_id)
        ev.add_field("trace.trace_id", trace_id)
        ev.add_field("ci_provider", "GitLab-CI")
        ev.add_field("execution_result", "passed" if self.succeeded else "failed")
        ev.send()
        return span_id


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--runtime_stats",
        type=str,
        help="Path to a file containing runtime statistics.",
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
    node = read_runtime_stats(args.runtime_stats)
    create_and_export_spans(node, args.type, args.trace_id, args.parent_id)
    libhoney.close()


if __name__ == "__main__":
    main()
