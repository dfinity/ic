#!/usr/bin/env python3
"""
Visualize the Pipeline configuration with Graphviz.

Usage:

   python3 ./visualize.py | dot -Tsvg -o /tmp/1.svg
"""
import functools
import glob

import yaml


def process_config(filename):
    with open(filename) as f:
        config = yaml.load(f, Loader=yaml.SafeLoader)
    nodes = []
    edges = []
    for name, pipeline in config.items():
        if name in (
            "include",
            "stages",
            "default",
            "variables",
            "before_script",
            "after_script",
        ):
            continue
        attributes = {}
        for attr in ("stage", "needs", "dependencies"):
            if attr in pipeline and pipeline[attr]:
                value = pipeline[attr]
                if isinstance(value, list):
                    value = ",".join(value)
                attributes[attr] = value
        nodes.append((name, attributes))
        extends = pipeline.get("extends", None)
        if extends:
            if not isinstance(extends, list):
                extends = [extends]
            for destination in extends:
                edges.append((name, destination))
    return nodes, edges


def process_all_configs(directory, out):
    nodes = []
    edges = []
    for filename in glob.glob(f"{directory}/*.yml"):
        n, e = process_config(filename)
        nodes.extend(n)
        edges.extend(e)
    pr = functools.partial(print, end="", file=out)
    pr('digraph G {\nsize="46,33!"\nratio="fill"\n')
    for name, attributes in nodes:
        pr(f'"{name}"')
        if attributes:
            pr(" [")
            sep = ""
            for attribute, value in attributes.items():
                pr(f'{sep}{attribute}="{value}"')
                sep = ", "
            pr("]")
        pr("\n")
    for name, extends in edges:
        pr(f'"{name}" -> "{extends}"\n')
    pr("}\n")


if __name__ == "__main__":
    import sys

    directory = "."
    if len(sys.argv) > 1:
        directory = sys.argv[1]
    process_all_configs(directory, sys.stdout)
