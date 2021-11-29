#!/usr/bin/env python3
import re
import sys

import matplotlib.pyplot as plt


def get_numbers(filename):
    """Determine the filename for one of the nightly results."""
    result = []
    with open(filename, "r") as f:
        r = re.compile(r"### threads (\d+) requests (\d+) time ([0-9.]+)")
        for line in f.readlines():
            m = r.match(line)
            if m:
                result.append((int(m.group(1)), float(m.group(3))))
    return result


def plot(results, title, outname):

    fig, ax = plt.subplots()
    ax.plot([x for x, _ in results], [y for _, y in results], label=title, marker="o")

    ax.set_xlabel("number of concurrent clients")
    ax.set_ylabel("requests / second")
    ax.set_title("IC replica throughput benchmarks")
    ax.legend()

    plt.xticks(rotation=70)
    plt.subplots_adjust(hspace=0, bottom=0.3)

    outname = "{}.png".format(outname)
    print("Output of image to: ", outname)

    plt.savefig(outname, dpi=600)


filename = sys.argv[1]
title = sys.argv[2]
outname = sys.argv[3]

result = get_numbers(filename)
plot(result, title, outname)
