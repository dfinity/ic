#!/bin/env python3
import itertools
import re
import sys
from os import path, walk


def main(argv):
    testnet_dir = path.dirname(path.abspath(argv[0]))
    env_dir = path.join(testnet_dir, "env")

    res = list(itertools.chain(*map(triples_from_file, host_files(env_dir))))

    testnets = sorted(set(m[0] for m in res))
    hosts = sorted(set(m[3] for m in res))

    table = {h: {tn: [] for tn in testnets} for h in hosts}

    for tn, typ, idx, host in res:
        table[host][tn].append("{}.{}".format(typ, idx))

    print("host;{}".format(";".join(sorted(testnets))))
    for k, v in sorted(table.items()):
        line = ";".join([", ".join(v[tn]) for tn in testnets])
        print("{};{}".format(k, line))


#    print(sorted(testnets))
#    print(len(list(testnets)))
#    print(sorted(hosts))
#    print(len(list(hosts)))
#    print(table)


def host_files(p):
    for root, dirs, files in walk(p):
        for f in filter(lambda f: f.endswith(".ini"), files):
            yield path.join(root, f)


NODE_DEF_RE = re.compile(r'^\s*([-a-zA-Z.0-9]+)\s+.*ic_host="([a-zA-Z-0-9.]+)"')
NODE_DEF_RE = re.compile(r'^\s*([-a-zA-Z0-9]+)\.([a-zA-Z0-9]+)\.([a-zA-Z0-9]+)\s+.*ic_host="([a-zA-Z-0-9.]+)"')


def triples_from_file(h):
    with open(h, "r") as f:
        matches = (NODE_DEF_RE.match(line) for line in f)
        matches = (m for m in matches if m is not None)
        return [(m[1], m[2], m[3], m[4]) for m in matches]


if __name__ == "__main__":
    main(sys.argv)
