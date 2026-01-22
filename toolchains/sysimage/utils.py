#!/usr/bin/env python3
#
# Common utilities
#


def parse_size(s):
    if s[-1] == "k" or s[-1] == "K":
        return 1024 * int(s[:-1])
    elif s[-1] == "m" or s[-1] == "M":
        return 1024 * 1024 * int(s[:-1])
    elif s[-1] == "g" or s[-1] == "G":
        return 1024 * 1024 * 1024 * int(s[:-1])
    else:
        return int(s)
