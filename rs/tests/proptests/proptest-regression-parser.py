#!/usr/bin/env python3
"""
A collection of helper functions that parse and analyse proptest-regression
files to help identify the issue with a regression.
"""
import argparse
import re

"""
Checks, whether the content of an array is a decimal string,
i.e. numerical values separated by comma.
"""


def is_decimal_array(data):
    pattern = r"[^\, 0-9]"
    if re.search(pattern, data):
        return False
    else:
        return True


def shrink_decimal_array(data):
    values = []

    data = data.split(",")
    values.append([data[0], 1])

    for datum in data[1:]:
        datum = datum.strip()

        if datum == values[-1][0]:
            values[-1][1] = values[-1][1] + 1
        else:
            values.append([datum, 1])
        pass

    output = ""
    for value in values:
        if value[1] == 1:
            output += str(value[0]) + ", "
        else:
            output += "(" + str(value[1]) + ")x" + str(value[0]) + ", "

    return output


def shrink_arrays(data):

    chunks = re.split(r"\[|\]", data)
    output = ""

    for chunk in chunks:

        if is_decimal_array(chunk):
            output += "["
            output += shrink_decimal_array(chunk)
            output += "]"
        else:
            output += chunk

    return output


def _get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-i",
        "--input",
        help="path of file to parse",
    )
    parser.add_argument("-o", "--output", help="output path (prints to stdio if omitted)")
    subparsers = parser.add_subparsers(help="Action", dest="function")

    subparsers.add_parser("shrink-arrays", help="Shrink arrays with repeating content")

    return parser.parse_args()


if __name__ == "__main__":
    args = _get_args()

    # Exit if no input file was provided
    if args.input is None:
        print("No input file provided")
        exit(0)

    # Read input file into a string
    with open(args.input, "r") as file:
        data = file.read()

    if args.function == "shrink-arrays":
        output = shrink_arrays(data)

    print(output)

    # Output printing/storing
