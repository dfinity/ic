#!/usr/bin/python3
import argparse
import re
import sys

import matplotlib.colors as colors

parser = argparse.ArgumentParser(prog="SVG flamegraph recoloring script")
parser.add_argument("-i", "--input", help="input file path", required=True)
parser.add_argument("-o", "--output", help="output file path", required=True)
parser.add_argument(
    "-k",
    "--keywords",
    help="path to the list\
                    of keywords that should be recolored in the\
                    flamegraph",
    required=True,
)
# https://matplotlib.org/stable/gallery/color/named_colors.html
parser.add_argument(
    "-c",
    "--color",
    help="color must be either in the RGB format\
                    x,y,z, each in [0, 255], or have a natural name\
                    of the color that is convertible to RGB using\
                    matplotlib's colors.to_rgb(color), e.g., blue",
    required=True,
)
parser.add_argument("-v", "--verbose", help="increase output verbosity", action="store_true")

args = parser.parse_args()

input_file = open(args.input, "r")

keywords = set()
with open(args.keywords) as file:
    for line in file:
        if re.compile("[a-z0-9_:]+").match(line) is None:
            print("Malformed keyword", line, "in", file)
            sys.exit(0)
        keywords.add(line.strip("\n"))

if args.verbose:
    print("Parsed keywords names:", keywords)
    print()

color = ""
rgb_color_re = re.compile(r"\d,\d,\d")
matched_rgb_color = rgb_color_re.match(args.color)
if matched_rgb_color is not None:
    if args.verbose:
        print("Parsed raw RGB color:", args.color)
    color = args.color
else:
    color_mpl = colors.to_rgb(args.color)
    color_hex = colors.to_hex(color_mpl)
    if args.verbose:
        print("Hex representation of the input color is", colors.to_hex(color_mpl))
    color = str(int(color_hex[1:3], 16)) + "," + str(int(color_hex[3:5], 16)) + "," + str(int(color_hex[5:7], 16))
    if args.verbose:
        print("Converted", args.color, "to", color)

if args.verbose:
    print()

output_file = open(args.output, "w+")


def contains(keywords, match):
    for name in keywords:
        matched = True if name in match else False
        if matched and args.verbose:
            print("Recoloring", match)
        if matched:
            return True
    return False


for line in input_file:
    line = re.sub(
        r'(<title>[a-zA-Z"=\s%\._\-\d`:;&(,)\<\>\{\}]*</title><rect[a-zA-Z\d"=\s%\.]+rgb\()(\d+,\d+,\d+)(\))',
        lambda m: m.group(1) + color + m.group(3)
        if contains(keywords, m.group(1))
        else m.group(1) + m.group(2) + m.group(3),
        line,
    )
    output_file.write(line)
