#!/bin/bash

# Usage
# On 1st use: `./main.sh path/to/flamegraph.svg path/to/ic`
# Then:       `./main.sh path/to/flamegraph.svg`
# This produces a recolored flamegraph path/to/flamegraph_recolored.svg.
# For recoloring all graphs in folder including subfolders, one could run
# `for f in $(find some/path -name "*.svg"); do ./main.sh $f; done`
#
# $1 is the flamegraph path
# $2 is the optional path to the ic folder. If $2 is not given,
# cached results will be used. If no cache is found, this script
# is noop.

# no arguments
if [ $# -eq 0 ]; then
    echo "No arguments supplied"
    exit 1

# flamegraph supplied
elif [ $# -eq 1 ]; then
    :
    # nothing to do here

# flamegraph and ic folder supplied
elif [ $# -eq 2 ]; then
    mkdir -p crate_names

    # parse crypto
    bash parse_crate_names_in_path.sh $2/rs/crypto >crate_names/crypto.txt
    # external crate but managed by crypto
    # also has 'ic' in its name, so including to avoid confusion
    echo ic_bls12_381 >>crate_names/crypto.txt
    bash parse_crate_names_in_path.sh $2/rs/certification >>crate_names/crypto.txt

    # parse consensus
    bash parse_crate_names_in_path.sh $2/rs/consensus >crate_names/consensus.txt
# too many arguments
else
    echo "Too many arguments supplied"
    exit 1

fi

fg_path_no_ext=$(echo -n $1 | sed 's/.svg//')
tmp1="$fg_path_no_ext""_tmp_1.svg"
tmp2="$fg_path_no_ext""_tmp_2.svg"

cp $1 $tmp1

python3 recolor.py -i $tmp1 -o $tmp2 -c dodgerblue -k crate_names/crypto.txt
rm $tmp1
mv $tmp2 $tmp1

python3 recolor.py -i $tmp1 -o $tmp2 -c purple -k crate_names/consensus.txt
rm $tmp1
mv $tmp2 $tmp1

mv $tmp1 "$fg_path_no_ext""_recolored.svg"
