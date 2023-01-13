# parse all crate names in path $1 and output "$crate_name::" as separate lines
# $1 path to the target dir

for p in $(find $1 -name BUILD.bazel); do cat $p | grep crate_name | egrep -o "\".*\"" | sed "s/\"//g;s/$/::/"; done
