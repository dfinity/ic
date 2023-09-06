#!/bin/bash
set -Eeuo pipefail

NNS_TOOLS_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
source "$NNS_TOOLS_DIR/lib/include.sh"

# Note, see functions.sh for examples
# This function will print help text where the first line is `##> function_name` and
# the last line is the line before  `function_name()`.  It expects all lines to have '##' at the beginning
help() {
    local CMD=$1

    OLDIFS=$IFS
    IFS=''
    cat "$LIB_DIR"/* \
        | sed -n "/##: $CMD\w*$/, /.*$CMD\(\)/{ /.*$CMD()/!p; }" \
        | sed "s/\$1/$CMD/" \
        | sed "s/##:/  /" \
        | sed 's/##/      /' \
        | while read -r line; do
            echo -e "\033[0;32m$line\033[0m"
        done

    IFS=$OLDIFS
    echo
}

is_valid_command() {
    local CMD=$1
    LC_ALL=C type $CMD 2>&1 | grep "$CMD is a function" >/dev/null
}

# Prints a prologue along with documentation for every function with documentation (see get_help_for)
general_help() {
    echo "
Usage: $0 <FUNCTION> (<ARG1> <ARG2> ... <ARGN>)
    This script runs functions found in functions.sh.  If that function has documentation, you can use \`help <FUNCTION>\`
    to view it.

Known Commands:
"
    for cmd in $(cat "$LIB_DIR"/* | grep "##: " | sed 's/##: //'); do
        help $cmd
    done
}

if [ $# -lt 1 ]; then
    general_help
    exit 1
fi

CMD=$1

if ! is_valid_command $CMD; then
    echo
    general_help
    print_red "$CMD is not a valid command"
    echo
    exit 1
fi

"$@"
