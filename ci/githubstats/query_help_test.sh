#!/bin/bash
set -euo pipefail

"$QUERY_PATH" --help
# argparse only formats the help of options, where a '%' must be written as '%%', when rendering it.
"$QUERY_PATH" top --help
"$QUERY_PATH" last --help
