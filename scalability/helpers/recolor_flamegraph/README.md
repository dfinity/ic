Script for flamegraph recoloring for the IC code.

## Use
- `./main.sh path/to/flamegraph.svg path/to/ic` on the first use (produces keywords used in recoloring)
- `./main.sh path/to/flamegraph.svg` otherwise

The generated crate names are stored in `crate_names/<component>.txt`, e.g., `crate_names/consensus.txt`.
To add a component that should be parsed by default, add the corresponding code to `main.sh`, similar
to how other component are handled.

The generated recolored graph is stored in `path/to/flamegraph_recolored.svg`.
The graph is recolored color by color in separate calls to the recoloring functionality.
To add a recoloring of an additional component, add corresponding code to `main.sh` , similar
to how other components are handled.

## Implementation

This script makes use of two other scripts: 1. `parse_crate_names_in_path.sh` and 2. `recolor.py`.
1) parses all BUILD.bazel files in path, extracts crate names, and appends "::" to them, e.g.,
   `parse_crate_names_in_path.sh ic/rs/consensus` would currently output "ic_consensus::" to stdout.
2) recolors a flamegraph based on keyword matching, e.g.,
   `python3 recolor.py -i fg.svg -o fg_recolored.svg -c purple -k crate_names/consensus.txt`
   would create a copy of `fg.svg`, stored in `fg_recolored.svg` with matches from
   `crate_names/consensus.txt`, i.e., currently "ic_consensus::", recolored in purple.