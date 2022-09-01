import argparse
import logging

from .collector import Collector
from .collector import RUST_BINARIES

logging.basicConfig(level=logging.INFO)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "artifacts_dir",
        metavar="ARTIFACTS_DIR",
        help="Where to place processed binaries",
    )
    parser.add_argument(
        "files",
        metavar="BINARY",
        nargs="*",
        help="Build artifact. If none are provided, uses a default list",
        default=RUST_BINARIES,
    )
    parser.add_argument("--source", metavar="SRCDIR", help="Directory to scan for binaries", default=None)
    args = parser.parse_args()
    Collector.collect(args.artifacts_dir, args.files, args.source)
