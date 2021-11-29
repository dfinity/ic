# This file makes pytest work outside the nix-shell. [e.g. with native toolchains].
# Pytest will execute this file and append the subdir to the system PATH.
import os
import sys

sys.path.append(os.path.abspath(os.path.dirname(__file__)))
