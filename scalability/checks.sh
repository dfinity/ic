#!/bin/bash
echo "Checking Python code .. "
pyflakes3 *.py ../ic-os/guestos/tests/*.py experiments/*.py common/*.py

# From https://stackoverflow.com/questions/4284313/how-can-i-check-the-syntax-of-python-script-without-executing-it
echo -n "Compiling Python code: "
echo experiments/run_*.py
python3 -m py_compile experiments/run_*.py

# Lot's of issues, don't use this yet
# pylint *.py
