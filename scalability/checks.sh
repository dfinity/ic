echo "Checking Python code .. "
pyflakes3 *.py ../ic-os/guestos/tests/*.py

# From https://stackoverflow.com/questions/4284313/how-can-i-check-the-syntax-of-python-script-without-executing-it
python -m py_compile *.py

# Lot's of issues, don't use this yet
# pylint *.py
