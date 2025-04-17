#!/bin/bash

set -e

# erestorecon (easy prestorecon) uses UNIX tools to parallelize restorecon,
# instead of the cpp based prestorecon.

find $@ -print0 | xargs -0 -P 0 restorecon -F
