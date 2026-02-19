#!/bin/bash

cd ../../backend && make extract-candid

cd .. && dfx generate basic_ibe || exit 1

rm -r frontend/src/declarations/basic_ibe > /dev/null 2>&1 || true

mkdir -p frontend/src/declarations/basic_ibe
mv src/declarations/basic_ibe frontend/src/declarations
rmdir -p src/declarations > /dev/null 2>&1 || true