#!/bin/bash

cd ../../backend && make extract-candid

cd .. && dfx generate basic_bls_signing || exit 1

rm -r frontend/src/declarations/basic_bls_signing > /dev/null 2>&1 || true

mkdir -p frontend/src/declarations/basic_bls_signing
mv src/declarations/basic_bls_signing frontend/src/declarations
rmdir -p src/declarations > /dev/null 2>&1 || true