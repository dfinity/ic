#!/bin/bash

cd ../.. && dfx generate encrypted_notes || exit 1

rm -r frontend/src/declarations/encrypted_notes > /dev/null 2>&1 || true

mkdir -p frontend/src/declarations/encrypted_notes
mv src/declarations/encrypted_notes frontend/src/declarations
rmdir -p src/declarations > /dev/null 2>&1 || true
