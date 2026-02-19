#!/bin/bash

cd ../../backend && make extract-candid

cd .. && dfx generate encrypted_chat || exit 1

rm -r frontend/src/declarations/encrypted_chat > /dev/null 2>&1 || true

mkdir -p frontend/src/declarations/encrypted_chat
mv src/declarations/encrypted_chat frontend/src/declarations
rmdir -p src/declarations > /dev/null 2>&1 || true