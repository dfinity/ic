#!/bin/bash

cd ../../backend && make extract-candid

cd .. && dfx generate password_manager_with_metadata || exit 1

rm -r frontend/src/declarations/password_manager_with_metadata > /dev/null 2>&1 || true

mkdir -p frontend/src/declarations/password_manager_with_metadata
mv src/declarations/password_manager_with_metadata frontend/src/declarations
rmdir -p src/declarations > /dev/null 2>&1 || true