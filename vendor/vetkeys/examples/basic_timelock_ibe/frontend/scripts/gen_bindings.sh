#!/bin/bash

cd ../../backend && make extract-candid && dfx generate basic_timelock_ibe && cd ../frontend && rm -r ./src/declarations >> /dev/null 2>&1
mv ../src/declarations ./src && rmdir ../src