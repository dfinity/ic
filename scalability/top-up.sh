#!/bin/bash
while read -r line; do
    echo "Topping up $line"
    dfx ledger --network=ic top-up $line --amount .2
done <canisters.txt
