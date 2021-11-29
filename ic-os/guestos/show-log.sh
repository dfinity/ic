#!/usr/bin/bash

#HOST=root@10.11.23.23
#HOST=qemu

#sshpass -p 'root' ssh "${HOST}" -o StrictHostKeyChecking=false -o UserKnownHostsFile=/dev/null 'journalctl -u dfinity -r' \
grep -v 'Could not find DC information in registry' \
    | grep -v 'Removed checkpoint @[0-9]*' \
    | grep -v 'Finished loading transcript with id=' \
    | grep -v "Finished waiting on [0-9]* transcripts to be loaded" \
    | grep -v "Start asynchronously loading the DKG transcript with id=" \
    | grep -v "Computed manifest of state @[0-9]* in" \
    | grep -v "Created checkpoint @[0-9]*" \
    | grep -v "New DKG summary with config ids created" \
    | grep -v "Waiting on [0-9]* transcripts to be loaded" \
    | grep -v "Failed to query stream slice for subnet" \
    | grep -v "WARNING: deleting key with ID" \
    | grep -v "starvation detected"
