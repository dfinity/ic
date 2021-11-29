#!/bin/bash
#
# Create all DFINITY_Lab users in DFINITY_Lab / Teams / everyone.
#
# To use this script, install python-gitlab with the command line utility gitlab,
# and put your gitlab API token into ~/.python-gitlab.cfg:
#
# [global]
# default = dfinity
#
# [foo]
# url = https://gitlab.com
# private_token = <your token>

# Try first adding with minimal access level (Developer). For those who can't be added this way,
# they'll be added on the 2nd or 3rd iteration with Maintainer or Owner permissions.
for access_level in 30 40 50; do
    gitlab group-member list --group-id 10126677 --all | sed -e 'N;N;s/\n/ /g' \
        | while read user; do
            set $user
            echo "Adding user $4 with ID $2"
            gitlab group-member create --group-id 13014545 --user-id $2 --access-level $access_level
        done
done
