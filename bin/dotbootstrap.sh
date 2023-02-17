#!/usr/bin/env bash

curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.3/install.sh
curl --proto =https --tlsv1.2 -sSf https://sh.rustup.rs
echo "scp -r jplevyak@jplevyak.homeip.net:.vim ~/.vim"
