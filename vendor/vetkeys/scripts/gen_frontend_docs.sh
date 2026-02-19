#! /bin/bash

set -e

npm i
npm run make:docs -w $(git rev-parse --show-toplevel)/frontend/ic_vetkeys
