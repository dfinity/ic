#!/usr/bin/env bash
# Checks that the digest pins in ci/container/ic-dev.digest and
# ci/container/ic-build.digest are well-formed and that every reference to
# ghcr.io/dfinity/ic-dev and ghcr.io/dfinity/ic-build under .devcontainer/ and
# .github/ is exactly ghcr.io/dfinity/<image>@<pinned digest>.
#
# container-autobuild.yml writes all of these together; a reference that
# differs (a hand edit, or a merge that kept an older pin) makes
# container-run.sh and CI run different images.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

status=0
for image in ic-dev ic-build; do
    digest_file="ci/container/$image.digest"
    if [ ! -f "$digest_file" ]; then
        echo "::error file=$digest_file::$digest_file is missing"
        status=1
        continue
    fi
    digest="$(<"$digest_file")"
    if ! [[ $digest =~ ^sha256:[0-9a-f]{64}$ ]]; then
        echo "::error file=$digest_file::$digest_file is malformed: '$digest'"
        status=1
        continue
    fi
    expected="ghcr.io/dfinity/$image@$digest"
    # Every reference by tag or digest, well-formed or not, so that a reference
    # rewritten to a tag or to a malformed digest is reported too.
    pattern="ghcr\.io/dfinity/$image(:|@)[A-Za-z0-9:._-]+"
    refs="$(grep -rhoE -- "$pattern" .devcontainer .github | sort -u || true)"
    if [ -z "$refs" ]; then
        echo "::error::no reference to ghcr.io/dfinity/$image found under .devcontainer/ or .github/ (stale pattern?)"
        status=1
        continue
    fi
    while IFS= read -r ref; do
        if [ "$ref" != "$expected" ]; then
            grep -rnF -- "$ref" .devcontainer .github | while IFS=: read -r file line _; do
                echo "::error file=$file,line=$line::$file:$line references $ref but $digest_file pins $expected"
            done
            status=1
        fi
    done <<<"$refs"
done

if [ "$status" -eq 0 ]; then
    echo "ci/container/*.digest agree with every image reference under .devcontainer/ and .github/"
fi
exit "$status"
