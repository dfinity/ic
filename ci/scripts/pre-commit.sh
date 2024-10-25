set -eEuo pipefail

rustup default stable

export PATH="$HOME/.local/bin:$PATH"
PIP_BREAK_SYSTEM_PACKAGES=1 pip3 install pre-commit

if [ "${CI_OVERRIDE_BUF_BREAKING:-false}" = "true" ]; then
    SKIP_CHECKS="bazel_rust_format_check,bazel_smoke,buf-breaking"
else
    SKIP_CHECKS="bazel_rust_format_check,bazel_smoke"
fi

# Make sure CI can pull from the private repo.
if ! SKIP=$SKIP_CHECKS pre-commit run -a --hook-stage=manual; then
    echo "Pre-commit checks failed. Here is the diff of the changes:"
    git diff
    echo
    echo "You can fix the code locally by following these instructions in the same branch."
    echo
    echo "install pre-commit by following https://pre-commit.com/#installation:"
    echo "(brew|pip) install pre-commit"
    echo "pre-commit install"
    echo
    echo "Then, to fix the checks in this branch, run:"
    echo "pre-commit run --from-ref=\$(git merge-base HEAD master) --to-ref=HEAD"
    echo
    echo "And then commit the changes."
    exit 1
fi
