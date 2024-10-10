#!/bin/bash

set -euxo pipefail

run_in_namespace=$(realpath toolchains/sysimage/run_in_namespace.sh)
ubuntu_base=$(realpath $UBUNTU_BASE_PATH)

icos_tmpdir=$(mktemp -d --tmpdir "icosbuildXXXX")
trap 'rm -rf "$icos_tmpdir"' INT TERM EXIT

cd $icos_tmpdir
mkdir new_root
# We install a base ubuntu in order to have a shell inside chroot.
tar -xaf $ubuntu_base -C new_root

echo "Test: Error when trying to use --mount without --chroot"
out=$($run_in_namespace --mount /bin/bash || true)
if [[ $out != *"Cannot use --mount option without specifying --chroot dir"* ]]; then
    echo "Wrong error reported: $out"
    exit 1
fi

echo "Test: Error when command is missing"
out=$($run_in_namespace --mount --chroot new_root || true)
if [[ $out != *"Missing command"* ]]; then
    echo "Wrong error reported: $out"
    exit 1
fi

echo "Test: We are root inside"
$run_in_namespace /bin/bash -x <<'EOF'
  if [[ $(id) != "uid=0(root) gid=0(root)"* ]]; then
    echo "We should be root in namespace but we are $(id)"
    exit 1
  fi
EOF

echo "Test: Files created inside are owned by current user outside"
$run_in_namespace /bin/bash -c "touch without_chroot.txt"
owner=$(stat -c "%U" "without_chroot.txt")
if [[ $owner != $(whoami) ]]; then
    echo "Wrong ownership: $owner, expected $(whoami)"
    exit 1
fi

echo "Test: Inside can read files that were created outside"
echo "foo" >new_root/file_from_outside.txt
$run_in_namespace --chroot new_root /bin/bash -x <<'EOF'
  if [[ $(<file_from_outside.txt) != "foo" ]]; then
    echo "Could not read file from chroot"
    exit 1
  fi
EOF

echo "Test: Outside can read files that were created inside"
$run_in_namespace --chroot new_root /bin/bash -x <<'EOF'
  echo "bar" > file_from_chroot.txt
EOF
if [[ $(<new_root/file_from_chroot.txt) != "bar" ]]; then
    echo "Could not read file from chroot"
    exit 1
fi

echo "Test: Can access system mounts inside"
$run_in_namespace --mount --chroot new_root /bin/bash -x <<'EOF'
  if [[ ! -e /dev/zero ]]; then
      echo "Could not access system mount"
      exit 1
  fi
EOF

echo "Test: System mounts get cleaned up"
if [[ -e new_root/dev/zero ]]; then
    echo "System mount should not be accessible from outside"
    exit 1
fi
