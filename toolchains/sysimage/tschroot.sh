#! /bin/sh
[ ! -d "$1" ] && echo "$1 is not a valid directory." && exit 1;
#trap "sudo umount \"${1}\"/dev \"${1}\"/proc" EXIT INT TERM HUP PIPE

   # sudo mount --bind /tmp "${1}/tmp" && \
#    mkdir -p "${1}/dev" && touch "${1}/dev/null" && sudo mount --bind /dev/null "${1}/dev/null" && \
#    mkdir "${1}/dev/pts" && sudo mount --bind /dev/pts "${1}/dev/pts" && \
#    touch "${1}/dev/random" && sudo mount --bind /dev/random "${1}/dev/random" && \
#    mkdir -p "${1}/dev/shm" && sudo mount --bind /dev/shm "${1}/dev/shm" && \
#    touch "${1}/dev/urandom" && sudo mount --bind /dev/urandom "${1}/dev/urandom" && \
#    mkdir -p "${1}/dev" && mount --bind /dev "${1}/dev" && \
#    mkdir -p "${1}/proc" && mount --bind /proc "${1}/proc" && \
#    mkdir -p "${1}/sys" && mount --bind /sys "${1}/sys" && \
    fakeroot fakechroot chroot "$@";
