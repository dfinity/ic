#! /bin/sh
[ ! -d "$1" ] && echo "$1 is not a valid directory." && exit 1;
trap "umount \"${1}\"/tmp \"${1}\"/dev/null \"${1}\"/dev/pts \"${1}\"/dev/random \"${1}\"/dev/shm \"${1}\"/dev/urandom \"${1}\"/proc" EXIT INT TERM HUP PIPE &&

    mount --bind /tmp "${1}/tmp" && \
    mkdir -p "${1}/dev" && touch "${1}/dev/null" && mount --bind /dev/null "${1}/dev/null" && \
    mkdir "${1}/dev/pts" && mount --bind /dev/pts "${1}/dev/pts" && \
    touch "${1}/dev/random" && mount --bind /dev/random "${1}/dev/random" && \
    mkdir -p "${1}/dev/shm" && mount --bind /dev/shm "${1}/dev/shm" && \
    touch "${1}/dev/urandom" && mount --bind /dev/urandom "${1}/dev/urandom" && \
    mkdir -p "${1}/proc" && mount --bind /proc "${1}/proc" && \
    chroot "$@";
