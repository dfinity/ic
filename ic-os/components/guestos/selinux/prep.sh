#!/bin/bash

set -e

# Policy building feeds wildcard-generated list of files to m4. Unfortunately,
# implicit sorting of all wildcard globs was added in make version 4.3, and we use 4.2.
# Simply patch the Makefile to manually force sorting.
sed -e 's/m4support = \(.*\)/m4support = $(sort \1)/' -i /usr/share/selinux/devel/include/Makefile
sed -e 's/header_interfaces := \(.*\)/header_interfaces := $(sort \1)/' -i /usr/share/selinux/devel/include/Makefile
sed -e 's/detected_mods := \(.*\)/detected_mods := $(sort \1)/' -i /usr/share/selinux/devel/include/Makefile

# Build SELinux modules
make -f /usr/share/selinux/devel/Makefile

# Install them
semodule -i *.pp
