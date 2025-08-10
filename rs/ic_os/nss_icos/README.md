# IC OS Name Service Switch plugin

This is a small Name Service Switch plugin that allows programs in HostOS
linked to the C library of the system to resolve the IPv6 address of GuestOS.
It can also deduce the HostOS IPv6 address from the GuestOS address.

## How is this used?

In either HostOS or GuestOS, simply attempt to resolve either `guestos` or
`hostos` (e.g. by `ping`ing the host name) and the correct IP address will be
resolved by the binary doing the name resolution.  `getent hosts [arg]` also
works correctly.  So does reverse resolution.

This only works for programs that respect the C library Name Service Switch
stack.  Programs compiled statically that do not link to the C library, and
programs that skip the C library's resolver (going directly to DNS) will not 
"see" the functionality of this plugin.

## Installation

After building in release mode, the library must be installed under the
same folder where the C library places all its other NSS plugins. In
Ubuntu, for example, that is `/usr/lib/x86_64-linux-gnu/`.

Here is an installation example (that works on latest LTS Ubuntu):

```
pushd target/release && \
cp libnss_icos.so libnss_icos.so.2 && \
sudo install -m 0644 libnss_icos.so.2 /usr/lib/x86_64-linux-gnu/ && \
sudo /sbin/ldconfig ; \
popd
```

## Configuration

The module's name (without `libnss`) must be added to the relevant database
configuration in `/etc/nsswitch.conf`.  This module currently only supports
the `hosts` database.  It should be added right after the `files` entry in
the `hosts` database configuration line.

## Theory of operation

The module will look up (once per running program) the local IPv6 address
configured for the machine, and use that as the basis to derive the HostOS
and GuestOS IP addresses.  This lookup happens the first time that the
running program invokes any of the `gethostby*` functions that the C library
processes.

On the basis of that IP address, and the IP addressing conventions established
by the Internet Computer, programs can determine the HostOS and GuestOS
addresses that correspond to the computer where this software is installed
(generally a HostOS or GuestOS instance):

* To resolve the `guestos` host name, the first two bytes of the host part of
  the local IPv6 address are substituted with octets `0x6801`.
* To resolve the `hostos` host name, the first two bytes of the host part of
  the local IPv6 address are substituted with octets `0x6800`.

Reverse resolution works exactly like that, but backwards.
