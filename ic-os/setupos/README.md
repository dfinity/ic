# Setup OS

## Index

* [About](#about)
  * [Features](#features)
* [Build](#build)
  * [Dependencies](#dependencies)
* [Usage](#usage)
  * [ISO](#iso)
  * [MaaS](#maas)
* [FAQ](#faq)
* [Appendix](#appendix)

## About

This folder holds all files to build the SetupOS ISO and MaaS image.

### Features

* Set firmware versions
* Apply UEFI configuration
* Purge existing partitions
* Create new partitions
* Install HostOS disk-image
* Install GuestOS disk-image
* Handle HSM and USB devices

## Build

### Dependencies

To build the Ubuntu Server 20.04 LTS based images, the following dependencies
have to be met. Please note that the script currently only supports Ubuntu
Linux.

* Operating System: Ubuntu 20.04.3
* Packages: `ca-certificates`, `curl`, `git`, `isolinux`, `p7zip-full`,
            `syslinux`, `xorriso`
* Connectivity: 443/tcp outbound

## Usage

Executing the Bash scripts in the _scripts_ folder, is enough to get the build
process started.

### ISO

Command to build the ISO image:
```
./scripts/build-iso.sh
```

Once the build process has finished successfully, the SetupOS ISO image can be
found in the _./build-out/_ folder.

For help and listing the available options, simply append the _--help_ flag:
```
./scripts/build-iso.sh --help
```

### MaaS

Command to build the MaaS image:
```
./scripts/build-maas.sh
```

Once the build process has finished successfully, the SetupOS MaaS images can be
found in the _./build-out/_ folder.

For help and listing the available options, simply append the _--help_ flag:
```
./scripts/build-maas.sh --help
```

## FAQ

## Appendix
