# IC-OS Testnet

## Index

* [About](#about)
  * [Overview](#overview)
  * [Support](#support)
  * [Dependencies](#dependencies)
* [Usage](#usage)
  * [Run-Deployment](#run-deployment)
  * [List-Inventory](#list-inventory)
  * [SSH-Config](#ssh-config)
  * [Delete-Deployment](#delete-deployment)
* [Inventory](#inventory)
  * [Hosts](#hosts)
  * [Resources](#resources)
  * [Nodes](#nodes)
  * [Mercury](#mercury)
  * [Monitoring](#monitoring)
* [Blueprint](#blueprint)
  * [HostOS](#hostos)
  * [GuestOS](#guestos)
  * [Ansible](#ansible)
* [Troubleshooting](#troubleshooting)
* [FAQ](#faq)
* [Appendix](#appendix)

## About

This document aims to provide an overview and understanding of the deployment
mechanism behind the new IC-OS based testnets. Please also read (and extend) the
FAQ at the end of this document.

### Overview

```
testnet/
       ansible/
                 ansible.cfg
                     The main Ansible configuration file. Tweak this file if you
                     happen to run into connectivity issues or timeouts.


                 roles/
                             ic_guest/
                                 Ansible role taking care of redeploying a
                                 testnet.
                                 Functionality:
                                   - pulls disk image on IC-OS hosts
                                   - pushes media images to IC-OS hosts
                                   - creates and destroys IC-OS guests
                                   - starts and stops IC-OS guests


                 inventory/
                             inventory
                                 Shell script which invokes Python tool to
                                 generate dynamic inventory.
                                 This wrapper script is necessary due to the
                                 use of Nix environment.

                             inventory.py
                                 This Python script generates the Ansible
                                 inventory, based on the hosts.ini input.
                                 Functionality:
                                   - Prepares IC-OS guest network config
                                   - Defines MAC addresses
                                   - Calculates IPv6 SLAAC addresses
                                   - Prepares config for media images
                                   - Generates SSH config per testnet

                                 Arguments:
                                   --list
                                         List inventory
                                   --host <hostname>
                                         List variables of <hostname>
                                   --all
                                         List all variables
                                   --ssh-config
                                         Configure local ssh client to access testnet hosts.
                                   --verbose
                                         Run Python tool with verbose output.


      config/
                 nftables.conf
                     This file holds the raw nftables ruleset. The default
                     ingress and egress (IPv4 and IPv6) policy is ACCEPT.
                     In other words, the firewall is not filtering any traffic
                     unless you explicitly change settings in this file.
                     :information_source: This configuration option might disappear in the near future.


                 ssh_authorized_keys/
                     This folder holds the authorized_keys files being injected
                     into the GuestOS. Please add your public SSH key to the
                     respective file.

                             admin
                                 Adding your public SSH key to this
                                 authorized_keys file will grant you admin
                                 (root) permissions inside the GuestOS.

                                   ssh admin@<hostname>

                             backup
                                 Adding your public SSH key to this
                                 authorized_keys file will grant you permissions
                                 for the backup/subnet recovery tasks.

                                 ssh backup@<hostname>

                             readonly
                                 Adding your public SSH key to this
                                 authorized_keys file will grant you read-only
                                 permissions in the GuestOS.

                                 ssh readonly@<hostname>


      env/
                 <testnet>/
                             hosts
                                 This file is a symbolic link to the inventory
                                 Shell script, not the actual Ansible inventory.

                                   hosts -> ../../ansible/inventory/inventory

                                When creating a new testnet, this link can be created with
                                `cd testnet/env/<testnet> && ln -sf ../../ansible/inventory/inventory hosts`

                             hosts.ini
                                 An abstracted, more human readable version of
                                 the Ansible inventory. Please define your
                                 subnet here.

                                 For examples, look at the hosts.ini of the
                                 'small01' or 'medium01' environments.


                 shared-config.yml
                     Ansible inventory configuration shared across testnets.
                     This includes data center IPv6 prefixes, Prometheus scraping
                     parameters and default values for Ansible roles.


      tools/
                 icos_deploy.sh
                     This is the actual deployment script. It takes care of
                     building the removable media files and redeploying a
                     testnet.

                     Command:
                       ./icos_deploy.sh --git-revision <hash> ${testnet}
```

### Support

Please send bugs and questions to the [#eng-testnet](https://dfinity.slack.com/archives/C014QBN5EE5) channel. The IC-OS team
is happy to help and will try to answer your questions in a timely manner.

### Dependencies

In order to run the Ansible deployment from your own machine or any remote
server, the following dependencies have to be met:
 - Operating System:
```
Ubuntu 20.04
```
:warning: Deployments from MacOS are not supported at the moment.

 - Packages:
```
apt -y install ansible coreutils jq mtools rclone tar util-linux unzip --no-install-recommends
```

If you are not working on a Ubuntu 20.04 based system, you can use the following
office builders.
Please make sure that you initialize the ssh agent before connecting, and to
forward the local ssh credentials.

Check the ssh-agent keys
```bash
ssh-add -L
```

```
# SSH to remote machine using your DFINITY SSH user
ssh -A zh1-spm22.zh1.dfinity.network
```

or
```
ssh -A zh1-spm34.zh1.dfinity.network
```

## Usage

### Understanding Ansible Playbooks

**Note:** this section has been copied from the old README file, and may be slightly out of date. However, it is still useful to understand the naming convention for the ansible playbooks.

The following provides a mental model for understanding the available playbooks.
Playbooks are the `*.yml` files in /dfinity/testnet. The file names are patterned
around adverbs, verbs and nouns as follows.

```bash
ansible-playbook -i env/xyz/hosts ic_${ optional adverb or adjective }_${ noun }_${ verb }.yml
```

Nouns

 Subnet: A collection of nodes that host a set of canisters.
  Nodes: All nodes in the IC that form subnets.
   Node: ...
    NNS: The NNS subnetwork that contains the registry.
    Env: All of the above.

Verbs

  Install: A one-time operation, the operator should only execute once for
           the lifecycle of the noun. Performing multiple successive installs
           will destroy the previous installation.

  Update:  A repeatable operation, the operator may execute through the
           life-cycle of a noun, for example to upgrade to new binaries
           or configurations.

  Extend:  A repeateable operation, just like Update. Usually refers to
           membership or other qualities that are not replaced, but extended,
           like disk space, memory, ...

  Destroy: A one-time operation, the operator should use this to end
           the lifecycle of a noun

Adjective

   independent: node or subnet installation without crypto material generation. Suitable for bootstrapping.

***Additional Options***

Ansible accepts setting variables from the command line with -e $key=$value. For instance:

  `-e yes_i_confirm=yes`: Skip confirmation prompts.
  `-e ic_no_destroy=yes`: For install verbs, skip the destroy operation.

### Run-Deployment

To initiate a redeployment of an IC-OS based testnet, simply run the following
commands:

```
# Clone the DFINITY Git repository
git clone git@gitlab.com:dfinity-lab/core/ic.git
cd ic/


# Run deployment to <testnet> (e.g. small01, medium01, ...)
./testnet/tools/icos_deploy.sh <testnet> --git-revision d53b551dc677a82c8420a939b5fee2d38f6f1e8b
```

You can get the latest git sha with disk image for a branch (e.g. master) by running:
```
./gitlab-ci/src/artifacts/newest_sha_with_disk_image.sh origin/master
```

### List-Inventory

To gather all facts of a testnet, simply run the dynamic inventory script:

```
testnet/env/<testnet>/hosts --list
```

To list all nodes from a testnet, you can run:
```
testnet/env/<testnet>/hosts --nodes
```

And to list only the IPv6 addresses:
```
testnet/env/<testnet>/hosts --ipv6
```

### Host-Variables

To list variables for a specific node, you can run the dynamic inventory script:

```
testnet/env/<testnet>/hosts --host <testnet>.1.2.testnet
```

### SSH-Config

SSH can be used to login to the individual nodes. Since nodes do not have IPv4
addresses or DNS records, you will need to use its public IPv6 address.

```
# Optional: Load your SSH private key to enable SSH agent forwarding
ssh-agent bash
ssh-add

# Remember to use the 'admin' account
ssh admin@feed:f00d:beef:cafe::1
```

Alternatively, generate the SSH configuration file from the dynamic inventory.
This allows you to use the inventory hostname in your SSH command.

```
testnet/env/<testnet>/hosts --ssh-config
```

The above adds the SSH config file into your SSH config directory
```
ls -l ~/.ssh/config.d/<testnet>
```

So you should be able to connect to the testnet nodes with:
```
ssh <testnet>.1.2.testnet
```
The above ssh configuration needs to be for each testnet, and needs to be
re-run whenever testnet configuration changes, for example when nodes are
added or removed.

### Delete-Deployment

## Inventory

This section describes the static inventory, which holds the minimal testnet definition
from which a full dynamic inventory is built during the deployment.

### Hosts

The first section defines the physical hosts being used for this testnet. Make
sure to use valid fully qualified domain names (FQDNs).

```
[physical_hosts]
sf1-spm00.sf1.dfinity.network
zh1-spm00.zh1.dfinity.network
```

### Resources

For large testnets it might make sense to adjust the default resources. The disk
size should not be smaller than 50 GB.

(example of changed `env/xsmall-a/hosts.ini`)
```
[physical_hosts]
zh1-spm19.zh1.dfinity.network ic_cores=2 ic_disk_gb=50 ic_memory_gb=8
```

The default resource allocation is:
```
ic_cores: 4
ic_disk_gb: 100
ic_memory_gb: 16
```

Alternatively, to avoid changing the `hosts.ini` file, temporary testnet configuration can be provided on the command line.
For instance, a testnet with larger disks (300 GB in this case) can be deployed this way:
```
./testnet/tools/icos_deploy.sh <testnet> \
  --git-revision $(./gitlab-ci/src/artifacts/newest_sha_with_disk_image.sh origin/master) \
  --ansible-args '-e ic_disk_gb=300'
```

### Nodes

The second part defines all nodes. You can define as many nodes and subnets as
you wish. Please make sure to use a unique `node_index` per node. The `ic_host=`
parameter assigns a node to a physical host.

`subnet_index` is extracted from the group name since some tests expect the
group name in a form of `subnet_X` where `X` is the `subnet_index`.  If
provided explicity as well for node, the `subnet_index` extracted from the
group name and the node name must match. If not, an error will be thrown.

`node_index` is extracted from the node name, IFF the name has the format
`<anything>.<node_index(int)>`.  The `node_index` can also be provided
explicitly but it must match the value extracted from the node name (if the
node is named in a compatible way).

For instance, the following is valid configuration:
```
[nns]
example.0.0 ic_host="zh1-spm00"
example.0.1 ic_host="zh1-spm00"
example.0.2 ic_host="sf1-spm00"
example.0.3 ic_host="sf1-spm00"

[subnet_1]
example.1.4 ic_host="zh1-spm00"
example.1.5 ic_host="zh1-spm00"
example.1.6 ic_host="sf1-spm00"
example.1.7 ic_host="sf1-spm00"

[subnet_2]
example.2.8 ic_host="zh1-spm00"
example.2.9 ic_host="zh1-spm00"
example.2.10 ic_host="sf1-spm00"
example.2.11 ic_host="sf1-spm00"

[nodes:children]
nns
subnet_1
subnet_2
```

The following is also valid:
```
[nns]
example.0.0 ic_host="zh1-spm00"

[subnet_1]
example.1.4 ic_host="zh1-spm00"

[nodes:children]
nns
subnet_1
```


The following is NOT valid because `example.2.4` should be in group name `subnet_2` but belongs to a group `subnet_1`:
```
[nns]
example.0.0 ic_host="zh1-spm00"

[subnet_1]
example.2.4 ic_host="zh1-spm00"

[nodes:children]
nns
subnet_1
```

The following is also NOT valid because `example.1.1` has an explicit `node_index` value set to value 4, whereas it should be `node_index=1`:
```
[nns]
example.0.0 ic_host="zh1-spm00"

[subnet_1]
example.1.1 node_index=4 ic_host="zh1-spm00"

[nodes:children]
nns
subnet_1
```

Again, in case of invalid configuration an exception will be thrown and the Ansible inventory will not be usable.

### Monitoring

The third section holds the Prometheus monitoring configuration. Please make
sure to use a unique port.

```
[prometheus]
# General prometheus config is in shared-config.yml
[prometheus:vars]
# Note: The port must be different for each deployment. Find used ports in all deployments with:
# cd testnet
# grep ic_p8s_service_discovery_metrics_addr= env/*/*host* | awk -F : '{print $1,$NF}' | sort -k2,3n
ic_p8s_service_discovery_metrics_addr=[2a05:d01c:e2c:a700:dfde:e933:cb63:f106]:8000
```
## Blueprint

This section describes the tools and architecture behind the new IC-OS
deployment.

### HostOS

:construction:

### GuestOS

:construction:

### Ansible

:construction:

## Troubleshooting

:construction:

## FAQ

Please help us to curate and extend this FAQ.

---

:question:
What does the notation `<testnet>` mean?

:white_check_mark:
This notation is simply a placeholder for a testnet define in:

`ic/testnet/env/*`

---

:question:
Question

:white_check_mark:
Answer

---

## Appendix
