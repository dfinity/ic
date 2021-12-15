# Analyzing Diverged States

## Context

A replicated state divergence occurs when a replicated state, obtained by
applying the same block to the same previous replicated state, is different
across replicas on a subnet.

There are a couple of situations in which diverged states may be encountered:

 * Single replica divergence: the `state_manager_last_diverged_state_timestamp`
   gets bumped, along with a "Replica diverged at height X" log message, meaning
   that the replica's state diverged from the state certified by the subnet (and
   included in the respective CUP).

 * More than 1/3 of replicas diverge: no CUPs are created for longer than one
   CUP interval; certified height stalls; eventually finalization rate drops to
   almost zero.

## Overview

IC replicas persist their replicated state under the `/var/ic/data/ic_state`
directory. There are a couple of subdirectories of interest there:

 * `diverged_checkpoints` lists checkpoints whose root hash do not match the
   root hash in the CUP (certified by a majority of subnet replicas).

 * `checkpoints` for valid checkpoints; or diverged but undetected ones, where
   the subnet stops producing CUPs because more than 1/3 of replicas diverge
   at the same time (meaning that the replica cannot mark the state diverged
   because there was no certified state for it to diverge from).

 * `backups` contains valid counterparts of diverged checkpoints, backed up
   if state sync was able to retrieve one during the same CUP interval.

Depending on which of the 2 situations above you are dealing with, the relevant
checkpoint may be found under one of the 2 directories. The contents of these
directories are checkpoints (also directories) named based on their height (the
16 digit zero-prefixed hexadecimal representation of the height).

## Obtaining the Manifests

Once the relevant checkpoint has been located, the next step is to compute its
manifest (a list of files and file chunks, with their associated hashes) and
compare it with either:

 1. the manifest of the same state from the same replica's `backups` directory
    (if state sync was able to complete within one CUP interval); or

 2. the manifest of the state whose hash was included in the CUP, retrieved
    from a "healthy" replica (although this gets garbage collected within a
    couple of CUP intervals, so it would have to be retrieved immediately); or

 3. the manifest of the checkpoint at the same height of other replicas on the
    subnet (if CUP creation has stalled; these checkpoints do not get garbage
    collected as long as the subnet is unable to certify a new CUP).

The manifest can be computed using `state-tool`, present on all replicas under
the `/opt/ic/bin` directory:

```bash
export REPLICA=2001:470:1:c76:5000:bdff:fe8b:3d7c
prodssh readonly@[$REPLICA]
export HEIGHT=0000000000822e2c
/opt/ic/bin/state-tool manifest --state /var/lib/ic/data/ic_state/checkpoints/$HEIGHT > /tmp/$HEIGHT.manifest
```

The various replicas' manifests can then be `scp`-ed to your machine, to be
compared against each other with a text diff tool:

```bash
export HEIGHT=0000000000822e2c
export REPLICA=2001:470:1:c76:5000:bdff:fe8b:3d7c
scp readonly@[$REPLICA]:/tmp/$HRIGHT.manifest $HEIGHT.$REPLICA.manifest
```

## Comparing States

A state manifest looks similar to this:

```
FILE TABLE
    idx     |    size    |                               hash                               |                         path
------------+------------+------------------------------------------------------------------+------------------------------------------------------
          0 |        463 | c1710b67f3d16fb461143177af0add8325eaff5d5ea8665f40f3914e99238c58 | canister_states/0000000000f000000101/canister.pbuf
          1 |        194 | ac6bbfe9308920b6aef5f5bd147bfec1ef9f3b37c6ac83a4a5f9676ec2940602 | canister_states/0000000000f000000101/queues.pbuf
          2 |    1626316 | 697ebb869c6e0387f482a1fdf48f0cee46c7e8262b0b3b1d53d59907f52ea61d | canister_states/0000000000f000000101/software.wasm
[...]
      22521 |    2256262 | eaf800300636ec8802c472583a92d3c3fdfbca0f14e57673e90e1e21647a09cf | system_metadata.pbuf
CHUNK TABLE
    idx     |  file_idx  |   offset   |    size    |                               hash
------------+------------+------------+------------+------------------------------------------------------------------
          0 |          0 |          0 |        463 | 62dcd6dfcbb0c023897e97346d9ff0b66d1d2aea5f5f9af104001c20e5adbab4
          1 |          1 |          0 |        194 | c171944a7a89c15ef0dd2a79b34192e313c4e2ec9e89bf5f607db1cb9d258382
          2 |          2 |          0 |    1048576 | 81a3e32e831a5a89171bedfd66973d0a0ee623b170e2ca6112211b269002b626
          3 |          2 |    1048576 |     577740 | 36e9ed789f8d95406c19078592648ad2d54a5f5b22e767c950c6a88c6b8a5d00
[...]
      73572 |      22521 |    2097152 |     159110 | 7825829d0135d625d6550536af98355b640dc0045c16d1c5797b62ba16af7bce


ROOT HASH: c31b0f3dac73ac1c72d8898aa19b549e1a73bf68481310a17718f2dca77b418c
```

The first part of the manifest lists all files that make up the checkpoint,
along with their size, hash and index. The second part lists file chunk hashes
(files are split into fixed size chunks, each of them hashed separately) with
each chunk pointing to the file it is part of (via `file_idx`).

Finally, there is the root hash, i.e. the overall hash of the state. Two
checkpoints whose root hashes are different will also have different hashes for
at least one file (chunk hash differences can be ignored, as different chunk
hashes mean different file hashes).

## Comparing State Files

There are a few types of files within a checkpoint directory. A divergence may
originate in any of them.

 1. `vmemory_0.bin` and `stable_memory.bin` are canister memories (heap and
    respectively stable memory). A difference here would point to nondeterminism
    in Execution.
 2. `software.wasm` is the compiled canister executable. Different `.wasm` files
    would likely also point to an issue in Execution.
 3. `.pbuf` files are Protocol Buffer files that contain subnet state
    (`system_metadata.pbuf` and `subnet_queues.pbuf` in the checkpoint root) or
    canister state (`canister.pbuf` and `queues.pbuf`).

`state-tool` provides the `decode` command for pretty printing the contents of
the latter for easy comparison:

```bash
export REPLICA=2001:470:1:c76:5000:bdff:fe8b:3d7c
prodssh readonly@[$REPLICA]
export HEIGHT=0000000000822e2c
export CANISTER=000000000130013b0101
/opt/ic/bin/state-tool decode --file /var/lib/ic/data/ic_state/checkpoints/$HEIGHT/canister_states/$CANISTER/canister.pbuf > /tmp/$HEIGHT.$CANISTER.canister
```

The resulting text file can be `scp`-ed back to your machine and compared
against the equivalent state file obtained from another replica. The comparison
will likely point to a single field or multiple related fields, which should
provide a hint as to the origin of the divergence.
