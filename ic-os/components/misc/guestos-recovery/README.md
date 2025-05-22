# GuestOS Recovery

This directory contains two main components:

## guestos-recovery-upgrader

The guestos-recovery-upgrader service is a lightweight component that can be triggered from the host machine boot menu (with a 15-second timeout) by inputting recovery, url, and hash boot parameters. If triggered, the guestos-recovery-upgrader performs a GuestOS upgrade for the inputted download url.

It is primarily designed to be used in the event of an NNS recovery.

## guestos-recovery-engine

The GuestOS image used in recovery then triggers the `guestos-recovery-engine` service that completes the recovery process. 
