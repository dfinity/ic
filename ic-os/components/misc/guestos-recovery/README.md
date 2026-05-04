# GuestOS Recovery

This directory contains two main components:

## guestos-recovery-upgrader

guestos-recovery-upgrader.sh is a lightweight component that can be triggered from the HostOS limited-console. If triggered, the guestos-recovery-upgrader performs a GuestOS upgrade for the inputted GuestOS update image version.

It is primarily designed to be used in the event of an NNS recovery.

## guestos-recovery-engine

The GuestOS image used in recovery then triggers the `guestos-recovery-engine` service that completes the recovery process. 
