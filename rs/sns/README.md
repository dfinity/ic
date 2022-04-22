# SNS
A service nervous system, or SNS for short, is an algorithmic DAO that allows
developers to create decentralized, token-based governance systems for their dapps.
Thus, similarly to how the Network Nervous System (NNS) is the open tokenized
governance system that controls the Internet Computer blockchain (IC), SNSs
allow control of dapps in a decentralized way.

This directory contains the code for the SNS.
Anyone can deploy an SNS and then assign the control of their dapp canister(s) to this
SNS so that subsequently the dapp can be upgraded via proposals on the SNS governance.

This README describes how to deploy, interact with, and maintain an SNS.

## SNS Background
A SNS consists of the following canisters:
* the _governance canister_ which enables decentralized decision making,
* the _ledger canister_ which determines the balances and transactions 
  for a SNS-specific governance token,
* the _root canister_ which is responsible for upgrading the other SNS canisters
  and the dapp canisters that the SNS controls.

[//]: # TODO - for more information we refer to [Wiki article]

## How to deploy and set up your SNS
There is a command line tool, sns-cli, that helps with SNS deployment.
Please follow the instructions in [this README](./cli/README.md)
regarding how you can use this tool
to deploy a full SNS, both locally for testing and on the Internet Computer.

The sns-cli tool allows you to initialize the ledger canister with
initial accounts and the governance cansiter with
initial neurons. 
It is recommended that users interact with the SNS 
by using the command line tool sns-quill (see below).
To create the
principals for the initial ledger and neuron 
accounts, users can thus use the sns quill tool 
(see [the sns quill README](./sns-quill/README.md)).
Also, the sns-cli tool allows you to initialize the governance
canister initial parameters.
For many parameters, if no choice is made, the parameters will
be set to a default (see [the README](./cli/README.md) for details).


After a successful deployment, your SNS consists of the governance,
ledger, and root canister.
[//]: # TODO - update once we have more canisters
Thereby, the governance canister is the
controller of the root canister and the root canister is the controller
of all other SNS canisters.
You can read all canister's ID as well as the control hierarchy
from the output of the sns-cli tool.


[//]: # TODO - once you have everything set up, might want to modify
parameters etc. (see cli tool for defaults and see below for configuration tips)

### How to hand over the dapp's control to the SNS
Handing over the control of your dapp canister(s) to the SNS needs
to be done in a separate step after the SNS has been deployed. 
This also allows, for example, to add additional canisters under the SNS's
control over time.

To hand over the control of your dapp to the SNS, set the
dapp canister's controller to the SNS root canister.

You can learn the SNS root canister's ID as follows. 
```shell
TODO
```

You can then set the controller of a dapp canister to SNS
root as follows.
```shell
TODO
```

You may choose to first just _add_ the SNS root canister
as an additional controller to your dapp, test that the
SNS works as you wish, and later remove all remaining controllers.

You can then remove controllers other than the SNS root canister
from the dapp's contollers as follows.
```shell
TODO
```

## How to interact with a SNS
The primary tool for developers and users to interact with the SNS
once it is deployed is the command line tool sns-quill.
Please refer to [this README](./sns-quill/README.md) for a more
detailed description of what commands to use to interact
with the SNS.


## How to configure / maintain an SNS

[//]: # TODO - list the parameters that cannot be set in the initialization tool if any
or just say that all of them can now be adjusted again by proposal


 
