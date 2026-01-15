# Service Nervous System (SNS)
A service nervous system, or SNS for short, is an algorithmic DAO that allows
developers to create decentralized, token-based governance systems for their dapps.
Thus, similarly to how the Network Nervous System (NNS) is the open tokenized
governance system that controls the Internet Computer blockchain (IC), SNSs
allow control of dapps in a decentralized way.

This directory contains most of the code for the SNS (see next section for
more details).
Anyone can deploy an SNS and then assign the control of their dapp
canister(s) to this
SNS so that subsequently the dapp can be upgraded via proposals on the
SNS governance.
Alternatively, one can get an SNS that is provided as a system function
by the IC.
For more information about the SNS and how to get one, we refer to
[this documentation](https://internetcomputer.org/docs/current/developer-docs/integrations/sns/).

## SNS Canisters
An SNS consists of the following canisters:
* the _governance canister_ which enables decentralized decision making,
* the _root canister_ which is responsible for upgrading the other SNS canisters
  and the dapp canisters that the SNS controls,
* the _decentralisation swap canister_ (a.k.a. SNS Swap) which facilitates an initial token
swap,
* the _ledger canister_ which determines the balances and transactions
    for a SNS-specific governance token, and
* the _index canister_ which provides a map from ledger accounts to relevant
  transactions.
  
You can find the code implementing most of these canisters here, expect for
the ledger canister and index canister. 
<!--  TODO: add links --> 

## How to deploy and set up your SNS
Please follow the instructions on [this page](https://internetcomputer.org/docs/current/developer-docs/integrations/sns/tokenomics/sns-checklist)
regarding how you can get an SNS.
We recommend also consulting
[this page](https://internetcomputer.org/docs/current/developer-docs/integrations/sns/testing/testing-before-launch)
to learn how to prepare for this step and to learn how an SNS can be tested.

<!--  Outdated: After a successful deployment, your SNS consists of the governance,
ledger, and root canister.
[//]: # TODO - update once we have more canisters
Thereby, the governance canister is the
controller of the root canister and the root canister is the controller
of all other SNS canisters.
You can read all canister's ID as well as the control hierarchy
from the output of the sns-cli tool. 
-->

## How to manage an SNS and interact with it
One the SNS is launched, it has to be managed by the SNS community.
For a guide on some important considerations in SNS management, we refer
to [this page](https://internetcomputer.org/docs/current/developer-docs/integrations/sns/managing/manage-sns-intro).

For interacting with the SNS, users can use a frontend integration or the
command line tool sns-quill.
Both are described in more detail on the Wiki.
<!-- TODO: add appropriate links-->

 
