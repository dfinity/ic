# What Is This?

The (NNS) Governance canister is the "heart" of the Network Nervous System
(NNS). This is where people stake ICP (tokens) (i.e. make it not liquid) in
order to create "neurons". Using their neurons, they can vote on proposals (and
make them). Proposals can do things like

  1. Set the code that operates the Internet Computer Protocol (ICP), including
     the Governance canister itself.

  2. Add nodes to a subnet of the IC.

  3. Create a Service Nervous System (SNS). In short, an SNS is to a dapp as the
     NNS is to the IC as a whole. See the rs/sns directory in this repository
     for more information about SNS.

Additional introductory information about the NNS can be found at
https://internetcomputer.org/nns .


# How Do Clients Use It?/Life of a Neuron

As alluded to earlier, there are two MAIN operations that clients perform using
this canister:

1. Stake ICP (tokens)/Create "neurons". A neuron is a voting entity.

2. Vote on proposals, which modify/configure/administer the ICP (platform)
   itself. Neurons are rewarded for voting.

The subsections bellow describe how these operations are performed in more detail.

Neurons can also make proposals (this is where proposals come from), but most
neurons do not do this.


## How to Stake/Create a Neuron

Like all operations that require ICP (tokens), this is a two step process:

0. The user has some principal P. P has some ICP (tokens).

1. By talking to the Ledger canister, P sends ICP (tokens) to the Governance
   canister. N.B. the destination subaccount is NOT the Governance's
   main/default subaccount! Rather, the subaccount is associated with P. More
   precisely, the destination subaccount is a hash and one of the inputs of the
   hash is P (using another input, called "memo", it is possible for P to be
   associated with multiple subaccounts).

2. Governance is not automatically aware of 1, so, P must also tell Governance,
   "check this subaccount, and create a neuron with it.". Governance then checks
   the balance of the subaccount, and if everything checks out, creates a neuron
   N for P.


## How to Vote

Confusingly, using only the steps described in the previous section, the neuron
N is not yet eligible to vote. To do that, the user must (as principal P) must
first modify N so that the ICP is locked up for _more time_. The terminology
that we use for this operation is "increase the dissolve delay". In order to
vote, a neuron's dissolve delay must be at least 6 months. (As of early 2025,
there are debates going on about lower that to 3 months.)

If a neuron is eligible (at the time of proposal creation/submission), P can
vote with it by making one call to the Governance canister.

(Informally, it is easier to say that P votes (via N), but technically, N is the
voting entity.)


# Architecture

TODO
