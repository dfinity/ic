# Security Policy


1. [Overview](#overview)
2. [Reporting Vulnerability](#reporting-vulnerability)
3. [Incident Handling](#incident-handling)
4. [Bug Bounty Rewards Policy](#bug-bounty-rewards-policy)


<a name="overview"></a>
# Overview 

Community plays an important role in keeping the Internet Computer’s ecosystem safe and secure. This policy seeks to establish a process for anyone to communicate and discuss the vulnerabilities they found in the Internet Computer Platform in a responsible manner. 

<a name="reporting-vulnerability"></a>
# Reporting Vulnerability 

DFINITY foundation is committed to resolve any serious security issues in a timely and transparent manner. Our Bug Bounty Program provides rewards as a way to provide encouragement. The community and security researchers are welcome to share any security issues that they consider relevant but the rewards will be provided to those issues that are shown to be present in the components that are part of the core Internet Computer Platform. The objective scope is provided in the following section.

### Vulnerability Disclosure Policy

1. Submit your security finding using this [web form](https://dfinity.org/bug-bounty/submit). The DFINITY Team will reach out to you via email within 3 business days from the time of submission. Ensure that you have provided the correct contact information.
2. Provide all relevant information related to the security issue like, but not limited to, the following: Proof of Concept, Methodology, Security tools used, Context of discovery, Your analysis of the issue, Logs and screenshots, Potential solution, etc.
3. Treat the report as confidential until the respective teams can fix the issue. Allow reasonable time to fix the issue.
4. Public disclosure of the vulnerability without abiding by this policy makes it ineligible for rewards.
5. Do not engage in social engineering techniques or spear-phishing campaigns.
6. Do not cause any harm to the data and system.
7. Submit all relevant security issues, but for it to be considered for rewards, the issue must be part of the core Internet Computer platform as objectively pointed out by the below ‘Scope and Targets’ section. All applications that are not part of the Internet Computer Platform that contains public information, for example, www.dfinity.org website are ineligible for rewards.
8. Bugs in third-party code are strictly excluded from the scope.
9. Duplicate reports and closely related submissions will be dealt with on a case-by-case basis. If the submissions are determined to be genuine, they may be rewarded based on a lower rewards scale.
10. Act responsibly and in good faith during the disclosure process.

### Scope and Targets

The primary targets for this vulnerability rewards program are as follows

1. Core Internet Computer Protocol stack
2. Network Nervous System canisters
3. Network Nervous System Frontend Dapp
4. Internet Identity: Internet Computer Authentication System
5. SDK, CDK, Candid & Motoko smart contract language
6. Internet Computer Infrastructure

#### Core Internet Computer Protocol stack

The Internet Computer Protocol is a distributed protocol run by multiple nodes that constitutes the Internet Computer blockchain network platform.In order to get a good overview of the Internet Computer and to get started with it please see [here](https://internetcomputer.org/how-it-works). 

Source code: [https://github.com/dfinity/ic](https://github.com/dfinity/ic)

#### Network Nervous System (NNS) canisters

All aspects of Internet Computer behavior are governed by the community of enthusiasts and users of InternetComputer through a democratic governance system called the Network Nervous System (NNS). A high-level introduction to the operation of the system can be obtained from [here](https://internetcomputer.org/nns/) and [this medium post](https://medium.com/dfinity/the-network-nervous-system-governing-the-internet-computer-1d176605d66a). 

Source code: [https://github.com/dfinity/ic/tree/master/rs/nns](https://github.com/dfinity/ic/tree/master/rs/nns)

#### ICP Ledger and ICRC-1/2 Token Standards

The ICP Ledger canister implements the Internet Computer’s native token ICP. When the ICP ledger came into existence there wasn't a standard for ledger implementations in the IC ecosystem. In the later stages, as IC evolved, Fungible tokens in the IC ecosystem were standardized in the form of ICRC-1 and ICRC-2 token standards. More documentation on the ledger can be found [here](https://internetcomputer.org/docs/current/developer-docs/integrations/ledger/).

Source code: [https://github.com/dfinity/ic/tree/master/rs/rosetta-api](https://github.com/dfinity/ic/tree/master/rs/rosetta-api)

#### Network Nervous System (NNS) Frontend dApp

The NNS front-end dApp provides a user-friendly way to interact with the Internet Computer’s governance system. With it, you can, for example
* Send/receive ICP
* Stake neurons
* Create canisters
* Top-up canisters with cycles
* View and vote on NNS proposals
* Participate in SNS swaps and governance

Source code: [https://github.com/dfinity/nns-dapp](https://github.com/dfinity/nns-dapp)

Domain: [https://nns.internetcomputer.org](https://nns.internetcomputer.org)

#### Internet Identity: Internet Computer Authentication System

The Internet Identity is an anonymous blockchain authentication framework supported by the Internet Computer. It builds on Web Authentication (WebAuthn) API supported by modern web browsers and operating systems. Here is the quick start [guide](https://internetcomputer.org/how-it-works/web-authentication-identity/) to Internet Identity and also check out the following [video](https://www.youtube.com/watch?v=9eUTcCP_ELM).

Source code: [https://github.com/dfinity/internet-identity](https://github.com/dfinity/internet-identity)

Domain: [https://identity.internetcomputer.org/](https://identity.ic0.app/)

#### Service Nervous System (SNS)

The SNS feature on the Internet Computer allows the dApps (Decentralized Applications) developers to roll out their own DAO (Decentralized Autonomous Organization). The SNS documentation can be found [ here](https://internetcomputer.org/docs/current/developer-docs/integrations/sns/).

Source code: [https://github.com/dfinity/ic/tree/master/rs/sns](https://github.com/dfinity/ic/tree/master/rs/sns)

#### Chain-key Bitcoin (ckBTC)

The ckBTC is a ICRC-2 compliant token that has brought Bitcoin into the InternetComputer’s ecosystem. The ckBTC is backed 1-to-1 by BTC. It has 2 important components:
* ckBTC Ledger
* ckBTC Minter
The documentation for ckBTC can be found [here](https://internetcomputer.org/docs/current/developer-docs/integrations/bitcoin/ckbtc).

Source code: [https://github.com/dfinity/ic/tree/master/rs/bitcoin/ckbtc](https://github.com/dfinity/ic/tree/master/rs/bitcoin/ckbtc).

#### SDK, CDK, Motoko smart contract language & Dev Tools

Motoko is the Internet Computer’s native language to write smart contracts. The Internet Computer ecosystem provides SDKs (Software Development Kit), CDKs (Canister Development Kit), libraries and other tools that supports developing smart contracts, dApps, clients in other languages like RUST and also simplifies the interaction with the platform.

Source code:
* [https://github.com/dfinity/motoko-base](https://github.com/dfinity/motoko-base)
* [https://github.com/dfinity/motoko](https://github.com/dfinity/motoko)
* [https://github.com/dfinity/sdk](https://github.com/dfinity/sdk)
* [https://github.com/dfinity/cdk-rs](https://github.com/dfinity/cdk-rs)
* [https://github.com/dfinity/agent-js](https://github.com/dfinity/agent-js)
* [https://github.com/dfinity/agent-rs](https://github.com/dfinity/agent-rs)
* [https://github.com/dfinity/candid](https://github.com/dfinity/candid)
* [https://github.com/dfinity/quill](https://github.com/dfinity/quill)

#### Infrastructure

##### IC-OS

The node software runs on the virtual machine termed ‘GuestOS’ that in turn runs on ‘HostOS’. In addition to these OSes, the boundary node systems have their own operating system ‘Boundary-guestOS’. Finally, the ‘SetupOS’ is used to install and set up a node. The details, documentation and scripts can be found [here](https://github.com/dfinity/ic/tree/master/ic-os). 

##### Boundary Nodes

One of the major components of the Internet Computer infrastructure are the boundary nodes. The boundary nodes sit on the perimeter and act as a gateway into the Internet Computer platform. Here is the list of boundary node domains:

    1. [https://github.com/dfinity/ic/tree/master/rs/boundary_node](https://github.com/dfinity/ic/tree/master/rs/boundary_node)
    2. boundary.icp0.io
    3. boundary.ic0.app
    4. boundary.dfinity.network

##### Other Infrastructure

In addition to the boundary nodes there are additional infrastructure assets that support the operations of the Internet Computer.  Here is the list of the domains:

    1. icp0.io
    2. raw.icp0.io
    3. nns.internetcomputer.org
    4. identity.internetcomputer.org
    5. icp-api.io
    6. icp[1-5].io
    7. ic0.app
    8. raw.ic0.app

### Out of Scope

We encourage community members and security researchers to report all relevant issues that they think have security implications for the platform. But all public websites, 3rd party libraries and applications are out of scope for the bug bounty program.

<a name="incident-handling"></a>
# Incident Handling

Once a submission has been made, DFINITY Foundation will respond within 3 business days. All valid security bugs will be handled in accordance with the [Security Patch Policy](https://dashboard.internetcomputer.org/proposal/48792) and will trigger an internal incident response process. We will keep you updated and work with you through the process. Once the security bug has been resolved a communication will be made to the community describing the Incident where we will provide an acknowledgment for your efforts and soon follow it up with the rewards.

<a name="bug-bounty-rewards-policy"></a>
# Bug Bounty Rewards Policy

The following section seeks to standardize the policy and process for the rewards allocation and distribution for the identified security bugs to ensure transparency, consistency and fairness.

<table>
  <tr>
   <td>Severity Category
   </td>
   <td>Rewards
   </td>
  </tr>
  <tr>
   <td><strong>CRITICAL</strong> 
<p>
The attack is easy to perform at a low cost and has a severe global impact.
<p>
Examples - Disclosure of subnet key shares, compromise of the integrity of the consensus process, for example,  insertion of an arbitrary block into the blockchain, RCE in internal networks, memory underflow/overflow issues resulting in theft or illegal minting of exorbitant ( > $1M) amount of ICPs/Cycles.
   </td>
   <td>$25000 -  $50000
   </td>
  </tr>
  <tr>
   <td><strong>HIGH</strong> 
<p>
The attack is relatively straightforward but may have additional constraints that may affect the ease or cost of the attack to a certain degree but still with a significant impact.
<p>
Example - A vulnerability that induces unauthorized access to neurons (access control bypass) but requires a significant amount of work per neuron, memory corruption of canisters resulting in loss of integrity but constrained by a limiting factor such as being exploitable only on canisters with certain pre-existing properties.
   </td>
   <td>$10000 - $25000
   </td>
  </tr>
  <tr>
   <td><strong>MEDIUM</strong>
<p>
The attack is difficult to perform, requires significant technical know-how and cost or the target may have to satisfy strict requirements in order to make a significant impact. Also, the attack that is simpler to perform but with moderate impact falls under this category.
<p>
Example - Memory corruption resulting in the crashing of a replica process, Client-side vulnerability that allows stealing of credentials or keys from the client (e.g., browser) by manipulating the user.
   </td>
   <td>$2000 - $10000
   </td>
  </tr>
  <tr>
   <td><strong>LOW</strong>
<p>
The attack that is very difficult to perform or has a minor impact falls under this category.
<p>
Example - A bug resulting in an attacker controlling what is displayed to the user without affecting the server-side data, UI redress, a bug that is not demonstrably exploitable but could be exploitable with more research.
   </td>
   <td>$500 to $2000
   </td>
  </tr>
  <tr>
   <td><strong>INFORMATIONAL</strong>
   </td>
   <td>NO REWARD
   </td>
  </tr>
</table>

### Rewards Payment Process

1. First, obtain an ICP wallet address. You may use any valid ICP wallet address that best fits your needs and convenience. Below are some custody option examples that you can choose from to obtain a KYC'ed ICP wallet address. 
    1. Self-Custody
        1. **NNS dApp**
            1. Learn[ how to get started](https://medium.com/dfinity/getting-started-on-the-internet-computers-network-nervous-system-app-wallet-61ecf111ea11).
        2. **Keysmith**
            1. Follow[ step-by-step instructions](https://mcusercontent.com/33c727489e01ff5b6e1fb6cc6/files/845941f5-7fcd-312f-6173-0970d12d2486/Self_Custody_Setup_via_Keysmith.pdf) to set up self-custody via Keysmith.
    2. 3rd Party Custody Solutions
        1. [Coinbase Pro/Retail](https://pro.coinbase.com/)
        2. [Klever](https://klever.io/)
        3. [Plug wallet](https://plugwallet.ooo/)
        4. [Stoic wallet](https://www.stoicwallet.com/)
        5. [Coinbase Custody](https://www.coinbase.com/custody)
2. Once your ICP wallet address is ready, send the address along with the email address you plan to associate your account with **<span style="text-decoration:underline;">before</span>** starting the KYC process. The provided email address will be whitelisted on the KYC website (~3 working days).
3. You will receive an email notification once your email has been whitelisted. **[Submit your KYC application](https://kyc.dfinity.org/)** by clicking on ‘Other’ and entering the email address you provided to receive a unique link to begin the verification process. The KYC will be performed by a 3rd party and all information that the DFINITY Foundation receives is the email address and the ICP wallet address.  

Make sure at every stage of the onboarding process that your wallet address and associated email address are entered correctly to avoid any delay. As a reminder, DFINITY is not responsible for your asset custody nor will it be held accountable for any loss of your ICP distributed to you in the ICP wallet address you have provided.

If you have any questions regarding your KYC application or obtaining your ICP wallet address, please contact [DFINITY Support](https://support.dfinity.org/hc/en-us).
