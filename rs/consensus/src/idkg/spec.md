# Canister Threshold Signatures

## Goal

We want canisters to be able to hold BTC, ETH, SOL and other tokens, and 
for them to create transactions on other networks, such as bitcoin, ethereum.
solana, etc. Since those networks use specific signature schemes, a canister
must be able to create signatures adhering to these schemes. Since a canister cannot
hold the secret key itself, the secret key will be shared among the replicas
of the subnet, and they must be able to collaboratively create threshold
signatures. Currently, we support threshold ECDSA and threshold Schnorr.

## High-level design

Each subnet may have several threshold master keys, indexed by a key ID.
However, the process for each key individually is largely the same. Therefore 
for now, we will assume just a single key. From this key, we will derive per-canister keys. 

A canister can via a system API request an ECDSA or Schnorr signature.
The correpsonding request context is stored in the replicated state. 
Consensus will observe the new request context and begin working on it as soon as the context is "completed".
By "completed" we mean that the context was matched to a "pre-signature" and assigned a random nonce. 
This is done by the DSM, which updates signature request contexts with pre-signatures that were delivered by consensus.

Once the request context contains the pre-signature and the random nonce,
the IDKG client of consensus will broadcast signature shares for the request. 
As soon as enough signature shares exist, a blockmaker will combine the signature shares,
and include the aggregated signature in the block.

The block (batch) containing the aggregated signature is subsequently delivered to execution,
where the request context is removed and a response to the requesting canister is inducted.

### Distributed Key Generation & Transcripts
To create threshold signatures we need a *transcript* that gives all
replicas shares of a secret key. However, this is not sufficient: we
need additional transcripts to share the ephemeral values used in a
signature. 

The creation of one ECDSA signature requires a transcript that
shares the ECDSA signing key `x`, and additionally four DKG transcripts,
with a special structure: we need transcripts `t1`, `t2`, `t3`, `t4`, such
that `t1` and `t2` share random values `r1` and `r2` respectively, `t3`
shares the product `r1 * r2`, and `t4` shares `x * r2`.

Similarly, the creation of one Schnorr signature requires a transcript that
shares the Schnorr signing key `x`, and one additional DKG transcript `t`,
where `t` shares a random value `r`.

Such transcripts are created via an 
*interactive distributed key generation protocol (IDKG)*. 
The DKG for these transcripts must be computationally efficient,
because we need four transcripts per signature, and we want to be able to
create many signatures. 
Because of this, we used an interactive DKG, instead of non-interactive DKG like we do for our threshold BLS signatures.

Consensus orchestrates the creation of these transcripts (here called a `Transcript`),
which will be stored in blocks.
Blocks will also contain
parameter specs (here called a `TranscriptParam`) indicating which transcripts should be created. 
Such parameter specs come in
different types, because some transcripts should share a random value, while
others need to share the product of two other transcripts. 
Since transcripts are fairly large objects, in order to reduce the on-chain storage,
compact *references* to transcripts are sometimes stored instead (here called a `TranscriptRef`);
such a reference stores just the metadata associated with the transcript, 
and the height of the (finalized) block where the transcript itself is stored.

A transcript consists of a set of a set of *supported dealings* as well as a *polynomial commitment*.
A *dealing* consists of encryptions all of the shares of a shared secret as well as a *polynomial commitment*.
A *supported dealing* consists of a dealing together with a quorum of *support shares*,
which guarantee that a sufficient number of encrypted shares are valid.
Even if some shares of such a dealing are invalid, a *complaint/opening mechanism* may be used to
correct any of these invalid shares using the valid shares.


This specification fleshes out the design in the *design doc*: https://eprint.iacr.org/2022/506.
The companion paper https://eprint.iacr.org/2021/1330 is essential in understanding 
the security properties of the protocol.


## Implementation Specification


### General Notes

We flag things with DIFF that are known to be different from the
current code base.


#### 3-valued boolean logic:
We treat `Option<bool>` as standard 3-valued boolean logic: 
true, false, or Idk.
````
Rules:  false && None == false
        true  && Idk == Idk
        false || Idk == Idk
        true  || Idk == true
        exists is treated as repeated ||
        forall is treated as repeated &&
````
This 3-valued boolean logic is mostly used to model the situation where the crypto component is unable
(for whatever reason) to either validate or invalidate a given cryptographic object.

Note that the registry and secret key store are not mentioned explicitly
in the logic --- one can think of them as "global variables".

Some things are still not specified here:
all things related to algorithm IDs
and key IDs, as well as processing time-outs for signing requests. 

### Basic types associated with transcripts and dealings


```rust
struct DealingBase {
// The object that is actually hashed and signed in a Dealing.
    transcript_id: TranscriptId,
    commitment: PolynomialCommitment,
    ciphertext: MEGaCiphertext,
    proof: Option<ContextualProof>
    fn key() -> (TranscriptId, NodeID) { return (transcript_id, dealer_id) }
}

struct Dealing extends struct DealingBase { 
// We'll use C++like OO notation, so Dealing contains all the fields of DealingBase, without qualification.
// This is just for convenience.
    dealer_id: NodeId,
    sig: Sig,
}
```

NOTE:  `(dealer_id,sig)` in `Dealing` corresponds to a `BasicSignature` in the code base. 

````rust
struct TranscriptId {
    id: u64, 
    // a counter, incremented every time we generate a new transcript param

    source_subnet_id: SubnetId,
    // ID of the subnet that initiated the construction of the transcript and
     // on which the dealers are hosted

    source_height: Height  
    // height at which the construction of the transcript was initiated, i.e., the height
    // at the corresponding transcript param was added to the pre_signatures_under_construction
    // field in the payload


}
````

NOTE: the `source_height` field may be used to manage purging and downloading 
of related artifacts --- 
dealings, support shares, complaints, and openings ---
each of which contains a `transcript_id`.  
Let `h` be the current finalized height of a node.
If `transcript_id.source_height > h + c` for some small constant `c >= 0`, 
the node may choose to
delay downloading of the artifact.
If `transcript_id.source_height < h`, the node may choose to purge the artifact, 
unless the
`transcript_id` appears in an object contained in the 
payload of the finalized tip.
This does not apply when we are doing xnet resharing on the target subnet,
as the `source_height` field refers to a a height on the source subnet,
not the target subnet.

````rust
enum Operation<M,U=M> { 
// The second parameter U defaults to M if not specified.
// An explicit parameter U is only used to define the type 
// TranscriptDependencies below.
    Random,                    // masked
    RandomUnmasked,            // unmasked
    UnmaskedTimesMasked(U, M), // masked
    ReshareOfMasked(M),        // unmasked
    ReshareOfUnmasked(U),      // unmasked
}

enum OperationType { Masked, Unmasked };

fn get_op_type<M,U>(Operation<M,U> op) -> OperationType
{
    match (op) {
        Random =>                   return Masked;
        RandomUnmasked =>           return Unmasked;
        UnmaskedTimesMasked(_,_) => return Masked;
        ReshareofMasked(_) =>       return Unmasked;
        ReshsareOfUnmasked(_) =>    return Unmaksed;
    }
}
````




````rust
struct TranscriptBase {
    // This is the "metadata" used for various transcript-related objects
    transcript_id: TranscriptId,
    registry_version: RegistryVersion,

    opt_target_subnet_id: Option<SubnetId>;
    // Only used for xnet resharing. 
    // The subnet hosting the receivers is by default the same as transcript_id.source_subnet_id, 
    // and is otherwise given by opt_target_subnet_id

    fn receivers() -> Set<NodeId> { 
       // INVARIANT: the receiver set is always determined by the registry_version.
       // DIFF: for historical reasons, the code stores an explicit receivers set, 
       // but it should always be equal to this value.
        match (opt_target_subnet_id) {
            None => return get_subnet_nodes(registry_version, transcript_id.source_subnet_id); 
            Some(target_subnet_id) => return get_subnet_nodes(registry_version, target_subnet_id); 
        }
    }
}

struct TranscriptXBase<T> extends struct TranscriptBase  {
    // This is "extended metadata", which includes information about the input transcripts
    // and corresponding operation
    operation: Operation<T>,

    fn get_op_type() -> OperationType { return op_type(operation); }

    fn dealers() -> Set<NodeId> { 
       // INVARIANT: dealers are always the receivers for any inputs; in the case of Random,
       // where there are no inputs, dealers == receivers. 
       // DIFF: for historical reasons, the code stores an explicit dealers set, 
       // but it should always be equal to this value.
        match (operation) {
            Random => return receivers();
            UnmaskedTimesMasked(u, m) => return u.receivers(); // INVARIANT: u.receivers() == v.receivers()
            ReshareofMasked(m) => return m.receivers();
            ReshsareOfUnmasked(u) => return u.receivers();
        }    
    }
}


struct Transcript extends struct TranscriptXBase<TranscriptRef> {
    // DIFF: in the code, we only encode the transcript IDs of the inputs, whereas here
    // we encode the metadata for the inputs, which makes it easier to express
    // and enforce invariants. Also in the code, the operation is encoded in a different
    // but equivalent way
    dealings: Set<SupportedDealing>,
    commitment: PolynomialCommitment,
}

struct TranscriptRef extends struct TranscriptBase {
    // A TranscriptRef is like a Transcript, but with only the metadata
    // and a pointer to the extended metadata and data itself

    // DIFF: in the code, only transcript_id and height are recorded.
    // Here, we record all the metadata, so that we can more easily 
    // express and enforce invariants. 

    height: Height // height at which the actual transcript is stored

    op_type: OperationType; // the operation type
    // NOTE: this is only used to express and enforce constraints
    // DIFF: the code enocodes op_type in a different way, using more compile-time data

    fn get_op_type() -> OperationType { return op_type; }

    // NOTE: while a TranscriptRef provides the receivers() and op_type() functionality,
    // it does not provide the dealers() functionality.
}

struct TranscriptParam extends struct TranscriptXBase<Transcript> { }

struct TranscriptParamRef extends struct TranscriptXBase<TranscriptRef> { }
````



````rust
struct UnmaskedSecretShare {
    share: Scalar
}

struct MaskedSecretShare {
    share: Scalar,
    mask:  Scalar
}

enum SecretShare {
    Masked(MaskedSecretShare),
    Unmasked(UnmaskedSecretShare)
}

type TranscriptDependencies = Operation<MaskedSecretShare,UnmaskedSecretShare>;
````


### Convenience functions

These are the only functions that are used to build `TranscriptParamRef`'s.
They enforce various invariants.

DIFF: the invariants enforced here are actually somewhat simpler and stricter than those enforced by the code.

````rust
fn build_random_param_ref(
    uid_generator: UIDGenerator,
    registry_version: RegistryVersion,
    height: Height,
) -> (TranscriptParamRef, UIDGenerator)
{
     uid_generator.next_transcript_id(height);
     param_ref= TranscriptParamRef(
                    TranscriptXBase<TranscriptRef>(
                        TranscriptBase(transcript_id, registry_version, None), 
                        Operation<TranscriptRef>::Random));
    return (param_ref, uid_generator);
    
}

fn build_random_unmaskef_param_ref(
    uid_generator: UIDGenerator,
    registry_version: RegistryVersion,
    height: Height,
) -> (TranscriptParamRef, UIDGenerator)
{
     uid_generator.next_transcript_id(height);
     param_ref= TranscriptParamRef(
                    TranscriptXBase<TranscriptRef>(
                        TranscriptBase(transcript_id, registry_version, None), 
                        Operation<TranscriptRef>::RandomUnmasked));
    return (param_ref, uid_generator);
    
}

fn build_unmasked_times_masked_param_ref(
    uid_generator: UIDGenerator,
    registry_version: RegistryVersion,
    height: Height,
    u: TranscriptRef,
    m: TranscriptRef,
) ->  (TranscriptParamRef, UIDGenerator)
{
    assert!(u.get_op_type() == Unmasked && m.get_op_type() == Masked && u.receivers() == m.receivers());

    uid_generator.next_transcript_id(height);
    param_ref = TranscriptParamRef(
                    TranscriptXBase<TranscriptRef>(
                        TranscriptBase(transcript_id, registry_version, None), 
                        Operation<TranscriptRef>::UnmaskedTimesMasked(u, m)));
    return (param_ref, uid_generator);
}


fn build_reshare_of_masked_param_ref(
    uid_generator: UIDGenerator,
    registry_version: RegistryVersion,
    height: Height,
    m: TranscriptRef,
) -> (TranscriptParamRef, UIDGenerator)
{
    assert!(m.get_op_type() == Masked);
 
    uid_generator.next_transcript_id(height);
    param_ref = TranscriptParamRef(
                    TranscriptXBase<TranscriptRef>(
                        TranscriptBase(transcript_id, registry_version, None), 
                        Operation<TranscriptRef>::ReshareOfMasked(m)));
    return (param_ref, uid_generator);
}

fn build_reshare_of_unmasked_param_ref(
    uid_generator: UIDGenerator,
    registry_version: RegistryVersion,
    height: Height,
    u: TranscriptRef,
    opt_target_subnet_id: Option<SubnetId>,
) -> (TranscriptParamRef, UIDGenerator)
{
    assert!(u.get_op_type() == Unmasked);

    uid_generator.next_transcript_id(height);
    param_ref = TranscriptParamRef(
                    TranscriptXBase<TranscriptRef>(
                        TranscriptBase(transcript_id, registry_version, opt_target_subnet_id), 
                        Operation<TranscriptRef>::ReshareOfUnmasked(u)));
    return (param_ref, uid_generator);
}
````



These are the only functions that 
are used to build `Transcript`'s and `TranscriptRef`'s.

````rust
fn build_transcript(
    param_ref: TranscriptParamRef,
    dealings: Set<SupportedDealing>,
    commitment: PolynomialCommitment,
) -> Transcript
{
    return Transcript(
               TranscriptXBase<TranscriptRef>(param_ref), 
               dealings, 
               commitment);
} 

fn build_transcript_ref(
    transcript: Transcript,
    height: Height,
) -> TranscriptRef
{
    return TranscriptRef(TranscriptBase(transcript), height, transcript.get_op_type());
}
````

Functions for computing support and collection thresholds

````rust
fn support_threshold(transcript_param_ref: TranscriptParamRef) -> Integer
// returns the number of support shares required per supported dealing
{
    n = Card(transcript_param_ref.receivers());
    f = Floor((n-1)/3);
    return 2*f+1; 
}

fn collection_threshold(transcript_param_ref: TranscriptParamRef) -> Integer
// returns the number of supported dealings required to build a transcript
{
    n = Card(transcript_param_ref.dealers());
    f = Floor((n-1)/3);
    match (operation) {
        UnmaskedTimesMasked(_) => return 2*f+1;
        _ => return f+1;
    }
}
````



### Pool management

#### Dealings

````rust
fn add_dealings_to_validated_pool(
    my_node_id: NodeId,
    validated_pool: Pool,
    finalized_chain: Chain,
) -> Set<Dealing|Complaint>
// Returns a set of new self-generated dealings/complaints to add to the validated pool. 
// Complaints may be generated if the input transcripts to a new transcript are not locally valid.
{
    requested_transcript_params: Set<TranscriptParam>
      = get_requested_transcript_params(finalized_chain);

    // keep only transcript params for which my_node_id is among the dealers
    S0 = { transcript_param in requested_transcript_params: my_node_id in transcript_param.dealers() };

    // filter out any transcript params for which a dealing has already been generated
    S1 = { transcript_param in S0:
               !(exists dealing in validated_pool of type Dealing: 
                     dealing.key() == (transcript_param.transcript_id, my_node_id) };

    // for each transcript_param in S1, try to generate a dealing or some complaints
    S2 = union over transcript_param in S1: 
             generate_dealing_or_complaints(transcript_param, my_node_id, validated_pool);

    return S2;
}

fn generate_dealing_or_complaints(
    transcript_param: TranscriptParam,
    my_node_id: NodeId,
    validated_pool: Pool,
) -> (Set<Dealing>)|(Set<Complaint>)
// Attempt to generate a dealing, which is returned as a singleton set.
// However, before that happens, we must load the shares of the input transcripts (if any).
// This may fail and may result in the generation of complaints.
{
    match (load_transcript_dependencies(transcript_param, my_node_id, validated_pool)) { 
        Ok(dependencies) => return generate_dealing(transcript_param, my_node_id, dependencies);
        Err(complaints) => return complaints; 
    }
}


fn load_transcript_dependencies(
    transcript_param: TranscriptParam,
    my_node_id: NodeId,
    validated_pool: Pool,
) -> Result<TranscriptDependencies,Set<Complaint>>
// Tries to compute the secret shares for the input transcripts.
// If this fails, a set of complaints is returned.
// Whenever secret shares are successfully computed, these shares may be cached for future use.
{
    // TODO: this is easily implemented using the load_transcript function below
}


fn generate_dealing(
    transcript_param: TranscriptParam,
    my_node_id: NodeId,
    dependencies: TranscriptDependencies
) -> Set<Dealing>
// Generates the corresponding dealing.
// May return empty set if crypto layer fails for any reason.
// Otherwise returns singleton set.
{
    // TODO
}
````

````rust
fn move_dealings_to_validated_pool(
    unvalidated_pool: Pool,
    validated_pool: Pool,
    finalized_chain: Chain,
) -> (Set<Dealing>, Set<Dealing>, Set<Dealing>) 
// Returns (V, I, R), where 
//    V is the set of dealings to be moved from the unvalidated pool to the validated pool,
//    I is the set of dealings to be be removed from the unvalidated pool and processed as HandleInvalid,
//    R is the set of dealings to be removed from the unvalidated pool and processed as RemoveFromUnvalidated.
// Some deduplication is performed.
// INVARIANT: after V is added to the validated pool, there are no dealings with duplicate key() values.
// NOTE: since deduplication is done locally, different replicas may end up
// with different dealings in their validated pools.  Dealings in I are patently invalid, and receipt 
// of such a dealing from a replica implicates that replica as corrupt. 
// Dealings in R are valid except that adding them to the validated pool would invalidate the above invariant.
{
    requested_transcript_params: Set<TranscriptParam>
      = get_requested_transcript_params(finalized_chain);

    validated_dealings = { dealing: dealing in validated_pool of type Dealing }; 

    V=I=R={};
    for (each dealing in unvalidated_pool of type Dealing) {
        is_valid = validate_dealing(dealing, requested_transcript_params);
        if (is_valid == Some(false))
            I += {dealing};  // invalid
        else if (exists dealing1 in (validated_dealings + V): dealing1.key() == dealing.key())
            R += {dealing};  // duplicate
        else if (is_valid == Some(true))
            V += {dealing};  // valid and not a duplicate
        // else leave in unvalidated pool
    }

    return (V, I, R);
}


fn validate_dealing(
    dealing: Dealing, 
    requested_transcript_params: Set<TranscriptParam>,
) ->  Option<bool>
// NOTE: for a variety of reasons, the crypto component may not be able to
// successfully determine the validity of a dealing, which is why we return a
// 3-valued boolean Option<bool>.
// See above for conventions on 3-valued boolean logic.
// We will also return None if there is no matching transcript_param.
{
    if  (exists transcript_param in requested_transcript_params: 
              transcript_param.transcript_id == dealing.transcript_id) {

        // we can only determine the validity of dealing if we have a corresponding requested transcript_param

        return  dealing.dealer_id in transcript_param.dealers() && 
                validate_dealing_commitment(dealing, transcript_param) &&
                validate_dealing_ciphertext(dealing, transcript_param) &&
                validate_dealing_proof(dealing, transcript_param) &&
                validate_dealing_sig(dealing, transcript_param)); 
    } 

    return None;
}
````


Auxiliary dealing validation functions


````rust
fn validate_dealing_commitment(dealing: Dealing, transcript_param: TranscriptParam) -> Option<bool>
{
    n = Card(transcript_param.receivers());
    f = Floor((n-1)/3);
    // check that dealing.commitment consists of f+1 group elements
}

fun validate_dealing_ciphertext(dealing: Dealing, transcript_param: TranscriptParam) -> Option<bool>
{
    n = Card(transcript_param.receivers())
    // check that the symmetric part of dealing.ciphertext consists of n scalars or scalar pairs,
    //    depending on whether transcript_param.operation indicates that this is 
    //    an unmasked or masked dealing
    // check that the asymmetric part of dealing.ciphertext is properly formatted with a valid PoP 
}

fn validate_dealing_proof(dealing: Dealing, transcript_param: TranscriptParam) -> Option<bool>
{
    // verify dealing.proof, based on transcript_param.operation
}

fn validate_dealing_sig(
    dealing: Dealing, 
    transcript_param: TranscriptParam, 
) -> Option<bool>
{
    return verify_sig(dealing.dealer_id, transcript_param.registry_version,
                      dealing.sig, DealingBase(dealing))
}
````

#### Dealing support


````rust
struct SupportShare {
    transcript_id: TranscriptId, 
    dealer_id: NodeId,
    dealing_hash: Hash,
    multi_sig_share: MultiSigShare, 
    // multi-signature share of a Dealing, which includes the signer ID  

    fn key() -> (TranscriptId, NodeId) { return (transcript_id, dealer_id) }
    fn signer() -> NodeId { return multi_sig.signer() }
}


struct SupportedDealing extends Dealing {
    multi_sig: MultiSig 
    // multi-signature of a dealing, which includes the set of signer IDs
}

struct MultiSignatureShare {
    fn signer() -> NodeId; // return ID of signer
}

struct MultiSig {
    fn signers () -> Set<NodeId>; // return the set of signer IDs
}
````


````rust
fn add_support_shares_to_validated_pool(
    my_node_id: NodeId,
    validated_pool: Pool,
    finalized_chain: Chain,
) -> Set<SupportShare>
// Returns a set of new self-generated support shares to add to the validated pool. 
{
    requested_transcript_param_refs: Set<TranscriptParamRef>
      = get_requested_transcript_param_refs(finalized_chain);
    // NOTE: we only require param refs here, which helps to facilitate xnet resharing

    S = union over dealing in validated_pool of type Dealing: 
             generate_support_share(dealing, requested_transcript_param_refs, my_node_id, validated_pool);

    return S;

}

fn generate_support_share(
    dealing: Dealing,
    requested_transcript_param_refs: Set<TranscriptParamRef>,
    my_node_id: NodeId,
    validated_pool: Pool,
) -> Set<SupportShare>
// return empty set of or singleton
{
    if (exists transcript_param_ref in requested_transcript_param_refs:
            transcript_param_ref.transcript_id == dealing.transcript_id && // check if this is a requested transcript_id
            my_node_id in transcript_param_ref.receivers() && // check if we are one of the receivers
            !(exists share in validated_pool of type SupportShare: // check if we already generated a support share
                  share.key() == dealing.key() &&
                  share.multi_sig_share.signer() == my_node_id)) {

        match (locally_validate_dealing(dealing, my_node_id, transcript_param_ref.registry_version)) { 

            Some(true) => {
                // the dealing also passes private validation
                match (generate_multi_sig_share(my_node_id, transcript_param_ref.registry_version, dealing)) {
                    Some(sig) => return { SupportShare(dealing.transcript_id, dealing.dealer_id,  
                                                       hash(dealing), my_node_id, sig); };
                    None => return { };
                }        
            }

            Some(false) => return { };
            // DIFF: the code actually removes a dealing if local validation fails. We do not recommend that.
            // FIXME: need to double check
            // NOTE: an implementation may want to cache this result to avoid re-computation

            None  => return { }; // transient validation error

    }
    else {
         return { };
    }
}


fn locally_validate_dealing(
    dealing: Dealing, 
    my_node_id: NodeId,
    registry_version: RegistryVersion,
                        
) -> Option<bool>
// decrypt and check my own share 
{
    match (decrypt_and_validate_my_share(dealing, my_node_id, registry_version) {
        Some(Ok(secret_share)) => return Some(true);
        Some(Err) => return Some(false);
        None => return None;
    }
}


fn decrypt_and_validate_my_share(
    dealing: Dealing, 
    my_node_id: NodeId,
    registry_version: RegistryVersion,
                        
) -> Option<Result<SecretShare>>;
// decrypt and check my own share. 
// decryption is done using associated data that encodes 
// (dealing.transcript_id, dealing.dealer_id).
// Returns Some(Ok(secret_share)) is everything is good, Some(Err) if decryption succeeds and yields a bad share,
// None if decryption fails.

// The implementation may assume dealing has already been publicly validated.
// DIFF: the code uses the index of dealing.dealer_id in transcript_param.dealers()
// in the associated data, rather than dealing.dealer_id. This should be OK, but is not ideal.
// DIFF: the code also includes the registry_version -- this is not strictly necessary,
// as all other data in the associated TranscariptParamRef has been agreed upon in consensus.
````


````rust
fn move_support_shares_to_validated_pool(
    unvalidated_pool: Pool,
    validated_pool: Pool,
    finalized_chain: Chain,
) -> (Set<SupportShare>, Set<SupportShare>, Set<SupportShare>)
// Returns (V, I, R), where 
//    V is the set of support shares to be moved from the unvalidated pool to the validated pool,
//    I is the set of support shares to be be removed from the unvalidated pool and processed as HandleInvalid,
//    R is the set of support shares to be removed from the unvalidated pool and processed as RemoveFromUnvalidated.
// Some deduplication is performed.
// INVARIANT: after V is added to the validated pool, there are no support shares with duplicate (key(),signer()) values.
// NOTE: since deduplication is done locally, different replicas may end up
// with different support shares in their validated pools.  Support shares in I are patently invalid, and receipt 
// of such a support share from a replica implicates that replica as corrupt. 
// Support shares in R are valid except that adding them to the validated pool would invalidate the above invariant.
{
    requested_transcript_param_refs: Set<TranscriptParamRef>
      = get_requested_transcript_param_refs(finalized_chain);
    // NOTE: we only require param refs here, which helps to facilitate xnet resharing

    dealings = { dealing in validated_pool of type Dealing };
    validated_shares = { share in validated_pool of type SupportShare };

    V=I=R={};
    for (each share in unvalidated_pool of type SupportShare) {
        match(validate_support_share(share, requested_transcript_param_refs, dealings)) {
            Err => R += {share}; // we can safely remove thus from the unvalidated_pool 
                                 // but we cannot safely assign blame
            Ok(is_valid) {
                if (is_valid == Some(false))
                    I += {share};  // invalid
                else if (exists share1 in (validated_shares + V): share1.key() == share.key() && 
                                                                  share1.signer() == share.signer())
                    R += {share};  // duplicate
                else if (is_valid == Some(true))
                    V += {share};  // valid and not a duplicate
                // else leave in unvalidated pool
            }
        }
    }

    return (V, I, R);

}


fn validate_support_share(share: SupportShare, 
                          requested_transcript_param_refs: Set<TranscriptParamRef>, 
                          dealings: Set<Dealings>, 
) -> Result<Option<bool>>
// Attempt to validate a support share with respect to a set of requested transcript params,
// and a set of validated dealings.
// Returns Err if the share is invalid, but blame cannot be assigned.
// Otherwise, returns Ok(is_valid), where is_valid==Some(true) (definitely valid),
// is_valid==Some(false) (definitely invalid), or is_valid==None (validity could not be determined).
{
    if (exists transcript_param_ref in requested_transcript_param_ref: 
            transcript_param_ref.transcript_id == share.transcript_id) {

        // we can only determine the validity of share if we have a corresponding requested transcript_param
        if (!(share.dealer_id in transcript_param_ref.dealers() &&
              share.multi_sig_share.signer() in transcript_param_ref.receivers())) {

            return Ok(Some(false)); // obviously bad dealer or signer
        }
        else {
            if (exists dealing in dealings: dealing.key() == share.key()) {
                // we can only determine the validity of share if we have a corresponding dealing

         
                if (hash(dealing) != share.dealing_hash) {  
                    // It is safe to remove this from the unvalidated_pool, but we cannot
                    // safely assign blame to any one replica in this case
                    return Err;
                 }
                 else {
                    // By first checking that hash(dealing) == share.dealing_hash we can
                    // hold accountable a replica who sends us an invalid support share
                
                    return Ok(verify_multi_sig_share(transcript_param.registry_version,
                                                     share.multi_sig_share, dealing));
                 }
            }
        }
    }

    return (None, false);
}
````



````rust
fn collect_transcript(
    transcript_param_ref: TranscriptParamRef,
    validated_pool: Pool,
) -> Option<Transcript>
{
    supp_thresh = support_threshold(transcript_param_ref);

    dealings: Set<SupportedDealing> = { };
    for (each dealing in validated_pool of type Dealing: dealing.transcript_id == transcript_param_ref.transcript_id}) {
        supp_shares = { supp_share in validated_pool of type SupportShare: supp_share.key() == dealing.key() };
        sig_shares = { supp_share.multi_sig_share: supp_share in supp_shares }; 
        if (Card(sig_shares) >= supp_thresh) {
            sig_shares = Retain(sig_shares, supp_thresh); // retain only supp_thresh shares
            match (combine_shares(sig_shares, transcript_param_ref.registry_version, dealing)) {
                Some(multi_sig) => dealings += { SupportedDealing(dealing, multi_sig) };
                None => { }
            }
        }
    }

    collect_thresh = collection_threshold(transcript_param_ref);
    if (Card(dealings) >= collect_thresh) {
        // we have a transcript!
        dealings = Retain(dealings, collect_thresh); // retain only collect_thresh dealings
        commitment = compute_polynomial_commitment(transcript_param_ref, dealings);
        return Some(build_transcript(transcript_param_ref, dealings, commitment));
    }

    // failure to build a transcript
    return None;
}


fn compute_polynomial_commitment(
    transcript_param_ref: TranscriptParamRef, 
    dealings: Set<SupportedDealing>
) -> PolynomialCommitment;
// computes the polynomial commitment based on the operation type of transcript_param_ref
// and the supplied dealings
````

#### Signature shares

````rust
struct EcdsaSigShare {

    sig_request_id: SigRequestId,
    // ID of the request

    signer_id: NodeId,
    // node that generated the share
    

    numer: MaskedSecretShare, // \nu in the design doc
    denom: MaskedSecretShare, // \mu in the design doc
    // components of the actual signature share

    fn key() -> (SigRequestId, NodeId) { return (sig_request_id, signer_id); }
}

struct SchnorrSigShare {

    sig_request_id: SigRequestId,
    // ID of the request

    signer_id: NodeId,
    // node that generated the share
    
    // internal share ...
}

enum SigShare {
    Ecdsa(EcdsaSigShare),
    Schnorr(SchnorrSigShare),
}

struct SigRequestId { 

    nonce: Nonce, // typedef'd to [u8; 32]
    // The seed s in the design doc, used to derive the randomizing value \delta.
    // This is also used as unique ID to identify the signing request.
    // In the code this is sometimes called a pseudo_random_id or a random_id.

    height: Height, 
    // height at which the corresponding signature request was matched with
    // a pre-signature

    pre_sig_id: PreSignatureId,
    // Id of the pre-signature this request was matched with

    // NOTE: the height field may be used to manage purging and downloading 
    // of related artifacts --- namely, signature shares ---
    // each of which contains a sig_request_id.  Let h be the current certified state height of a nodes.
    // If sig_request_id.height > h + c for some small constant c >= 0, the node may choose to
    // delay downloading of the artifact.
    // If sig_request_id.height < h, the node may choose to purge the artifact, unless the context in certified state still requests this signature

}

struct EcdsaSigInput {
    path: Vec<Vec<u8>>,
    hash: Hash,
    nonce: Nonce,
    quadruple: PreSigQuadruple,
    key: Transcript,

    // INVARIANT: all transcripts in quadruple have the same registry_version, 
    // and hence the same receiver set, as the key

    fn signers() -> Set<NodeId> { return key.receivers(); }
}

struct EcdsaSigInputRef {
    path: Vec<Vec<u8>>,
    hash: Hash,
    nonce: Nonce,
    quadruple_ref: PreSigQuadrupleRef,
    key_ref: TranscriptRef,

    fn signers() -> Set<NodeId> { return key.receivers(); }
}

struct SchnorrSigInput {
    path: Vec<Vec<u8>>,
    message: Vec<u8>,
    nonce: Nonce,
    pre_sig: PreSigTranscript,
    key: Transcript,

    // INVARIANT: all transcripts in pre-signature have the same registry_version, 
    // and hence the same receiver set, as the key

    fn signers() -> Set<NodeId> { return key.receivers(); }
}

struct SchnorrSigInputRef {
    path: Vec<Vec<u8>>,
    message: Vec<u8>,
    nonce: Nonce,
    pre_sig_ref: PreSigTranscriptRef,
    key_ref: TranscriptRef,

    fn signers() -> Set<NodeId> { return key.receivers(); }
}

enum SigInput {
    Ecdsa(EcdsaSigInput)
    Schnorr(SchnorrSigInput)
}

type PreSignatureId = u64;
// It is assumed that pre-signature IDs are sorted in order of the time the
// construction of the pre-signature was initiated.

struct PreSigQuadrupleRef {
    kappa_unmasked_ref: TranscriptRef,
    lambda_ref: TranscriptRef,
    kappa_unmasked_times_lambda_ref: TranscriptRef,
    key_times_lambda_ref: TranscriptRef,
    key_unmasked_ref: TranscriptRef,
}


struct PreSigQuadruple {
    kappa_unmasked: Transcript,
    lambda: Transcript,
    kappa_unmasked_times_lambda: Transcript,
    key_times_lambda: Transcript,
}

struct PreSigTranscriptRef {
    blinder_unmasked_ref: TranscriptRef,
    key_unmasked_ref: TranscriptRef,
}


struct PreSigTranscript {
    blinder_unmasked: Transcript,
    lambda: Transcript,
}

enum PreSigRef {
    Ecdsa(PreSigQuadrupleRef),
    Schnorr(PreSigTranscriptRef)
}

// NOTE: to generate a signature share, we only need the secret shares for
// lambda_masked, kappa_unmasked_times_lambda, and key_times_lambda.
// We just need the constant term of the polynomial commitment of kappa_unmasked.

struct EcdsaSigInputDependencies {
    lambda_masked: MaskedSecretShare, 
    kappa_unmasked_times_lambda: MaskedSecretShare, 
    key_times_lambda: MaskedSecretShare
}
````


````rust
fn add_sig_shares_to_validated_pool(
    my_node_id: NodeId,
    validated_pool: Pool,
    finalized_chain: Chain,
) -> Set<SigShare>
// Returns a set of new self-generated signature shares to add to the validated pool. 
{
    requested_sig_inputs:  Map<SigRequestId, SigInput>
        = get_requested_sig_inputs(certified_state, finalized_tip);

    // keep only sig inputs for which my_node_id is among the signers
    S0 = { (sig_request_id, sig_input)  in requested_sig_inputs: my_node_id in sig_input.signers() };

    // filter out sig inputs for which a corresponding sig share has already been generated
    S1 = { (sig_request_id, sig_input)  in S0:
                !(exists share in validated_pool of type SigShare: 
                      share.key() == (sig_request_id, my_node_id)) }

    return union over (sig_request_id, sig_input) in S1: 
               generate_sig_share_or_complaints(sig_request_id, sig_input, my_node_id, validated_pool);

}

fn generate_sig_share_or_complaints(
    sig_request_id: SigRequestId,
    sig_input: SigInput,
    my_node_id: NodeId,
    validated_pool: Pool,
) -> (Set<SigShare>)|(Set<Complaint>)
// Attempt to generate a sig share, which is returned as a singleton set.
// However, before that happens, we must load the shares of the input transcripts (if any).
// This may fail and may result in the generation of complaints.
{
    match (load_input_dependencies(sig_input, my_node_id, validated_pool)) { 
        Ok(dependencies) => return generate_sig_share(sig_request_id, sig_input, my_node_id, dependencies);
        Err(complaints) => return complaints; 
    }
}

fn generate_sig_share(
    sig_request_id: SigRequestId, 
    sig_input: SigInput, 
    my_node_id: NodeId,  
    dependencies: SigInputDependencies
) -> Set<SigShare>
// Generates the corresponding signature share.
// May return empty set if crypto layer fails for any reason.
// Otherwise returns singleton set.
{
   // TODO
}

fn load_input_dependencies(
    sig_input: SigInput,
    my_node_id: NodeId,
    validated_pool: Pool,
) -> Result<SigInputDependencies,Set<Complaint>>
// Tries to compute the secret shares for the input transcripts.
// If this fails, a set of complaints is returned.
// Whenever secret shares are successfully computed, these shares may be cached for future use.
{
    // TODO: this is easily implemented using the load_transcript function below
}
````



````rust
fn move_sig_shares_to_validated_pool(
    unvalidated_pool: Pool,
    validated_pool: Pool,
    finalized_chain: Chain,
) -> (Set<SigShare>, Set<SigShare>, Set<SigShare>)
// Returns (V, I, R), where 
//    V is the set of signature shares to be moved from the unvalidated pool to the validated pool,
//    I is the set of signature shares to be be removed from the unvalidated pool and processed as HandleInvalid,
//    R is the set of signature shares to be removed from the unvalidated pool and processed as RemoveFromUnvalidated.
// Some deduplication is performed.
// INVARIANT: after V is added to the validated pool, there are no signature shares with duplicate key() values.
// NOTE: since deduplication is done locally, different replicas may end up
// with different signature shares in their validated pools.  Signature shares in I are patently invalid, and receipt 
// of such a signature share from a replica implicates that replica as corrupt. 
// Signature shares in R are valid except that adding them to the validated pool would invalidate the above invariant.
{
    requested_sig_inputs:  Map<SigRequestId, SigInput>
        = get_requested_sig_inputs(certified_state, finalized_tip);

    validated_shares = { share: share in validated_pool of type SigShare };

    V=I=R={};
    for (each share in unvalidated_pool of type SigShare) {
        is_valid = validate_sig_share(share, requested_sig_inputs);
        if (is_valid == Some(false))
            I += {share};  // invalid
        else if (exists share1 in (validated_shares + V): share1.key() == share.key())
            R += {share};  // duplicate
        else if (is_valid == Some(true))
            V += {share};  // valid and not a duplicate
        // else leave in unvalidated pool
    }

    return (V, I, R);
}

fn validate_sig_share(
    share: SigShare,
    requested_sig_inputs: Map<SigRequestId,SigInput>,
) ->  Option<bool>
{
    if (exists (sig_request_id, sig_input) in requested_sig_inputs:
             sig_request_id == share.sig_request_id) {

        // we can only determine the validity of share if we have a corresponding requested input
        return validate_sig_share_content(share, sig_input);
    }

    return None;
}

fn validate_sig_share_content(
    share: SigShare,
    inputs: SigInput,
) ->  Option<bool>;
// This does the low-level validation of the (numer, denom) components of share
// with respect to inputs. 
````

#### Complaints and openings

````rust
struct ComplaintBase {
    transcript_id: TranscriptId,
    dealer_id: NodeId,
    complainer_point: EccPoint,
    complainer_proof: EqDlogProof,

    fn key() -> (TranscriptId, NodeID) { return (transcript_id, dealer_id) }
}

struct Complaint extends struct ComplaintBase { 
    complainer_id: NodeId,
    sig: Sig,
}


struct OpeningBase {
    transcript_id: TranscriptId,
    dealer_id: NodeId,
    opener_share: SecretShare,

    fn key() -> (TranscriptId, NodeID) { return (transcript_id, dealer_id) }
}

// DIFF: the current code base includes the complainer_id in the
// the opening, but I think this is not helpful and may lead to
// an unnecessary explosion of artifacts that need to be transmitted. 
// That is, the code base generates different openings with respect to
// different complaints, even though these openings are otherwise identical.
// I can't see any benefit to doing this, so I've expressed the logic
// without this.
// We should compare this logic to the code base, and then decide if thetre is
// a reason not to move to the logic here.
// This may take significant refactoring, and hence there may not be the resources
// to do this in a timely fashion.

struct Opening extends struct OpeningBase {
    opener_id: NodeId,
    sig: Sig,
}
````

````rust
fn move_complaints_to_validated_pool(
    unvalidated_pool: Pool,
    validated_pool: Pool,
    finalized_chain: Chain,
) -> (Set<Complaint>, Set<Complaint>, Set<Complaint>)
// Returns (V, I, R), where 
//    V is the set of complaints to be moved from the unvalidated pool to the validated pool,
//    I is the set of complaints to be be removed from the unvalidated pool and processed as HandleInvalid,
//    R is the set of complaints to be removed from the unvalidated pool and processed as RemoveFromUnvalidated.
// Some deduplication is performed.
// INVARIANT: after V is added to the validated pool, there are no complaints with duplicate key() values.
// NOTE: since deduplication is done locally, different replicas may end up
// with different complaints in their validated pools.  Complaints in I are patently invalid, and receipt 
// of such a complaint from a replica implicates that replica as corrupt. 
// Complaints in R are valid except that adding them to the validated pool would invalidate the above invariant.
// DIFF: all of this logic is likely different from the code base.
{
    active_transcripts: Set<Transcript>
      = get_active_transcripts(finalized_chain);

    validated_complaints = { complaint: complaint in validated_pool of type Complaint }; 

    V=I=R={};
    for (each complaint in unvalidated_pool of type Complaint) {
        is_valid = validate_complaint(complaint, active_transcripts);
        if (is_valid == Some(false))
            I += {complaint};  // invalid
        else if (exists complaint1 in (validated_complaints + V): complaint1.key() == complaint.key())
            R += {complaint};  // duplicate
        else if (is_valid == Some(true))
            V += {complaint};  // valid and not a duplicate
        // else leave in unvalidated pool
    }

    return (V, I, R);
}

fn validate_complaint(
    complaint: Complaint, 
    active_transcripts: Set<Transcript>,
) -> Option<bool>
// DIFF: all of this logic is likely different from the code base.
{
    if  (exists transcript in active_transcripts:
              transcript.transcript_id == complaint.transcript_id) {

        // we can only determine the validity of a complaint if we have a corresponding active transcript

        if (complaint.complainer_id in transcript.receivers() &&
            exists dealing in transcript.dealings: dealing.dealer_id == complaint.dealer_id) {

            return validate_complaint_sig(complaint, transcript) &&
                   validate_complaint_content(complaint, dealing);
        }
        else {
            return Some(false); 
        }
   
    } 

    return None;
}

fn validate_complaint_content(
    complaint: Complaint,
    dealing: Dealing,
) -> Option<bool>;
// This does the low-level validation of the complaint.

fn validate_complaint_sig(
    complaint: Complaint, 
    transcript: Transcript, 
) -> Option<bool>
{
    return verify_sig(complaint.complainer_id, transcript.registry_version,
                      complaint.sig, ComplaintBase(complaint))
}
````


````rust
fn add_openings_to_validated_pool(
    my_node_id: NodeId,
    validated_pool: Pool,
    finalized_chain: Chain,
) -> Set<Opening>
// Returns a set of new self-generated openings to add to the validated pool.
{
    active_transcripts: Set<Transcript>
      = get_active_transcripts(finalized_chain);

    S = union over complaint in validated pool of type Complaint
            generate_opening(complaint, active_transcripts, my_node_id, validate_pool);

    return S;
}

fn generate_opening(
    complaint: Complaint,
    active_transcripts: Set<Transcript>,
    my_node_id: NodeId,
    validated_pool: Pool,
) -> Set<SupportShare>
// return empty set of or singleton
{
    if (exists transcript in active_transcripts:
            transcript.transcript_id == complaint.transcript_id && // check if this is an active transcript_id                
            my_node_id in transcript.receivers() && // check if we are one of the receivers
            !(exists opening in validated_pool of type Opening: // check if we already generated an opening
                  opening.key() == complaint.key() &&
                  opening.opener_id == my_node_id))
    {

        if (exists dealing in transcript.dealings: dealing.dealer_id == complaint.dealer_id) {
            // this must exist and be unique

            match (decrypt_and_validate_my_share(dealing, my_node_id, transcript.registry_version)) {

                Some(Ok(secret_share)) => {
                    opening_base = OpeningBase(complaint.transcript_id, complaint.dealer_id, secret_share); 
                    match (generate_sig(my_node_id, transcript.registry_version, opening_base)) {
                        Some(sig) => return { Opening(opening_base, my_node_id, sig) };
                        None => return { };
                    }
                }

                Some(Err) => return { }; 
                // an implementation may want to cache this result to avoid a re-computation

                None => return { };
            }
        }
    }

    return { };

}
````



````rust
fn move_openings_to_validated_pool(
    unvalidated_pool: Pool,
    validated_pool: Pool,
    finalized_chain: Chain,
) -> (Set<Opening>, Set<Opening>, Set<Opening>)
// Returns (V, I, R), where 
//    V is the set of openings to be moved from the unvalidated pool to the validated pool,
//    I is the set of openings to be be removed from the unvalidated pool and processed as HandleInvalid,
//    R is the set of openings to be removed from the unvalidated pool and processed as RemoveFromUnvalidated.
// Some deduplication is performed.
// INVARIANT: after V is added to the validated pool, there are no openings with duplicate key() values.
// NOTE: since deduplication is done locally, different replicas may end up
// with different openings in their validated pools.  Openings in I are patently invalid, and receipt 
// of such a opening from a replica implicates that replica as corrupt. 
// Openings in R are valid except that adding them to the validated pool would invalidate the above invariant.
// DIFF: all of this logic is likely different from the code base.
{
    active_transcripts: Set<Transcript>
      = get_active_transcripts(finalized_chain);

    complaints = { complaint in validated_pool of type Complaint };
    validated_openings = { opening: opening in validated_pool of type Opening }; 

    V=I=R={};
    for (each opening in unvalidated_pool of type Dealing) {
        is_valid = validate_opening(opening, requested_transcript_params);
        if (is_valid == Some(false))
            I += {opening};  // invalid
        else if (exists opening1 in (validated_openings + V): opening1.key() == opening.key() &&
                                                              opening1.opener_id == opening.opener_id)
            R += {opening};  // duplicate
        else if (is_valid == Some(true))
            V += {opening};  // valid and not a duplicate
        // else leave in unvalidated pool
    }

    return (V, I, R);
}

fn validate_opening(
    opening: Opening, 
    active_transcripts: Set<Transcript>,
    complaints: Complaints,
) ->  Option<bool>
// Attempt to validate an opening with respect to a set of active transcripts,
// and a set of validated complaints.
// DIFF: all of this logic is likely different from the code base.
{
    if  (exists transcript in active_transcripts:
              transcript.transcript_id == opening.transcript_id) {

        // we can only determine the validity of an opening if we have a corresponding active transcript

        if (opening.opener_id in transcript.receivers() &&
            exists dealing in transcript.dealings: dealing.dealer_id == opening.dealer_id) {

            match (validate_opening_sig(opening, transcript) &&
                   validate_opening_content(opening, dealing)) {

                Some(false) => return Some(false);
                None => return None;
                Some(true) {
                    if (exists complaint in complaints: complaint.key() == dealing.key())
                        // We only want to move an opening to the validated pool if there is
                        // a corresponding complaint. This is not strictly necessary, but it 
                        // prevents us from relaying openings unnecessarily.
                        return Some(true);
                    else
                        return Some(false);
                 
                }
            }
        }
        else {
            return Some(false);
        }
    } 

    return None;
}

fn validate_opening_content(
    opening: Opening,
    dealing: Dealing,
) -> Option<bool>;
// This does the low-level validation of the opening. 

fn validate_opening_sig(
    opening: Opening, 
    transcript: Transcript, 
) -> Option<bool>
{
    return verify_sig(opening.opener_id, transcript.registry_version,
                      opening.sig, OpeningBase(opening))
}
````


````rust
fn load_transcript(
    transcript: Transcript,
    my_node_id: NodeId,
    validated_pool: Pool,
) -> Result<SecretShare,Set<Complaint>>
// Attempts to compute my secret share for a transcript.
// If it fails, it returns a set of complaints.
{
    points: Set<(NodeId, SecretShare)>
      = { }

    for (each dealing in transcript.dealings) {
        match (decrypt_and_validate_my_share(dealing, my_node_id, transcript.registry_version) {
            Some(secret_share) => points += { (dealing.dealer_id, secret_share) };
            Some(Err) => {
                // try to recover using openings
                openings = { opening in validated_pool of type Opening: opening.key() == dealing.key() };
                match recover_my_share(openings, my_node_id, transcript.receivers()) {
                    Some(secret_share) => points += { (dealing.dealer_id, secret_share) }
                    None => {
                        if (!(exists complaint in validated_pool of type Complaint: complaint.key() == dealer.key())) {
                            match (generate_complaint(dealing, my_node_id, transcript) { 
                                Some(complaint) => return Err({complaint})
                                None => return Err({})
                            }
                        }
                        return Err({});
                    }
                }
            }
            None => return Err({});
        }
    }

    return Ok(interpolate_secrete_share(points, transcript));
}

fn recover_my_share(
    openings: Set<Opening>,   
    my_node_id: NodeId, 
    receivers: Set<NodeId>
) -> Option<SecretShare>
// If we have enough openings to interpolate, returns Some(secret_share), otherwise None.
{
    // TODO
}

fn generate_complaint(
    dealing: Dealing, 
    my_node_id: NodeId, 
    transcript: Transcript, 
) -> Option<Complaint>;
// Attempts to generate complaint
{
    // TODO
}

fn interpolate_secrete_share(points: Set<(NodeId, SecretShare)>, transcript: Transcript) -> SecretShare;
// interpolate a secret share
{
    // TODO
}
````

### Basic crypto-level stuff

````rust
fn verify_sig(node_id: NodeId, 
              registry_version: RegistryVersion, 
              sig: Sig, object: SignableObject
) -> Option<bool>;
// Verifies that sig is a valid signature on object under the public key
// belonging to node_id in version registry_version of the registry.

fn generate_multi_sig_share(node_id: NodeId, 
                            registry_version: RegistryVersion,
                            object: SignableObject
) -> Option<MultiSigShare>;
// Generates a multi-signature share on object under the public key
// belonging to node_id in version registry_version of the registry.

fn verify_multi_sig_share(registry_version: RegistryVersion,
                          multi_sig_share: MultiSigShare, 
                          object: SignableObject
) -> Option<bool>;
// verify a multi-signature share

fn combine_shares(sig_shares: Set<MultiSigShare>,
                  registry_version: RegistryVersion,
                  object: SignableObject
) -> Option<MultiSig>;
// combines shares
// It is assumed that the shares are valid, but return None on transient failures
````

### Blockchain stuff

````rust
fn get_requested_transcript_params(chain: Chain) -> Set<TranscriptParam>
// fetches all transcript params that are requested by the tip of chain
{
   // TODO
}

fn get_requested_transcript_param_refs(chain: Chain) -> Set<TranscriptParamRef>
// fetches all transcript param refs that are requested by the tip of chain
{
   // TODO
}

fn get_active_transcripts(chain: Chain) -> Set<Transcript>
// fetches all transcripts that are active in the tip of chain
{
   // TODO
}

fn get_requested_sig_inputs(certified_state: State, tip: Block) -> Map<SigRequestId,SigInput>
// gets the input data for all ongoing signatures at the tip of the chain
{
   // Skip sinature requests that haven't been completed yet (not matched
   // to a pre-signature or no assigned random nonce)

   // Create the Siginputs by getting the matched pre-signature
   // from the finalized tip
}

fn get_requested_reshare_params(chain: Chain) -> Map<ReshareRequestId, TranscriptParam>
// fetches all transcript params corresponding to ongoing reshare requests at the tip of chain
{
   // TODO
}
````


````rust
type SignatureAgreements = Map<SigRequestId, CompletedSignature>;
type AvailablePreSigs = Map<PreSigId, PreSigRef>;
type PreSigsInCreation = Map<PreSigId, PreSigInCreation>;
type OngoingReshareRequests = Map<ReshareRequestId,TranscriptParamRef>;
type ReshareAgreements = Map<ReshareRequestId,CompletedReshareRequest>;

struct IDkgPayload {
    signature_agreements: SignatureAgreements,
    // collection of completed signatures

    available_pre_signatures: AvailablePreSigs,
    // pre-signatures that are fully constructed

    pre_signatures_in_creation: PreSigsInCreation,
    // pre-signatures that are under construction

    uid_generator: UIDGenerator,
    // "next" UID

    current_key_state: Option<TranscriptRef>,
    // key to be used for current interval

    next_key_state: NextKeyState,
    // key under construction for next interval

    reshare_agreements: ReshareAgreements,
    // completed reshare requests

    ongoing_reshare_requests: OngoingReshareRequests,
    // reshare requests being serviced

    transcripts: Set<Transcript>,
    // transcripts created at this height -- TranscriptRef's point here

    // INVARIANT: the function oldest_registry_version_in_use function takes into account
    // registry versions in current_key_state, next_key_state,
    // and ongoing_reshare_requests and signature requests in certified state, that were 
    // already matched to available pre-signatures.
    // This ensures that when subnet membership changes, replicas that are leaving will
    // stay around long enough for them to play their assigned roles in the protocol.

}


enum CompletedSignature {
    Reported,
    Unreported(Signature), // Signature is a Vec<u8>

// NOTE: the reason for this enum type is to allow signatures to be reported to execution exactly once. 
// When a signature is freshly constructed, it is added a block as Unreported.
// However, it may appear in some number of subsequent blocks as Reported. 
// When the block containing the reported signature is finalized, execution layer may pass the signature along.
// We leave the reported signature in subsequent block so long as the the call context still contains the 
// the corresponding signing request.
// All of this achieves two goals: (1) a signature will be reported just once to execution, and (2)
// consensus will not attempt to generate another signature if the signing request persists in the call context.
}

struct PreSigQuadrupleInCreation {
    kappa_unmasked_param_ref: TranscriptParamRef,
    kappa_unmasked_ref: Option<TranscriptRef>,

    lambda_param_ref: TranscriptParamRef,
    lambda_ref: Option<TranscriptRef>,

    kappa_unmasked_times_lambda_param_ref: Option<TranscriptParamRef>,
    kappa_unmasked_times_lambda_ref: Option<TranscriptRef>,

    key_times_lambda_param_ref: Option<TranscriptParamRef>,
    key_times_lambda_ref: Option<TranscriptRef>,
}

struct PreSigTranscriptInCreation {
    blinder_unmasked_param_ref: TranscriptParamRef,
    blinder_unmasked_ref: Option<TranscriptRef>,
}


// Logic for key construction can follow one of these paths:
//    1. Begin -> MakingRandom -> MakingRandomUnmasked -> Created
//    2. Begin -> MakingReshared -> Created
//    3. Ibid
//    4. MakingReshared -> Created
// Path #1 is used when we are generating a fresh random key from scratch.
// Path #2 is used when there is a resharing of an existing key,
//     which is currently triggered only by a change in subnet membership.
// Path #3 is used when we simply reuse an existing key.
// Path #4 is used for xnet resharing on the target subnet
enum NextKeyState {
    Begin,
    // Initial state

    MakingRandom(TranscriptParamRef),
    // Create initial random transcript

    MakingRandomUnmasked(TranscriptParamRef),
    // create initial unmasked key transcript by resharing the random transcript

    MakingReshared(TranscriptParamRef),
    // reshare unmasked transcript

    Created(TranscriptRef),
    // next key successfully constructed

    Ibid,
    // reuse old key as new key

    // DIFF: the Ibid value is not in the code...it simplifies some logic (maybe).
}

struct UIDGenerator {
    my_subnet_id: SubnetId;
    next_unused_transcript_id: u64;
    next_unused_pre_sig_id: u64;

    fn next_transcript_id(height: Height) -> TranscriptId
    {  return TranscriptId(next_unused_transcript_id++, my_subnet_id, height); } 
    // DIFF:  unlike the code, we explicitly pass in the height.

    fn next_pre_sig_id() -> PreSigId { return PreSigId(next_unused_pre_sig_id++); }
}

struct SigningRequestCall {
    path: Vec<Vec<u8>>,
    // We assume path here is a complete derivation path,
    // including the signer's CanisterId as the first component

    payload: HashOrMessage,
    // This is the hash of the message for Ecdsa or the message itself for Schnorr.

    matched_pre_signature: Option<(Height, PreSigId)>
    // The request context will be updated (this field set to some value), as
    // soon as the DSM matches it with a pre-signature delivered by consensus

    nonce: Option<Nonce>,
    // This is a random nonce that should be generated by the RandomTape in
    // such a way that it is unpredictable before such time as the rest of the
    // SigningRequestCall is committed.  This is also used as unique ID to
    // identify the signing request.  In the code this is sometimes called a
    // pseudo_random_id or a random_id.
    // The DSM assignes the random nonce to the context by using the random tape
    // of the round immediately subsequent to the round at which this context was
    // matched to a pre-signature.
}


type ReshareRequestId = ???; // implementation defined: could be CallbackId

struct ReshareRequestCall {
    target_subnet_id: SubnetId;
    target_registry_version: RegistryVersion,
}

enum CompletedReshareRequest {
    Unreported(TranscriptParamRef, Set<Dealing>),
    Reported

    // The logic here is similar to that of CompletedSignatures (above)
}



type TranscriptCache = Set<Transcript>;
type SignatureCache = Map<SigRequestId, Signature>;
type ReshareCash = Map<ReshareRequestId, Set<Dealing>>;
// Used for payload validation -- see below
````

````rust
fn build_idkg_payload(
    notarized_chain: Chain,
    signing_request_calls: List<SigningRequestCall>,
    reshare_request_calls: Map<ReshareRequestId,ReshareRequestCall>,
    next_registry_version: RegistryVersion,
    validated_pool: Pool,
) -> IDkgPayload
// Builds a new payload for a block that extends the block at the tip of notarized_chain.
// signing_request_calls is obtained from the certified state of the validation context
// to be used for the new block. 
// It is assumed that this list orders the calls in the order in which they were made by execution.
// next_registry_version is the registry version to be used in the next interval.
{
    (payload, _) = 
        build_idkg_payload_common(notarized_chain, signing_request_calls, reshare_request_calls, 
                                   next_registry_version, 
                                   Some(validated_pool), None, None, None); 

    return payload;
}

fn validate_idkg_payload(
    payload: IDkgPayload,
    finalized_chain: Chain,
    signing_request_calls: List<SigningRequestCall>,
    reshare_request_calls: Map<ReshareRequestId,ReshareRequestCall>,
    next_registry_version: RegistryVersion,
) -> Option<bool>
// Validates payload. Return value is the usual 3-valued boolean logic.
// Some(true) means valid, Some(false) means invalid, and None means undetermined.

// The basic strategy is to use the signatures and transcripts in the given payload to
// build a new payload for a block that extends the notarized chain,
// and then test if the new payload is equal to the given paylooad.
{
    transcript_cache = payload.transcripts;
    signature_cache = { (sig_request_id, sig): 
                          (sig_request_id, Unreported(sig)) in payload.signature_agreements };
    reshare_cache = { (reshare_request_id, dealings): 
                          (reshare_request, Unreported(param_ref,dealings)) in payload.reshare_agreeents; };

    (computed_payload, test) = 
        build_idkg_payload_common(finalized_chain, signing_request_calls, reshare_request_calls,
                                   next_registry_version, 
                                   None, Some(transcript_cache), Some(signature_cache), Some(reshare_cache));

    match (test) {
        Some(true) => return Some(false); // some crypto test definitely failed => invalid
        Some(false) => return None; // some crypto test could not be performed but all others passed => undetermined
        None => return Some(payload == computed_payload);
    }

    // NOTE: we do not explicitly check that transcript_cache contains two different transcripts with the same
    // transcript_id, or any extraneous transcripts. If that happens, then payload != computed_payload.
    // Similarly, we do not explicitly check that signature_cache contains any extraneous signatures.
}
````


````rust
fn build_idkg_payload_common(
    notarized_chain: Chain,
    signing_request_calls: List<SigningRequestCall>,
    reshare_request_calls: Map<ReshareRequestId,ReshareRequestCall>,
    next_registry_version: RegistryVersion,
    opt_validated_pool: Option<Pool>,
    opt_transcript_cache: Option<TranscriptCache>, 
    opt_signature_cache: Option<SignatureCache>,   
    opt_reshare_cache: Option<ReshareCache>,
) -> (IDkgPayload, Option<bool>)
// Builds a new payload for a block that extends the block at the tip of notarized_chain.
// signing_requests is obtained from the certified state of the validation context
// to be used for the new block. 
// It is assumed that this list orders the calls in the order in which they were made by execution.
// next_registry_version is the registry version to be used in the next interval.
//
// The opt_transcript_cache and opt_signature_cache params are used only for building a payload
// for purposes of block validation.
// The second return value is only used in this case:  
//    set to Some(true) if some crypto test definitely failed;
//    set to Some(false) if some crypto test could not be performed but all others passed;
//    set to None otherwise (all crypto tests definitely passed).
{
    parent_block = tip(notarized_chain);
    parent_payload = parent_block.idkg_payload();
    parent_height = parent_block.height();
 
    signature_agreements     = parent_payload.signature_agreements;
    available_pre_signatures     = parent_payload.available_pre_signatures;
    pre_signatures_in_creation   = parent_payload.pre_signatures_in_creation;
    uid_generator            = parent_payload.uid_generator;
    current_key_state        = parent_payload.current_key_state;
    next_key_state           = parent_payload.next_key_state;
    reshare_agreements       = parent_payload.reshare_agreements;
    ongoing_reshare_requests = parent_payload.ongoing_reshare_requests;
    transcripts              = { };

    height = parent_height+1;

    test = None;

    (signature_agreements, test) =
        update_signature_agreements(signature_agreements, available_pre_signatures, finalized_chain, signing_request_calls, opt_validated_pool, opt_signature_cache);

    match (current_key_state) {
        Some(current_key_ref) => {

            if certified_state_height >= last_summary_height {
                purge_old_key_pre_signatures(available_pre_signatures, signing_request_calls, current_key_ref);
            }

            (pre_signatures_in_creation, uid_generator) = 
                make_new_pre_sigs_if_needed(available_pre_signatures, pre_signatures_in_creation, uid_generator, current_key_ref, height); 

            (pre_signatures_in_creation, available_pre_signatures, uid_generator, new_transcripts, test) =
                update_pre_signatures_in_creation(pre_signatures_in_creation, available_pre_signatures, uid_generator,
                                              current_key_ref, height, opt_validated_pool, opt_transcript_cache, test);
            transcripts += new_transcripts;

        }
        None => { }
    }


    (next_key_state, uid_generator, new_transcripts, test) = 
        update_next_key_state(next_key_state, uid_generator, current_key_state,  height, 
                        next_registry_version, opt_validated_pool, opt_transcript_cache, test);


    (reshare_agreements, ongoing_reshare_requests, test) =
        update_reshare_agreements(reshare_agreements, ongoing_reshare_requests, 
                                  finalized_chain, reshare_request_calls, opt_validated_pool, opt_reshare_cache);

    match (current_key_state) {
        Some(current_key_ref) => {
            (ongoing_reshare_requests, uid_generator) =
                update_ongoing_reshare_requests(ongoing_reshare_requests, uid_generator, current_key_ref, 
                                                reshare_agreements, reshare_request_calls, height); 
        }
        None => { }
    }


    transcripts += new_transcripts;


    return (IDkgPayload(signature_agreements, available_pre_signatures, 
                        pre_signatures_in_creation, uid_generator, current_key_state, next_key_state, 
                        reshare_agreements, ongoing_reshare_requests, transcripts),
            test);

}
````



````rust
fn update_signature_agreements(
    signature_agreements: SignatureAgreements,
    available_pre_signatures: AvailablePreSignatures,
    finalized_chain: Chain,
    signing_request_calls: List<SigningRequestCall>,
    opt_validated_pool: Option<Pool>,
    opt_signature_cache: Option<SignatureCache>,
    test: Option<bool>,
) -> (SignatureAgreements, OngoingSignatures, Option<bool>)
{
    signing_request_nonces = { call.nonce: call in signing_request_calls } 

    // first, clean up signature agreements:
    //     if the agreement is still in signing_request_calls, make it Reported; 
    //     otherwise, just remove it
    signature_agreements = { (sig_request_id, Reported) :
                                 sig_request_id in Domain(signature_agreements) && 
                                 sig_request_id.nonce in signing_request_nonces }

    for (each (sig_request_id, sig_input) in get_requested_sig_inputs(certified_state, finalized_chain.tip() )) {
        // reject requests that
        // 1. request an invalid key
        // 2. have expired
        // 3. were matched to non-existant pre-signature (i.e. after recovery)
    }

    // second, try to construct signatures for open requests
    (completed_sigs, test) = 
      = get_completed_signatures(finalized_chain, opt_validated_pool, opt_signature_cache, test); 

    // third, move any newly constructed sigs to signature_agreements 
    for (each sig_request_id in Domain(completed_sigs)) {
        signature_agreements[sig_request_id] = Unreported(completed_sig[sig_request_id]);
    }

    return (signature_agreements, , test);
}

fn get_completed_signatures(
    finalized_chain: Chain, 
    opt_validated_pool: Option<Pool>, 
    opt_signature_cache: Option<SignatureCache>,
    test: Option<bool>,
) -> (Map<SigRequestId, Signature>, Option<bool>)
{
    // Gather all requested signatures from finalized_chain.
    // This gathers the data for all ongoing signatures at the tip of finalized_chain,
    // which is the same as the ongoing_signatures value in the caller (update_signature_agreements).
    requested_sig_inputs:  Map<SigRequestId, SigInput>
        = get_requested_sig_inputs(finalized_chain);

    sig_map: Map<SigRequestId, Signature> = { };
    for (each (sig_request_id, sig_input) in requested_sig_inputs) {
        match (opt_signature_cache) {
            None => { // block builder path
                shares = { share in opt_validated_pool.unwrap() of type SigShare: share.sig_request_id == sig_request_id };
                match (combine_sig_shares(sig_input, shares)) {
                    Some(sig) => sig_map[sig_request_id] = sig;
                    None => { }
                }
            }
            Some(signature_cache) => { // block validator path
                if (exists sig_request_id in Domain(signature_cache)) {
                    sig = signature_cache[sig_request_id];
                    match (validate_sig(sig_input, sig)) {
                        Some(true) => sig_map[sig_request_id] = sig;
                        Some(false) => { test = Some(true); }
                        None => { if (test == None) test = Some(false); }
                    }
                }
            }
        }
    }

    return (sig_map, test);
}

fn combine_sig_shares(
    sig_input: SigInput, 
    shares: Set<SigShare>,
) -> Option<Signature>;
// Crypto-layer function to combine shares and compute a signature.

fn validate_sig(
    sig_input: SigInput, 
    sig: Signature,
) -> Option<bool>;
// Crypto-layer function to validate a signature.
````

````rust
// Delete all unmatched, available pre-signatures that 
// reference a non-existant key transcript (i.e. because it was rotated)
fn purge_old_key_pre_signatures(
    available_pre_signatures: AvailablePreSignatures,
    signing_request_calls: List<SigningRequestCall>,
    key_transcript: KeyTranscript,
) {
    for (pre_sig_id, pre_sig) in available_pre_signatures {
        if not pre_sig_id matched in signing_request_calls
            && pre_sig.key_transcript () != key_transcript {
            
            Delete(available_pre_signatures[pre_sig_id]);
        }
    }
}
````


````rust
fn make_new_pre_sigs_if_needed(
    available_pre_signatures: AvailablePreSignatures,
    pre_signatures_in_creation: PreSignaturesInCreation,
    uid_generator: UIDGenerator,
    registry_version: RegistryVersion,
    height: Height,
    key_transcript: KeyTranscript,
) -> (PreSignaturesInCreation, UIDGenerator)
// initiates construction of new pre-signatures, so that the total number of "extant" pre-signatures
// (i.e., those available and in creation) is equal to MAX_EXTANT_PRESIGS. 
{
    num_extant_pre_signatures = Card(Domain(available_pre_signatures)) + Card(Domain(pre_signatures_in_creation));

    if (num_extant_pre_signatures < MAX_EXTANT_PRESIGS) {
        for (i in [1..MAX_EXTANT_PRESIGS-num_extant_pre_signatures]) {
            (pre_sig_id, pre_signature, uid_generator) = if key_transcript of type ECDSA {
                make_new_ecdsa_quadruple(uid_generator, registry_version, height)
            } else if key_transcript of type Schnorr {
                make_new_schnorr_pre_sig(uid_generator, registry_version, height)
            }
            pre_signatures_in_creation += { (pre_sig_id, pre_signature) } ;
        }
    }

    return (pre_signatures_in_creation, uid_generator);
}

fn make_new_ecdsa_quadruple(
    uid_generator: UIDGenerator,
    registry_version,
    height: Height,
) -> (PreSigId, PreSignatureInCreation, UIDGenerator)

{
    (kappa_param_ref, uid_generator) = build_random_unmasked_param_ref(uid_generator, registry_version, height);
    (lambda_param_ref, uid_generator) = build_random_param_ref(uid_generator, registry_version, height);

    quadruple = QuadrupleInCreation(kappa_param_ref, None, lambda_param_ref, None, None, None, None, None);
    quadruple_id = uid_generator.next_quadruple_id();

    return (quadruple_id, quadruple, uid_generator); 
}

fn make_new_schnorr_pre_sig(
    uid_generator: UIDGenerator,
    registry_version,
    height: Height,
) -> (PreSigId, PreSignatureInCreation, UIDGenerator)

{
    (blinder_param_ref, uid_generator) = build_random_unmasked param_ref(uid_generator, registry_version, height);

    pre_sig = TranscriptInCreation(blinder_param_ref, None);
    pre_sig_id = uid_generator.next_pre_sig_id();

    return (pre_sig_id, pre_sig, uid_generator); 
}
````

````rust
fn update_pre_signatures_in_creation(
    pre_signatures_in_creation: PreSignaturesInCreation,
    available_pre_signatures: AvailablePreSignatures,
    uid_generator: UIDGenerator,
    current_key_ref: TranscriptRef,
    height: Height,
    opt_validated_pool: Option<Pool>,
    opt_transcript_cache: Option<TranscriptCache>,
    test: Option<bool>,
) -> (PreSignaturesInCreation, AvailablePreSignatures, UIDGenerator, Set<Transcript>, Option<bool>)
// Returns updated versions of pre_signatures_in_creation, available_pre_signatures, and uid_generator,
// along with any newly created transcripts.
{
    registry_version = current_key_ref.registry_version;

    new_transcripts: Set<Transcript> = { };

    for (each pre_sig_id in Domain(pre_signatures_in_creation)) {
        if current_key_ref of type ECDSA {
            update_ecdsa_pre_sig_in_creation(pre_sig_id, ...)
        } else if current_key_ref of type Schnorr {
            update_schnorr_pre_sig_in_creation(pre_sig_id, ...)
        }
    }

    return (pre_signatures_in_creation, available_pre_signatures, uid_generator, new_transcripts, test);
}

fn update_ecdsa_pre_sig_in_creation(
    pre_sig_id: PreSigId,
    pre_signatures_in_creation: PreSignaturesInCreation,
    available_pre_signatures: AvailablePreSignatures,
    uid_generator: UIDGenerator,
    current_key_ref: TranscriptRef,
    height: Height,
    opt_validated_pool: Option<Pool>,
    opt_transcript_cache: Option<TranscriptCache>,
    test: Option<bool>,
) {
    quadruple = pre_signatures_in_creation[pre_sig_id];

    // ******** update transcripts

    (quadruple.lambda_ref, new_transcripts, test) =  
        update_transcript(quadruple.lambda_param_ref, quadruple.lambda_ref,
                          height, new_transcripts, opt_validated_pool, opt_transcript_cache, test);

    (quadruple.kappa_unmasked_ref, new_transcripts, test) =  
        update_transcript(quadruple.kappa_unmasked_param_ref, quadruple.kappa_unmasked_ref,
                          height, new_transcripts, opt_validated_pool, opt_transcript_cache, test);

    (quadruple.kappa_unmasked_times_lambda_ref, new_transcripts, test) =  
        update_transcript(quadruple.kappa_unmasked_times_lambda_param_ref, quadruple.kappa_unmasked_times_lambda_ref,
                          height, new_transcripts, opt_validated_pool, opt_transcript_cache, test);

    (quadruple.key_times_lambda_ref, new_transcripts, test) =  
        update_transcript(quadruple.key_times_lambda_param_ref, quadruple.key_times_lambda_ref,
                          height, new_transcripts, opt_validated_pool, opt_transcript_cache, test);

    // ******** update params

    // **** update quadruple.kappa_unmasked_times_lambda_param_ref
    match (quadruple.kappa_unmasked_times_lambda_param_ref) {
        None => {
            match (quadruple.kappa_unmasked_ref) {
                    Some(kappa_unmasked_ref) => {
                        (kappa_unmasked_times_lambda_param_ref, uid_generator) = 
                            build_unmasked_times_masked_param_ref(uid_generator, registry_version, height, kappa_unmasked_ref, lambda_ref);
                        quadruple.kappa_unmasked_times_lambda_param_ref = Some(kappa_unmasked_times_lambda_param_ref);
                    }
                    None => { }
                }
            }
        Some(_) => { }
    }

    // **** update quadruple.key_times_lambda_param_ref
    match (quadruple.key_times_lambda_param_ref) {
        None => {
            match (quadruple.lambda_ref) {
                Some(lambda_ref) => {
                    (key_times_lambda_param_ref, uid_generator) = 
                        build_unmasked_times_masked_param_ref(uid_generator, registry_version, height, current_key_ref, lambda_ref);
                    quadruple.key_times_lambda_param_ref = Some(key_times_lambda_param_ref);
                }
                None => { }
            }
        }
        Some(_) => { }
    }


    pre_signatures_in_creation[pre_sig_id] = quadruple;

    // ******** now see if this quadruple is complete, and if so, move to available_pre_signatures
    match ((quadruple.kappa_unmasked_ref, quadruple.lambda_ref, 
           quadruple.kappa_unmasked_times_lambda_ref, quadruple.key_times_lambda_ref)) {

        (Some(kappa_unmasked_ref), Some(lambda_ref), Some(kappa_unmasked_times_lambda_ref), Some(key_times_lambda_ref)) => {

            completed_quadruple = QuadrupleRef(kappa_unmasked_ref, lambda_ref, kappa_unmasked_times_lambda_ref, key_times_lambda_ref);
            available_pre_signatures[pre_sig_id] = completed_quadruple;
            Delete(pre_signatures_in_creation[pre_sig_id]);
        }
        _ => { }
    }
}

fn update_schnorr_pre_sig_in_creation()(
    pre_signatures_in_creation: PreSignaturesInCreation,
    available_pre_signatures: AvailablePreSignatures,
    uid_generator: UIDGenerator,
    current_key_ref: TranscriptRef,
    height: Height,
    opt_validated_pool: Option<Pool>,
    opt_transcript_cache: Option<TranscriptCache>,
    test: Option<bool>,
) {
    pre_sig = pre_signatures_in_creation[pre_sig_id];

    // ******** update transcripts

    (pre_sig.blinder_ref, new_transcripts, test) =  
        update_transcript(pre_sig.blinder_param_ref, pre_sig.blinder_ref,
                          height, new_transcripts, opt_validated_pool, opt_transcript_cache, test);


    pre_signatures_in_creation[pre_sig_id] = pre_sig;

    // ******** now see if this pre_sig is complete, and if so, move to available_pre_signatures
    match (pre_sig.blinder_ref) {

        Some(blinder_unmasked_ref) => {
            completed_pre_sig = SchnorrPreSigRef(blinder_unmasked_ref);
            available_pre_signatures[pre_sig_id] = completed_pre_sig;
            Delete(pre_signatures_in_creation[pre_sig_id]);
        }
        _ => { }
    }
}

fn update_transcript(
    opt_param_ref: Option<TranscriptParamRef>, 
    opt_transcript_ref: Option<TranscriptRef>,
    height: Height,
    new_transcripts: Set<Transcript>,
    opt_validated_pool: Option<Pool>,
    opt_transcript_cache: Option<TranscriptCache>,
    test: Option<bool>,
) -> (Option<TranscriptRef>, Set<Transcript>, Option<bool>)
// Attempts to build a new transcript based on opt_param_ref.
// If opt_param_ref == None or opt_transcript_ref != None, then it does nothing
// and returns (opt_transcript_ref, new_transcripts, test).
// Otherwise, it attempts to build a transcript.
// If successful, it will build a transcript_ref using transcript and height, 
// adds transcript to new_transcripts, and returns 
// (Some(transcript_ref), new_transcripts+{transcript}, test).
// Otherwise, returns (None, new_transcripts, test), possibly with test updated
// on the block validator path, if a crypto test was not successful.
{
    match (opt_param_ref) {
        Some(param_ref) => {
            match (opt_transcript_ref) {
                Some(transcript_ref) => { } 
                None => {
                    match (opt_transcript_cache) {
                        None => { // block builder path
                            match (collect_transcript(param_ref, opt_validated_pool.unwrap()) {
                                Some(transcript) => {
                                    return (Some(build_transcript_ref(transcript, height)),
                                            new_transcripts + {transcript});
                                }
                                None => { }
                            }
                        }
                        Some (transcript_cache) { // block validator path
                            if (exists transcript in transcript_cache: 
                                    transcript.transcript_id == param_ref.transcript_id) {
                                match (validate_transcript(transcript, param_ref)) {
                                    Some(true) => 
                                        return (Some(build_transcript_ref(transcript, height)),
                                                new_transcripts + {transcript});
                                    Some(false) => { test = Some(true); }
                                    None => { if (test == None) test = Some(false); }
                                }
                            }
                        }
                    }
                }
            }
        }
        None => { }
    }

    return (opt_transcript_ref, new_transcripts, test);

}

fn validate_transcript(
    transcript: Transcript, 
    param_ref: TranscriptParamRef, 
) -> Option<bool>
// Validate transcript against param_ref, which checks 
// (1) that the metadata is correct, 
// (2) that there is the correct number of supported dealings, 
// (3) that each such supported dealing has a valid multi-signature with the correct number of shares, 
// (4) that the polynomial commitment is computed correctly from the dealings.
{
    // TODO
}
````


````rust
fn update_next_key_state(
    next_key_state: NextKeyState,
    uid_generator: UIDGenerator, 
    current_key_state: Option<TranscriptRef>,
    height; Height, 
    next_registry_version: RegistryVersion, 
    opt_validated_pool: Option<Pool>, 
    opt_transcript_cache: Option<TranscriptCache>,
    test: Option<bool>,
) -> (NextKeyState, UIDGenerator, Set<TranscriptRef>, Option<bool>)
// Attempt to build the key for the next interval.
{
    new_transcripts = { };

    match (current_key_state) {
        None => {
            // Begin -> MakingRandom -> MakingRandomUnmasked -> Created
            // MakingReshared -> Created

            match (next_key_state) {

                Begin => {
                    // move to MakingRandom state
                    (random_param_ref, uid_generator) = build_random_param_ref(uid_generator, next_registry_version, height);
                    next_key_state = NextKeyState::MakingRandom(random_param_ref);
                }

                MakingRandom(random_param_ref) => {
                    // see if we have built the random transcript, and if so move to MakingRandomUnmasked state

                    (opt_random_ref, new_transcripts, test) =
                        update_transcript(Some(random_param_ref), None, opt_validated_pool, height, new_transcripts, 
                                          opt_transcript_cache, test); 

                    match (opt_random_ref) {
                        Some(random_ref) => {
                            (random_unmasked_param_ref, uid_generator) = 
                                build_reshare_of_masked_param_ref(
                                    uid_generator, random_ref.registry_version, height, random_ref);
                            next_key_state = NextKeyState::MakingRandomUnmasked(random_unmasked_param_ref);
                         }
                         None => { }
                    }
                }

                MakingRandomUnmasked(random_unmasked_param_ref) => {
                    // see if we have built the random unmaksed transcript, and if so move to Created state

                    (opt_random_unmasked_ref, new_transcripts, test) =
                        update_transcript(Some(random_unmasked_param_ref), None, opt_validated_pool, 
                                          height, new_transcripts, opt_transcript_cache, test); 

                    match (opt_random_unmasked_ref) {
                        Some(random_unmasked_ref) => next_key_state = NextKeyState::Created(random_unmasked_ref);
                        None  => { }
                    }
                }

                MakingReshared(reshared_param_ref) => {
                    // should only be used for xnet resharing
                    // see if we have built the reshared transcript, and if so move to Created state

                    (opt_reshared_ref, new_transcripts, test) =
                        update_transcript(Some(reshared_param_ref), None, opt_validated_pool, height, new_transcripts, 
                                          opt_transcript_cache, test); 

                    match (opt_reshared_ref) {
                        Some(reshared_ref) => next_key_state = NextKeyState::Created(reshared_ref);
                        None => { }
                    }
                }

                Created(_) => { } // nothing to do

                _ => assert!(false); //should be unreachable
            }
        }

        Some(current_key_ref) => {

            // Begin -> MakingReshared -> Created
            // Ibid

            match (next_key_state) {

                Begin => (next_key_state, uid_generator) = reshare_key(current_key_ref, uid_generator, next_registry_version, height);

                MakingReshared(reshared_param_ref) => {
                    // see if we have built the reshared transcript, and if so move to Created state

                    (opt_reshared_ref, new_transcripts, test) =
                        update_transcript(Some(reshared_param_ref), None, opt_validated_pool, height, new_transcripts, 
                                          opt_transcript_cache, test); 

                    match (opt_reshared_ref) {
                        Some(reshared_ref) => next_key_state = NextKeyState::Created(reshared_ref);
                        None => { }
                    }
                }

                Created(_) => { } // nothing to do 

                Ibid => { } // nothing to do 

                _ => assert!(false); //should be unreachable
            } 
        }
    } 

    return (next_key_state, uid_generator, new_transcripts, test);
}
````


````rust
fn update_reshare_agreements(
    reshare_agreements: ReshareAgreements,
    ongoing_reshare_requests: OngoingReshareRequests,
    finalized_chain: Chain,
    reshare_request_calls: Map<ReshareRequestId,ReshareRequestCall>,
    opt_validated_pool: Option<Pool>,
    opt_reshare_cache: Option<ReshareCache>,
    test: Option<bool>,
) -> (ReshareAgreements, OngoingReshareRequests, Option<bool>)
{

    // first, clean up reshare agreements:
    //     if the agreement is still in reshare_request_calls, make it Reported; 
    //     otherwise, just remove it
    reshare_agreements = { (reshare_request_id, Reported) :
                                 reshare_request_id in Domain(reshare_agreements) && 
                                 reshare_request_id in Domain(reshare_request_calls) }

    // second, try to satisfy requests in ongoing_reshare_requests
    (completed_reshare_requests, test) = 
      = get_completed_reshare_requests(finalized_chain, opt_validated_pool, opt_reshare_cache, test); 

    // third, move any newly satisfied requests from ongoing_reshare_requests to reshare_agreements 
    for (each reshare_request_id in Domain(completed_reshare_requests)) {
        reshare_agreements[reshare_request_id] = 
            Unreported(ongoing_reshare_request[reshare_request_id], completed_reshare_requests[reshare_request_id]);
        Delete(ongoing_reshare_requests[reshare_request_id]);
    }

    return (reshare_agreements, ongoing_reshare_requests, test);
}

fn get_completed_reshare_requests(
    finalized_chain: Chain, 
    opt_validated_pool: Option<Pool>, 
    opt_reshare_cache: Option<ReshareCache>,
    test: Option<bool>,
) -> (Map<ReshareRequestId, Set<Dealing>>, Option<bool>)
{
    // Gather all transcript params corresponding to ongoing reshare requests at the tip of chain
    // which is the same as the ongoing_reshare_requests value in the caller (update_reshare_agreements).
    // NOTE: on the block builder path, we only need the corresponding transcript_id's,
    // while on the block validator path, we need the full transcript to carry out dealing validation
    requested_reshare_params:  Map<ReshareRequestId, TranscriptParam>
        = get_requested_reshare_params(finalized_chain);

    reshare_map: Map<ReshareRequestId, Set<Dealing>> = { };
    for (each (reshare_request_id, transcript_param) in requested_reshare_params) {
        match (opt_reshare_cache) {
            None => { // block builder path
                match (collect_reshare_dealings(transcript_param.transcript_id, opt_validated_pool.unwrap())) {
                    Some(dealings) => reshare_map[reshare_request_id] = dealings;
                    None => { }
                }
            }
            Some(reshare_cache) => { // block validator path
                if (exists reshare_request_id in Domain(reshare_cache)) {
                    dealings = reshare_cache[reshare_request_id];
                    match (validate_reshare_dealings(transcript_param, dealings) {
                        Some(true) => reshare_map[reshare_request_id] = dealings;
                        Some(false) => { test = Some(true); }
                        None => { if (test == None) test = Some(false); }
                    }
                }
            }
        }
    }

    return (reshare_map, test);
}


fn collect_reshare_dealings(
    transcript_id: TranscriptId,
    validated_pool: Pool,
) -> Option<Set<Dealing>>
{
    // TODO: try to find the right numer of validated dealings with matching transcript_id to satisfy a reshare request
}

fn validate_reshare_dealings(
    transcript_param: TranscriptParam,
    dealings: Set<Dealing>
) -> Option<bool>
{
    // TODO: validate the given dealings with respect to transcript_param
}
````


````rust
fn update_ongoing_reshare_requests(
    ongoing_reshare_requests: OngoingReshareRequests,
    uid_generator: UIDGenerator, 
    current_key_ref: TranscriptParamRef,
    reshare_agreements: ReshareAgreements,
    reshare_request_calls: Map<ReshareRequestId,ReshareRequestCall>,
    height: Height,
) -> (OngoingReshareRequests, UIDGenerator)
{
    active_ids = Union(Domain(reshare_agreements), Domain(ongoing_reshare_requests));

    for (each reshare_request_id in Domain(reshare_request_calls)) {
        if (!(reshare_request_id in active_ids)) {
            request_call = reshare_request_call[reshare_request_id];
            (reshared_param_ref, uid_generator) = 
                build_reshare_of_unmasked_param_ref(uid_generator, request_call.target_registry_version, height,  
                                                    current_key_ref, Some(request_call.target_subnet_id));
            ongoing_reshare_requests[reshare_request_id] = reshared_param_ref;
        }
    }

    return (ongoing_reshare_requests, uid_generator);
}
    

````



````rust
fn build_idkg_summary_payload(
    notarized_chain: Chain,
    my_subnet_id: SubnetId,
    registry_version: RegistryVersion,
    next_registry_version: RegistryVersion,
) -> IDkgPayload
// Builds a new summary payload for a block that extends the block at the tip of notarized_chain.
// registry_version is the registry version to be used in this interval.
// next_registry_version is the registry version to be used in the next interval.
{
    parent_block = tip(notarized_chain);
    parent_payload = parent_block.idkg_payload();
    parent_height = parent_block.height();

    signature_agreements     = parent_payload.signature_agreements;
    available_pre_signatures     = parent_payload.available_pre_signatures;
    pre_signatures_in_creation   = parent_payload.pre_signatures_in_creation;
    uid_generator            = parent_payload.uid_generator;
    current_key_state        = parent_payload.current_key_state;
    next_key_state           = parent_payload.next_key_state;
    reshare_agreements       = parent_payload.reshare_agreements;
    ongoing_reshare_requests = parent_payload.ongoing_reshare_requests;
    transcripts              = { };

    height = parent_height+1;

    // *** update height of uid_generator to the height of the new block
    uid_generator.next_unused_transcript_id.height = height;

    // *** update current_key_state
    match (current_key_state) {

        None => {
            match (next_key_state) {
                Begin | MakingRandom(_) | MakingRandomUnmasked(_) | MakingReshared(_)  => { }
                Ibid => assert!(false); //should be unreachable
                Created(created_key_ref) => {
                    // path #1 or #4 succeeded
                    current_key_state = Some(created_key_ref); 
                }
            }
        }


        Some(current_key_ref) => {
            match (next_key_state) {
                Begin | MakingReshared(_) | Ibid => { }
                MakingRandom(_) | MakingRandomUnmasked(_) => assert!(false);  // should be unreachable
                Created(created_key_ref) => current_key_state = Some(created_key_ref);  // path #2 succeeded
            }
        }
    }

    // *** update next_key_state, as well as available_pre_signatures, pre_signatures_in_creation,
    // and ongoing_reshare_requests, if necessary
    match (next_key_state) {
        Created(_) => {
            // we have created a new key, so we toss out pre-signatures in creation and
            // ongoing reshare requests associated with the old key
            pre_signatures_in_creation = { };
            ongoing_reshare_requests = { };
            next_key_state = Ibid; // default construction path is path #3

            // Note that we don't purge available pre-signatures at this point,
            // as we cannot be sure that they weren't already matched to new
            // signature requests at the latest certified state height (which
            // is lagging behind the finalized height).
        }
        _ => { } // default is to continue whatever construction path were on
    }


    // *** test for subnet membership change
    // The logic is that if we have a key that is not being reshared, then we initiate reshare
    // if the receiver set of that key is not equal to the subnet membership of next_registry_version.
    // With this logic ,if a resharig attempt has not succeeded at the end of a CUP interval,
    // that resharing attempt will simply continue as long as it takes.

    match (current_key_state, next_key_state) {
        (Some(current_key_ref), Ibid) => {

            if (current_key_ref.receivers() != get_subnet_nodes(next_registry_version, my_subnet_id))
                next_key_state = Begin;
                // if there is a membership change, this will trigger a reshare
        }
        _ => { }
    }

    // *** update active transcript refs
    result = IDkgPayload(signature_agreements, available_pre_signatures, 
                          pre_signatures_in_creation, uid_generator, current_key_state, next_key_state, 
                          reshare_agreements, ongoing_reshare_requests, transcripts);

    updated_result = update_transcript_refs(result, finalized_chain);

    return updated_result;
}


fn reshare_key(
    current_key_ref: TranscriptRef,
    uid_generator: UIDGenerator,
    next_registry_version: RegistryVersion,
    height: Height,
) -> (NextKeyState, UIDGenerator)
// Reshare an existing key
{
    (reshared_param_ref, uid_generator) = build_reshare_of_unmasked_param_ref(uid_generator, next_registry_version, height, current_key_ref);
    next_key_state = NextKeyState::MakingReshared(reshared_param_ref);
    return (next_key_state, uid_generator);
}



fn update_transcript_refs(
    payload: IDkgPayload,
    chain: Chain
) -> IDkgPayload
// Assumes payload is in a block extending chain.
// This identifies all of the transcript refs in payload, and then 
// copies the actual transcripts from previous blocks in the chain to the transcripts
// field of payload, and then updates the transcripts refs so that the height fields 
// in these refs to point to this new block.
{
    // TODO
}
````

````rust
fn build_bootstrap_summary_payload(
    my_subnet_id: SubnetId,
    opt_xnet_reshared_param_ref: Option<TranscriptParamRef>,
) -> IDkgPayload
// Builds a new summary payload for a genesis block.
//
// If this subnet is being initialized an xnet resharing, the optional
// TranscriptParamRef for that resharing is passed in here;  
// in addition, a set of "initial dealings" will be injected into the
// validated pool -- it is assumed that these dealings were already publicly
// validated on the source subnet. 
// DIFF: we only use a TranscriptParamRef here, while the code uses 
// a TranscriptParam. 
{
    signature_agreements     = { };
    available_pre_signatures     = { };
    pre_signatures_in_creation   = { };
    uid_generator            = UIDGenerator(my_subnet_id, 0, 0);
    current_key_state        = None;
    reshare_agreements       = { };
    ongoing_reshare_requests = { };
    transcripts              = { };

    match (opt_xnet_reshared_param_ref) {
        None => next_key_state = NextKeyState::Begin;
        Some(xnet_reshared_param_ref) =>  next_key_state = NextKeyState::MakingReshared(xnet_reshared_param_ref);
    }

    return IDkgPayload(signature_agreements, available_pre_signatures, 
                        pre_signatures_in_creation, uid_generator, current_key_state, next_key_state, 
                        reshare_agreements, ongoing_reshare_requests, transcripts);
}
````


