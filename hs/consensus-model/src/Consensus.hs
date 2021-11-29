{-# LANGUAGE ImplicitParams #-}
{-# LANGUAGE RecordWildCards #-}

{-@ LIQUID "--max-case-expand=0" @-}
{-@ LIQUID "--no-adt" @-}
{-@ LIQUID "--exact-data-con" @-}

module Consensus where

import Data.Function (on)
import Data.List
import Lib
import Types
import Prelude hiding (round)

{-@ registry_version :: ConsensusPoolSection -> Height -> RegistryVersion @-}
registry_version :: ConsensusPoolSection -> Height -> RegistryVersion
registry_version _validated_pool _height =
  -- TODO: registry_version
  "0.1.0"

{-
node_registry ::
  (?topo :: Topology) => SubnetId -> RegistryVersion -> [ReplicaId]
node_registry _ _ = replicas ?topo -- TODO: node_registry
-}

{-@
threshold_committee ::
  Height ->
  ConsensusPoolSection ->
  HighLow ->
  Maybe (DkgId, Threshold, [ReplicaId])
@-}

threshold_committee ::
  (?topo :: Topology) =>
  Height ->
  ConsensusPoolSection ->
  HighLow ->
  Maybe (DkgId, Threshold, [ReplicaId])
threshold_committee _height _validated_pool _high_or_low =
  -- Find largest DKG transcript, and return the information from that.
  -- TODO: threshold_committee
  Just (0, length replicas `div` 3 * 2 + 1, replicas)

{-@
notarization_committee ::
  Height ->
  ConsensusPoolSection ->
  Maybe (Threshold, [ReplicaId])
@-}

notarization_committee ::
  (?topo :: Topology) =>
  Height ->
  ConsensusPoolSection ->
  Maybe (Threshold, [ReplicaId])
notarization_committee _ _ =
  -- TODO: notarization_committee
  Just (length replicas `div` 3 * 2 + 1, replicas)

{-
get_purge_height :: ConsensusPool -> Height
get_purge_height (_validated_pool, _unvalidated_pool) =
  -- Determine purge height based on latest CUP available
  -- TODO: get_purge_height
  0
-}

{-@ random_beacon_height :: ConsensusPoolSection -> Maybe Height @-}
random_beacon_height :: ConsensusPoolSection -> Maybe Height
random_beacon_height validated_pool =
  safe_maximum
    [ height
      | RandomBeaconMsg (RandomBeacon height _parent _sig) <-
          msgs validated_pool
    ]

{-@ notarized_height :: ConsensusPoolSection -> Maybe Height @-}
notarized_height :: ConsensusPoolSection -> Maybe Height
notarized_height validated_pool =
  safe_maximum
    [ height
      | NotarizationMsg (Notarization _signers height _block_hash _sig) <-
          msgs validated_pool
    ]

{-@ finalized_height :: ConsensusPoolSection -> Maybe Height @-}
finalized_height :: ConsensusPoolSection -> Maybe Height
finalized_height validated_pool =
  safe_maximum
    [ height
      | FinalizationMsg (Finalization _signers height _block_hash _sig) <-
          msgs validated_pool
    ]

{-@ current_round :: ConsensusPoolSection -> Maybe {h:_ | 0 < h} @-}
current_round :: ConsensusPoolSection -> Maybe Height
current_round validated_pool = do
  rb_h <- random_beacon_height validated_pool
  n_h <- notarized_height validated_pool
  pure $ min rb_h n_h + 1

{-@
round_start_time :: ConsensusPoolSection -> Height -> Maybe Time
@-}

round_start_time :: ConsensusPoolSection -> Height -> Maybe Time
round_start_time validated_pool round =
  safe_minimum
    [ time
      | ( RandomBeaconMsg (RandomBeacon rb_round _parent _sig),
          time_beacon
          ) <-
          validated_pool,
        rb_round == round - 1,
        ( NotarizationMsg (Notarization _signers n_round _block _sig'),
          time_notarization
          ) <-
          validated_pool,
        n_round == round - 1,
        let time = max time_beacon time_notarization
    ]

{-@
slot_duration :: RegistryVersion -> SubnetId -> Maybe Duration
@-}

slot_duration :: RegistryVersion -> SubnetId -> Maybe Duration
slot_duration _registry_version _subnet_id =
  -- TODO: slot_duration
  Just 2 -- (2020-11-16): This is an arbitrary choice of 2 seconds; this
  -- affects the testing!

{-@
block_maker_rank ::
  ConsensusPoolSection -> Height -> ReplicaId -> SubnetId -> Maybe Rank
@-}

block_maker_rank ::
  ConsensusPoolSection -> Height -> ReplicaId -> SubnetId -> Maybe Rank
block_maker_rank _validated_pool _round _repl_id _subnet_id =
  -- TODO: block_maker_rank
  Just 0

{-@
block_maker_timeout ::
  ConsensusPoolSection -> Rank -> Height -> SubnetId -> Maybe Duration
@-}

block_maker_timeout ::
  ConsensusPoolSection -> Rank -> Height -> SubnetId -> Maybe Duration
block_maker_timeout validated_pool rank height subnet_id = do
  dur <- slot_duration (registry_version validated_pool height) subnet_id
  pure $ fromIntegral rank * dur

{-@
notary_timeout ::
  ConsensusPoolSection -> Rank -> Height -> SubnetId -> Maybe Duration
@-}

notary_timeout ::
  ConsensusPoolSection -> Rank -> Height -> SubnetId -> Maybe Duration
notary_timeout validated_pool rank height subnet_id = do
  -- NOTE: this is a strawman proposal, and may very well be adjusted later
  dur <- slot_duration (registry_version validated_pool height) subnet_id
  pure $ (fromIntegral rank + 1) * dur

{-@
on_state_change ::
  Config ->
  ConsensusPool ->
  Time ->
  [ChangeAction]
@-}

on_state_change ::
  (?topo :: Topology) =>
  Config ->
  ConsensusPool ->
  Time ->
  [ChangeAction]
on_state_change config pool time =
  random_beacon_changes config pool
    <> random_tape_changes config pool
    <> block_making config pool time
    <> notarization config pool time
    <> finalization config pool
    <> cup_making config pool

{-@
random_beacon_changes ::
  Config ->
  ConsensusPool ->
  [ChangeAction]
@-}

random_beacon_changes ::
  (?topo :: Topology) => Config -> ConsensusPool -> [ChangeAction]
random_beacon_changes
  (my_id, _subnet_id)
  (validated_pool, unvalidated_pool) =
    [ AddToValidated (RandomBeaconShareMsg share)
      | Just rb_h <- [random_beacon_height validated_pool],
        let height = rb_h + 1,
        Just n_h <- [notarized_height validated_pool],
        height - 1 <= n_h,
        Just (dkg_id, _threshold, committee) <-
          [threshold_committee height validated_pool Low],
        my_id `elem` committee,
        null
          [ rbs_id
            | RandomBeaconShareMsg
                (RandomBeaconShare rbs_id rbs_h' _parent' _sig') <-
                msgs validated_pool,
              rbs_h' == height,
              rbs_id == my_id
          ],
        RandomBeaconMsg beacon@(RandomBeacon rb_h' _parent' _sig') <-
          msgs validated_pool,
        rb_h' == height - 1,
        let parent = hash_random_beacon beacon,
        let sig = sign_random_beacon_share my_id dkg_id height parent,
        let share = RandomBeaconShare my_id height parent sig
    ]
      <> [ AddToValidated
             (RandomBeaconMsg (RandomBeacon height beacon_hash sig))
           | Just rb_h <- [random_beacon_height validated_pool],
             let height = rb_h + 1,
             Just (_dkg_id, threshold, _committee) <-
               [threshold_committee height validated_pool Low],
             Just (beacon_hash, shares) <-
               [random_beacon_share_signatures validated_pool height],
             genericLength shares >= threshold,
             let sig = aggregate_random_beacon_signature_shares shares
         ]
      <> [ MoveToValidated share_msg
           | share_msg@( RandomBeaconShareMsg
                           share@(RandomBeaconShare _signer height _parent _sig)
                         ) <-
               msgs unvalidated_pool,
             random_beacon_height validated_pool == Just (height - 1),
             Just Valid == validate_random_beacon_share validated_pool share
         ]
      <> [ HandleInvalid share_msg
           | share_msg@( RandomBeaconShareMsg
                           share@(RandomBeaconShare _signer height _parent _sig)
                         ) <-
               msgs unvalidated_pool,
             random_beacon_height validated_pool == Just (height - 1),
             Just Invalid == validate_random_beacon_share validated_pool share
         ]
      <> [ MoveToValidated beacon_msg
           | beacon_msg@( RandomBeaconMsg
                            beacon@(RandomBeacon height _parent _sig)
                          ) <-
               msgs unvalidated_pool,
             random_beacon_height validated_pool == Just (height - 1),
             Just Valid == validate_random_beacon validated_pool beacon
         ]
      <> [ HandleInvalid beacon_msg
           | beacon_msg@( RandomBeaconMsg
                            beacon@(RandomBeacon height _parent _sig)
                          ) <-
               msgs unvalidated_pool,
             random_beacon_height validated_pool == Just (height - 1),
             Just Invalid == validate_random_beacon validated_pool beacon
         ]

{-@
random_beacon_share_signatures ::
  ConsensusPoolSection ->
  h:Height ->
  Maybe
    ( HashOfRandomBeacon,
      [(ReplicaId, _)]<{\x y -> nfstcmp x y}>
    )
@-}

-- INVARIANT: Any random beacon shares in the validated pool at a given height
-- will always have the same parent.
random_beacon_share_signatures ::
  ConsensusPoolSection ->
  Height ->
  Maybe
    ( HashOfRandomBeacon,
      [(ReplicaId, RandomBeaconShareSignature)]
    )
random_beacon_share_signatures validated_pool height =
  case xs of
    [] -> Nothing
    _ ->
      let (hashes, shares) = unzip xs
       in case nub hashes of
            [x] -> Just (x, nubFst shares)
            _ -> Nothing
  where
    xs =
      [ (beacon_hash, (signer, sig))
        | RandomBeaconShareMsg (RandomBeaconShare signer h beacon_hash sig) <-
            msgs validated_pool,
          h == height
      ]

{-@
validate_random_beacon_share ::
  ConsensusPoolSection ->
  RandomBeaconShare ->
  Maybe Valid
@-}

validate_random_beacon_share ::
  (?topo :: Topology) =>
  ConsensusPoolSection ->
  RandomBeaconShare ->
  Maybe Valid
validate_random_beacon_share
  validated_pool
  (RandomBeaconShare signer height parent sig) =
    if null beacons
      then Nothing
      else
        Just $
          if null validated_pool'
            then Invalid
            else Valid
    where
      beacons =
        [ beacon
          | RandomBeaconMsg (beacon@(RandomBeacon h _parent' _sig')) <-
              msgs validated_pool,
            h == height - 1
        ]
      validated_pool' =
        [ beacon
          | beacon@(RandomBeacon h _parent' _sig') <- beacons,
            h == height - 1,
            parent == hash_random_beacon beacon,
            Just (dkg_id, _threshold, committee) <-
              [threshold_committee height validated_pool Low],
            signer `elem` committee,
            Valid
              == verify_random_beacon_share_sig dkg_id signer height parent sig
        ]

{-@
validate_random_beacon ::
  ConsensusPoolSection ->
  RandomBeacon ->
  Maybe Valid
@-}

validate_random_beacon ::
  (?topo :: Topology) =>
  ConsensusPoolSection ->
  RandomBeacon ->
  Maybe Valid
validate_random_beacon
  validated_pool
  (RandomBeacon height parent sig) =
    if null beacons
      then Nothing
      else
        Just $
          if null validated_pool'
            then Invalid
            else Valid
    where
      beacons =
        [ beacon
          | RandomBeaconMsg (beacon@(RandomBeacon h _parent' _sig')) <-
              msgs validated_pool,
            h == height - 1
        ]
      validated_pool' =
        [ beacon
          | beacon@(RandomBeacon h _parent' _sig') <- beacons,
            h == height - 1,
            parent == hash_random_beacon beacon,
            Just (dkg_id, _threshold, _committee) <-
              [threshold_committee height validated_pool Low],
            Valid == verify_random_beacon_sig dkg_id height parent sig
        ]

{-@
block_making ::
  Config ->
  ConsensusPool ->
  Time ->
  [ChangeAction]
@-}

block_making :: Config -> ConsensusPool -> Time -> [ChangeAction]
block_making
  (my_id, subnet_id)
  (validated_pool, unvalidated_pool)
  current_time =
    [ AddToValidated
        (BlockProposalMsg (BlockProposal my_id block_hash block sig))
      | Just round <- [current_round validated_pool],
        null
          [ bp_id
            | BlockProposalMsg
                ( BlockProposal
                    bp_id
                    _bp_block_hash1
                    (Block h1 _parent' _rank' _payload')
                    _sig'
                  ) <-
                msgs validated_pool,
              bp_id == my_id,
              h1 == round
          ],
        Just round_start <- [round_start_time validated_pool round],
        let reg_version = registry_version validated_pool round,
        Just rank <- [block_maker_rank validated_pool round my_id subnet_id],
        null
          [ signer
            | BlockProposal
                signer
                _bp_block_hash2
                (Block h2 _parent' rank' _payload')
                _sig' <-
                non_equivocating_block_proposals validated_pool round,
              h2 == round,
              rank' < rank
          ],
        Just timeout <-
          [block_maker_timeout validated_pool rank round subnet_id],
        current_time >= round_start ^+ timeout,
        -- 'round' here is the height
        Just parent <-
          [select_chain_to_extend validated_pool (round - 1)],
        let payload = create_block_payload (bp_block parent) (), -- TODO
        let block = Block round (bp_block_hash parent) rank payload,
        let block_hash = hash_block block,
        let sig = sign_block my_id reg_version block
    ]
      ++ [ -- Mark block proposal as valid if:
           -- - it is in the unvalidated pool
           -- - we don't already have a block proposal from this block maker
           --   in this round
           -- - the block proposal is for the current round
           -- - the block maker rank is computed correctly
           -- - sufficient time has passed in the current round for the block
           --   rank
           -- - we have a notarized block that matches the block parent hash,
           --   and the parent is of height one less than the proposal.
           -- - the block proposal contains a valid signature
           -- - the block payload is valid
           MoveToValidated proposal
           | Just round <- [current_round validated_pool],
             Just round_start <- [round_start_time validated_pool round],
             let reg_version = registry_version validated_pool round,
             proposal@( BlockProposalMsg
                          ( BlockProposal
                              signer
                              _block_hash
                              block@(Block h parent_hash rank _payload)
                              sig
                            )
                        ) <-
               msgs unvalidated_pool,
             h == round,
             null
               [ signer'
                 | BlockProposalMsg
                     ( BlockProposal
                         signer'
                         _block_hash
                         (Block h2 _parent' _rank' _payload')
                         _sig'
                       ) <-
                     msgs validated_pool,
                   h2 == round,
                   signer' == signer
               ],
             Just rank
               == block_maker_rank validated_pool round signer subnet_id,
             Just timeout <-
               [block_maker_timeout validated_pool rank round subnet_id],
             current_time >= round_start ^+ timeout,
             BlockProposalMsg
               ( BlockProposal
                   _parent_signer
                   _block_hash
                   parent_block@( Block
                                    hp
                                    _grandparent_hash
                                    _parent_rank
                                    _parent_payload
                                  )
                   _parent_sig
                 ) <-
               msgs validated_pool,
             hp == round - 1,
             hash_block parent_block == parent_hash,
             NotarizationMsg
               ( Notarization
                   _notaries
                   n_round
                   n_hash
                   _notarization_sig
                 ) <-
               msgs validated_pool,
             n_round == round - 1,
             n_hash == parent_hash,
             Valid == verify_block_sig signer reg_version block sig
             -- TODO: Validating payloads can be deferred until later, since
             -- while it's important to the operation of consensus overall,
             -- it's not essential to the process of reaching consensus on
             -- blocks. Manu has a list of properties in mind of what needs to
             -- be tested, and it will need to validate against the entire
             -- chain back to genesis, but this can be deferred for now.
             -- Valid == validate_payload (error "TODO: validate_payload args")
         ]
      ++ [ HandleInvalid
             ( BlockProposalMsg
                 ( BlockProposal
                     signer
                     block_hash
                     (Block round parent_hash rank payload)
                     sig
                 )
             )
           | -- TODO
             let round = undefined, -- TODO: round
             let parent_hash = undefined, -- TODO: parent_hash
             let rank = undefined, -- TODO: rank
             let block_hash = undefined, -- TODO: block_hash
             let payload = undefined, -- TODO: payload
             let signer = undefined, -- TODO: sig
             let sig = undefined, -- TODO: sig
             False
         ]

{-@
nselect_chain_to_extend ::
  ConsensusPoolSection ->
  h:Height ->
  Maybe {v:Block|b_height v == h}
@-}

-- Select the best notarized block at a given height, by looking at all blocks
-- that are contained in notarized block proposals at the given height, and
-- returning the smallest
select_chain_to_extend ::
  ConsensusPoolSection ->
  Height ->
  Maybe BlockProposal
select_chain_to_extend validated_pool height =
  safe_minimum
    [ proposal
      | BlockProposalMsg
          proposal@(BlockProposal _signer block_hash block _sig) <-
          msgs validated_pool,
        NotarizationMsg (Notarization _signers h block_hash' _not_sig) <-
          msgs validated_pool,
        h == height,
        b_height block == height,
        block_hash == block_hash'
    ]

{-@
notarization ::
  Config ->
  ConsensusPool ->
  Time ->
  [ChangeAction]
@-}

notarization ::
  (?topo :: Topology) =>
  Config ->
  ConsensusPool ->
  Time ->
  [ChangeAction]
notarization
  (my_id, subnet_id)
  (validated_pool, unvalidated_pool)
  current_time =
    [ AddToValidated
        (NotarizationShareMsg (NotarizationShare my_id height block_hash sig))
      | Just not_height <- [notarized_height validated_pool],
        let height = not_height + 1,
        Just height == current_round validated_pool,
        Just (_threshold, committee) <-
          [notarization_committee height validated_pool],
        my_id `elem` committee,
        -- 'lowest_ranked_block_proposals' will only return proposals at the
        -- queried height.
        [ BlockProposal
            _signer
            block_hash
            (Block _height _parent_hash rank _payload)
            _block_sig
          ] <-
          [lowest_ranked_block_proposals validated_pool height],
        null
          [ share
            | NotarizationShareMsg
                ( share@( NotarizationShare
                            not_id'
                            not_height'
                            not_block_hash'
                            _sig'
                          )
                  ) <-
                msgs validated_pool,
              not_id' == my_id,
              not_height' == height,
              not_block_hash' == block_hash
          ],
        let reg_version = registry_version validated_pool height,
        Just round_start <- [round_start_time validated_pool height],
        Just required_timeout <-
          [notary_timeout validated_pool rank height subnet_id],
        current_time >= round_start ^+ required_timeout,
        let sig =
              sign_notarization_share
                my_id
                reg_version
                height
                block_hash
    ]
      ++ [ AddToValidated
             (NotarizationMsg (Notarization signers height block_hash sig))
           | ((height, block_hash), shares) <-
               notarization_share_signatures validated_pool,
             Just (threshold, _notarization_committee) <-
               [ notarization_committee
                   height
                   validated_pool
               ],
             let signers = map fst shares,
             genericLength shares >= threshold,
             let sig = aggregate_notarization_signature_shares shares,
             null
               [ block_hash'
                 | NotarizationMsg
                     (Notarization signers' height' block_hash' sig') <-
                     msgs validated_pool,
                   signers' == signers,
                   height' == height,
                   block_hash' == block_hash,
                   sig' == sig
               ]
         ]
      ++ [ AddToValidated
             (EquivocationProofMsg (EquivocationProof signer height bp1 bp2))
           | Just nheight <- [notarized_height (validated_pool)],
             let height = nheight + 1,
             length (lowest_ranked_block_proposals validated_pool height) > 1,
             Just bp1@(BlockProposal signer _block_hash1 _block1 _sig1) <-
               [ safe_minimum
                   (lowest_ranked_block_proposals validated_pool height)
               ],
             Just bp2@(BlockProposal signer' _block_hash2 _block2 _sig2) <-
               [ safe_minimum
                   ( lowest_ranked_block_proposals validated_pool height
                       \\ [bp1]
                   )
               ],
             signer == signer',
             null
               [ s
                 | EquivocationProofMsg (EquivocationProof s h _bp1' _bp2') <-
                     msgs validated_pool,
                   s == signer,
                   h == height
               ]
         ]
      ++ [ MoveToValidated share
           | share@( NotarizationShareMsg
                       (NotarizationShare signer height block_hash sig)
                     ) <-
               msgs unvalidated_pool,
             Just (_threshold, committee) <-
               [ notarization_committee
                   height
                   validated_pool
               ],
             let reg_version = registry_version validated_pool height,
             signer `elem` committee,
             BlockProposalMsg
               ( BlockProposal
                   _block_signer
                   bp_block_hash
                   (Block h _parent_hash _rank _payload)
                   _block_sig
                 ) <-
               msgs validated_pool,
             Valid
               == verify_notarization_share_sig
                 reg_version
                 signer
                 height
                 block_hash
                 sig,
             h == height,
             bp_block_hash == block_hash
         ]
      ++ [ HandleInvalid share
           | share@( NotarizationShareMsg
                       (NotarizationShare signer height block_hash sig)
                     ) <-
               msgs unvalidated_pool,
             Just (_threshold, committee) <-
               [notarization_committee height validated_pool],
             let reg_version = registry_version validated_pool height,
             signer `notElem` committee
               || Invalid
                 == verify_notarization_share_sig
                   reg_version
                   signer
                   height
                   block_hash
                   sig
         ]
      ++ [ MoveToValidated
             notarization_message
           | notarization_message@( NotarizationMsg
                                      ( Notarization
                                          notaries
                                          height
                                          block_hash
                                          notarization_sig
                                        )
                                    ) <-
               msgs unvalidated_pool,
             Just (threshold, committee) <-
               [ notarization_committee
                   height
                   validated_pool
               ],
             let reg_version = registry_version validated_pool height,
             notaries `isSubsetOf` committee,
             genericLength notaries >= threshold,
             BlockProposalMsg
               ( BlockProposal
                   _block_signer
                   bp_block_hash
                   (Block h _parent_hash _rank _payload)
                   _sig
                 ) <-
               msgs validated_pool,
             Valid
               == verify_notarization_sig
                 reg_version
                 notaries
                 height
                 block_hash
                 notarization_sig,
             h == height,
             bp_block_hash == block_hash
         ]
      ++ concat
        [ [MoveToValidated proposal, MoveToValidated notarization_message]
          | proposal@( BlockProposalMsg
                         ( BlockProposal
                             _block_signer
                             bp_block_hash
                             (Block height _parent_hash _rank _payload)
                             _sig
                           )
                       ) <-
              msgs unvalidated_pool,
            proposal `notElem` msgs validated_pool,
            notarization_message@( NotarizationMsg
                                     ( Notarization
                                         notaries
                                         h
                                         block_hash
                                         notarization_sig
                                       )
                                   ) <-
              msgs unvalidated_pool,
            h == height,
            Just (threshold, committee) <-
              [ notarization_committee
                  height
                  validated_pool
              ],
            let reg_version = registry_version validated_pool height,
            notaries `isSubsetOf` committee,
            genericLength notaries >= threshold,
            Valid
              == verify_notarization_sig
                reg_version
                notaries
                height
                block_hash
                notarization_sig,
            bp_block_hash == block_hash,
            NotarizationMsg
              ( Notarization
                  _notaries'
                  h'
                  _parent_hash
                  _notarization_sig'
                ) <-
              msgs validated_pool,
            h' == height - 1
        ]
      ++ [ HandleInvalid notarization_message
           | notarization_message@( NotarizationMsg
                                      ( Notarization
                                          notaries
                                          height
                                          block_hash
                                          notarization_sig
                                        )
                                    ) <-
               msgs unvalidated_pool,
             Just (threshold, committee) <-
               [ notarization_committee
                   height
                   validated_pool
               ],
             let reg_version = registry_version validated_pool height,
             notaries `isNotSubsetOf` committee
               || genericLength notaries < threshold
               || Invalid
                 == verify_notarization_sig
                   reg_version
                   notaries
                   height
                   block_hash
                   notarization_sig
         ]
      ++ [ MoveToValidated proof_msg
           | proof_msg@( EquivocationProofMsg
                           proof@(EquivocationProof _signer height _bp1 _bp2)
                         ) <-
               msgs unvalidated_pool,
             let reg_version = registry_version validated_pool height,
             Valid == validate_equivocation_proof reg_version proof
         ]
      ++ [ HandleInvalid proof_msg
           | proof_msg@( EquivocationProofMsg
                           proof@(EquivocationProof _signer height _bp1 _bp2)
                         ) <-
               msgs unvalidated_pool,
             let reg_version = registry_version validated_pool height,
             validate_equivocation_proof reg_version proof == Invalid
         ]

{-@
notarization_share_signatures ::
  ConsensusPoolSection ->
  [ ( (Height, HashOfBlock),
      [(ReplicaId, _)]<{\x y -> nfstcmp x y}>
    )
  ]
@-}

notarization_share_signatures ::
  ConsensusPoolSection ->
  [ ( (Height, HashOfBlock),
      [(ReplicaId, NotarizationShareSignature)]
    )
  ]
notarization_share_signatures validated_pool =
  concatMap
    ( \xs ->
        let (hashes, shares) = unzip xs
         in case nub hashes of
              -- Note that this will always be the case, because 'xs' was
              -- produced using groupBy.
              [x] -> [(x, nubFst shares)]
              _ -> []
    )
    $ groupBy
      ((==) `on` (fst . fst))
      [ ((height, block_hash), (signer, sig))
        | NotarizationShareMsg
            (NotarizationShare signer height block_hash sig) <-
            msgs validated_pool
      ]

{-@
validate_equivocation_proof :: RegistryVersion -> EquivocationProof -> Valid
@-}

validate_equivocation_proof :: RegistryVersion -> EquivocationProof -> Valid
validate_equivocation_proof
  reg_version
  ( EquivocationProof
      signer
      height
      ( BlockProposal
          signer1
          _block_hash1
          block1@(Block height1 _parent_hash1 _rank1 _payload1)
          sig1
        )
      ( BlockProposal
          signer2
          _block_hash2
          block2@(Block height2 _parent_hash2 _rank2 _payload2)
          sig2
        )
    ) =
    if height == height1
      && height == height2
      && signer == signer1
      && signer == signer2
      && Valid == verify_block_sig signer1 reg_version block1 sig1
      && Valid == verify_block_sig signer2 reg_version block2 sig2
      then Valid
      else Invalid

{-@
lowest_ranked_block_proposals ::
  ConsensusPoolSection ->
  h:Height -> [{v:BlockProposal|b_height (bpBlock v) == h}]
@-}

-- NOTE: This excludes blocks from block makers for which we have observed an
-- equivocation proof at this height
lowest_ranked_block_proposals ::
  ConsensusPoolSection -> Height -> [BlockProposal]
lowest_ranked_block_proposals validated_pool height =
  [ proposal
    | proposal@( BlockProposal
                   signer
                   _block_hash
                   (Block h _parent_hash rank _payload)
                   _sig
                 ) <-
        non_equivocating_block_proposals validated_pool height,
      h == height,
      null
        [ signer'
          | BlockProposal
              signer'
              _block_hash
              (Block h' _parent_hash' rank' _payload')
              _sig' <-
              non_equivocating_block_proposals validated_pool height,
            signer == signer',
            h' == height,
            rank' < rank
        ]
  ]

{-@
non_equivocating_block_proposals ::
  ConsensusPoolSection ->
  h:Height -> [{v:BlockProposal|b_height (bpBlock v) == h}]
@-}

-- Returns the validated block proposals at the specified height that are from
-- block makers for which no equivocation has been observed at this height.
non_equivocating_block_proposals ::
  ConsensusPoolSection -> Height -> [BlockProposal]
non_equivocating_block_proposals validated_pool height =
  [ proposal
    | BlockProposalMsg
        proposal@( BlockProposal
                     signer
                     _block_hash
                     (Block h _parent_hash _rank _payload)
                     _sig
                   ) <-
        msgs validated_pool,
      h == height,
      null
        [ signer'
          | EquivocationProofMsg (EquivocationProof signer' h' _bp1 _bp2) <-
              msgs validated_pool,
            signer == signer',
            height == h'
        ]
  ]

{-@
finalization ::
  Config ->
  ConsensusPool ->
  [ChangeAction]
@-}

finalization ::
  (?topo :: Topology) =>
  Config ->
  ConsensusPool ->
  [ChangeAction]
finalization (my_id, _subnet_id) (validated_pool, unvalidated_pool) =
  -- Create a finalization share for a certain height and block_hash if:
  -- - the height is greater than the current finalized height (because there
  --   is no point in creating a finalization share for already finalized
  --   heights)
  -- - the height is less or equal to the notarized height, because we can
  --   only create finalization shares when we no longer create notarization
  --   shares for that height
  -- - This replica is a notary at that height
  -- - Look at all the notarized blocks at this height. Since this height is
  --   notarized, we know we will get at least one. If we get exactly one,
  --   then check whether this replica created a notarization share for other
  --   any other block hashes. If not, create a finalization share for this
  --   block hash.
  [ AddToValidated (FinalizationShareMsg share)
    | Just not_height <- [notarized_height validated_pool],
      Just fin_height <- [finalized_height validated_pool],
      height <- [fin_height + 1 .. not_height],
      let reg_version = registry_version validated_pool height,
      Just (_threshold, committee) <-
        [notarization_committee height validated_pool],
      my_id `elem` committee,
      -- (2020-11-18): Is this right? We are assuming here that there is
      -- only ever one notarized block at a given height.
      [block_hash] <- nub [get_notarized_block_hashes validated_pool height],
      null
        [ share
          | share@( NotarizationShareMsg
                      (NotarizationShare my_id' height' block_hash' _sig')
                    ) <-
              msgs validated_pool,
            my_id == my_id',
            height == height',
            block_hash /= block_hash'
        ],
      let sig = sign_finalization_share my_id reg_version height block_hash,
      let share = FinalizationShare my_id height block_hash sig,
      FinalizationShareMsg share `notElem` msgs validated_pool
  ]
    ++
    -- Mark a finalization share as valid if
    -- - it is for a height greater than the current finalized height
    -- - the signer is part of the notarization committee for that height
    -- - the signature is valid
    -- - we have a valid notarization that matches the block hash contained
    --   in the finalization share
    [ MoveToValidated share
      | share@( FinalizationShareMsg
                  (FinalizationShare signer height block_hash sig)
                ) <-
          msgs unvalidated_pool,
        Just fin_height <- [finalized_height validated_pool],
        height > fin_height,
        Just (_threshold, committee) <-
          [notarization_committee height validated_pool],
        signer `elem` committee,
        let reg_version = registry_version validated_pool height,
        Valid
          == verify_finalization_share_sig
            reg_version
            signer
            height
            block_hash
            sig,
        NotarizationMsg (Notarization _signers height' block_hash' _sig') <-
          msgs validated_pool,
        height == height',
        block_hash == block_hash'
    ]
    ++
    -- Mark a finalization share as invalid if one of the following holds
    -- - the signer is not a notary for that height
    -- - the signature is invalid
    [ HandleInvalid share
      | share@( FinalizationShareMsg
                  (FinalizationShare signer height block_hash sig)
                ) <-
          msgs validated_pool,
        Just (_threshold, committee) <-
          [notarization_committee height validated_pool],
        let reg_version = registry_version validated_pool height,
        signer `notElem` committee
          || Invalid
            == verify_finalization_share_sig
              reg_version
              signer
              height
              block_hash
              sig
    ]
    ++
    -- Create a Finalization for some height and block hash from finalization
    -- shares if
    -- - there is no validated finalization for that height and block hash yet
    -- - there is a valid notarization for this block hash
    -- - we have t distinct finalization shares on block hash from
    --   notarization committee members at the relevant height, where t is the
    --   notarization threshold at the relevant height
    [ AddToValidated
        ( FinalizationMsg
            (Finalization signers height block_hash sig)
        )
      | ((height, block_hash), shares) <-
          finalization_share_signatures validated_pool,
        Just fin_height <- [finalized_height validated_pool],
        height > fin_height,
        -- Ensure there was a notarization for this height
        NotarizationMsg
          (Notarization _not_signers height' block_hash' _not_sig) <-
          msgs validated_pool,
        height == height',
        block_hash == block_hash',
        Just (threshold, _notarization_committee) <-
          [ notarization_committee
              height
              validated_pool
          ],
        let signers = map fst shares,
        genericLength shares >= threshold,
        let sig = aggregate_finalization_signature_shares shares
    ]
    ++
    -- Mark a Finalization as valid if
    -- - this is for a height > the current finalized height (as otherwise it
    --   is not relevant)
    -- - we have a validated notarized block that matches the finalization
    --   block hash
    -- - the Finalization is signed by sufficiently many notaries, and has a
    --   valid signature
    [ MoveToValidated finalization_message
      | finalization_message@( FinalizationMsg
                                 ( Finalization
                                     signers
                                     height
                                     block_hash
                                     sig
                                   )
                               ) <-
          msgs unvalidated_pool,
        Just fin_height <- [finalized_height validated_pool],
        height > fin_height,
        BlockProposalMsg
          ( BlockProposal
              _block_signer
              bp_block_hash
              (Block h _parent _rank _payload)
              _block_sig
            ) <-
          msgs validated_pool,
        h == height,
        bp_block_hash == block_hash,
        NotarizationMsg
          (Notarization _not_signers height' block_hash' _not_sig) <-
          msgs validated_pool,
        height' == height,
        block_hash' == block_hash,
        let reg_version = registry_version validated_pool height,
        Just (threshold, committee) <-
          [notarization_committee height validated_pool],
        signers `isSubsetOf` committee,
        genericLength signers >= threshold,
        Valid
          == verify_finalization_sig
            reg_version
            signers
            height
            block_hash
            sig
    ]
    ++
    -- Mark a finalization as invalid if one of the following hold:
    -- - one of the signers was not a notary
    -- - it is signed by less than the threshold amount of notaries
    -- - the signature is invalid
    [ HandleInvalid finalization_message
      | finalization_message@( FinalizationMsg
                                 ( Finalization
                                     signers
                                     height
                                     block_hash
                                     sig
                                   )
                               ) <-
          msgs unvalidated_pool,
        Just (threshold, committee) <-
          [notarization_committee height validated_pool],
        let reg_version = registry_version validated_pool height,
        signers `isNotSubsetOf` committee
          || genericLength signers < threshold
          || Invalid
            == verify_finalization_sig
              reg_version
              signers
              height
              block_hash
              sig
    ]

{-@
finalization_share_signatures ::
  ConsensusPoolSection ->
  [ ( (Height, HashOfBlock),
      [(ReplicaId, _)]<{\x y -> nfstcmp x y}>
    )
  ]
@-}

finalization_share_signatures ::
  ConsensusPoolSection ->
  [ ( (Height, HashOfBlock),
      [(ReplicaId, FinalizationShareSignature)]
    )
  ]
finalization_share_signatures validated_pool =
  concatMap
    ( \xs ->
        let (hashes, shares) = unzip xs
         in case nub hashes of
              -- Note that this will always be the case, because 'xs' was
              -- produced using groupBy.
              [x] -> [(x, nubFst shares)]
              _ -> []
    )
    $ groupBy
      ((==) `on` (fst . fst))
      [ ((height, block_hash), (signer, sig))
        | FinalizationShareMsg
            (FinalizationShare signer height block_hash sig) <-
            msgs validated_pool
      ]

{-@
get_notarized_block_hashes :: ConsensusPoolSection -> Height -> [HashOfBlock]
@-}

-- Get all hashes of blocks for which a notarization exists in the validated
-- pool at a given height
get_notarized_block_hashes ::
  ConsensusPoolSection -> Height -> [HashOfBlock]
get_notarized_block_hashes validated_pool height =
  [ block_hash
    | NotarizationMsg (Notarization _signers h block_hash _sig) <-
        msgs validated_pool,
      h == height
  ]

{-@
random_tape_changes ::
  Config ->
  ConsensusPool ->
  [ChangeAction]
@-}

-- TODO: We don't strictly need a random tape to verify the action of
-- consensus, and so this, similar to catch-up packages, can wait until we've
-- verified the core algorithms.
random_tape_changes :: Config -> ConsensusPool -> [ChangeAction]
random_tape_changes _config _pool = []

{-@
cup_making ::
  Config ->
  ConsensusPool ->
  [ChangeAction]
@-}

-- TODO: This is not strictly necessary for defining how consensus operates,
-- since really this is an optimization feature for the system that allows us
-- to purge out old artifacts and for nodes to be more efficient in catching
-- up state with one another.
cup_making :: Config -> ConsensusPool -> [ChangeAction]
cup_making _ _ = []

is_valid_pool :: ValidatedPoolSection -> Bool
is_valid_pool validated_pool =
  -- All random beacon shares for height H refer to the same beacon.
  null
    [ h1
      | RandomBeaconShareMsg (RandomBeaconShare _ h1 b1 _) <-
          msgs validated_pool,
        RandomBeaconShareMsg (RandomBeaconShare _ h2 b2 _) <-
          msgs validated_pool,
        h1 == h2,
        b1 /= b2
    ]
    -- All notarization shares at a given height H refer to the same block.
    && null
      [ h1
        | NotarizationShareMsg (NotarizationShare _ h1 b1 _) <-
            msgs validated_pool,
          NotarizationShareMsg (NotarizationShare _ h2 b2 _) <-
            msgs validated_pool,
          h1 == h2,
          b1 /= b2
      ]
    -- All notarization shares at a given height H refer to the same block.
    && null
      [ h1
        | FinalizationShareMsg (FinalizationShare _ h1 b1 _) <-
            msgs validated_pool,
          FinalizationShareMsg (FinalizationShare _ h2 b2 _) <-
            msgs validated_pool,
          h1 == h2,
          b1 /= b2
      ]

{-@
apply_change ::
  ChangeAction ->
  ConsensusPool ->
  Time ->
  ConsensusPool
@-}

height_of :: ConsensusMessage -> Height
height_of (RandomBeaconShareMsg RandomBeaconShare {..}) = rbs_height
height_of (RandomBeaconMsg RandomBeacon {..}) = rb_height
height_of (BlockProposalMsg BlockProposal {..}) = b_height bp_block
height_of (NotarizationShareMsg NotarizationShare {..}) = ns_height
height_of (NotarizationMsg Notarization {..}) = n_height
height_of (FinalizationShareMsg FinalizationShare {..}) = fs_height
height_of (FinalizationMsg Finalization {..}) = f_height
height_of (RandomTapeShareMsg RandomTapeShare {..}) = rts_height
height_of (RandomTapeMsg RandomTape {..}) = rt_height
height_of (CatchUpPackageShareMsg CatchUpPackageShare {..}) =
  b_height cups_block
height_of (CatchUpPackageMsg CatchUpPackage {..}) = b_height cup_block
height_of (EquivocationProofMsg EquivocationProof {..}) = ep_height

apply_change :: Time -> ConsensusPool -> ChangeAction -> ConsensusPool
apply_change time (val, unval) (AddToValidated msg) =
  ((msg, time) : val, unval)
apply_change _time (val, unval) (MoveToValidated msg) =
  let (matching, not_matching) = partition ((== msg) . fst) unval
   in (matching ++ val, not_matching)
apply_change _time (val, unval) (RemoveFromValidated msg) =
  let (_matching, not_matching) = partition ((== msg) . fst) val
   in (not_matching, unval)
apply_change _time (val, unval) (RemoveFromUnvalidated msg) =
  let (_matching, not_matching) = partition ((== msg) . fst) unval
   in (val, not_matching)
apply_change _time (val, unval) (PurgeValidatedBelow h) =
  let (matching, _not_matching) = partition ((>= h) . height_of . fst) val
   in (matching, unval)
apply_change _time (val, unval) (PurgeUnvalidatedBelow h) =
  let (matching, _not_matching) = partition ((>= h) . height_of . fst) unval
   in (val, matching)
apply_change _time (val, unval) (HandleInvalid msg) =
  let (_, not_matching) = partition ((== msg) . fst) unval
   in (val, not_matching)
