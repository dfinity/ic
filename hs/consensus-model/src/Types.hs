{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE ImplicitParams #-}
{-# LANGUAGE OverloadedStrings #-}

{-@ LIQUID "--max-case-expand=0" @-}
{-@ LIQUID "--no-adt" @-}
{-@ LIQUID "--exact-data-con" @-}

module Types where

import Codec.Candid
import Control.DeepSeq
import Crypto.Sign.Ed25519 (PublicKey, SecretKey)
import Data.ByteString (ByteString)
import Data.ByteString.Char8 (pack)
import Data.Function
import Data.List.Safe as Safe
import Data.Map (Map)
import qualified Data.Map as M
import GHC.Generics
import Lib
import Text.Show.Pretty
import Prelude hiding (round)

{-@ type Threshold = Nat @-}
type Threshold = Nat

{-@ type Height = Nat @-}
type Height = Nat

{-@ type Rank = Nat @-}
type Rank = Nat

{-@ type Slot = Nat @-}
type Slot = Nat

{-@ type DkgId = Nat @-}
type DkgId = Nat

{-@ type RegistryVersion = Nat @-}
type RegistryVersion = String

{-@ data HighLow = High | Low @-}
data HighLow = High | Low
  deriving (Eq, Show, Generic, PrettyVal, NFData)

{-@ data Valid = Valid | Invalid @-}
data Valid = Valid | Invalid
  deriving (Eq, Show, Generic, PrettyVal, NFData)

data Topology = Topology
  { thisSubnet :: SubnetId,
    network :: Map SubnetId [ReplicaId]
  }

replicas :: (?topo :: Topology) => [ReplicaId]
replicas = network ?topo M.! thisSubnet ?topo

{-@
data ReplicaId = ReplicaId
  { replica_id :: NodeId,
    replica_pk :: _,
    replica_sk :: _
  }
@-}

data ReplicaId = ReplicaId
  { replica_id :: NodeId,
    replica_pk :: PublicKey,
    replica_sk :: SecretKey
  }
  deriving (Eq, Ord, Generic)

instance NFData ReplicaId where
  rnf (ReplicaId x y z) = x `seq` y `seq` z `seq` ()

instance Show ReplicaId where
  show = show . replica_id

instance PrettyVal ReplicaId where
  prettyVal = prettyVal . replica_id

{-@ measure replica_ids @-}

replica_ids :: NonEmpty ReplicaId -> NonEmpty Principal
replica_ids [] = []
replica_ids (x : xs) = replica_id x : replica_ids xs

{-@ type SubnetId = Principal @-}
type SubnetId = Principal

{-@ type NodeId = Principal @-}
type NodeId = Principal

{-@ type Config = (ReplicaId, SubnetId) @-}
type Config = (ReplicaId, SubnetId)

{-@
data ConsensusMessage
  = RandomBeaconShareMsg RandomBeaconShare
  | RandomBeaconMsg RandomBeacon
  | BlockProposalMsg BlockProposal
  | NotarizationShareMsg NotarizationShare
  | NotarizationMsg Notarization
  | FinalizationShareMsg FinalizationShare
  | FinalizationMsg Finalization
  | RandomTapeShareMsg RandomTapeShare
  | RandomTapeMsg RandomTape
  | CatchUpPackageShareMsg CatchUpPackageShare
  | CatchUpPackageMsg CatchUpPackage
  | EquivocationProofMsg EquivocationProof
@-}

data ConsensusMessage
  = RandomBeaconShareMsg RandomBeaconShare
  | RandomBeaconMsg RandomBeacon
  | BlockProposalMsg BlockProposal
  | NotarizationShareMsg NotarizationShare
  | NotarizationMsg Notarization
  | FinalizationShareMsg FinalizationShare
  | FinalizationMsg Finalization
  | RandomTapeShareMsg RandomTapeShare
  | RandomTapeMsg RandomTape
  | CatchUpPackageShareMsg CatchUpPackageShare
  | CatchUpPackageMsg CatchUpPackage
  | EquivocationProofMsg EquivocationProof
  deriving (Eq, Show, Generic, PrettyVal, NFData)

{-@ random_beacon_shares :: ConsensusPoolSection -> [RandomBeaconShare] @-}
random_beacon_shares :: ConsensusPoolSection -> [RandomBeaconShare]
random_beacon_shares [] = []
random_beacon_shares ((RandomBeaconShareMsg x, _) : xs) =
  x : random_beacon_shares xs
random_beacon_shares (_ : xs) = random_beacon_shares xs

{-@ notarization_shares :: ConsensusPoolSection -> [NotarizationShare] @-}
notarization_shares :: ConsensusPoolSection -> [NotarizationShare]
notarization_shares [] = []
notarization_shares ((NotarizationShareMsg x, _) : xs) =
  x : notarization_shares xs
notarization_shares (_ : xs) = notarization_shares xs

{-@ finalization_shares :: ConsensusPoolSection -> [FinalizationShare] @-}
finalization_shares :: ConsensusPoolSection -> [FinalizationShare]
finalization_shares [] = []
finalization_shares ((FinalizationShareMsg x, _) : xs) =
  x : finalization_shares xs
finalization_shares (_ : xs) = finalization_shares xs

{-@ type ConsensusPoolSection = [(ConsensusMessage, Time)] @-}
type ConsensusPoolSection = [(ConsensusMessage, Time)]

{-@ measure msgs @-}
msgs :: ConsensusPoolSection -> [ConsensusMessage]
msgs [] = []
msgs ((x, _) : xs) = x : msgs xs

{-
{-@ inline compatible_msgs @-}
compatible_msgs :: ConsensusMessage -> ConsensusMessage -> Bool
compatible_msgs (FinalizationShareMsg f1) (FinalizationShareMsg f2)
  | fsHeight f1 == fsHeight f2 = fsBlock f1 == fsBlock f2
  | otherwise = True
compatible_msgs _ _ = True

{-@ inline compatible @-}
compatible :: ConsensusMessage -> ChangeAction -> Bool
compatible msg (AddToValidated v) = compatible_msgs msg v
compatible msg (MoveToValidated v) = compatible_msgs msg v
compatible _ (HandleInvalid _) = True

{-@ is_valid_action ::
      xs:ValidatedPoolSection -> ChangeAction -> Bool / [len xs] @-}
{-@ reflect is_valid_action @-}

is_valid_action :: ValidatedPoolSection -> ChangeAction -> Bool
is_valid_action [] _ = True
is_valid_action ((x, _) : xs) ca =
  compatible x ca && is_valid_action xs ca

{-@ type ValidatedPoolSection =
      [(ConsensusMessage, Time)]<{\m1 m2 ->
        compatible_msgs (fst m1) (fst m2)}> @-}
-}

{-@ type ValidatedPoolSection = [(ConsensusMessage, Time)] @-}
type ValidatedPoolSection = [(ConsensusMessage, Time)]

{-@ type ConsensusPool = (ValidatedPoolSection, ConsensusPoolSection) @-}
type ConsensusPool = (ValidatedPoolSection, ConsensusPoolSection)

{-@ measure validated @-}
validated :: ConsensusPool -> ConsensusPoolSection
validated (validated_pool, _) = validated_pool

{-@ measure unvalidated @-}
unvalidated :: ConsensusPool -> ConsensusPoolSection
unvalidated (_, unvalidated_pool) = unvalidated_pool

------------------------------------------------------------------------
-- Random Beacons
------------------------------------------------------------------------

data RandomBeaconShareSignature
  = RandomBeaconShareSignature ThresholdSignatureShare
  deriving (Eq, Show, Generic, PrettyVal, NFData)

sign_random_beacon_share ::
  ReplicaId ->
  DkgId ->
  Height ->
  HashOfRandomBeacon ->
  RandomBeaconShareSignature
sign_random_beacon_share _my_id _dkg_id _height _parent =
  RandomBeaconShareSignature (ThresholdSignatureShare "")

verify_random_beacon_share_sig ::
  DkgId ->
  ReplicaId ->
  Height ->
  HashOfRandomBeacon ->
  RandomBeaconShareSignature ->
  Valid
verify_random_beacon_share_sig
  _dkg_id
  signer
  _height
  _beacon_hash
  (RandomBeaconShareSignature sig) =
    if verify_threshold_sig_share (replica_pk signer) sig
      then Valid
      else Invalid

{-@
data RandomBeaconShare = RandomBeaconShare
  { rbs_replicaId :: ReplicaId,
    rbs_height :: Height,
    rbs_parent :: HashOfRandomBeacon,
    rbs_randomBeaconShareSignature :: _
  }
@-}

data RandomBeaconShare = RandomBeaconShare
  { rbs_replicaId :: ReplicaId,
    rbs_height :: Height,
    rbs_parent :: HashOfRandomBeacon,
    rbs_randomBeaconShareSignature :: RandomBeaconShareSignature
  }
  deriving (Eq, Show, Generic, PrettyVal, NFData)

-- We don't actually need to use a hash of the random beacon; we can assume
-- infinite memory and assume all data is visible.
{-@ data HashOfRandomBeacon = HashOfRandomBeacon Hash @-}

data HashOfRandomBeacon = HashOfRandomBeacon Hash
  deriving (Eq, Show, Generic, PrettyVal, NFData)

hash_random_beacon :: RandomBeacon -> HashOfRandomBeacon
hash_random_beacon
  ( RandomBeacon
      height
      (HashOfRandomBeacon parent)
      (RandomBeaconSignature sig)
    ) =
    HashOfRandomBeacon $
      hash $
        pack (show height)
          <> getHash parent
          <> getThresholdSignature sig

data RandomBeaconSignature = RandomBeaconSignature ThresholdSignature
  deriving (Eq, Show, Generic, PrettyVal, NFData)

aggregate_random_beacon_signature_shares ::
  [(ReplicaId, RandomBeaconShareSignature)] -> RandomBeaconSignature
aggregate_random_beacon_signature_shares _ =
  -- TODO: aggregate_signature_shares
  RandomBeaconSignature (ThresholdSignature "")

verify_random_beacon_sig ::
  DkgId ->
  Height ->
  HashOfRandomBeacon ->
  RandomBeaconSignature ->
  Valid
verify_random_beacon_sig _dkg_id _ _ (RandomBeaconSignature _sig) =
  -- TODO: verify_random_beacon_sig
  Valid

{-@
data RandomBeacon = RandomBeacon
  { rb_height :: Height,
    rb_parent :: HashOfRandomBeacon,
    rb_randomBeaconSignature :: _
  }
@-}

data RandomBeacon = RandomBeacon
  { rb_height :: Height,
    rb_parent :: HashOfRandomBeacon,
    rb_randomBeaconSignature :: RandomBeaconSignature
  }
  deriving (Eq, Show, Generic, PrettyVal, NFData)

------------------------------------------------------------------------
-- Blocks and Block Proposals
------------------------------------------------------------------------

{-@ data HashOfBlock = HashOfBlock Hash @-}

-- We don't actually need to use a hash of the block; we can assume infinite
-- memory and assume all data is visible.
data HashOfBlock = HashOfBlock Hash
  deriving (Eq, Show, Generic, PrettyVal, NFData)

instance Ord HashOfBlock where
  HashOfBlock (Hash x) <= HashOfBlock (Hash y) = x <= y

hash_block :: Block -> HashOfBlock
hash_block (Block height (HashOfBlock parent) slot payload) =
  HashOfBlock $
    hash $
      pack (show height)
        <> getHash parent
        <> pack (show slot)
        <> getPayload payload

data Payload = Payload {getPayload :: ByteString}
  deriving (Eq, Show, Generic, PrettyVal, NFData)

{-@
data Block = Block
  { b_height :: Height,
    b_parent :: HashOfBlock,
    b_slot :: Slot,
    b_payload :: _
  }
@-}

data Block = Block
  { b_height :: Height,
    b_parent :: HashOfBlock,
    b_slot :: Slot,
    b_payload :: Payload
  }
  deriving (Eq, Show, Generic, PrettyVal, NFData)

-- Block comparison, current using rank then block hash, but could be updated
-- to use chain weight.
instance Ord Block where
  blk1@(Block height1 _parent1 rank1 _payload1)
    <= blk2@(Block height2 _parent2 rank2 _payload2)
      | height1 == height2 =
        (rank1 < rank2 || rank1 == rank2)
          && hash_block blk1 <= hash_block blk2
      | otherwise = error "Cannot compare Blocks at different heights"

create_block_payload :: Block -> () -> Payload
create_block_payload _parent _ =
  -- TODO: create_block_payload
  Payload ""

-- TODO: For the purpose of validating the operation of consensus, we
-- presently ignore what it means for a block payload to be valid, even though
-- in future this will become important to correctness.
validate_block_payload :: Payload -> Valid
validate_block_payload (Payload _) = Valid

data BlockSignature = BlockSignature Signature
  deriving (Eq, Show, Generic, PrettyVal, NFData)

sign_block :: ReplicaId -> RegistryVersion -> Block -> BlockSignature
sign_block my_id _reg_version (Block height (HashOfBlock parent) slot payload) =
  BlockSignature $
    sign (replica_sk my_id) $
      pack (show height)
        <> getHash parent
        <> pack (show slot)
        <> getPayload payload

verify_block_sig ::
  ReplicaId -> RegistryVersion -> Block -> BlockSignature -> Valid
verify_block_sig my_id _ _ (BlockSignature sig) =
  if verify (replica_pk my_id) sig
    then Valid
    else Invalid

{-@
data BlockProposal = BlockProposal
  { bp_replicaId :: ReplicaId,
    bp_block :: Block,
    bp_signature :: _
  }
@-}

data BlockProposal = BlockProposal
  { bp_replicaId :: ReplicaId,
    bp_block_hash :: HashOfBlock,
    bp_block :: Block,
    bp_signature :: BlockSignature
  }
  deriving (Eq, Show, Generic, PrettyVal, NFData)

{-@ measure bpBlock @-}

bpBlock :: BlockProposal -> Block
bpBlock (BlockProposal _ _ b _) = b

-- BlockProposal comparison is defined as the comparision between the
-- contained blocks
instance Ord BlockProposal where
  BlockProposal _ _ block1 _ <= BlockProposal _ _ block2 _ = block1 <= block2

------------------------------------------------------------------------
-- Notarizations
------------------------------------------------------------------------

data NotarizationShareSignature = NotarizationShareSignature MultiSignature
  deriving (Eq, Show, Generic, PrettyVal, NFData)

sign_notarization_share ::
  ReplicaId ->
  RegistryVersion ->
  Height ->
  HashOfBlock ->
  NotarizationShareSignature
sign_notarization_share my_id _dkg_id height (HashOfBlock block) =
  NotarizationShareSignature $
    sign_multi (replica_sk my_id) $
      pack (show height) <> getHash block

verify_notarization_share_sig ::
  RegistryVersion ->
  ReplicaId ->
  Height ->
  HashOfBlock ->
  NotarizationShareSignature ->
  Valid
verify_notarization_share_sig
  _reg_version
  my_id
  _height
  _block_hash
  (NotarizationShareSignature sig) =
    if verify_multi [replica_pk my_id] sig
      then Valid
      else Invalid

{-@
data NotarizationShare = NotarizationShare
  { ns_replicaId :: ReplicaId,
    ns_height :: Height,
    ns_block :: HashOfBlock,
    ns_notarizationShareSignature :: _
  }
@-}

data NotarizationShare = NotarizationShare
  { ns_replicaId :: ReplicaId,
    ns_height :: Height,
    ns_block :: HashOfBlock,
    ns_notarizationShareSignature :: NotarizationShareSignature
  }
  deriving (Eq, Show, Generic, PrettyVal, NFData)

data NotarizationSignature = NotarizationSignature MultiSignature
  deriving (Eq, Show, Generic, PrettyVal, NFData)

aggregate_notarization_signature_shares ::
  [(ReplicaId, NotarizationShareSignature)] -> NotarizationSignature
aggregate_notarization_signature_shares shares =
  NotarizationSignature
    (foldMap (\(_, NotarizationShareSignature sig) -> sig) shares)

verify_notarization_sig ::
  RegistryVersion ->
  [ReplicaId] ->
  Height ->
  HashOfBlock ->
  NotarizationSignature ->
  Valid
verify_notarization_sig
  _reg_version
  ids
  _height
  _block_hash
  (NotarizationSignature sig) =
    if verify_multi (map replica_pk ids) sig
      then Valid
      else Invalid

{-@
data Notarization = Notarization
  { n_replicaIds :: [ReplicaId],
    n_height :: Height,
    n_block :: HashOfBlock,
    n_notarizationSignature :: _
  }
@-}

data Notarization = Notarization
  { n_replicaIds :: [ReplicaId],
    n_height :: Height,
    n_block :: HashOfBlock,
    n_notarizationSignature :: NotarizationSignature
  }
  deriving (Eq, Show, Generic, PrettyVal, NFData)

------------------------------------------------------------------------
-- Finalizations
------------------------------------------------------------------------

data FinalizationShareSignature = FinalizationShareSignature MultiSignature
  deriving (Eq, Show, Generic, PrettyVal, NFData)

sign_finalization_share ::
  ReplicaId ->
  RegistryVersion ->
  Height ->
  HashOfBlock ->
  FinalizationShareSignature
sign_finalization_share my_id _dkg_id height (HashOfBlock block) =
  FinalizationShareSignature $
    sign_multi (replica_sk my_id) $
      pack (show height) <> getHash block

verify_finalization_share_sig ::
  RegistryVersion ->
  ReplicaId ->
  Height ->
  HashOfBlock ->
  FinalizationShareSignature ->
  Valid
verify_finalization_share_sig
  _reg_version
  my_id
  _height
  _block_hash
  (FinalizationShareSignature sig) =
    if verify_multi [replica_pk my_id] sig
      then Valid
      else Invalid

{-@
data FinalizationShare = FinalizationShare
  { fs_replicaId :: ReplicaId,
    fs_height :: Height,
    fs_block :: HashOfBlock,
    fs_finalizationShareSignature :: _
  }
@-}

data FinalizationShare = FinalizationShare
  { fs_replicaId :: ReplicaId,
    fs_height :: Height,
    fs_block :: HashOfBlock,
    fs_finalizationShareSignature :: FinalizationShareSignature
  }
  deriving (Eq, Show, Generic, PrettyVal, NFData)

{-@ measure fsHeight @-}

fsHeight :: FinalizationShare -> Height
fsHeight (FinalizationShare _ h _ _) = h

{-@ measure fsBlock @-}

fsBlock :: FinalizationShare -> HashOfBlock
fsBlock (FinalizationShare _ _ b _) = b

data FinalizationSignature = FinalizationSignature MultiSignature
  deriving (Eq, Show, Generic, PrettyVal, NFData)

aggregate_finalization_signature_shares ::
  [(ReplicaId, FinalizationShareSignature)] -> FinalizationSignature
aggregate_finalization_signature_shares shares =
  FinalizationSignature
    (foldMap (\(_, FinalizationShareSignature sig) -> sig) shares)

verify_finalization_sig ::
  RegistryVersion ->
  [ReplicaId] ->
  Height ->
  HashOfBlock ->
  FinalizationSignature ->
  Valid
verify_finalization_sig
  _reg_version
  ids
  _height
  _block_hash
  (FinalizationSignature sig) =
    if verify_multi (map replica_pk ids) sig
      then Valid
      else Invalid

{-@
data Finalization = Finalization
  { f_replicaIds :: [ReplicaId],
    f_height :: Height,
    f_block :: HashOfBlock,
    f_finalizationSignature :: _
  }
@-}

data Finalization = Finalization
  { f_replicaIds :: [ReplicaId],
    f_height :: Height,
    f_block :: HashOfBlock,
    f_finalizationSignature :: FinalizationSignature
  }
  deriving (Eq, Show, Generic, PrettyVal, NFData)

------------------------------------------------------------------------
-- Random Tape
------------------------------------------------------------------------

data RandomTapeShareSignature = RandomTapeShareSignature Signature
  deriving (Eq, Show, Generic, PrettyVal, NFData)

{-@
data RandomTapeShare = RandomTapeShare
  { rts_height :: Height,
    rts_randomTapeShareSignature :: _
  }
@-}

data RandomTapeShare = RandomTapeShare
  { rts_height :: Height,
    rts_randomTapeShareSignature :: RandomTapeShareSignature
  }
  deriving (Eq, Show, Generic, PrettyVal, NFData)

data RandomTapeSignature = RandomTapeSignature Signature
  deriving (Eq, Show, Generic, PrettyVal, NFData)

{-@
data RandomTape = RandomTape
  { rt_replicaId :: ReplicaId,
    rt_height :: Height,
    rt_randomTapeSignature :: _
  }
@-}

data RandomTape = RandomTape
  { rt_replicaId :: ReplicaId,
    rt_height :: Height,
    rt_randomTapeSignature :: RandomTapeSignature
  }
  deriving (Eq, Show, Generic, PrettyVal, NFData)

data HashOfState = HashOfState Hash
  deriving (Eq, Show, Generic, PrettyVal, NFData)

------------------------------------------------------------------------
-- State and Catchup Packages
------------------------------------------------------------------------

data StateShareSignature = StateShareSignature Signature
  deriving (Eq, Show, Generic, PrettyVal, NFData)

{-@
data CatchUpPackageShare = CatchUpPackageShare
  { cups_replicaId :: ReplicaId,
    cups_block :: Block,
    cups_randomBeacon :: RandomBeacon,
    cups_state :: _,
    cups_stateShareSignature :: _
  }
@-}

data CatchUpPackageShare = CatchUpPackageShare
  { cups_replicaId :: ReplicaId,
    cups_block :: Block,
    cups_randomBeacon :: RandomBeacon,
    cups_state :: HashOfState,
    cups_stateShareSignature :: StateShareSignature
  }
  deriving (Eq, Show, Generic, PrettyVal, NFData)

data StateSignature = StateSignature Signature
  deriving (Eq, Show, Generic, PrettyVal, NFData)

{-@
data CatchUpPackage = CatchUpPackage
  { cup_block :: Block,
    cup_randomBeacon :: RandomBeacon,
    cup_state :: _,
    cup_stateSignature :: _
  }
@-}

data CatchUpPackage = CatchUpPackage
  { cup_block :: Block,
    cup_randomBeacon :: RandomBeacon,
    cup_state :: HashOfState,
    cup_stateSignature :: StateSignature
  }
  deriving (Eq, Show, Generic, PrettyVal, NFData)

------------------------------------------------------------------------
-- Equivocation Proofs
------------------------------------------------------------------------

{-@
data EquivocationProof = EquivocationProof
  { ep_replicaId :: ReplicaId,
    ep_height :: Height,
    ep_blockProposal1 ::
      {v:BlockProposal | b_height (bpBlock v) == ep_height},
    ep_blockProposal2 ::
      {v:BlockProposal | b_height (bpBlock v) == ep_height}
  }
@-}

data EquivocationProof = EquivocationProof
  { ep_replicaId :: ReplicaId,
    ep_height :: Height,
    ep_blockProposal1 :: BlockProposal,
    ep_blockProposal2 :: BlockProposal
  }
  deriving (Eq, Show, Generic, PrettyVal, NFData)

------------------------------------------------------------------------
-- Change Actions
------------------------------------------------------------------------

{-@
data ChangeAction
  = AddToValidated ConsensusMessage
  | MoveToValidated ConsensusMessage
  | RemoveFromValidated ConsensusMessage
  | RemoveFromUnvalidated ConsensusMessage
  | PurgeValidatedBelow Height
  | PurgeUnvalidatedBelow Height
  | HandleInvalid ConsensusMessage
@-}

data ChangeAction
  = AddToValidated ConsensusMessage
  | MoveToValidated ConsensusMessage
  | RemoveFromValidated ConsensusMessage
  | RemoveFromUnvalidated ConsensusMessage
  | PurgeValidatedBelow Height
  | PurgeUnvalidatedBelow Height
  | HandleInvalid ConsensusMessage
  deriving (Eq, Show, Generic, PrettyVal, NFData)
