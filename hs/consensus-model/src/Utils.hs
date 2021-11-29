{-# LANGUAGE ImplicitParams #-}
{-# LANGUAGE OverloadedStrings #-}

module Utils where

import Control.Monad
import qualified Crypto.Sign.Ed25519 as Ed25519
import Data.Function
import Data.List.Safe as Safe
import Data.Map (Map)
import qualified Data.Map as M
import Lib
import Types
import Prelude hiding (round)

------------------------------------------------------------------------------
-- UTILITY FUNCTIONS
------------------------------------------------------------------------------

create_random_beacon_share :: ReplicaId -> RandomBeacon -> RandomBeaconShare
create_random_beacon_share
  my_id
  parent@(RandomBeacon height _grandparent _sig) =
    RandomBeaconShare
      my_id
      (height + 1)
      beacon_hash
      ( sign_random_beacon_share
          my_id
          0 -- dkg_id
          (height + 1)
          beacon_hash
      )
    where
      beacon_hash = hash_random_beacon parent

create_random_beacon :: (?topo :: Topology) => RandomBeacon -> RandomBeacon
create_random_beacon parent@(RandomBeacon height _grandparent_hash _sig) =
  RandomBeacon
    (height + 1)
    beacon_hash
    (everyone_sign_random_beacon 0 (height + 1) beacon_hash)
  where
    beacon_hash = hash_random_beacon parent

sign_random_beacon ::
  [ReplicaId] ->
  DkgId ->
  Height ->
  HashOfRandomBeacon ->
  RandomBeaconSignature
sign_random_beacon replicaIds dkg_id height parent_hash =
  aggregate_random_beacon_signature_shares $
    map
      ( \my_id ->
          ( my_id,
            sign_random_beacon_share
              my_id
              dkg_id
              height
              parent_hash
          )
      )
      replicaIds

everyone_sign_random_beacon ::
  (?topo :: Topology) =>
  DkgId ->
  Height ->
  HashOfRandomBeacon ->
  RandomBeaconSignature
everyone_sign_random_beacon = sign_random_beacon replicas

create_block :: Block -> Block
create_block
  parent@(Block height _grandparent_hash _slot _payload) =
    Block
      (height + 1)
      (hash_block parent)
      0
      (Payload "")

create_block_proposal :: ReplicaId -> Block -> BlockProposal
create_block_proposal my_id block =
  BlockProposal
    my_id
    (hash_block block)
    block
    (sign_block my_id "0.1.0" block)

sign_notarization ::
  [ReplicaId] ->
  RegistryVersion ->
  Height ->
  HashOfBlock ->
  NotarizationSignature
sign_notarization replicaIds reg_version height block_hash =
  aggregate_notarization_signature_shares $
    map
      ( \my_id ->
          ( my_id,
            sign_notarization_share
              my_id
              reg_version
              height
              block_hash
          )
      )
      replicaIds

everyone_sign_notarization ::
  (?topo :: Topology) =>
  RegistryVersion ->
  Height ->
  HashOfBlock ->
  NotarizationSignature
everyone_sign_notarization = sign_notarization replicas

create_notarization :: (?topo :: Topology) => Block -> Notarization
create_notarization block@(Block height _parent _slot _payload) =
  Notarization
    replicas
    height
    block_hash
    sig
  where
    block_hash = hash_block block
    sig = everyone_sign_notarization "0.1.0" height block_hash

sign_finalization ::
  [ReplicaId] ->
  RegistryVersion ->
  Height ->
  HashOfBlock ->
  FinalizationSignature
sign_finalization replicaIds reg_version height block_hash =
  aggregate_finalization_signature_shares $
    map
      ( \my_id ->
          ( my_id,
            sign_finalization_share
              my_id
              reg_version
              height
              block_hash
          )
      )
      replicaIds

everyone_sign_finalization ::
  (?topo :: Topology) =>
  RegistryVersion ->
  Height ->
  HashOfBlock ->
  FinalizationSignature
everyone_sign_finalization = sign_finalization replicas

create_finalization :: (?topo :: Topology) => Block -> Finalization
create_finalization block@(Block height _parent _slot _payload) =
  Finalization
    replicas
    height
    block_hash
    sig
  where
    block_hash = hash_block block
    sig = everyone_sign_finalization "0.1.0" height block_hash

create_topology :: Map SubnetId [ReplicaId] -> (Topology, Config)
create_topology net =
  ( Topology
      { thisSubnet = sub,
        network = net
      },
    (Prelude.head (net M.! sub), sub)
  )
  where
    sub = Prelude.head (M.keys net)

register_node :: NodeId -> IO ReplicaId
register_node nodeId = do
  (pk, sk) <- Ed25519.createKeypair
  pure $ ReplicaId nodeId pk sk

register_nodes :: [NodeId] -> IO [ReplicaId]
register_nodes = mapM register_node

add_to_unvalidated_pool ::
  Time -> ConsensusPool -> ConsensusMessage -> ConsensusPool
add_to_unvalidated_pool time (validated_pool, unvalidated_pool) msg =
  (validated_pool, (msg, time) : unvalidated_pool)

all_validated_beacons :: ConsensusPoolSection -> [(RandomBeacon, Time)]
all_validated_beacons [] = []
all_validated_beacons ((RandomBeaconMsg beacon, t) : xs) =
  (beacon, t) : all_validated_beacons xs
all_validated_beacons (_ : xs) = all_validated_beacons xs

all_validated_blocks :: ConsensusPoolSection -> [(Block, Time)]
all_validated_blocks [] = []
all_validated_blocks ((BlockProposalMsg (BlockProposal _ _ block _), t) : xs) =
  (block, t) : all_validated_blocks xs
all_validated_blocks (_ : xs) = all_validated_blocks xs

-- A lens traversal over the blocks in a consensus pool
blocks ::
  Applicative f =>
  (Block -> f Block) ->
  ConsensusPool ->
  f ConsensusPool
blocks f (validated_pool, unvalidated_pool) =
  (,) <$> traverse g validated_pool <*> pure unvalidated_pool
  where
    g (msg, time) =
      (,) <$> h msg <*> pure time
    h (BlockProposalMsg bp) =
      BlockProposalMsg
        <$> ( BlockProposal <$> pure (bp_replicaId bp)
                <*> pure (bp_block_hash bp)
                <*> f (bp_block bp)
                <*> pure (bp_signature bp)
            )
    h msg = pure msg

-- A lens traversal over the initial random beacon in a consensus pool
randomBeacons ::
  Applicative f =>
  (RandomBeacon -> f RandomBeacon) ->
  ConsensusPool ->
  f ConsensusPool
randomBeacons f (validated_pool, unvalidated_pool) =
  (,) <$> traverse g validated_pool <*> pure unvalidated_pool
  where
    g (msg, time) =
      (,) <$> h msg <*> pure time
    h (RandomBeaconMsg rb) = RandomBeaconMsg <$> f rb
    h msg = pure msg
