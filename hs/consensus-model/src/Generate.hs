{-# LANGUAGE ImplicitParams #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Generate where

import Consensus
import Control.Applicative
import Control.Monad
import Hedgehog hiding (Action)
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range
import Types

chooseReplicaId ::
  (MonadGen m, ?topo :: Topology, ?rv :: RegistryVersion) =>
  m ReplicaId
chooseReplicaId = Gen.element replicas

genHeight :: MonadGen m => m Height
genHeight = Gen.int $ Range.linear 1 100

genSlot :: MonadGen m => m Height
genSlot = Gen.int $ Range.linear 1 10

genPayload :: MonadGen m => m Payload
genPayload = pure $ Payload ""

genRandomBeaconShare ::
  (MonadGen m, ?topo :: Topology, ?rv :: RegistryVersion) =>
  m RandomBeaconShare
genRandomBeaconShare = do
  rbs_replicaId <- chooseReplicaId
  rbs_height <- genHeight
  rbs_parent <- hash_random_beacon <$> genRandomBeacon
  rbs_randomBeaconShareSignature <- undefined
  pure RandomBeaconShare {..}

genRandomBeacon :: MonadGen m => m RandomBeacon
genRandomBeacon = do
  rb_height <- genHeight
  rb_parent <- hash_random_beacon <$> genRandomBeacon
  rb_randomBeaconSignature <- undefined
  pure RandomBeacon {..}

genBlock ::
  (MonadGen m, ?topo :: Topology, ?rv :: RegistryVersion) =>
  m Block
genBlock = do
  b_height <- genHeight
  b_parent <- hash_block <$> genBlock
  b_slot <- genSlot
  b_payload <- genPayload
  pure Block {..}

genBlockProposal ::
  (MonadGen m, ?topo :: Topology, ?rv :: RegistryVersion) =>
  m BlockProposal
genBlockProposal = do
  bp_replicaId <- chooseReplicaId
  bp_block <- genBlock
  let bp_block_hash = hash_block bp_block
  bp_signature <- pure $ sign_block bp_replicaId ?rv bp_block
  pure BlockProposal {..}

genNotarizationShare ::
  (MonadGen m, ?topo :: Topology, ?rv :: RegistryVersion) =>
  m NotarizationShare
genNotarizationShare = do
  ns_replicaId <- chooseReplicaId
  ns_height <- genHeight
  ns_block <- hash_block <$> genBlock
  ns_notarizationShareSignature <- undefined
  pure NotarizationShare {..}

genNotarization ::
  (Alternative m, MonadGen m, ?topo :: Topology, ?rv :: RegistryVersion) =>
  m Notarization
genNotarization = do
  n_height <- genHeight
  let Just (threshold, signers) = notarization_committee n_height undefined
  n_replicaIds <- Gen.subsequence signers
  guard $ length n_replicaIds >= threshold
  n_block <- hash_block <$> genBlock
  n_notarizationSignature <- undefined
  pure Notarization {..}

genFinalizationShare ::
  (MonadGen m, ?topo :: Topology, ?rv :: RegistryVersion) =>
  m FinalizationShare
genFinalizationShare = do
  fs_replicaId <- chooseReplicaId
  fs_height <- genHeight
  fs_block <- hash_block <$> genBlock
  fs_finalizationShareSignature <- undefined
  pure FinalizationShare {..}

genFinalization ::
  (Alternative m, MonadGen m, ?topo :: Topology, ?rv :: RegistryVersion) =>
  m Finalization
genFinalization = do
  f_height <- genHeight
  let Just (threshold, signers) = notarization_committee f_height undefined
  f_replicaIds <- Gen.subsequence signers
  guard $ length f_replicaIds >= threshold
  f_block <- hash_block <$> genBlock
  f_finalizationSignature <- undefined
  pure Finalization {..}

genRandomTapeShare :: MonadGen m => m RandomTapeShare
genRandomTapeShare = do
  rts_height <- genHeight
  rts_randomTapeShareSignature <- undefined
  pure RandomTapeShare {..}

genRandomTape ::
  (MonadGen m, ?topo :: Topology, ?rv :: RegistryVersion) =>
  m RandomTape
genRandomTape = do
  rt_replicaId <- chooseReplicaId
  rt_height <- genHeight
  rt_randomTapeSignature <- undefined
  pure RandomTape {..}

genCatchUpPackageShare ::
  (MonadGen m, ?topo :: Topology, ?rv :: RegistryVersion) =>
  m CatchUpPackageShare
genCatchUpPackageShare = do
  cups_replicaId <- chooseReplicaId
  cups_block <- genBlock
  cups_randomBeacon <- genRandomBeacon
  cups_state <- undefined
  cups_stateShareSignature <- undefined
  pure CatchUpPackageShare {..}

genCatchUpPackage ::
  (MonadGen m, ?topo :: Topology, ?rv :: RegistryVersion) =>
  m CatchUpPackage
genCatchUpPackage = do
  cup_block <- genBlock
  cup_randomBeacon <- genRandomBeacon
  cup_state <- undefined
  cup_stateSignature <- undefined
  pure CatchUpPackage {..}

genEquivocationProof ::
  (MonadGen m, ?topo :: Topology, ?rv :: RegistryVersion) =>
  m EquivocationProof
genEquivocationProof = do
  ep_replicaId <- chooseReplicaId
  ep_height <- genHeight
  ep_blockProposal1 <- genBlockProposal
  ep_blockProposal2 <- genBlockProposal
  pure EquivocationProof {..}

genConsensusMessage ::
  (Alternative m, MonadGen m, ?topo :: Topology, ?rv :: RegistryVersion) =>
  m ConsensusMessage
genConsensusMessage =
  Gen.frequency
    [ (1, RandomBeaconShareMsg <$> genRandomBeaconShare),
      (1, RandomBeaconMsg <$> genRandomBeacon),
      (1, BlockProposalMsg <$> genBlockProposal),
      (1, NotarizationShareMsg <$> genNotarizationShare),
      (1, NotarizationMsg <$> genNotarization),
      (1, FinalizationShareMsg <$> genFinalizationShare),
      (1, FinalizationMsg <$> genFinalization),
      (1, RandomTapeShareMsg <$> genRandomTapeShare),
      (1, RandomTapeMsg <$> genRandomTape),
      (1, CatchUpPackageShareMsg <$> genCatchUpPackageShare),
      (1, CatchUpPackageMsg <$> genCatchUpPackage),
      (1, EquivocationProofMsg <$> genEquivocationProof)
    ]

genValidatedPool ::
  (Alternative m, MonadGen m, ?topo :: Topology, ?rv :: RegistryVersion) =>
  m ConsensusPoolSection
genValidatedPool =
  Gen.list
    (Range.linear 1 100)
    ((,) <$> genConsensusMessage <*> Gen.int (Range.linear 1 1000))
