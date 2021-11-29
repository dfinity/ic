{-# LANGUAGE DefaultSignatures #-}

module Bisimilar where

import Codec.Candid (Principal (..))
import Control.Monad.IO.Class
import Errors
import GHC.Stack
import Lib
import Text.Show.Pretty
import Types

infix 1 @??=

(@??=) :: (MonadIO m, Bisimilar a, PrettyVal a, HasCallStack) => a -> a -> m ()
actual @??= expected = liftIO $ assertEq' beq "" expected actual

-- This is a variant of Eq that may ignore certain fields
class Bisimilar a where
  beq :: a -> a -> Bool
  default beq :: Eq a => a -> a -> Bool
  beq = (==)

instance Bisimilar Int

instance Bisimilar Block where
  beq x y =
    b_height x `beq` b_height y
      && b_slot x `beq` b_slot y
      && (b_height x <= 1 || b_parent x `beq` b_parent y)

instance Bisimilar BlockProposal where
  beq x y =
    bp_block x `beq` bp_block y

instance Bisimilar BlockSignature

instance Bisimilar CatchUpPackage

instance Bisimilar CatchUpPackageShare

instance Bisimilar ChangeAction where
  AddToValidated x `beq` AddToValidated y = x `beq` y
  MoveToValidated x `beq` MoveToValidated y = x `beq` y
  RemoveFromValidated x `beq` RemoveFromValidated y = x `beq` y
  RemoveFromUnvalidated x `beq` RemoveFromUnvalidated y = x `beq` y
  PurgeValidatedBelow x `beq` PurgeValidatedBelow y = x `beq` y
  PurgeUnvalidatedBelow x `beq` PurgeUnvalidatedBelow y = x `beq` y
  HandleInvalid x `beq` HandleInvalid y = x `beq` y
  _ `beq` _ = False

instance Bisimilar ConsensusMessage where
  RandomBeaconShareMsg x `beq` RandomBeaconShareMsg y = x `beq` y
  RandomBeaconMsg x `beq` RandomBeaconMsg y = x `beq` y
  BlockProposalMsg x `beq` BlockProposalMsg y = x `beq` y
  NotarizationShareMsg x `beq` NotarizationShareMsg y = x `beq` y
  NotarizationMsg x `beq` NotarizationMsg y = x `beq` y
  FinalizationShareMsg x `beq` FinalizationShareMsg y = x `beq` y
  FinalizationMsg x `beq` FinalizationMsg y = x `beq` y
  RandomTapeShareMsg x `beq` RandomTapeShareMsg y = x `beq` y
  RandomTapeMsg x `beq` RandomTapeMsg y = x `beq` y
  CatchUpPackageShareMsg x `beq` CatchUpPackageShareMsg y = x `beq` y
  CatchUpPackageMsg x `beq` CatchUpPackageMsg y = x `beq` y
  EquivocationProofMsg x `beq` EquivocationProofMsg y = x `beq` y
  _ `beq` _ = False

instance Bisimilar EquivocationProof

instance Bisimilar Finalization where
  x `beq` y =
    f_height x `beq` f_height y
      && f_block x `beq` f_block y

instance Bisimilar FinalizationShare where
  x `beq` y =
    fs_height x `beq` fs_height y
      && fs_block x `beq` fs_block y

instance Bisimilar FinalizationShareSignature

instance Bisimilar FinalizationSignature

instance Bisimilar Hash where
  Hash _x `beq` Hash _y = True -- (2020-11-30): A hack for now

instance Bisimilar HashOfBlock where
  HashOfBlock x `beq` HashOfBlock y = x `beq` y

instance Bisimilar HashOfRandomBeacon where
  HashOfRandomBeacon x `beq` HashOfRandomBeacon y = x `beq` y

instance Bisimilar HashOfState where
  HashOfState x `beq` HashOfState y = x `beq` y

instance Bisimilar HighLow

instance Bisimilar Notarization where
  x `beq` y =
    n_height x `beq` n_height y
      && n_block x `beq` n_block y

instance Bisimilar NotarizationShare where
  x `beq` y =
    ns_height x `beq` ns_height y
      && ns_block x `beq` ns_block y

instance Bisimilar NotarizationShareSignature

instance Bisimilar NotarizationSignature

instance Bisimilar Payload

instance Bisimilar Principal

instance Bisimilar RandomBeacon where
  x `beq` y =
    rb_height x `beq` rb_height y
      && (rb_height x <= 1 || rb_parent x `beq` rb_parent y)

instance Bisimilar RandomBeaconShare where
  x `beq` y =
    rbs_height x `beq` rbs_height y
      && (rbs_height x <= 1 || rbs_parent x `beq` rbs_parent y)

instance Bisimilar RandomBeaconShareSignature

instance Bisimilar RandomBeaconSignature

instance Bisimilar RandomTape

instance Bisimilar RandomTapeShare

instance Bisimilar RandomTapeShareSignature

instance Bisimilar RandomTapeSignature

instance Bisimilar ReplicaId where
  x `beq` y = replica_id x `beq` replica_id y

instance Bisimilar StateShareSignature

instance Bisimilar StateSignature

instance Bisimilar Valid

instance Bisimilar a => Bisimilar [a] where
  [] `beq` [] = True
  (x : xs) `beq` (y : ys) = x `beq` y && xs `beq` ys
  _ `beq` _ = False
