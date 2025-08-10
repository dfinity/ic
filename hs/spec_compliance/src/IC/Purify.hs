{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TypeFamilies #-}

module IC.Purify where

import Control.Monad.ST
import Data.Bifunctor
import Data.Either
import Data.Functor
import Data.Kind (Type)

class SnapshotAble i where
  type SnapshotOf i :: Type
  persist :: i s -> ST s (SnapshotOf i)
  recreate :: SnapshotOf i -> ST s (i s)

class Purify i a where
  create :: (forall s. ST s (i s)) -> a
  createMaybe :: (forall s. ST s (b, Either c (i s))) -> (b, Either c a)
  perform :: (forall s. i s -> ST s b) -> a -> (a, b)

newtype Snapshot a = Snapshot a
  deriving (Show)

instance (SnapshotAble i, SnapshotOf i ~ a) => Purify i (Snapshot a) where
  create act = Snapshot $ runST $ act >>= persist

  createMaybe act = runST $ do
    act >>= \case
      (x, Left e) -> return (x, Left e)
      (x, Right i) -> do
        s' <- persist i
        return (x, Right (Snapshot s'))

  perform act (Snapshot s) = runST $ do
    i <- recreate s
    x <- act i
    s' <- persist i
    return (Snapshot s', x)

newtype Replay i = Replay (forall s. ST s (i s))

instance Show (Replay i) where show _ = "Replay ..."

instance Purify a (Replay a) where
  create = Replay

  createMaybe act = runST $ second ($> replay') <$> act
    where
      replay' = Replay $ fromRight err . snd <$> act
      err = error "createMaybe: ST action was not deterministic?"

  perform act (Replay replay) = runST $ do
    x <- replay >>= act
    return (replay', x)
    where
      replay' = Replay $ do x <- replay; void (act x); return x
