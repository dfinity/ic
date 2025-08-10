{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

-- | This module implements the (possible pruned) merkle trees used in the
-- Internet Computer, in particular
--  * Conversion from a labeled tree (with blobs)
--  * Root hash reconstruction
--  * Lookup
--  * Pruning
--  * Checking well-formedness
module IC.HashTree where

import Crypto.Hash (SHA256, hashlazy)
import Data.ByteArray (convert)
import qualified Data.ByteString.Lazy as BS
import qualified Data.Map.Lazy as M
import qualified Data.Set as S

type Blob = BS.ByteString

type Path = [Label]

type Label = Blob

type Value = Blob

type Hash = Blob

data LabeledTree
  = Value Value
  | SubTrees (M.Map Blob LabeledTree)
  deriving (Show)

data HashTree
  = EmptyTree
  | Fork HashTree HashTree
  | Labeled Blob HashTree
  | Leaf Value
  | Pruned Hash
  deriving (Show)

construct :: LabeledTree -> HashTree
construct (Value v) = Leaf v
construct (SubTrees m) =
  foldBinary
    EmptyTree
    Fork
    [Labeled k (construct v) | (k, v) <- M.toAscList m]

foldBinary :: a -> (a -> a -> a) -> [a] -> a
foldBinary e (⋔) = go
  where
    go [] = e
    go [x] = x
    go xs = go xs1 ⋔ go xs2
      where
        (xs1, xs2) = splitAt (length xs `div` 2) xs

reconstruct :: HashTree -> Hash
reconstruct = go
  where
    go EmptyTree = h $ domSep "ic-hashtree-empty"
    go (Fork t1 t2) = h $ domSep "ic-hashtree-fork" <> go t1 <> go t2
    go (Labeled l t) = h $ domSep "ic-hashtree-labeled" <> l <> go t
    go (Leaf v) = h $ domSep "ic-hashtree-leaf" <> v
    go (Pruned h) = h

h :: BS.ByteString -> BS.ByteString
h = BS.fromStrict . convert . hashlazy @SHA256

domSep :: Blob -> Blob
domSep s = BS.singleton (fromIntegral (BS.length s)) <> s

data Res = Absent | Unknown | Error String | Found Value
  deriving (Eq, Show)

-- See lookupL in IC.Test.HashTree for a high-level spec
lookupPath :: HashTree -> Path -> Res
lookupPath tree (l : ls) = find Absent (flatten tree)
  where
    find r [] = r
    find r (Labeled l' t : ts)
      | l < l' = r
      | l == l' = lookupPath t ls
      | otherwise = find Absent ts
    find _ (Pruned _ : ts) = find Unknown ts
    find _ (EmptyTree : _) = error "Empty in flattened list"
    find _ (Fork _ _ : _) = error "Fork in flattened list"
    find _ (Leaf _ : _) = Error "Found leaf when expecting subtree"
lookupPath (Leaf v) [] = Found v
lookupPath (Pruned _) [] = Unknown
lookupPath (Labeled _ _) [] = Error "Found forest when expecting leaf"
lookupPath (Fork _ _) [] = Error "Found forest when expecting leaf"
lookupPath _ [] = Error "Found forest when expecting leaf"

flatten :: HashTree -> [HashTree]
flatten t = go t [] -- using difference lists
  where
    go EmptyTree = id
    go (Fork t1 t2) = go t1 . go t2
    go t = (t :)

prune :: HashTree -> [Path] -> HashTree
prune tree [] = Pruned (reconstruct tree)
prune tree paths | [] `elem` paths = tree
prune tree paths = go tree
  where
    -- These labels are available
    present :: S.Set Label
    present = S.fromList [l | Labeled l _ <- flatten tree]

    -- We need all requested labels, and if not present, the immediate neighbors
    -- This maps labels to paths at that label that we need
    wanted :: M.Map Label (S.Set Path)
    wanted =
      M.fromListWith S.union $
        concat
          [ if l `S.member` present
              then [(l, S.singleton p)]
              else
                [(l', S.empty) | Just l' <- pure $ l `S.lookupLT` present]
                  ++ [(l', S.empty) | Just l' <- pure $ l `S.lookupGT` present]
            | l : p <- paths
          ]

    -- Smart constructor to avoid unnecessary forks
    fork t1 t2
      | prunedOrEmpty t1, prunedOrEmpty t2 = Pruned (reconstruct (Fork t1 t2))
      | otherwise = Fork t1 t2
      where
        prunedOrEmpty (Pruned _) = True
        prunedOrEmpty EmptyTree = True
        prunedOrEmpty _ = False

    go EmptyTree = EmptyTree
    go (Labeled l subtree)
      | Just path_tails <- M.lookup l wanted = Labeled l (prune subtree (S.toList path_tails))
    go (Fork t1 t2) = fork (go t1) (go t2)
    go tree = Pruned (reconstruct tree)

wellFormed :: HashTree -> Either String ()
wellFormed (Leaf _) = return ()
wellFormed tree = wellFormedForest $ flatten tree

wellFormedForest :: [HashTree] -> Either String ()
wellFormedForest trees = do
  isInOrder [l | Labeled l _ <- trees]
  sequence_ [wellFormed t | Labeled _ t <- trees]
  sequence_ [Left "Value in forest" | Leaf _ <- trees]

isInOrder :: [Label] -> Either String ()
isInOrder [] = return ()
isInOrder [_] = return ()
isInOrder (x : y : zs)
  | x < y = isInOrder (y : zs)
  | otherwise = Left $ "Tree values out of order: " ++ show x ++ " " ++ show y
