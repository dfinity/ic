{-# LANGUAGE OverloadedStrings #-}

module IC.HashTree.CBOR where

import Codec.CBOR.Term
import qualified Data.Text as T
import IC.CBOR.Patterns
import IC.HashTree

encodeHashTree :: HashTree -> Term
encodeHashTree = go
  where
    go EmptyTree = TList [TInteger 0]
    go (Fork t1 t2) = TList [TInteger 1, go t1, go t2]
    go (Labeled l t) = TList [TInteger 2, TBlob l, go t]
    go (Leaf v) = TList [TInteger 3, TBlob v]
    go (Pruned h) = TList [TInteger 4, TBlob h]

parseHashTree :: Term -> Either T.Text HashTree
parseHashTree = go
  where
    go (TList_ [TNat 0]) = return EmptyTree
    go (TList_ [TNat 1, t1, t2]) = Fork <$> parseHashTree t1 <*> parseHashTree t2
    go (TList_ [TNat 2, TBlob l, t]) = Labeled l <$> parseHashTree t
    go (TList_ [TNat 3, TBlob v]) = return $ Leaf v
    go (TList_ [TNat 4, TBlob h]) = return $ Pruned h
    go t = Left $ "Cannot parse as a Hash Tree: " <> T.pack (show t)
