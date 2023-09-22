-- Unit/Prop tests for IC.HashTree
{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module IC.Test.HashTree (hashTreeTests) where

import Codec.CBOR.Term
import Codec.CBOR.Write
import Data.Bifunctor
import qualified Data.ByteString.Lazy as BS
import Data.List
import qualified Data.Map.Lazy as M
import IC.HashTree
import IC.HashTree.CBOR
import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck
import qualified Text.Hex as T

hashTreeTests :: TestTree
hashTreeTests =
  testGroup
    "Hash tree tests"
    [ testGroup
        "Examples in spec document"
        [ testCase "CBOR of full tree" $
            asHex (toLazyByteString $ encodeTerm $ encodeHashTree exampleTree)
              @?= exampleTreeCBOR,
          testCase "root hash of full tree" $
            asHex (reconstruct exampleTree)
              @?= "eb5c5b2195e62d996b84c9bcc8259d19a83786a2f59e0878cec84c811f669aa0",
          testCase "CBOR of pruned tree" $
            asHex (toLazyByteString $ encodeTerm $ encodeHashTree prunedTree)
              @?= prunedTreeCBOR,
          testCase "root hash of pruned tree" $
            asHex (reconstruct exampleTree)
              @?= asHex (reconstruct prunedTree),
          testCase "tree lokups" $ do
            lookupPath prunedTree ["a", "a"] @?= Unknown
            lookupPath prunedTree ["a", "y"] @?= Found "world"
            lookupPath prunedTree ["aa"] @?= Absent
            lookupPath prunedTree ["ax"] @?= Absent
            lookupPath prunedTree ["b"] @?= Unknown
            lookupPath prunedTree ["bb"] @?= Unknown
            lookupPath prunedTree ["d"] @?= Found "morning"
            lookupPath prunedTree ["e"] @?= Absent
        ],
      testProperty "lookup succeeds" $ \lt (AsPath p) ->
        lookupPath (construct lt) p === lookupL lt p,
      testProperty "prune preserves hash" $ \lt (AsPaths ps) ->
        let ht = construct lt
         in reconstruct ht === reconstruct (prune ht ps),
      testProperty "prune preserves lookups" $ \lt (AsPaths ps) (AsPath p) ->
        let ht = construct lt
         in notError (lookupPath ht p)
              ==> if any (`isPrefixOf` p) ps
                then lookupPath (prune ht ps) p === lookupPath ht p
                else lookupPath (prune ht ps) p `elemP` [Unknown, Absent]
    ]

asHex :: BS.ByteString -> T.Text
asHex = T.encodeHex . BS.toStrict

exampleTree :: HashTree
exampleTree =
  Fork
    ( Fork
        ( Labeled
            "a"
            ( Fork
                ( Fork
                    (Labeled "x" (Leaf "hello"))
                    EmptyTree
                )
                (Labeled "y" (Leaf "world"))
            )
        )
        (Labeled "b" (Leaf "good"))
    )
    ( Fork
        (Labeled "c" EmptyTree)
        ( Labeled "d" (Leaf "morning")
        )
    )

prunedTree :: HashTree
prunedTree = prune exampleTree [["a", "y"], ["ax"], ["d"]]

exampleTreeCBOR :: T.Text
exampleTreeCBOR = "8301830183024161830183018302417882034568656c6c6f810083024179820345776f726c6483024162820344676f6f648301830241638100830241648203476d6f726e696e67"

prunedTreeCBOR :: T.Text
prunedTreeCBOR = "83018301830241618301820458201b4feff9bef8131788b0c9dc6dbad6e81e524249c879e9f10f71ce3749f5a63883024179820345776f726c6483024162820458207b32ac0c6ba8ce35ac82c255fc7906f7fc130dab2a090f80fe12f9c2cae83ba6830182045820ec8324b8a1f1ac16bd2e806edba78006479c9877fed4eb464a25485465af601d830241648203476d6f726e696e67"

-- This is, in a way, the spec for lookupPath
lookupL :: LabeledTree -> Path -> Res
lookupL (Value _) (_ : _) = Error "Found leaf when expecting subtree"
lookupL (SubTrees sts) (l : ls) = case M.lookup l sts of
  Just st -> lookupL st ls
  Nothing -> Absent
lookupL (Value v) [] = Found v
lookupL (SubTrees _) [] = Error "Found forest when expecting leaf"

notError :: Res -> Bool
notError (Error _) = False
notError _ = True

-- Property based testing infrastructure
-- (slightly more verbose because IC.HashTree is not very typed

elemP :: (Eq a, Show a) => a -> [a] -> Property
x `elemP` xs = disjoin $ map (x ===) xs

genValue :: Gen Value
genValue = BS.pack <$> arbitrary

genLabel :: Gen Label
genLabel = oneof [pure "", pure "hello", pure "world", BS.pack <$> arbitrary]

newtype AsLabel = AsLabel {asLabel :: Label}

instance Arbitrary AsLabel where arbitrary = AsLabel <$> genLabel

instance Show AsLabel where show (AsLabel l) = show l

newtype AsPath = AsPath {asPath :: Path}

instance Arbitrary AsPath where
  arbitrary = AsPath . map asLabel <$> arbitrary
  shrink (AsPath ps) = map AsPath (init (inits ps))

instance Show AsPath where show (AsPath l) = show l

newtype AsPaths = AsPaths {_asPaths :: [Path]}

instance Arbitrary AsPaths where
  arbitrary = AsPaths . map asPath <$> arbitrary
  shrink (AsPaths ps) =
    AsPaths
      <$> [as ++ bs | (as, _, bs) <- splits]
        ++ [as ++ [v'] ++ bs | (as, v, bs) <- splits, AsPath v' <- shrink (AsPath v)]
    where
      splits = [(as, v, bs) | i <- [0 .. length ps - 1], (as, v : bs) <- pure $ splitAt i ps]

instance Show AsPaths where show (AsPaths l) = show l

instance Arbitrary LabeledTree where
  arbitrary = sized go
    where
      go 0 = Value <$> genValue
      go n =
        oneof
          [ Value <$> genValue,
            resize (n `div` 2) $
              SubTrees . M.fromList . map (first asLabel) <$> arbitrary
          ]
  shrink (Value _) = [Value ""]
  shrink (SubTrees m) =
    SubTrees
      <$> [M.delete k m | k <- M.keys m]
        ++ [M.insert k v' m | (k, v) <- M.toList m, v' <- shrink v]
