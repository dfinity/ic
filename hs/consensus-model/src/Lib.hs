{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# OPTIONS_GHC -Wno-orphans #-}

{-@ LIQUID "--max-case-expand=0" @-}
{-@ LIQUID "--no-adt" @-}
{-@ LIQUID "--exact-data-con" @-}

module Lib where

import Codec.Candid
import Control.DeepSeq
import qualified Crypto.Hash.SHA512 as SHA512
import qualified Crypto.Sign.Ed25519 as Ed25519
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.ByteString.Char8 (unpack)
import Data.Function
import Data.List.Safe as Safe
import Data.Set (Set)
import qualified Data.Set as Set
import qualified Data.Text as T
import Data.Time
import Data.Time.Format.ISO8601
import GHC.Generics
import Numeric (showHex)
import Numeric.Natural
import Text.Show.Pretty
import Prelude hiding (round)

instance PrettyVal ByteString where
  prettyVal = String . unpack

instance PrettyVal Natural where
  prettyVal = String . show

instance PrettyVal UTCTime where
  prettyVal = String . iso8601Show

instance PrettyVal Ed25519.PublicKey where
  prettyVal (Ed25519.PublicKey pk) =
    String ("<pk " ++ foldr showHex "" (BS.unpack (BS.take 16 pk)) ++ ">")

instance PrettyVal Ed25519.SecretKey where
  prettyVal (Ed25519.SecretKey sk) =
    String ("<sk " ++ foldr showHex "" (BS.unpack (BS.take 16 sk)) ++ ">")

instance PrettyVal Principal where
  prettyVal = String . T.unpack . prettyPrincipal

{-@ type Nat = {v:Int|0 <= v} @-}
type Nat = Int

{-@ type Time = Nat @-}
type Time = Nat

{-@ type Duration = Nat @-}
type Duration = Nat

{-@ assume GHC.Enum.enumFromTo ::
      (Enum a) => lo:a -> hi:a -> [{v:a | lo <= v && v <= hi}] @-}

{-@ safe_maximum ::
      forall <p :: a -> Bool>. (Ord a) => x:[a<p>] -> Maybe a<p> @-}

safe_maximum :: Ord a => [a] -> Maybe a
safe_maximum = Safe.maximum

{-@ safe_minimum ::
      forall <p :: a -> Bool>. (Ord a) => x:[a<p>] -> Maybe a<p> @-}

safe_minimum :: Ord a => [a] -> Maybe a
safe_minimum = Safe.minimum

{-@ measure elts @-}
elts :: (Ord a) => [a] -> Set a
elts [] = Set.empty
elts (x : xs) = Set.singleton x `Set.union` elts xs

{-@ measure unique @-}
unique :: (Ord a) => [a] -> Bool
unique [] = True
unique (x : xs) = unique xs && not (Set.member x (elts xs))

{-@ type NonEmpty a = {v:[a]|elts v /= empty} @-}
type NonEmpty a = [a]

{-@
assume isSubsetOf ::
  Ord a => xs:[a] -> ys:[a] -> {b:Bool|b <=> Set_sub (elts xs) (elts ys)}
@-}

-- An expensive helper function that allows us to think of lists as sets.
isSubsetOf :: Ord a => [a] -> [a] -> Bool
isSubsetOf = Set.isSubsetOf `on` Set.fromList

{-@
assume isNotSubsetOf ::
  Ord a => xs:[a] -> ys:[a] -> {b:Bool|not b <=> Set_sub (elts xs) (elts ys)}
@-}

isNotSubsetOf :: Ord a => [a] -> [a] -> Bool
isNotSubsetOf = (not .) . isSubsetOf

{-@ filter ::
      forall <p :: a -> Bool, w :: a -> Bool -> Bool>.
      {y :: a, b::{v:Bool<w y>|v} |- {v:a|v == y} <: a<p>}
      (x:a -> Bool<w x>) ->
      xs:[a] ->
      {ys:[a<p>] | len ys <= len xs} @-}

filter :: (a -> Bool) -> [a] -> [a]
filter f (x : xs)
  | f x = x : Lib.filter f xs
  | otherwise = Lib.filter f xs
filter _ [] = []

{-@ inline nfstcmp @-}
nfstcmp :: Eq a => (a, b) -> (a, b) -> Bool
nfstcmp (x, _) (y, _) = x /= y

{-@ nubFst ::
      forall <p :: Tuple a b -> Bool>.
      Eq a =>
      xs:[Tuple a b <<p>>] ->
      {ys:[Tuple a b <<p>>]<{\x y -> nfstcmp x y}> | len ys <= len xs}
      / [len xs] @-}

nubFst :: Eq a => [(a, b)] -> [(a, b)]
nubFst [] = []
nubFst (x : xs) = x : nubFst (Lib.filter (nfstcmp x) xs)

{-@
(^+) :: Num a => a -> a -> a
@-}

(^+) :: Num a => a -> a -> a
(^+) = (+)

data Hash = Hash {getHash :: ByteString}
  deriving (Eq, Show, Generic, NFData)

-- instance Eq Hash where
--   _ == _ = True

instance PrettyVal Hash where
  prettyVal (Hash h) =
    String $ "<hash " ++ foldr showHex "" (BS.unpack (BS.take 16 h)) ++ ">"

hash :: ByteString -> Hash
hash payload = Hash (SHA512.hash payload)

data Signature = Signature {getSignature :: ByteString}
  deriving (Eq, Show, Generic, NFData)

-- instance Eq Signature where
--   _ == _ = True

instance PrettyVal Signature where
  prettyVal (Signature sig) =
    String $
      "<sig "
        ++ foldr showHex "" (BS.unpack (BS.take 16 sig))
        ++ ">"

sign :: Ed25519.SecretKey -> ByteString -> Signature
sign sk payload = Signature (Ed25519.sign sk payload)

verify :: Ed25519.PublicKey -> Signature -> Bool
verify pk (Signature sig) = Ed25519.verify pk sig

data MultiSignature = MultiSignature [Signature]
  deriving (Eq, Show, Generic, NFData)

instance PrettyVal MultiSignature where
  prettyVal (MultiSignature sigs) =
    List $ map prettyVal sigs

instance Semigroup MultiSignature where
  MultiSignature xs <> MultiSignature ys = MultiSignature (xs <> ys)

instance Monoid MultiSignature where
  mempty = MultiSignature []
  mappend = (<>)

sign_multi :: Ed25519.SecretKey -> ByteString -> MultiSignature
sign_multi sk payload = MultiSignature [sign sk payload]

-- A multi-signature is a composite of individual signature from multiple
-- parties, such that we can recover who participated in building the
-- composite. This is different from threshold signature where we only now
-- that a threshold majority provided a valid signature, but not which members
-- of the committee did so.
-- TODO: For the time being I will fake a multi-signature by carrying around a
-- list of independent signatures.
verify_multi :: [Ed25519.PublicKey] -> MultiSignature -> Bool
verify_multi pks (MultiSignature sigs) =
  all (\pk -> all (verify pk) sigs) pks

data ThresholdSignatureShare = ThresholdSignatureShare
  { getThresholdSignatureShare :: ByteString
  }
  deriving (Eq, Show, Generic, NFData)

instance PrettyVal ThresholdSignatureShare where
  prettyVal (ThresholdSignatureShare sig) =
    String $
      "<tshare "
        ++ foldr showHex "" (BS.unpack (BS.take 16 sig))
        ++ ">"

data ThresholdSignature = ThresholdSignature
  { getThresholdSignature :: ByteString
  }
  deriving (Eq, Show, Generic, NFData)

instance PrettyVal ThresholdSignature where
  prettyVal (ThresholdSignature sig) =
    String $
      "<tsig "
        ++ foldr showHex "" (BS.unpack (BS.take 16 sig))
        ++ ">"

-- TODO: In order to test actual verification of threshold signatures, we'd
-- need to use DKG to produce at threshold key, and we'd need to link in a BLS
-- library to validate the signature. Thus, for the time being we simply
-- assume that all shares are valid, and that they trivially combine to form a
-- valid signature.
verify_threshold_sig_share ::
  Ed25519.PublicKey ->
  ThresholdSignatureShare ->
  Bool
verify_threshold_sig_share _ _ = True

verify_threshold_sig ::
  Ed25519.PublicKey ->
  ThresholdSignature ->
  Bool
verify_threshold_sig _ _ = True
