{-# LANGUAGE BlockArguments #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}

module IC.Crypto.CanisterSig
  ( genPublicKey,
    genSig,
    verify,
  )
where

import Codec.CBOR.Term
import Codec.CBOR.Write
import Control.Monad
import Data.Bifunctor
import qualified Data.ByteString.Builder as BS
import qualified Data.ByteString.Lazy as BS
import Data.Serialize.Get
import qualified Data.Text as T
import IC.CBOR.Parser
import IC.CBOR.Patterns
import IC.Certificate
import IC.Certificate.CBOR
import IC.Certificate.Validate
import IC.Hash
import IC.HashTree
import IC.HashTree.CBOR
import IC.Types

-- | Produces a public key, without the DER wrapping
genPublicKey :: EntityId -> BS.ByteString -> BS.ByteString
genPublicKey (EntityId cid) seed =
  BS.toLazyByteString $
    BS.word8 (fromIntegral (BS.length cid))
      <> BS.lazyByteString cid
      <> BS.lazyByteString seed

-- | Parses the public key into a canister id and a seed
parsePublicKey :: BS.ByteString -> Either T.Text (EntityId, BS.ByteString)
parsePublicKey =
  first T.pack . runGetLazy do
    t <- getWord8
    id <- BS.fromStrict <$> getByteString (fromIntegral t)
    seed <- BS.fromStrict <$> (remaining >>= getByteString)
    return (EntityId id, seed)

genSig :: Certificate -> HashTree -> BS.ByteString
genSig cert tree =
  toLazyByteString $
    encodeTerm $
      TTagged 55799 $
        TMap
          [ (TString "certificate", TBlob (encodeCert cert)),
            (TString "tree", encodeHashTree tree)
          ]

parseSig :: BS.ByteString -> Either T.Text (Certificate, HashTree)
parseSig s = do
  kv <- decodeWithTag s >>= parseMap "canister signature"
  certificate <-
    parseField "certificate" kv
      >>= parseBlob "certificate"
      >>= decodeCert
  tree <- parseField "tree" kv >>= parseHashTree
  return (certificate, tree)

verify :: BS.ByteString -> BS.ByteString -> BS.ByteString -> BS.ByteString -> Either T.Text ()
verify root_key pk msg sig = do
  (id, seed) <- parsePublicKey pk
  (certificate, tree) <- parseSig sig

  validateCertificate root_key certificate

  expected_tree_hash <- case lookupPath
    (cert_tree certificate)
    ["canister", rawEntityId id, "certified_data"] of
    Found h -> return h
    r ->
      Left $
        "Did not find certified_data data for canister id "
          <> T.pack (prettyID id)
          <> " in certificate (got "
          <> T.pack (show r)
          <> ")\n"
          <> T.pack (show (cert_tree certificate))

  let actual_tree_hash = reconstruct tree

  unless (expected_tree_hash == actual_tree_hash) $ do
    Left $
      "Tree hashes did not match.\n"
        <> "Certified tree hash: "
        <> T.pack (prettyBlob expected_tree_hash)
        <> "\n"
        <> "Actual    tree hash: "
        <> T.pack (prettyBlob actual_tree_hash)

  case lookupPath tree ["sig", sha256 seed, sha256 msg] of
    Found "" -> return ()
    Found b -> Left $ "Signature found, but value not \"\", but " <> T.pack (prettyBlob b)
    _ ->
      Left $
        "Did not find signature in tree\n"
          <> "Seed: "
          <> T.pack (prettyBlob seed)
          <> "\n"
          <> "Msg:  "
          <> T.pack (prettyBlob msg)
          <> "\n"
          <> "Tree: "
          <> T.pack (show tree)
