{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ViewPatterns #-}

module IC.Certificate.CBOR (encodeCert, decodeCert) where

import Codec.CBOR.Term
import Codec.CBOR.Write
import qualified Data.Text as T
import IC.CBOR.Parser
import IC.CBOR.Patterns
import IC.Certificate
import IC.HashTree
import IC.HashTree.CBOR

encodeCert :: Certificate -> Blob
encodeCert Certificate {..} =
  toLazyByteString $
    encodeTerm $
      TTagged 55799 $
        TMap $
          [ (TString "tree", encodeHashTree cert_tree),
            (TString "signature", TBlob cert_sig)
          ]
            ++ [ ( TString "delegation",
                   TMap
                     [ (TString "subnet_id", TBlob del_subnet_id),
                       (TString "certificate", TBlob del_certificate)
                     ]
                 )
                 | Just Delegation {..} <- pure cert_delegation
               ]

decodeCert :: Blob -> Either T.Text Certificate
decodeCert s = do
  kv <- decodeWithTag s >>= parseMap "certificate"
  cert_tree <- parseField "tree" kv >>= parseHashTree
  cert_sig <- parseField "signature" kv >>= parseBlob "signature"
  cert_delegation <- optionalField "delegation" kv >>= mapM parseDelegation
  return $ Certificate {..}

parseDelegation :: Term -> Either T.Text Delegation
parseDelegation t = do
  kv <- parseMap "delegation" t
  del_subnet_id <- parseField "subnet_id" kv >>= parseBlob "subnet_id"
  del_certificate <- parseField "certificate" kv >>= parseBlob "certificate"
  return $ Delegation {..}
