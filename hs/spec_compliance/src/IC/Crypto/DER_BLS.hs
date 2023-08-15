-- This module is a bit like IC.Crypto.DER, but only handles BLS signature
-- checking
--
-- This is used in IC.Crypto.CanisterSig to check signatures (which are only
-- BLS), and breaks the module cycle
{-# LANGUAGE OverloadedStrings #-}

module IC.Crypto.DER_BLS (verify) where

import Control.Monad
import Control.Monad.Error.Class
import Data.ASN1.BitArray
import Data.ASN1.Types
import qualified Data.ByteString.Lazy as BS
import Data.Int
import qualified Data.Text as T
import qualified IC.Crypto.BLS as BLS
import IC.Crypto.DER.Decode

blsAlgoOID :: OID
blsAlgoOID = [1, 3, 6, 1, 4, 1, 44668, 5, 3, 1, 2, 1]

blsCurveOID :: OID
blsCurveOID = [1, 3, 6, 1, 4, 1, 44668, 5, 3, 2, 1]

decode :: BS.ByteString -> Either T.Text BS.ByteString
decode bs = case safeDecode bs of
  Left err -> Left $ "Could not decode DER: " <> T.pack err
  Right asn -> case asn of
    [ Start Sequence,
      Start Sequence,
      OID algo,
      OID curve,
      End Sequence,
      BitString ba,
      End Sequence
      ]
        | algo == blsAlgoOID && curve == blsCurveOID ->
            Right (BS.fromStrict (bitArrayGetData ba))
        | otherwise ->
            Left $ "Unexpected cipher: algo = " <> T.pack (show algo) <> " curve  = " <> T.pack (show curve)
    _ -> Left $ "Unexpected DER shape: " <> T.pack (show asn)

verify :: BS.ByteString -> BS.ByteString -> BS.ByteString -> BS.ByteString -> Either T.Text ()
verify domain_sep der_pk payload sig = do
  pk <- decode der_pk
  assertLen "BLS public key" 96 pk
  assertLen "BLS signature" 48 sig

  unless (BLS.verify pk msg sig) $ do
    when (BLS.verify pk payload sig) $
      throwError $
        "domain separator " <> T.pack (show domain_sep) <> " missing"
    throwError "signature verification failed"
  where
    msg = BS.singleton (fromIntegral (BS.length domain_sep)) <> domain_sep <> payload

assertLen :: T.Text -> Int64 -> BS.ByteString -> Either T.Text ()
assertLen what len bs
  | BS.length bs == len = return ()
  | otherwise = throwError $ what <> " has wrong length " <> T.pack (show (BS.length bs)) <> ", expected " <> T.pack (show len)
