{-# LANGUAGE OverloadedStrings #-}

module IC.Crypto.DER (Suite (..), encode, decode) where

import Data.ASN1.BinaryEncoding
import Data.ASN1.BitArray
import Data.ASN1.Encoding
import Data.ASN1.Types
import qualified Data.ByteString.Lazy as BS
import qualified Data.Text as T
import IC.Crypto.DER.Decode

data Suite = Ed25519 | WebAuthn | ECDSA | Secp256k1 | BLS | CanisterSig deriving (Show)

webAuthnOID :: OID
webAuthnOID = [1, 3, 6, 1, 4, 1, 56387, 1, 1]

canisterSigOID :: OID
canisterSigOID = [1, 3, 6, 1, 4, 1, 56387, 1, 2]

ed25519OID :: OID
ed25519OID = [1, 3, 101, 112]

ecPublicKeyOID :: OID
ecPublicKeyOID = [1, 2, 840, 10045, 2, 1]

secp256r1OID :: OID
secp256r1OID = [1, 2, 840, 10045, 3, 1, 7]

secp256k1OID :: OID
secp256k1OID = [1, 3, 132, 0, 10]

blsAlgoOID :: OID
blsAlgoOID = [1, 3, 6, 1, 4, 1, 44668, 5, 3, 1, 2, 1]

blsCurveOID :: OID
blsCurveOID = [1, 3, 6, 1, 4, 1, 44668, 5, 3, 2, 1]

encode :: Suite -> BS.ByteString -> BS.ByteString
encode Ed25519 = encodeDER [ed25519OID]
encode WebAuthn = encodeDER [webAuthnOID]
encode ECDSA = encodeDER [ecPublicKeyOID, secp256r1OID]
encode Secp256k1 = encodeDER [ecPublicKeyOID, secp256k1OID]
encode BLS = encodeDER [blsAlgoOID, blsCurveOID]
encode CanisterSig = encodeDER [canisterSigOID]

encodeDER :: [OID] -> BS.ByteString -> BS.ByteString
encodeDER oids pk =
  encodeASN1 DER $
    [ Start Sequence,
      Start Sequence
    ]
      ++ [OID oid | oid <- oids]
      ++ [ End Sequence,
           BitString (toBitArray (BS.toStrict pk) 0),
           End Sequence
         ]

decode :: BS.ByteString -> Either T.Text (Suite, BS.ByteString)
decode bs = case safeDecode bs of
  Left err -> Left $ "Could not decode DER: " <> T.pack err
  Right asn -> case asn of
    [ Start Sequence,
      Start Sequence,
      OID algo,
      End Sequence,
      BitString ba,
      End Sequence
      ]
        | algo == webAuthnOID ->
            Right (WebAuthn, BS.fromStrict (bitArrayGetData ba))
        | algo == ed25519OID ->
            Right (Ed25519, BS.fromStrict (bitArrayGetData ba))
        | algo == canisterSigOID ->
            Right (CanisterSig, BS.fromStrict (bitArrayGetData ba))
        | otherwise ->
            Left $ "Unexpected cipher: algo = " <> T.pack (show algo)
    [ Start Sequence,
      Start Sequence,
      OID algo,
      OID curve,
      End Sequence,
      BitString ba,
      End Sequence
      ]
        | algo == ecPublicKeyOID && curve == secp256r1OID ->
            Right (ECDSA, BS.fromStrict (bitArrayGetData ba))
        | algo == ecPublicKeyOID && curve == secp256k1OID ->
            Right (Secp256k1, BS.fromStrict (bitArrayGetData ba))
        | algo == blsAlgoOID && curve == blsCurveOID ->
            Right (BLS, BS.fromStrict (bitArrayGetData ba))
        | otherwise ->
            Left $ "Unexpected cipher: algo = " <> T.pack (show algo) <> " curve  = " <> T.pack (show curve)
    _ -> Left $ "Unexpected DER shape: " <> T.pack (show asn)
