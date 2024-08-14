{-# LANGUAGE BlockArguments #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

-- |
-- This module implements WebAuthN crypto. WebauthN is a big mess, involving
-- nesting of CBOR, DER and JSON…
module IC.Crypto.WebAuthn
  ( init,
    SecretKey,
    createECDSAKey,
    createRSAKey,
    toPublicKey,
    sign,
    verify,
  )
where

import Codec.CBOR.Term
import Codec.CBOR.Write (toLazyByteString)
import Control.Monad
import Control.Monad.Except
import Crypto.Hash.Algorithms (SHA256 (..))
import qualified Crypto.Number.Serialize as EC
import qualified Crypto.PubKey.ECC.ECDSA as EC
import qualified Crypto.PubKey.ECC.Generate as EC
import qualified Crypto.PubKey.ECC.Types as EC
import qualified Crypto.PubKey.RSA as RSA (generate)
import qualified Crypto.PubKey.RSA.PKCS15 as RSA
import qualified Crypto.PubKey.RSA.Types as RSA
import Crypto.Random (drgNewSeed, seedFromInteger, withDRG)
import Data.ASN1.BinaryEncoding
import Data.ASN1.Encoding
import Data.ASN1.Types
import qualified Data.Aeson as JSON
import qualified Data.Aeson.Types as JSON
import Data.Bifunctor
import Data.ByteString.Base64.URL.Lazy as Base64
import qualified Data.ByteString.Lazy.Char8 as BS
import Data.Hashable
import qualified Data.Map as M
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import IC.CBOR.Parser
import IC.Crypto.DER.Decode
import qualified IC.HTTP.CBOR as CBOR
import IC.HTTP.GenR.Parse
import IC.Hash
import IC.Utils

parseSig :: BS.ByteString -> Either T.Text (BS.ByteString, BS.ByteString, BS.ByteString)
parseSig =
  CBOR.decode >=> record do
    ad <- field blob "authenticator_data"
    cdj <- toUtf8 <$> field text "client_data_json"
    sig <- field blob "signature"
    return (ad, cdj, sig)

genSig :: (BS.ByteString, BS.ByteString, BS.ByteString) -> BS.ByteString
genSig (ad, cdj, sig) =
  toLazyByteString $
    encodeTerm $
      TTagged 55799 $
        TMap
          [ (TString "authenticator_data", TBytes (BS.toStrict ad)),
            (TString "client_data_json", TString (T.decodeUtf8 (BS.toStrict cdj))),
            (TString "signature", TBytes (BS.toStrict sig))
          ]

parseClientDataJson :: BS.ByteString -> Either T.Text BS.ByteString
parseClientDataJson blob =
  first T.pack $
    JSON.eitherDecode blob >>= JSON.parseEither p
  where
    p = JSON.withObject "clientData" $ \o -> do
      x <- o JSON..: "challenge"
      either JSON.parseFail return $ Base64.decodeUnpadded (BS.pack x)

genClientDataJson :: BS.ByteString -> BS.ByteString
genClientDataJson challenge =
  JSON.encode $
    JSON.Object $
      "challenge"
        JSON..= BS.unpack (Base64.encodeUnpadded challenge)
        <> "type"
        JSON..= ("webauthn.get" :: T.Text)
        <> "origin"
        JSON..= ("ic-ref-test" :: T.Text)

verifyCOSESig :: BS.ByteString -> BS.ByteString -> BS.ByteString -> Either T.Text ()
verifyCOSESig s msg sig = do
  kv <- decodeWithoutTag s >>= parseMap "COSE key"
  m <- M.fromList <$> mapM keyVal kv
  let field n = case M.lookup n m of
        Just x -> return x
        Nothing -> throwError $ "COSE: missing entry " <> tshow n
  let intField n =
        field n >>= \case
          TInt i -> pure i
          _ -> throwError $ "COSE field " <> tshow n <> " not an int"
  let integerField n =
        field n >>= \case
          TBytes b -> pure $ EC.os2ip b
          _ -> throwError $ "COSE field " <> tshow n <> " not bytes"

  ty <- intField 1
  alg <- intField 3
  case (ty, alg) of
    (2, -7) -> do
      crv <- intField (-1)
      unless (crv == 1) $
        throwError $
          "parsePublicKey: unknown curve: " <> tshow crv
      x <- integerField (-2)
      y <- integerField (-3)
      let pk = EC.PublicKey curve (EC.Point x y)
      sig <- parseCOSEECDSASig sig
      unless (EC.verify SHA256 pk sig (BS.toStrict msg)) $
        throwError "WebAuthn signature verification failed"
    (3, -257) -> do
      n <- integerField (-1)
      e <- integerField (-2)
      let pk = RSA.PublicKey 256 n e
      unless (RSA.verify (Just SHA256) pk (BS.toStrict msg) (BS.toStrict sig)) $
        throwError "WebAuthn signature verification failed"
    _ -> throwError $ "COSE: Unsupported pair of type, algorithm: " <> tshow ty <> " " <> tshow alg
  where
    keyVal (TInt k, v) = pure (fromIntegral k, v)
    keyVal (TInteger k, v) = pure (k, v)
    keyVal _ = throwError "Non-integer key in CBOR map"
    tshow :: (Show a) => a -> T.Text
    tshow v = T.pack (show v)

genCOSEECDSAKey :: EC.PublicKey -> BS.ByteString
genCOSEECDSAKey (EC.PublicKey _curve (EC.Point x y)) =
  toLazyByteString $
    encodeTerm $
      TMap
        [ (TInt 1, TInt 2),
          (TInt 3, TInt (-7)),
          (TInt (-1), TInt 1),
          (TInt (-2), TBytes (EC.i2ospOf_ 32 x)),
          (TInt (-3), TBytes (EC.i2ospOf_ 32 y))
        ]
genCOSEECDSAKey (EC.PublicKey _ EC.PointO) = error "genCOSEKey: Point at infinity"

genCOSERSAKey :: RSA.PublicKey -> BS.ByteString
genCOSERSAKey (RSA.PublicKey _keyLength n e) =
  toLazyByteString $
    encodeTerm $
      TMap
        [ (TInt 1, TInt 3),
          (TInt 3, TInt (-257)),
          (TInt (-1), TBytes (EC.i2osp n)),
          (TInt (-2), TBytes (EC.i2osp e))
        ]

parseCOSEECDSASig :: BS.ByteString -> Either T.Text EC.Signature
parseCOSEECDSASig s =
  first T.pack (safeDecode s) >>= \case
    [Start Sequence, IntVal r, IntVal s, End Sequence] -> pure $ EC.Signature r s
    a -> throwError $ "Unexpected DER encoding for COSE sig: " <> T.pack (show a)

genCOSEECDSASig :: EC.Signature -> BS.ByteString
genCOSEECDSASig (EC.Signature r s) =
  encodeASN1
    DER
    [Start Sequence, IntVal r, IntVal s, End Sequence]

data SecretKey
  = ECDSASecretKey EC.PrivateKey EC.PublicKey
  | RSASecretKey RSA.PrivateKey
  deriving (Show)

curve :: EC.Curve
curve = EC.getCurveByName EC.SEC_p256r1

createECDSAKey :: BS.ByteString -> SecretKey
createECDSAKey seed =
  ECDSASecretKey (EC.PrivateKey curve d) (EC.PublicKey curve q)
  where
    n = EC.ecc_n $ EC.common_curve curve
    d = fromIntegral (hash seed) `mod` (n - 2) + 1
    q = EC.generateQ curve d

createRSAKey :: BS.ByteString -> SecretKey
createRSAKey seed =
  RSASecretKey $ snd $ fst $ withDRG drg (RSA.generate 256 3)
  where
    drg = drgNewSeed $ seedFromInteger $ fromIntegral $ hash seed

toPublicKey :: SecretKey -> BS.ByteString
toPublicKey key = case key of
  (ECDSASecretKey _ pk) -> genCOSEECDSAKey pk
  (RSASecretKey pk) -> genCOSERSAKey (RSA.private_pub pk)

sign :: SecretKey -> BS.ByteString -> IO BS.ByteString
sign (ECDSASecretKey sk _) msg = do
  let cdj = genClientDataJson msg
  let ad = "arbitrary?"
  sig <- EC.sign sk SHA256 (BS.toStrict (ad <> sha256 cdj))
  return $ genSig (ad, cdj, genCOSEECDSASig sig)
sign (RSASecretKey pk) msg = do
  let cdj = genClientDataJson msg
  let ad = "arbitrary?"
  case RSA.sign Nothing (Just SHA256) pk (BS.toStrict (ad <> sha256 cdj)) of
    Left err -> error (show err)
    Right sig ->
      return $ genSig (ad, cdj, BS.fromStrict sig)

verify :: BS.ByteString -> BS.ByteString -> BS.ByteString -> Either T.Text ()
verify pk msg sig = do
  (ad, cdj, sig) <- parseSig sig
  verifyCOSESig pk (ad <> sha256 cdj) sig
  challenge <- parseClientDataJson cdj
  unless (challenge == msg) $
    throwError $
      "Wrong challenge. Expected "
        <> T.pack (show msg)
        <> " got "
        <> T.pack (show challenge)
