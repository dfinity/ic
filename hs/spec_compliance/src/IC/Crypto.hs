{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

-- |
-- Everything related to signature creation and checking
module IC.Crypto
  ( SecretKey (..),
    createSecretKeyEd25519,
    createSecretKeyWebAuthnECDSA,
    createSecretKeyWebAuthnRSA,
    createSecretKeyECDSA,
    createSecretKeySecp256k1,
    createSecretKeyBLS,
    toPublicKey,
    signPure,
    sign,
    verify,
  )
where

import Control.Monad
import Control.Monad.Except
import qualified Data.ByteString.Lazy as BS
import Data.Int
import qualified Data.Text as T
import qualified IC.Crypto.BLS as BLS
import qualified IC.Crypto.CanisterSig as CanisterSig
import qualified IC.Crypto.DER as DER
import qualified IC.Crypto.ECDSA as ECDSA
import qualified IC.Crypto.Ed25519 as Ed25519
import qualified IC.Crypto.Secp256k1 as Secp256k1
import qualified IC.Crypto.WebAuthn as WebAuthn

data SecretKey
  = Ed25519 Ed25519.SecretKey
  | ECDSA ECDSA.SecretKey
  | Secp256k1 Secp256k1.SecretKey
  | WebAuthn WebAuthn.SecretKey
  | BLS BLS.SecretKey
  deriving (Show)

createSecretKeyEd25519 :: BS.ByteString -> SecretKey
createSecretKeyEd25519 = Ed25519 . Ed25519.createKey

createSecretKeyWebAuthnECDSA :: BS.ByteString -> SecretKey
createSecretKeyWebAuthnECDSA = WebAuthn . WebAuthn.createECDSAKey

createSecretKeyWebAuthnRSA :: BS.ByteString -> SecretKey
createSecretKeyWebAuthnRSA = WebAuthn . WebAuthn.createRSAKey

createSecretKeyECDSA :: BS.ByteString -> SecretKey
createSecretKeyECDSA = ECDSA . ECDSA.createKey

createSecretKeySecp256k1 :: BS.ByteString -> SecretKey
createSecretKeySecp256k1 = Secp256k1 . Secp256k1.createKey

createSecretKeyBLS :: BS.ByteString -> SecretKey
createSecretKeyBLS = BLS . BLS.createKey

toPublicKey :: SecretKey -> BS.ByteString
toPublicKey (Ed25519 sk) = DER.encode DER.Ed25519 $ Ed25519.toPublicKey sk
toPublicKey (WebAuthn sk) = DER.encode DER.WebAuthn $ WebAuthn.toPublicKey sk
toPublicKey (ECDSA sk) = DER.encode DER.ECDSA $ ECDSA.toPublicKey sk
toPublicKey (Secp256k1 sk) = DER.encode DER.Secp256k1 $ Secp256k1.toPublicKey sk
toPublicKey (BLS sk) = DER.encode DER.BLS $ BLS.toPublicKey sk

signPure :: BS.ByteString -> SecretKey -> BS.ByteString -> BS.ByteString
signPure domain_sep sk payload = case sk of
  Ed25519 sk -> Ed25519.sign sk msg
  WebAuthn _ -> error "WebAuthn not a pure signature"
  ECDSA _ -> error "ECDSA not a pure signature"
  Secp256k1 _ -> error "Secp256k1 is not a pure signature"
  BLS sk -> BLS.sign sk msg
  where
    msg
      | BS.null domain_sep = payload
      | otherwise = BS.singleton (fromIntegral (BS.length domain_sep)) <> domain_sep <> payload

sign :: BS.ByteString -> SecretKey -> BS.ByteString -> IO BS.ByteString
sign domain_sep sk payload = case sk of
  Ed25519 sk -> return $ Ed25519.sign sk msg
  WebAuthn sk -> WebAuthn.sign sk msg
  ECDSA sk -> ECDSA.sign sk msg
  Secp256k1 sk -> Secp256k1.sign sk msg
  BLS sk -> return $ BLS.sign sk msg
  where
    msg
      | BS.null domain_sep = payload
      | otherwise = BS.singleton (fromIntegral (BS.length domain_sep)) <> domain_sep <> payload

verify :: BS.ByteString -> BS.ByteString -> BS.ByteString -> BS.ByteString -> BS.ByteString -> Either T.Text ()
verify root_key domain_sep der_pk payload sig =
  DER.decode der_pk >>= \case
    (DER.WebAuthn, pk) -> WebAuthn.verify pk msg sig
    (DER.Ed25519, pk) -> do
      assertLen "Ed25519 public key" 32 pk
      assertLen "Ed25519 signature" 64 sig

      unless (Ed25519.verify pk msg sig) $ do
        when (Ed25519.verify pk payload sig) $
          throwError $
            "domain separator " <> T.pack (show domain_sep) <> " missing"
        throwError "signature verification failed"
    (DER.ECDSA, pk) -> do
      unless (ECDSA.verify pk msg sig) $ do
        when (ECDSA.verify pk payload sig) $
          throwError $
            "domain separator " <> T.pack (show domain_sep) <> " missing"
        throwError "signature verification failed"
    (DER.Secp256k1, pk) -> Secp256k1.verify pk msg sig
    (DER.BLS, pk) -> do
      assertLen "BLS public key" 96 pk
      assertLen "BLS signature" 48 sig

      unless (BLS.verify pk msg sig) $ do
        when (BLS.verify pk payload sig) $
          throwError $
            "domain separator " <> T.pack (show domain_sep) <> " missing"
        throwError "signature verification failed"
    (DER.CanisterSig, pk) -> CanisterSig.verify root_key pk msg sig
  where
    msg = BS.singleton (fromIntegral (BS.length domain_sep)) <> domain_sep <> payload

assertLen :: T.Text -> Int64 -> BS.ByteString -> Either T.Text ()
assertLen what len bs
  | BS.length bs == len = return ()
  | otherwise = throwError $ what <> " has wrong length " <> T.pack (show (BS.length bs)) <> ", expected " <> T.pack (show len)
