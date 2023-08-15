{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeApplications #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module IC.Crypto.ECDSA
  ( SecretKey,
    createKey,
    toPublicKey,
    IC.Crypto.ECDSA.sign,
    IC.Crypto.ECDSA.verify,
  )
where

import Crypto.ECC
import Crypto.Error
import Crypto.Hash.Algorithms
import Crypto.Number.Serialize
import Crypto.PubKey.ECDSA
import Crypto.Random
import qualified Data.ByteString.Lazy as BS
import Data.Hashable
import Data.Proxy

newtype SecretKey = SecretKey (KeyPair Curve_P256R1)
  deriving (Show)

deriving instance Show (KeyPair Curve_P256R1)

createKey :: BS.ByteString -> SecretKey
createKey seed =
  SecretKey $ fst $ withDRG drg (curveGenerateKeyPair Proxy)
  where
    drg = drgNewSeed $ seedFromInteger $ fromIntegral $ hash seed

toPublicKey :: SecretKey -> BS.ByteString
toPublicKey (SecretKey kp) =
  BS.fromStrict $ encodePublic (Proxy @Curve_P256R1) $ keypairGetPublic kp

sign :: SecretKey -> BS.ByteString -> IO BS.ByteString
sign (SecretKey kp) msg = do
  (r, s) <-
    signatureToIntegers Proxy
      <$> Crypto.PubKey.ECDSA.sign (Proxy @Curve_P256R1) (keypairGetPrivate kp) SHA256 (BS.toStrict msg)
  return $ BS.fromStrict $ i2ospOf_ 32 r <> i2ospOf_ 32 s

verify :: BS.ByteString -> BS.ByteString -> BS.ByteString -> Bool
verify pk msg sig
  | CryptoPassed pk <- decodePublic (Proxy @Curve_P256R1) (BS.toStrict pk),
    BS.length sig == 64,
    (rb, sb) <- BS.splitAt 32 sig,
    let r = os2ip $ BS.toStrict rb,
    let s = os2ip $ BS.toStrict sb,
    CryptoPassed sig <- signatureFromIntegers (Proxy @Curve_P256R1) (r, s) =
      Crypto.PubKey.ECDSA.verify
        (Proxy @Curve_P256R1)
        SHA256
        pk
        sig
        (BS.toStrict msg)
  | otherwise = False
