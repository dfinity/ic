{-# LANGUAGE BlockArguments #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}

module IC.Crypto.Secp256k1
  ( init,
    SecretKey,
    createKey,
    toPublicKey,
    sign,
    verify,
  )
where

import Control.Monad
import Control.Monad.Except
import Crypto.Hash.Algorithms (SHA256 (..))
import Crypto.Number.Serialize
import qualified Crypto.PubKey.ECC.ECDSA as EC
import qualified Crypto.PubKey.ECC.Generate as EC
import qualified Crypto.PubKey.ECC.Prim as EC
import qualified Crypto.PubKey.ECC.Types as EC
import Data.Bifunctor
import qualified Data.ByteString.Lazy as BS
import Data.Hashable
import Data.Serialize.Get
import qualified Data.Text as T

data SecretKey = SecretKey EC.PrivateKey EC.PublicKey
  deriving (Show)

toPublicKey :: SecretKey -> BS.ByteString
toPublicKey (SecretKey _ (EC.PublicKey _ (EC.Point x y))) =
  BS.singleton 0x04 <> BS.fromStrict (i2ospOf_ 32 x <> i2ospOf_ 32 y)
toPublicKey (SecretKey _ (EC.PublicKey _ EC.PointO)) = error "toPublicKey: Point at infinity"

curve :: EC.Curve
curve = EC.getCurveByName EC.SEC_p256k1

createKey :: BS.ByteString -> SecretKey
createKey seed =
  SecretKey (EC.PrivateKey curve d) (EC.PublicKey curve q)
  where
    n = EC.ecc_n $ EC.common_curve curve
    d = fromIntegral (hash seed) `mod` (n - 2) + 1
    q = EC.generateQ curve d

sign :: SecretKey -> BS.ByteString -> IO BS.ByteString
sign (SecretKey sk _) msg = do
  EC.Signature r s <- EC.sign sk SHA256 (BS.toStrict msg)
  return $ BS.fromStrict $ i2ospOf_ 32 r <> i2ospOf_ 32 s

-- Parsing SEC keys. Unfortunately not supported directly in cryptonite
-- https://github.com/haskell-crypto/cryptonite/issues/302
parsePublicKey :: BS.ByteString -> Either T.Text EC.PublicKey
parsePublicKey =
  first T.pack . runGetLazy do
    t <- getWord8
    when (t == 0x03) $ do
      fail "compressed secp256k1 public keys not supported"
    when (t /= 0x04) $
      fail "unexpected public key byte t"
    x <- os2ip <$> getByteString 32
    y <- os2ip <$> getByteString 32
    let p = EC.Point x y
    unless (EC.isPointValid curve p) $ do
      fail "point not valid"
    return $ EC.PublicKey curve p

parseSig :: BS.ByteString -> Either T.Text EC.Signature
parseSig =
  first T.pack . runGetLazy do
    r <- os2ip <$> getByteString 32
    s <- os2ip <$> getByteString 32
    return $ EC.Signature r s

verify :: BS.ByteString -> BS.ByteString -> BS.ByteString -> Either T.Text ()
verify pk msg sig = do
  pk <- parsePublicKey pk
  sig <- parseSig sig
  unless (EC.verify SHA256 pk sig (BS.toStrict msg)) $
    throwError "secp256k1 signature did not validate"
