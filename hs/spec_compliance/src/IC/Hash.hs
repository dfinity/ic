{-# LANGUAGE TypeApplications #-}

module IC.Hash where

import Crypto.Hash (SHA224, SHA256, hashlazy)
import Data.ByteArray (convert)
import qualified Data.ByteString.Lazy as BS

sha256 :: BS.ByteString -> BS.ByteString
sha256 = BS.fromStrict . convert . hashlazy @SHA256

sha224 :: BS.ByteString -> BS.ByteString
sha224 = BS.fromStrict . convert . hashlazy @SHA224
