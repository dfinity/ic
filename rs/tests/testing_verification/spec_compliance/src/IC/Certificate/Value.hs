-- Encoding and decoding of state tree values
{-# LANGUAGE TypeSynonymInstances #-}

module IC.Certificate.Value (CertVal (..)) where

import qualified Data.ByteString.Lazy as BS
import Data.Serialize.LEB128
import qualified Data.Text as T
import IC.Types
import IC.Utils
import Numeric.Natural

class CertVal a where
  toCertVal :: a -> Blob
  fromCertVal :: Blob -> Maybe a

instance CertVal Blob where
  toCertVal = id
  fromCertVal = Just

instance CertVal T.Text where
  toCertVal = toUtf8
  fromCertVal = fromUtf8

instance CertVal Natural where
  toCertVal = BS.fromStrict . toLEB128
  fromCertVal = forgetLeft . fromLEB128 . BS.toStrict

forgetLeft :: Either a b -> Maybe b
forgetLeft = either (const Nothing) Just
