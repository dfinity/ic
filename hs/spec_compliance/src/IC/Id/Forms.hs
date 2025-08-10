{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

-- |
-- Implements the special forms of ids (https://sdk.dfinity.org/docs/interface-spec/index.html#id-classes)
module IC.Id.Forms where

import qualified Data.ByteString.Lazy as BS
import IC.Hash

type Blob = BS.ByteString

mkOpaqueId :: Blob -> Blob
mkOpaqueId b =
  b <> BS.singleton 1 <> BS.singleton 1

isOpaqueId :: Blob -> Bool
isOpaqueId b = BS.drop (BS.length b - 2) b == BS.singleton 1 <> BS.singleton 1

mkSelfAuthenticatingId :: Blob -> Blob
mkSelfAuthenticatingId pubkey =
  sha224 pubkey <> BS.singleton 2

isSelfAuthenticatingId :: Blob -> Blob -> Bool
isSelfAuthenticatingId pubkey id =
  mkSelfAuthenticatingId pubkey == id

mkDerivedId :: Blob -> Blob -> Blob
mkDerivedId registering bytes =
  sha224 (len_prefixed registering <> bytes) <> BS.singleton 3

isDerivedId :: Blob -> Blob -> Bool
isDerivedId registering blob =
  BS.length blob == 256 `div` 8 + 8 + 1
    && BS.last blob == 3
    && BS.take (256 `div` 8) blob == sha224 registering

isAnonymousId :: Blob -> Bool
isAnonymousId blob = blob == "\x04"

len_prefixed :: BS.ByteString -> BS.ByteString
len_prefixed s = BS.singleton (fromIntegral (BS.length s)) <> s
