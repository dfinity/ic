{-# OPTIONS_GHC -fno-warn-unused-imports -Wno-unused-top-binds #-}
{-# LANGUAGE DeriveGeneric #-}
#include "bls_BLS12381.h"
module IC.Crypto.BLS
 ( init
 , SecretKey
 , createKey
 , toPublicKey
 , sign
 , verify
 ) where

import Prelude hiding (init)
import qualified Data.ByteString.Lazy as BS
import qualified Data.ByteString as BSS
import Control.Monad
import Foreign
import Foreign.Ptr
import Foreign.Marshal.Alloc
import GHC.Generics (Generic)
import System.IO.Unsafe
import Foreign.C.String
import Foreign.C.Types

data C'octet = C'octet CInt CInt CString

instance Storable C'octet where
    sizeOf    _ = (#size octet)
    alignment _ = alignment (undefined :: CInt)
    peek ptr = do
        len <- (#peek octet, len) ptr
        max <- (#peek octet, max) ptr
        val <- (#peek octet, val) ptr
        return  (C'octet len max val)
    poke ptr (C'octet len max val) = do
        (#poke octet, len) ptr len
        (#poke octet, max) ptr max
        (#poke octet, val) ptr val


foreign import ccall unsafe "bls_BLS12381.h BLS_BLS12381_INIT"
     c'BLS_BLS12381_INIT :: IO CInt
foreign import ccall unsafe "bls_BLS12381.h BLS_BLS12381_KEY_PAIR_GENERATE"
     c'BLS_BLS12381_KEY_PAIR_GENERATE :: Ptr C'octet -> Ptr C'octet -> Ptr C'octet -> IO CInt
foreign import ccall unsafe "bls_BLS12381.h BLS_BLS12381_CORE_SIGN"
     c'BLS_BLS12381_CORE_SIGN :: Ptr C'octet -> Ptr C'octet -> Ptr C'octet -> IO CInt
foreign import ccall unsafe "bls_BLS12381.h BLS_BLS12381_CORE_VERIFY"
     c'BLS_BLS12381_CORE_VERIFY :: Ptr C'octet -> Ptr C'octet -> Ptr C'octet -> IO CInt

init :: IO ()
init = do
  r <- c'BLS_BLS12381_INIT
  unless (r == 0) $ fail "Could not initialize BLS"


-- Cache the public key as well
data SecretKey = SecretKey BS.ByteString BS.ByteString
  deriving (Show, Generic)

toPublicKey :: SecretKey -> BS.ByteString
toPublicKey (SecretKey _ pk) = pk

useAsOctet :: BS.ByteString -> (Ptr C'octet -> IO a) -> IO a
useAsOctet bs a =
  BSS.useAsCStringLen (BS.toStrict bs) $ \(cstr, len) ->
    alloca $ \oct_ptr -> do
      poke oct_ptr (C'octet (fromIntegral len) (fromIntegral len) cstr)
      a oct_ptr

allocOctet :: Int -> (Ptr C'octet -> IO a) -> IO a
allocOctet size a =
  allocaBytes size $ \cstr ->
    alloca $ \oct_ptr -> do
      poke oct_ptr (C'octet 0 (fromIntegral size) cstr)
      a oct_ptr

packOctet :: Ptr C'octet -> IO BS.ByteString
packOctet oct_ptr = do
  C'octet len _ cstr' <- peek oct_ptr
  bs <- BSS.packCStringLen (cstr', fromIntegral len)
  return (BS.fromStrict bs)

createKey :: BS.ByteString -> SecretKey
createKey seed = unsafePerformIO $
  useAsOctet seed $ \seed_ptr ->
    allocOctet 48 $ \sk_ptr ->
      allocOctet (4*48+1) $ \pk_ptr -> do
        r <- c'BLS_BLS12381_KEY_PAIR_GENERATE seed_ptr sk_ptr pk_ptr
        unless (r == 0) $ fail "Could not create BLS keys"
        SecretKey <$> packOctet sk_ptr <*> packOctet pk_ptr

sign :: SecretKey -> BS.ByteString -> BS.ByteString
sign (SecretKey sk _) msg = unsafePerformIO $
  useAsOctet sk $ \sk_ptr ->
    useAsOctet msg $ \msg_ptr ->
      allocOctet (48+1) $ \sig_ptr -> do
        r <- c'BLS_BLS12381_CORE_SIGN sig_ptr msg_ptr sk_ptr
        unless (r == 0) $ fail "Could not create BLS keys"
        packOctet sig_ptr

verify :: BS.ByteString -> BS.ByteString -> BS.ByteString -> Bool
verify pk msg sig = unsafePerformIO $
  useAsOctet pk $ \pk_ptr ->
    useAsOctet sig $ \sig_ptr ->
      useAsOctet msg $ \msg_ptr -> do
        r <- c'BLS_BLS12381_CORE_VERIFY sig_ptr msg_ptr pk_ptr
        return (r == 0)
