{-# LANGUAGE BinaryLiterals #-}
-- Unit test for IC.Test.Crypto.BLS
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ViewPatterns #-}

module IC.Test.BLS (blsTests) where

import Data.Bits
import qualified Data.ByteString.Lazy as BS
import qualified IC.Crypto.BLS as BLS
import Test.Tasty
import Test.Tasty.QuickCheck

blsTests :: TestTree
blsTests =
  testGroup
    "BLS crypto tests"
    [ testProperty "public key is 96 bytes" $
        \(BS.pack -> seed) ->
          let sk = BLS.createKey seed
           in let pk = BLS.toPublicKey sk
               in BS.length pk === 96,
      testProperty "public key high bits are either 0b100 or 0b100" $
        \(BS.pack -> seed) ->
          let sk = BLS.createKey seed
           in let pk = BLS.toPublicKey sk
               in BS.head pk `shiftR` 5 === 0b100 .||. BS.head pk `shiftR` 5 === 0b101,
      testProperty "signature is 48 bytes" $
        \(BS.pack -> seed) (BS.pack -> msg) ->
          let sk = BLS.createKey seed
           in let sig = BLS.sign sk msg
               in BS.length sig === 48,
      testProperty "signature high bits are either 0b100 or 0b100" $
        \(BS.pack -> seed) (BS.pack -> msg) ->
          let sk = BLS.createKey seed
           in let sig = BLS.sign sk msg
               in BS.head sig `shiftR` 5 === 0b100 .||. BS.head sig `shiftR` 5 === 0b101,
      testProperty "create-sign-verify" $
        \(BS.pack -> seed) (BS.pack -> msg) ->
          let sk = BLS.createKey seed
           in let sig = BLS.sign sk msg
               in BLS.verify (BLS.toPublicKey sk) msg sig,
      testProperty "invalid sig" $
        \(BS.pack -> seed) (BS.pack -> msg) (BS.pack -> sig) ->
          let sk = BLS.createKey seed
           in not (BLS.verify (BLS.toPublicKey sk) msg sig),
      testProperty "wrong message" $
        \(BS.pack -> seed) (BS.pack -> msg1) (BS.pack -> msg2) ->
          let sk = BLS.createKey seed
           in let sig = BLS.sign sk msg2
               in msg1 /= msg2 ==> not (BLS.verify (BLS.toPublicKey sk) msg1 sig)
    ]
