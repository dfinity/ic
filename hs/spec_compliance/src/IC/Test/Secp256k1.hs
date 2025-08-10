{-# LANGUAGE BinaryLiterals #-}
-- Unit test for IC.Test.Crypto.Secp256k1
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ViewPatterns #-}

module IC.Test.Secp256k1 (secp256k1Tests) where

import qualified Data.ByteString.Lazy as BS
import qualified Data.Text as T
import qualified IC.Crypto.Secp256k1 as Secp256k1
import Test.QuickCheck.IO ()
import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck

assertRight :: Either T.Text () -> Assertion
assertRight (Right ()) = return ()
assertRight (Left err) = assertFailure (T.unpack err)

assertLeft :: Either T.Text () -> Assertion
assertLeft (Left _) = return ()
assertLeft (Right _) = assertFailure "Unexpected success"

secp256k1Tests :: TestTree
secp256k1Tests =
  testGroup
    "Secp256k1 crypto tests"
    [ testProperty "create-sign-verify" $
        \(BS.pack -> seed) (BS.pack -> msg) -> do
          let sk = Secp256k1.createKey seed
          sig <- Secp256k1.sign sk msg
          assertRight $ Secp256k1.verify (Secp256k1.toPublicKey sk) msg sig,
      testProperty "invalid sig" $
        \(BS.pack -> seed) (BS.pack -> msg) (BS.pack -> sig) ->
          let sk = Secp256k1.createKey seed
           in assertLeft $ Secp256k1.verify (Secp256k1.toPublicKey sk) msg sig,
      testProperty "wrong message" $
        \(BS.pack -> seed) (BS.pack -> msg1) (BS.pack -> msg2) ->
          msg1 /= msg2 ==> do
            let sk = Secp256k1.createKey seed
            sig <- Secp256k1.sign sk msg2
            assertLeft $ Secp256k1.verify (Secp256k1.toPublicKey sk) msg1 sig
    ]
