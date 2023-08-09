{-# LANGUAGE BinaryLiterals #-}
-- Unit test for IC.Test.Crypto.WebAuthn
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ViewPatterns #-}

module IC.Test.WebAuthn (webAuthnTests) where

import qualified Data.ByteString.Lazy as BS
import qualified Data.Text as T
import qualified IC.Crypto.WebAuthn as WebAuthn
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

webAuthnTests :: TestTree
webAuthnTests =
  testGroup
    "WebAuthn crypto tests"
    [ testProperty "ECDSA: create-sign-verify" $
        \(BS.pack -> seed) (BS.pack -> msg) -> do
          let sk = WebAuthn.createECDSAKey seed
          sig <- WebAuthn.sign sk msg
          assertRight $ WebAuthn.verify (WebAuthn.toPublicKey sk) msg sig,
      testProperty "ECDSA: invalid sig" $
        \(BS.pack -> seed) (BS.pack -> msg) (BS.pack -> sig) ->
          let sk = WebAuthn.createECDSAKey seed
           in assertLeft $ WebAuthn.verify (WebAuthn.toPublicKey sk) msg sig,
      testProperty "ECDSA: wrong message" $
        \(BS.pack -> seed) (BS.pack -> msg1) (BS.pack -> msg2) ->
          msg1 /= msg2 ==> do
            let sk = WebAuthn.createECDSAKey seed
            sig <- WebAuthn.sign sk msg2
            assertLeft $ WebAuthn.verify (WebAuthn.toPublicKey sk) msg1 sig,
      testProperty "RSA: create-sign-verify" $
        \(BS.pack -> seed) (BS.pack -> msg) -> do
          let sk = WebAuthn.createRSAKey seed
          sig <- WebAuthn.sign sk msg
          assertRight $ WebAuthn.verify (WebAuthn.toPublicKey sk) msg sig,
      testProperty "RSA: invalid sig" $
        \(BS.pack -> seed) (BS.pack -> msg) (BS.pack -> sig) ->
          let sk = WebAuthn.createRSAKey seed
           in assertLeft $ WebAuthn.verify (WebAuthn.toPublicKey sk) msg sig,
      testProperty "RSA: wrong message" $
        \(BS.pack -> seed) (BS.pack -> msg1) (BS.pack -> msg2) ->
          msg1 /= msg2 ==> do
            let sk = WebAuthn.createRSAKey seed
            sig <- WebAuthn.sign sk msg2
            assertLeft $ WebAuthn.verify (WebAuthn.toPublicKey sk) msg1 sig
    ]
