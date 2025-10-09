{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedLabels #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TupleSections #-}
{-# LANGUAGE TypeApplications #-}

-- |
--
-- This module contains a test suite for the Internet Computer
module IC.Test.Spec (icTests) where

import Codec.Candid (Principal (..))
import qualified Codec.Candid as Candid
import Codec.Compression.GZip (compress)
import Control.Exception (try)
import Control.Monad
import qualified Data.ByteString.Lazy as BS
import Data.Either (isLeft)
import Data.Functor
import qualified Data.HashMap.Lazy as HM
import Data.List
import qualified Data.Map.Lazy as M
import Data.Row as R
import Data.Serialize.LEB128 (toLEB128)
import qualified Data.Set as S
import qualified Data.Text as T
import Data.Time.Clock.POSIX
import qualified Data.Vector as Vec
import Data.Word
import IC.Certificate
import IC.Crypto
import qualified IC.Crypto.CanisterSig as CanisterSig
import qualified IC.Crypto.DER as DER
import IC.HTTP.GenR
import IC.HTTP.RequestId
import IC.Hash
import IC.HashTree hiding (Blob, Label)
import IC.Id.Forms hiding (Blob)
import IC.Id.Fresh
import IC.Management (CanisterSettings, InstallCodeArgs, ProvisionalCreateCanisterArgs, entityIdToPrincipal)
import IC.Test.Agent
import IC.Test.Agent.Calls (httpbin_proto)
import IC.Test.Agent.SafeCalls
import IC.Test.Agent.UnsafeCalls
import IC.Test.Agent.UserCalls
import IC.Test.Spec.Utils
import IC.Test.Universal
import IC.Types (EntityId (..), SubnetType (..), TestSubnetConfig)
import Numeric.Natural
import Test.Tasty
import Test.Tasty.HUnit

-- * The test suite (see below for helper functions)

icTests :: TestSubnetConfig -> TestSubnetConfig -> AgentConfig -> IO TestTree
icTests my_sub other_sub conf =
  let (my_subnet_id_as_entity, my_type, my_nodes, my_ranges, _) = my_sub
   in let ((ecid_as_word64, last_canister_id_as_word64) : _) = my_ranges
       in let (_, last_canister_id_as_word64) = last my_ranges
           in let (other_subnet_id_as_entity, _, other_nodes, ((other_ecid_as_word64, other_last_canister_id_as_word64) : _), _) = other_sub
               in let my_subnet_id = rawEntityId my_subnet_id_as_entity
                   in let other_subnet_id = rawEntityId other_subnet_id_as_entity
                       in let my_is_root = isRootTestSubnet my_sub
                           in let ecid = rawEntityId $ wordToId ecid_as_word64
                               in let other_ecid = rawEntityId $ wordToId other_ecid_as_word64
                                   in let initial_cycles = case my_type of
                                            System -> 0
                                            _ -> (2 ^ (60 :: Int))
                                       in do
                                            (store_canister_id, ucan_chunk_hash) <- withAgentConfig conf $ do
                                              universal_wasm <- getTestWasm "universal_canister_no_heartbeat.wasm.gz"
                                              store_canister_id <- ic_provisional_create ic00 ecid Nothing Nothing Nothing
                                              ucan_chunk_hash <- ic_upload_chunk ic00 store_canister_id universal_wasm
                                              ic_install_single_chunk ic00 (enum #install) store_canister_id store_canister_id ucan_chunk_hash ""
                                              return (store_canister_id, ucan_chunk_hash)
                                            let extended_conf = conf {tc_ucan_chunk_hash = Just ucan_chunk_hash, tc_store_canister_id = Just store_canister_id}
                                            return $
                                              withAgentConfig extended_conf $
                                                testGroup "Interface Spec acceptance tests" $
                                                  let test_subnet_msg sub subnet_id subnet_id' cid = do
                                                        cid2 <- ic_create (ic00viaWithCyclesSubnet subnet_id cid 20_000_000_000_000) ecid Nothing
                                                        ic_install (ic00viaWithCyclesSubnet subnet_id cid 0) (enum #install) cid2 trivialWasmModule ""
                                                        cid3 <- ic_provisional_create (ic00viaWithCyclesSubnet subnet_id cid 20_000_000_000_000) ecid Nothing Nothing Nothing
                                                        ic_install (ic00viaWithCyclesSubnet subnet_id cid 0) (enum #install) cid3 trivialWasmModule ""
                                                        ic_install (ic00viaWithCyclesSubnet subnet_id cid 0) (enum #reinstall) cid3 trivialWasmModule ""
                                                        ic_install' (ic00viaWithCyclesSubnet' subnet_id' cid 0) (enum #reinstall) cid3 trivialWasmModule "" >>= isReject [3]
                                                        _ <- ic_raw_rand (ic00viaWithCyclesSubnet subnet_id cid 0) ecid
                                                        return ()
                                                   in let test_subnet_msg_canister_http sub subnet_id cid = do
                                                            _ <- ic_http_get_request (ic00viaWithCyclesSubnet subnet_id cid) sub httpbin_proto ("equal_bytes/8") Nothing Nothing cid
                                                            return ()
                                                       in let test_subnet_msg' sub subnet_id cid = do
                                                                ic_create' (ic00viaWithCyclesSubnet' subnet_id cid 20_000_000_000_000) ecid Nothing >>= isReject [3]
                                                                ic_provisional_create' (ic00viaWithCyclesSubnet' subnet_id cid 20_000_000_000_000) ecid Nothing Nothing Nothing >>= isReject [3]
                                                                cid2 <- ic_create (ic00viaWithCycles cid 20_000_000_000_000) ecid Nothing
                                                                ic_install' (ic00viaWithCyclesSubnet' subnet_id cid 0) (enum #install) cid2 trivialWasmModule "" >>= isReject [3]
                                                                ic_raw_rand' (ic00viaWithCyclesSubnet' subnet_id cid 0) ecid >>= isReject [3]
                                                           in let test_subnet_msg_canister_http' sub subnet_id cid = do
                                                                    ic_http_get_request' (ic00viaWithCyclesSubnet' subnet_id cid) sub httpbin_proto ("equal_bytes/8") Nothing Nothing cid >>= isReject [3]
                                                               in let install_with_cycles_at_id n cycles prog = do
                                                                        let specified_raw_id = rawEntityId $ wordToId n
                                                                        let specified_id = entityIdToPrincipal $ EntityId specified_raw_id
                                                                        cid <- ic_provisional_create ic00 specified_raw_id (Just specified_id) (Just cycles) Nothing
                                                                        assertBool "canister was not created at its specified ID" $ cid == specified_raw_id
                                                                        universal_wasm <- getTestWasm "universal_canister_no_heartbeat.wasm.gz"
                                                                        ic_install ic00 (enum #install) cid universal_wasm (run prog)
                                                                        return cid
                                                                   in [ testGroup
                                                                          "regular canisters"
                                                                          [ simpleTestCase "create and install" ecid $ \_ ->
                                                                              return (),
                                                                            testCase "create_canister necessary" $
                                                                              ic_install'' defaultUser (enum #install) doesn'tExist trivialWasmModule ""
                                                                                >>= isErrOrReject [3, 5],
                                                                            testGroup
                                                                              "provisional_create_canister_with_cycles"
                                                                              [ testCase "specified_id does not belong to the subnet's canister ranges" $ do
                                                                                  let specified_id = entityIdToPrincipal $ EntityId doesn'tExist
                                                                                  ic_provisional_create' ic00 ecid (Just specified_id) (Just (2 ^ (60 :: Int))) Nothing >>= isReject [4]
                                                                              ],
                                                                            testCaseSteps "management requests" $ \step -> do
                                                                              step "Create (provisional)"
                                                                              can_id <- create ecid

                                                                              step "Install"
                                                                              ic_install ic00 (enum #install) can_id trivialWasmModule ""

                                                                              step "Install again fails"
                                                                              ic_install'' defaultUser (enum #install) can_id trivialWasmModule ""
                                                                                >>= isErrOrReject [3, 5]

                                                                              step "Reinstall"
                                                                              ic_install ic00 (enum #reinstall) can_id trivialWasmModule ""

                                                                              step "Reinstall as wrong user"
                                                                              ic_install'' otherUser (enum #reinstall) can_id trivialWasmModule ""
                                                                                >>= isErrOrReject [3, 5]

                                                                              step "Upgrade"
                                                                              ic_install ic00 (enumNothing #upgrade) can_id trivialWasmModule ""

                                                                              step "Upgrade as wrong user"
                                                                              ic_install'' otherUser (enumNothing #upgrade) can_id trivialWasmModule ""
                                                                                >>= isErrOrReject [3, 5]

                                                                              step "Change controller"
                                                                              ic_set_controllers ic00 can_id [otherUser]

                                                                              step "Change controller (with wrong controller)"
                                                                              ic_set_controllers'' defaultUser can_id [otherUser]
                                                                                >>= isErrOrReject [3, 5]

                                                                              step "Reinstall as new controller"
                                                                              ic_install (ic00as otherUser) (enum #reinstall) can_id trivialWasmModule "",
                                                                            testCaseSteps "install (gzip compressed)" $ \step -> do
                                                                              cid <- create ecid
                                                                              let compressedModule = compress trivialWasmModule

                                                                              step "Install compressed module"
                                                                              ic_install ic00 (enum #install) cid compressedModule ""

                                                                              cs <- ic_canister_status ic00 cid
                                                                              cs .! #module_hash @?= Just (sha256 compressedModule)

                                                                              step "Reinstall compressed module"
                                                                              ic_install ic00 (enum #reinstall) cid compressedModule ""

                                                                              cs <- ic_canister_status ic00 cid
                                                                              cs .! #module_hash @?= Just (sha256 compressedModule)

                                                                              step "Install raw module"
                                                                              ic_install ic00 (enum #reinstall) cid trivialWasmModule ""

                                                                              cs <- ic_canister_status ic00 cid
                                                                              cs .! #module_hash @?= Just (sha256 trivialWasmModule)

                                                                              step "Upgrade to a compressed module"
                                                                              ic_install ic00 (enumNothing #upgrade) cid compressedModule ""

                                                                              cs <- ic_canister_status ic00 cid
                                                                              cs .! #module_hash @?= Just (sha256 compressedModule),
                                                                            testCaseSteps "reinstall on empty" $ \step -> do
                                                                              step "Create"
                                                                              can_id <- create ecid

                                                                              step "Reinstall over empty canister"
                                                                              ic_install ic00 (enum #reinstall) can_id trivialWasmModule "",
                                                                            testCaseSteps "canister_status" $ \step -> do
                                                                              step "Create empty"
                                                                              cid <- create ecid
                                                                              cs <- ic_canister_status ic00 cid
                                                                              cs .! #status @?= enum #running
                                                                              cs .! #settings .! #controllers @?= Vec.fromList [Principal defaultUser]
                                                                              cs .! #module_hash @?= Nothing

                                                                              step "Install"
                                                                              ic_install ic00 (enum #install) cid trivialWasmModule ""
                                                                              cs <- ic_canister_status ic00 cid
                                                                              cs .! #module_hash @?= Just (sha256 trivialWasmModule),
                                                                            testCaseSteps "canister lifecycle" $ \step -> do
                                                                              cid <-
                                                                                install ecid $
                                                                                  onPreUpgrade $
                                                                                    callback $
                                                                                      ignore (stableGrow (int 1))
                                                                                        >>> stableWrite (int 0) (i2b getStatus)

                                                                              step "Is running (via management)?"
                                                                              cs <- ic_canister_status ic00 cid
                                                                              cs .! #status @?= enum #running

                                                                              step "Is running (local)?"
                                                                              query cid (replyData (i2b getStatus)) >>= asWord32 >>= is 1

                                                                              step "Stop"
                                                                              ic_stop_canister ic00 cid

                                                                              step "Is stopped (via management)?"
                                                                              cs <- ic_canister_status ic00 cid
                                                                              cs .! #status @?= enum #stopped

                                                                              step "Stop is noop"
                                                                              ic_stop_canister ic00 cid

                                                                              step "Cannot call (update)?"
                                                                              call' cid reply >>= isReject [5]

                                                                              step "Cannot call (query)?"
                                                                              query' cid reply >>= isQueryReject ecid [5]

                                                                              step "Upgrade"
                                                                              upgrade cid $ setGlobal (i2b getStatus)

                                                                              step "Start canister"
                                                                              ic_start_canister ic00 cid

                                                                              step "Is running (via managemnet)?"
                                                                              cs <- ic_canister_status ic00 cid
                                                                              cs .! #status @?= enum #running

                                                                              step "Is running (local)?"
                                                                              query cid (replyData (i2b getStatus)) >>= asWord32 >>= is 1

                                                                              step "Was stopped during pre-upgrade?"
                                                                              query cid (replyData (stableRead (int 0) (int 4))) >>= asWord32 >>= is 3

                                                                              step "Was stopped during post-upgrade?"
                                                                              query cid (replyData getGlobal) >>= asWord32 >>= is 3

                                                                              step "Can call (update)?"
                                                                              call_ cid reply

                                                                              step "Can call (query)?"
                                                                              query_ cid reply

                                                                              step "Start is noop"
                                                                              ic_start_canister ic00 cid,
                                                                            testCaseSteps "canister stopping" $ \step -> do
                                                                              cid <- install ecid noop

                                                                              step "Is running (via management)?"
                                                                              cs <- ic_canister_status ic00 cid
                                                                              cs .! #status @?= enum #running

                                                                              step "Is running (local)?"
                                                                              query cid (replyData (i2b getStatus)) >>= asWord32 >>= is 1

                                                                              step "Create message hold"
                                                                              (messageHold, release) <- createMessageHold ecid

                                                                              step "Create long-running call"
                                                                              grs1 <- submitCall cid $ callRequest cid messageHold
                                                                              awaitKnown grs1 >>= isPendingOrProcessing

                                                                              step "Normal call (to sync)"
                                                                              call_ cid reply

                                                                              step "Stop"
                                                                              grs2 <- submitCall cid $ stopRequest cid
                                                                              awaitKnown grs2 >>= isPendingOrProcessing

                                                                              step "Is stopping (via management)?"
                                                                              cs <- ic_canister_status ic00 cid
                                                                              cs .! #status @?= enum #stopping

                                                                              step "Next stop waits, too"
                                                                              grs3 <- submitCall cid $ stopRequest cid
                                                                              awaitKnown grs3 >>= isPendingOrProcessing

                                                                              step "Cannot call (update)?"
                                                                              call' cid reply >>= isReject [5]

                                                                              step "Cannot call (query)?"
                                                                              query' cid reply >>= isQueryReject ecid [5]

                                                                              step "Release the held message"
                                                                              release

                                                                              step "Wait for calls to complete"
                                                                              awaitStatus grs1 >>= isReply >>= is ""
                                                                              awaitStatus grs2 >>= isReply >>= is (Candid.encode ())
                                                                              awaitStatus grs3 >>= isReply >>= is (Candid.encode ())

                                                                              step "Is stopped (via management)?"
                                                                              cs <- ic_canister_status ic00 cid
                                                                              cs .! #status @?= enum #stopped

                                                                              step "Cannot call (update)?"
                                                                              call' cid reply >>= isReject [5]

                                                                              step "Cannot call (query)?"
                                                                              query' cid reply >>= isQueryReject ecid [5],
                                                                            testCaseSteps "starting a stopping canister" $ \step -> do
                                                                              cid <- install ecid noop

                                                                              step "Create message hold"
                                                                              (messageHold, _) <- createMessageHold ecid

                                                                              step "Create long-running call"
                                                                              grs1 <- submitCall cid $ callRequest cid messageHold
                                                                              awaitKnown grs1 >>= isPendingOrProcessing

                                                                              step "Normal call (to sync)"
                                                                              call_ cid reply

                                                                              step "Stop"
                                                                              grs2 <- submitCall cid $ stopRequest cid
                                                                              awaitKnown grs2 >>= isPendingOrProcessing

                                                                              step "Is stopping (via management)?"
                                                                              cs <- ic_canister_status ic00 cid
                                                                              cs .! #status @?= enum #stopping

                                                                              step "Restart"
                                                                              ic_start_canister ic00 cid

                                                                              step "Is running (via management)?"
                                                                              cs <- ic_canister_status ic00 cid
                                                                              cs .! #status @?= enum #running,
                                                                            testCaseSteps "canister deletion" $ \step -> do
                                                                              cid <- install ecid noop

                                                                              step "Deletion fails"
                                                                              ic_delete_canister' ic00 cid >>= isReject [5]

                                                                              step "Create message hold"
                                                                              (messageHold, release) <- createMessageHold ecid

                                                                              step "Create long-running call"
                                                                              grs1 <- submitCall cid $ callRequest cid messageHold
                                                                              awaitKnown grs1 >>= isPendingOrProcessing

                                                                              step "Start stopping"
                                                                              grs2 <- submitCall cid $ stopRequest cid
                                                                              awaitKnown grs2 >>= isPendingOrProcessing

                                                                              step "Is stopping?"
                                                                              cs <- ic_canister_status ic00 cid
                                                                              cs .! #status @?= enum #stopping

                                                                              step "Deletion fails"
                                                                              ic_delete_canister' ic00 cid >>= isReject [5]

                                                                              step "Let canister stop"
                                                                              release
                                                                              awaitStatus grs1 >>= isReply >>= is ""
                                                                              awaitStatus grs2 >>= isReply >>= is (Candid.encode ())

                                                                              step "Is stopped?"
                                                                              cs <- ic_canister_status ic00 cid
                                                                              cs .! #status @?= enum #stopped

                                                                              step "Deletion succeeds"
                                                                              ic_delete_canister ic00 cid

                                                                              -- Disabled; such a call gets accepted (200) but
                                                                              -- then the status never shows up, which causes a timeout
                                                                              --
                                                                              -- step "Cannot call (update)?"
                                                                              -- call' cid reply >>= isReject [3]

                                                                              step "Cannot call (inter-canister)?"
                                                                              cid2 <- install ecid noop
                                                                              do call cid2 $ inter_update cid defArgs
                                                                                >>= isRelay
                                                                                >>= isReject [3]

                                                                              step "Cannot call (query)?"
                                                                              query' cid reply >>= isQueryReject ecid [3]

                                                                              step "Cannot query canister_status"
                                                                              ic_canister_status'' defaultUser cid >>= isErrOrReject [3, 5]

                                                                              step "Deletion fails"
                                                                              ic_delete_canister'' defaultUser cid >>= isErrOrReject [3, 5],
                                                                            testCaseSteps "canister lifecycle (wrong controller)" $ \step -> do
                                                                              cid <- install ecid noop

                                                                              step "Start as wrong user"
                                                                              ic_start_canister'' otherUser cid >>= isErrOrReject [3, 5]
                                                                              step "Stop as wrong user"
                                                                              ic_stop_canister'' otherUser cid >>= isErrOrReject [3, 5]
                                                                              step "Canister Status as wrong user"
                                                                              ic_canister_status'' otherUser cid >>= isErrOrReject [3, 5]
                                                                              step "Delete as wrong user"
                                                                              ic_delete_canister'' otherUser cid >>= isErrOrReject [3, 5],
                                                                            testCaseSteps "aaaaa-aa (inter-canister)" $ \step -> do
                                                                              -- install universal canisters to proxy the requests
                                                                              cid <- install ecid noop
                                                                              cid2 <- install ecid noop

                                                                              step "Create"
                                                                              can_id <- ic_provisional_create (ic00via cid) ecid Nothing Nothing Nothing

                                                                              step "Install"
                                                                              ic_install (ic00via cid) (enum #install) can_id trivialWasmModule ""

                                                                              step "Install again fails"
                                                                              ic_install' (ic00via cid) (enum #install) can_id trivialWasmModule ""
                                                                                >>= isReject [3, 5]

                                                                              step "Reinstall"
                                                                              ic_install (ic00via cid) (enum #reinstall) can_id trivialWasmModule ""

                                                                              step "Reinstall (gzip compressed)"
                                                                              ic_install (ic00via cid) (enum #reinstall) can_id (compress trivialWasmModule) ""

                                                                              step "Reinstall as wrong user"
                                                                              ic_install' (ic00via cid2) (enum #reinstall) can_id trivialWasmModule ""
                                                                                >>= isReject [3, 5]

                                                                              step "Upgrade"
                                                                              ic_install (ic00via cid) (enumNothing #upgrade) can_id trivialWasmModule ""

                                                                              step "Change controller"
                                                                              ic_set_controllers (ic00via cid) can_id [cid2]

                                                                              step "Change controller (with wrong controller)"
                                                                              ic_set_controllers' (ic00via cid) can_id [cid2]
                                                                                >>= isReject [3, 5]

                                                                              step "Reinstall as new controller"
                                                                              ic_install (ic00via cid2) (enum #reinstall) can_id trivialWasmModule ""

                                                                              step "Create"
                                                                              can_id2 <- ic_provisional_create (ic00via cid) ecid Nothing Nothing Nothing

                                                                              step "Reinstall on empty"
                                                                              ic_install (ic00via cid) (enum #reinstall) can_id2 trivialWasmModule "",
                                                                            simpleTestCase "aaaaa-aa (inter-canister, large)" ecid $ \cid -> do
                                                                              can_id <- ic_provisional_create (ic00via cid) ecid Nothing Nothing Nothing
                                                                              ic_set_controllers (ic00via cid) can_id [store_canister_id, cid]
                                                                              ic_install_single_chunk (ic00via store_canister_id) (enum #install) can_id store_canister_id ucan_chunk_hash ""
                                                                              do call can_id $ replyData "Hi"
                                                                                >>= is "Hi",
                                                                            simpleTestCase "randomness" ecid $ \cid -> do
                                                                              r1 <- ic_raw_rand (ic00via cid) ecid
                                                                              r2 <- ic_raw_rand (ic00via cid) ecid
                                                                              BS.length r1 @?= 32
                                                                              BS.length r2 @?= 32
                                                                              assertBool "random blobs are different" $ r1 /= r2,
                                                                            testGroup
                                                                              "simple calls"
                                                                              [ simpleTestCase "Call" ecid $ \cid ->
                                                                                  call cid (replyData "ABCD") >>= is "ABCD",
                                                                                simpleTestCase "Call (query)" ecid $ \cid -> do
                                                                                  query cid (replyData "ABCD") >>= is "ABCD",
                                                                                simpleTestCase "Call no non-existent update method" ecid $ \cid ->
                                                                                  do
                                                                                    awaitCall' cid $
                                                                                      rec
                                                                                        [ "request_type" =: GText "call",
                                                                                          "sender" =: GBlob defaultUser,
                                                                                          "canister_id" =: GBlob cid,
                                                                                          "method_name" =: GText "no_such_update",
                                                                                          "arg" =: GBlob ""
                                                                                        ]
                                                                                    >>= isErrOrReject [5],
                                                                                simpleTestCase "Call no non-existent query method" ecid $ \cid ->
                                                                                  do
                                                                                    let cbor =
                                                                                          rec
                                                                                            [ "request_type" =: GText "query",
                                                                                              "sender" =: GBlob defaultUser,
                                                                                              "canister_id" =: GBlob cid,
                                                                                              "method_name" =: GText "no_such_update",
                                                                                              "arg" =: GBlob ""
                                                                                            ]
                                                                                    (rid, res) <- queryCBOR cid cbor
                                                                                    res <- queryResponse res
                                                                                    isQueryReject ecid [5] (rid, res),
                                                                                simpleTestCase "reject" ecid $ \cid ->
                                                                                  call' cid (reject "ABCD") >>= isReject [4],
                                                                                simpleTestCase "reject (query)" ecid $ \cid ->
                                                                                  query' cid (reject "ABCD") >>= isQueryReject ecid [4],
                                                                                simpleTestCase "No response" ecid $ \cid ->
                                                                                  call' cid noop >>= isReject [5],
                                                                                simpleTestCase "No response does not rollback" ecid $ \cid -> do
                                                                                  call'' cid (setGlobal "FOO") >>= isErrOrReject [5]
                                                                                  query cid (replyData getGlobal) >>= is "FOO",
                                                                                simpleTestCase "No response (query)" ecid $ \cid ->
                                                                                  query' cid noop >>= isQueryReject ecid [5],
                                                                                simpleTestCase "Double reply" ecid $ \cid ->
                                                                                  call' cid (reply >>> reply) >>= isReject [5],
                                                                                simpleTestCase "Double reply (query)" ecid $ \cid ->
                                                                                  query' cid (reply >>> reply) >>= isQueryReject ecid [5],
                                                                                simpleTestCase "Reply data append after reply" ecid $ \cid ->
                                                                                  call' cid (reply >>> replyDataAppend "foo") >>= isReject [5],
                                                                                simpleTestCase "Reply data append after reject" ecid $ \cid ->
                                                                                  call' cid (reject "bar" >>> replyDataAppend "foo") >>= isReject [5],
                                                                                simpleTestCase "Caller" ecid $ \cid ->
                                                                                  call cid (replyData caller) >>= is defaultUser,
                                                                                simpleTestCase "Caller (query)" ecid $ \cid ->
                                                                                  query cid (replyData caller) >>= is defaultUser
                                                                              ],
                                                                            testGroup
                                                                              "Settings"
                                                                              [ testGroup
                                                                                  "Controllers"
                                                                                  $ [ testCase "A canister can request its own status if it does not control itself" $ do
                                                                                        let controllers = [defaultUser, otherUser]
                                                                                        cid <- ic_provisional_create ic00 ecid Nothing Nothing Nothing
                                                                                        ic_set_controllers ic00 cid controllers
                                                                                        ic_install_single_chunk ic00 (enum #install) cid store_canister_id ucan_chunk_hash ""

                                                                                        cs <- ic_canister_status (ic00via cid) cid
                                                                                        assertBool "canister should not control itself in this test" $ not $ elem cid controllers
                                                                                        Vec.toList (cs .! #settings .! #controllers) `isSet` map Principal controllers,
                                                                                      testCase "Changing controllers" $ do
                                                                                        let controllers = [defaultUser, otherUser]
                                                                                        cid <- ic_provisional_create ic00 ecid Nothing Nothing Nothing
                                                                                        ic_set_controllers ic00 cid controllers
                                                                                        ic_install_single_chunk ic00 (enum #install) cid store_canister_id ucan_chunk_hash ""

                                                                                        -- Set new controller
                                                                                        ic_set_controllers (ic00as defaultUser) cid [ecdsaUser]

                                                                                        -- Only that controller can get canister status
                                                                                        ic_canister_status'' defaultUser cid >>= isErrOrReject [3, 5]
                                                                                        ic_canister_status'' otherUser cid >>= isErrOrReject [3, 5]
                                                                                        ic_canister_status'' anonymousUser cid >>= isErrOrReject [3, 5]
                                                                                        ic_canister_status'' secp256k1User cid >>= isErrOrReject [3, 5]
                                                                                        cs <- ic_canister_status (ic00as ecdsaUser) cid
                                                                                        cs .! #settings .! #controllers @?= Vec.fromList [Principal ecdsaUser],
                                                                                      simpleTestCase "Multiple controllers (aaaaa-aa)" ecid $ \cid -> do
                                                                                        let controllers = [cid, otherUser]
                                                                                        cid2 <- ic_create_with_controllers (ic00viaWithCycles cid 20_000_000_000_000) ecid controllers
                                                                                        ic_set_controllers (ic00via cid) cid2 (controllers ++ [store_canister_id])
                                                                                        ic_install_single_chunk (ic00via store_canister_id) (enum #install) cid2 store_canister_id ucan_chunk_hash ""
                                                                                        ic_set_controllers (ic00via cid) cid2 controllers

                                                                                        -- Controllers should be able to fetch the canister status.
                                                                                        cs <- ic_canister_status (ic00via cid) cid2
                                                                                        Vec.toList (cs .! #settings .! #controllers) `isSet` map Principal controllers
                                                                                        cs <- ic_canister_status (ic00as otherUser) cid2
                                                                                        Vec.toList (cs .! #settings .! #controllers) `isSet` map Principal controllers

                                                                                        -- Non-controllers cannot fetch the canister status
                                                                                        ic_canister_status'' ecdsaUser cid >>= isErrOrReject [3, 5]
                                                                                        ic_canister_status'' anonymousUser cid >>= isErrOrReject [3, 5]
                                                                                        ic_canister_status'' secp256k1User cid >>= isErrOrReject [3, 5],
                                                                                      simpleTestCase "> 10 controllers" ecid $ \cid -> do
                                                                                        ic_create_with_controllers' (ic00viaWithCycles cid 20_000_000_000_000) ecid (replicate 11 cid) >>= isReject [4]
                                                                                        ic_set_controllers' ic00 cid (replicate 11 cid) >>= isReject [4],
                                                                                      simpleTestCase "No controller" ecid $ \cid -> do
                                                                                        cid2 <- ic_create_with_controllers (ic00viaWithCycles cid 20_000_000_000_000) ecid []
                                                                                        ic_canister_status'' defaultUser cid2 >>= isErrOrReject [3, 5]
                                                                                        ic_canister_status'' otherUser cid2 >>= isErrOrReject [3, 5],
                                                                                      testCase "Controller is self" $ do
                                                                                        cid <- install ecid noop
                                                                                        ic_set_controllers ic00 cid [cid] -- Set controller of cid to be itself

                                                                                        -- cid can now request its own status
                                                                                        cs <- ic_canister_status (ic00via cid) cid
                                                                                        cs .! #settings .! #controllers @?= Vec.fromList [Principal cid],
                                                                                      testCase "Duplicate controllers" $ do
                                                                                        let controllers = [defaultUser, defaultUser, otherUser]
                                                                                        cid <- ic_provisional_create ic00 ecid Nothing Nothing Nothing
                                                                                        ic_set_controllers ic00 cid controllers
                                                                                        cs <- ic_canister_status (ic00as defaultUser) cid
                                                                                        Vec.toList (cs .! #settings .! #controllers) `isSet` map Principal controllers
                                                                                    ]
                                                                                    ++ ( let invalid_compute_allocation :: CanisterSettings =
                                                                                               empty
                                                                                                 .+ #controllers
                                                                                                 .== Nothing
                                                                                                 .+ #compute_allocation
                                                                                                 .== Just 101
                                                                                                 .+ #memory_allocation
                                                                                                 .== Nothing
                                                                                                 .+ #freezing_threshold
                                                                                                 .== Nothing
                                                                                                 .+ #reserved_cycles_limit
                                                                                                 .== Nothing
                                                                                                 .+ #log_visibility
                                                                                                 .== Nothing
                                                                                                 .+ #wasm_memory_limit
                                                                                                 .== Nothing
                                                                                          in let invalid_memory_allocation :: CanisterSettings =
                                                                                                   empty
                                                                                                     .+ #controllers
                                                                                                     .== Nothing
                                                                                                     .+ #compute_allocation
                                                                                                     .== Nothing
                                                                                                     .+ #memory_allocation
                                                                                                     .== Just (2 ^ 64 + 1)
                                                                                                     .+ #freezing_threshold
                                                                                                     .== Nothing
                                                                                                     .+ #reserved_cycles_limit
                                                                                                     .== Nothing
                                                                                                     .+ #log_visibility
                                                                                                     .== Nothing
                                                                                                     .+ #wasm_memory_limit
                                                                                                     .== Nothing
                                                                                              in let invalid_freezing_threshold :: CanisterSettings =
                                                                                                       empty
                                                                                                         .+ #controllers
                                                                                                         .== Nothing
                                                                                                         .+ #compute_allocation
                                                                                                         .== Nothing
                                                                                                         .+ #memory_allocation
                                                                                                         .== Nothing
                                                                                                         .+ #freezing_threshold
                                                                                                         .== Just (2 ^ 64)
                                                                                                         .+ #reserved_cycles_limit
                                                                                                         .== Nothing
                                                                                                         .+ #log_visibility
                                                                                                         .== Nothing
                                                                                                         .+ #wasm_memory_limit
                                                                                                         .== Nothing
                                                                                                  in let invalid_settings =
                                                                                                           [ ("Invalid compute allocation (101)", invalid_compute_allocation),
                                                                                                             ("Invalid memory allocation (2^48+1)", invalid_memory_allocation),
                                                                                                             ("Invalid freezing threshold (2^64)", invalid_freezing_threshold)
                                                                                                           ]
                                                                                                      in let test_modes =
                                                                                                               [ ( "via provisional_create_canister_with_cycles:",
                                                                                                                   \(desc, settings) -> testCase desc $ do
                                                                                                                     ic_provisional_create' ic00 ecid Nothing Nothing (Just settings) >>= isReject [5]
                                                                                                                 ),
                                                                                                                 ( "via create_canister:",
                                                                                                                   \(desc, settings) -> simpleTestCase desc ecid $ \cid -> do
                                                                                                                     ic_create' (ic00via cid) ecid (Just settings) >>= isReject [5]
                                                                                                                 ),
                                                                                                                 ( "via update_settings",
                                                                                                                   \(desc, settings) -> simpleTestCase desc ecid $ \cid -> do
                                                                                                                     ic_update_settings' ic00 cid settings >>= isReject [5]
                                                                                                                 )
                                                                                                               ]
                                                                                                          in map (\(desc, test) -> testGroup desc (map test invalid_settings)) test_modes
                                                                                       ),
                                                                                simpleTestCase "Valid allocations" ecid $ \cid -> do
                                                                                  let settings :: CanisterSettings =
                                                                                        empty
                                                                                          .+ #controllers
                                                                                          .== Nothing
                                                                                          .+ #compute_allocation
                                                                                          .== Just 1
                                                                                          .+ #memory_allocation
                                                                                          .== Just (1024 * 1024)
                                                                                          .+ #freezing_threshold
                                                                                          .== Just 1000_000
                                                                                          .+ #reserved_cycles_limit
                                                                                          .== Nothing
                                                                                          .+ #log_visibility
                                                                                          .== Nothing
                                                                                          .+ #wasm_memory_limit
                                                                                          .== Nothing
                                                                                  cid2 <- ic_create (ic00viaWithCycles cid 20_000_000_000_000) ecid (Just settings)
                                                                                  cs <- ic_canister_status (ic00via cid) cid2
                                                                                  cs .! #settings .! #compute_allocation @?= 1
                                                                                  cs .! #settings .! #memory_allocation @?= 1024 * 1024
                                                                                  cs .! #settings .! #freezing_threshold @?= 1000_000
                                                                              ],
                                                                            testGroup
                                                                              "state"
                                                                              [ simpleTestCase "set/get" ecid $ \cid -> do
                                                                                  call_ cid $ setGlobal "FOO" >>> reply
                                                                                  query cid (replyData getGlobal) >>= is "FOO",
                                                                                simpleTestCase "set/set/get" ecid $ \cid -> do
                                                                                  call_ cid $ setGlobal "FOO" >>> reply
                                                                                  call_ cid $ setGlobal "BAR" >>> reply
                                                                                  query cid (replyData getGlobal) >>= is "BAR",
                                                                                simpleTestCase "resubmission" ecid $ \cid -> do
                                                                                  -- Submits the same request (same nonce) twice, checks that
                                                                                  -- the IC does not act twice.
                                                                                  -- (Using growing stable memory as non-idempotent action)
                                                                                  callTwice' cid (ignore (stableGrow (int 1)) >>> reply) >>= isReply >>= is ""
                                                                                  query cid (replyData (i2b stableSize)) >>= is "\1\0\0\0"
                                                                              ],
                                                                            testGroup
                                                                              "inter-canister calls"
                                                                              [ testGroup
                                                                                  "builder interface"
                                                                                  [ testGroup
                                                                                      "traps without call_new"
                                                                                      [ simpleTestCase "call_data_append" ecid $ \cid ->
                                                                                          call' cid (callDataAppend "Foo" >>> reply) >>= isReject [5],
                                                                                        simpleTestCase "call_on_cleanup" ecid $ \cid ->
                                                                                          call' cid (callOnCleanup (callback noop) >>> reply) >>= isReject [5],
                                                                                        simpleTestCase "call_cycles_add" ecid $ \cid ->
                                                                                          call' cid (callCyclesAdd (int64 0) >>> reply) >>= isReject [5],
                                                                                        simpleTestCase "call_perform" ecid $ \cid ->
                                                                                          call' cid (callPerform >>> reply) >>= isReject [5]
                                                                                      ],
                                                                                    simpleTestCase "call_new clears pending call" ecid $ \cid -> do
                                                                                      do
                                                                                        call cid $
                                                                                          callNew "foo" "bar" "baz" "quux"
                                                                                            >>> callDataAppend "hey"
                                                                                            >>> inter_query cid defArgs
                                                                                        >>= isRelay
                                                                                        >>= isReply
                                                                                        >>= is ("Hello " <> cid <> " this is " <> cid),
                                                                                    simpleTestCase "call_data_append really appends" ecid $ \cid -> do
                                                                                      do
                                                                                        call cid $
                                                                                          callNew
                                                                                            (bytes cid)
                                                                                            (bytes "query")
                                                                                            (callback relayReply)
                                                                                            (callback relayReject)
                                                                                            >>> callDataAppend (bytes (BS.take 3 (run defaultOtherSide)))
                                                                                            >>> callDataAppend (bytes (BS.drop 3 (run defaultOtherSide)))
                                                                                            >>> callPerform
                                                                                        >>= isRelay
                                                                                        >>= isReply
                                                                                        >>= is ("Hello " <> cid <> " this is " <> cid),
                                                                                    simpleTestCase "call_on_cleanup traps if called twice" ecid $ \cid ->
                                                                                      do
                                                                                        call' cid $
                                                                                          callNew
                                                                                            (bytes cid)
                                                                                            (bytes "query")
                                                                                            (callback relayReply)
                                                                                            (callback relayReject)
                                                                                            >>> callOnCleanup (callback noop)
                                                                                            >>> callOnCleanup (callback noop)
                                                                                            >>> reply
                                                                                        >>= isReject [5]
                                                                                  ],
                                                                                simpleTestCase "to nonexistent canister" ecid $ \cid ->
                                                                                  call cid (inter_call "foo" "bar" defArgs) >>= isRelay >>= isReject [3],
                                                                                simpleTestCase "to nonexistent canister (user id)" ecid $ \cid ->
                                                                                  call cid (inter_call defaultUser "bar" defArgs) >>= isRelay >>= isReject [3],
                                                                                simpleTestCase "to nonexistent method" ecid $ \cid ->
                                                                                  call cid (inter_call cid "bar" defArgs) >>= isRelay >>= isReject [5],
                                                                                simpleTestCase "Call from query method traps (in update call)" ecid $ \cid ->
                                                                                  callToQuery'' cid (inter_query cid defArgs) >>= is2xx >>= isReject [5],
                                                                                simpleTestCase "Call from query method traps (in query call)" ecid $ \cid ->
                                                                                  query' cid (inter_query cid defArgs) >>= isQueryReject ecid [5],
                                                                                simpleTestCase "Call from query method traps (in inter-canister-call)" ecid $ \cid ->
                                                                                  do
                                                                                    call cid $
                                                                                      inter_call
                                                                                        cid
                                                                                        "query"
                                                                                        defArgs
                                                                                          { other_side = inter_query cid defArgs
                                                                                          }
                                                                                    >>= isRelay
                                                                                    >>= isReject [5],
                                                                                simpleTestCase "Self-call (to update)" ecid $ \cid ->
                                                                                  call cid (inter_update cid defArgs)
                                                                                    >>= isRelay
                                                                                    >>= isReply
                                                                                    >>= is ("Hello " <> cid <> " this is " <> cid),
                                                                                simpleTestCase "Self-call (to query)" ecid $ \cid -> do
                                                                                  call cid (inter_query cid defArgs)
                                                                                    >>= isRelay
                                                                                    >>= isReply
                                                                                    >>= is ("Hello " <> cid <> " this is " <> cid),
                                                                                simpleTestCase "update commits" ecid $ \cid -> do
                                                                                  do
                                                                                    call cid $
                                                                                      setGlobal "FOO"
                                                                                        >>> inter_update cid defArgs {other_side = setGlobal "BAR" >>> reply}
                                                                                    >>= isRelay
                                                                                    >>= isReply
                                                                                    >>= is ""

                                                                                  query cid (replyData getGlobal) >>= is "BAR",
                                                                                simpleTestCase "query does not commit" ecid $ \cid -> do
                                                                                  do
                                                                                    call cid $
                                                                                      setGlobal "FOO"
                                                                                        >>> inter_query cid defArgs {other_side = setGlobal "BAR" >>> reply}
                                                                                    >>= isRelay
                                                                                    >>= isReply
                                                                                    >>= is ""

                                                                                  do query cid $ replyData getGlobal
                                                                                    >>= is "FOO",
                                                                                simpleTestCase "query no response" ecid $ \cid ->
                                                                                  do call cid $ inter_query cid defArgs {other_side = noop}
                                                                                    >>= isRelay
                                                                                    >>= isReject [5],
                                                                                simpleTestCase "query double reply" ecid $ \cid ->
                                                                                  do call cid $ inter_query cid defArgs {other_side = reply >>> reply}
                                                                                    >>= isRelay
                                                                                    >>= isReject [5],
                                                                                simpleTestCase "Reject code is 0 in reply" ecid $ \cid ->
                                                                                  do call cid $ inter_query cid defArgs {on_reply = replyData (i2b reject_code)}
                                                                                    >>= asWord32
                                                                                    >>= is 0,
                                                                                simpleTestCase "Second reply in callback" ecid $ \cid -> do
                                                                                  do
                                                                                    call cid $
                                                                                      setGlobal "FOO"
                                                                                        >>> replyData "First reply"
                                                                                        >>> inter_query
                                                                                          cid
                                                                                          defArgs
                                                                                            { on_reply = setGlobal "BAR" >>> replyData "Second reply",
                                                                                              on_reject = setGlobal "BAZ" >>> relayReject
                                                                                            }
                                                                                    >>= is "First reply"

                                                                                  -- now check that the callback trapped and did not actual change the global
                                                                                  -- to make this test reliable, stop and start the canister, this will
                                                                                  -- ensure all outstanding callbacks are handled
                                                                                  barrier [cid]

                                                                                  query cid (replyData getGlobal) >>= is "FOO",
                                                                                simpleTestCase "partial reply" ecid $ \cid ->
                                                                                  do
                                                                                    call cid $
                                                                                      replyDataAppend "FOO"
                                                                                        >>> inter_query cid defArgs {on_reply = replyDataAppend "BAR" >>> reply}
                                                                                    >>= is "BAR", -- check that the FOO is silently dropped
                                                                                simpleTestCase "cleanup not executed when reply callback does not trap" ecid $ \cid -> do
                                                                                  call_ cid $
                                                                                    inter_query
                                                                                      cid
                                                                                      defArgs
                                                                                        { on_reply = reply,
                                                                                          on_cleanup = Just (setGlobal "BAD")
                                                                                        }
                                                                                  query cid (replyData getGlobal) >>= is "",
                                                                                simpleTestCase "cleanup not executed when reject callback does not trap" ecid $ \cid -> do
                                                                                  call_ cid $
                                                                                    inter_query
                                                                                      cid
                                                                                      defArgs
                                                                                        { other_side = reject "meh",
                                                                                          on_reject = reply,
                                                                                          on_cleanup = Just (setGlobal "BAD")
                                                                                        }
                                                                                  query cid (replyData getGlobal) >>= is "",
                                                                                testGroup
                                                                                  "two callbacks"
                                                                                  [ simpleTestCase "reply after trap" ecid $ \cid ->
                                                                                      do
                                                                                        call cid $
                                                                                          inter_query cid defArgs {on_reply = trap "first callback traps"}
                                                                                            >>> inter_query cid defArgs {on_reply = replyData "good"}
                                                                                        >>= is "good",
                                                                                    simpleTestCase "trap after reply" ecid $ \cid ->
                                                                                      do
                                                                                        call cid $
                                                                                          inter_query cid defArgs {on_reply = replyData "good"}
                                                                                            >>> inter_query cid defArgs {on_reply = trap "second callback traps"}
                                                                                        >>= is "good",
                                                                                    simpleTestCase "both trap" ecid $ \cid ->
                                                                                      do
                                                                                        call' cid $
                                                                                          inter_query cid defArgs {on_reply = trap "first callback traps"}
                                                                                            >>> inter_query cid defArgs {on_reply = trap "second callback traps"}
                                                                                        >>= isReject [5]
                                                                                  ],
                                                                                simpleTestCase "Call to other canister (to update)" ecid $ \cid -> do
                                                                                  cid2 <- install ecid noop
                                                                                  do call cid $ inter_update cid2 defArgs
                                                                                    >>= isRelay
                                                                                    >>= isReply
                                                                                    >>= is ("Hello " <> cid <> " this is " <> cid2),
                                                                                simpleTestCase "Call to other canister (to query)" ecid $ \cid -> do
                                                                                  cid2 <- install ecid noop
                                                                                  do call cid $ inter_query cid2 defArgs
                                                                                    >>= isRelay
                                                                                    >>= isReply
                                                                                    >>= is ("Hello " <> cid <> " this is " <> cid2)
                                                                              ],
                                                                            testGroup "Delegation targets" $
                                                                              let callReq cid =
                                                                                    ( rec
                                                                                        [ "request_type" =: GText "call",
                                                                                          "sender" =: GBlob defaultUser,
                                                                                          "canister_id" =: GBlob cid,
                                                                                          "method_name" =: GText "update",
                                                                                          "arg" =: GBlob (run reply)
                                                                                        ],
                                                                                      rec
                                                                                        [ "request_type" =: GText "query",
                                                                                          "sender" =: GBlob defaultUser,
                                                                                          "canister_id" =: GBlob cid,
                                                                                          "method_name" =: GText "query",
                                                                                          "arg" =: GBlob (run reply)
                                                                                        ]
                                                                                    )

                                                                                  mgmtReq cid =
                                                                                    ( rec
                                                                                        [ "request_type" =: GText "call",
                                                                                          "sender" =: GBlob defaultUser,
                                                                                          "canister_id" =: GBlob "",
                                                                                          "method_name" =: GText "canister_status",
                                                                                          "arg" =: GBlob (Candid.encode (#canister_id .== Principal cid))
                                                                                        ],
                                                                                      rec
                                                                                        [ "request_type" =: GText "query",
                                                                                          "sender" =: GBlob defaultUser,
                                                                                          "canister_id" =: GBlob "",
                                                                                          "method_name" =: GText "canister_status",
                                                                                          "arg" =: GBlob (Candid.encode (#canister_id .== Principal cid))
                                                                                        ]
                                                                                    )

                                                                                  good cid call query dels = do
                                                                                    call <- addExpiry call
                                                                                    let rid = requestId call
                                                                                    -- sign request with delegations
                                                                                    delegationEnv defaultSK dels call >>= postCallCBOR cid >>= code2xx
                                                                                    -- wait for it
                                                                                    void $ awaitStatus (getRequestStatus' defaultUser cid rid) >>= isReply
                                                                                    -- also read status with delegation
                                                                                    sreq <-
                                                                                      addExpiry $
                                                                                        rec
                                                                                          [ "request_type" =: GText "read_state",
                                                                                            "sender" =: GBlob defaultUser,
                                                                                            "paths" =: GList [GList [GBlob "request_status", GBlob rid]]
                                                                                          ]
                                                                                    delegationEnv defaultSK dels sreq >>= postReadStateCBOR cid >>= void . code2xx
                                                                                    -- also make query call
                                                                                    query <- addExpiry query
                                                                                    let qrid = requestId query
                                                                                    delegationEnv defaultSK dels query >>= postQueryCBOR cid >>= code2xx

                                                                                  badSubmit cid req dels = do
                                                                                    req <- addExpiry req
                                                                                    -- sign request with delegations (should fail)
                                                                                    delegationEnv defaultSK dels req >>= postCallCBOR cid >>= code400

                                                                                  badRead cid req dels error_code = do
                                                                                    req <- addExpiry req
                                                                                    let rid = requestId req
                                                                                    -- submit with plain signature
                                                                                    envelope defaultSK req >>= postCallCBOR cid >>= code202
                                                                                    -- wait for it
                                                                                    void $ awaitStatus (getRequestStatus' defaultUser cid rid) >>= isReply
                                                                                    -- also read status with delegation
                                                                                    sreq <-
                                                                                      addExpiry $
                                                                                        rec
                                                                                          [ "request_type" =: GText "read_state",
                                                                                            "sender" =: GBlob defaultUser,
                                                                                            "paths" =: GList [GList [GBlob "request_status", GBlob rid]]
                                                                                          ]
                                                                                    delegationEnv defaultSK dels sreq >>= postReadStateCBOR cid >>= void . error_code

                                                                                  badQuery cid req dels = do
                                                                                    req <- addExpiry req
                                                                                    -- sign request with delegations (should fail)
                                                                                    delegationEnv defaultSK dels req >>= postQueryCBOR cid >>= code400

                                                                                  goodTestCase name mkReq mkDels =
                                                                                    testCase name $ let cid = store_canister_id in good cid (fst $ mkReq cid) (snd $ mkReq cid) (mkDels cid)

                                                                                  badTestCase name mkReq read_state_error_code mkDels =
                                                                                    testGroup
                                                                                      name
                                                                                      [ testCase "in submit" $ let cid = store_canister_id in badSubmit cid (fst $ mkReq cid) (mkDels cid),
                                                                                        testCase "in read_state" $ let cid = store_canister_id in badRead cid (fst $ mkReq cid) (mkDels cid) read_state_error_code,
                                                                                        testCase "in query" $ let cid = store_canister_id in badQuery cid (snd $ mkReq cid) (mkDels cid)
                                                                                      ]

                                                                                  withEd25519 = zip [createSecretKeyEd25519 (BS.singleton n) | n <- [0 ..]]
                                                                                  withWebAuthnECDSA = zip [createSecretKeyWebAuthnECDSA (BS.singleton n) | n <- [0 ..]]
                                                                                  withWebAuthnRSA = zip [createSecretKeyWebAuthnRSA (BS.singleton n) | n <- [0 ..]]
                                                                                  withSelfLoop = zip [createSecretKeyEd25519 (BS.singleton n) | n <- repeat 0]
                                                                                  withCycle = zip [createSecretKeyEd25519 (BS.singleton n) | n <- [y | _ <- [(0 :: Integer) ..], y <- [0, 1]]]
                                                                               in [ goodTestCase "one delegation, singleton target" callReq $ \cid ->
                                                                                      withEd25519 [Just [cid]],
                                                                                    badTestCase "one delegation, wrong singleton target" callReq code403 $ \_cid ->
                                                                                      withEd25519 [Just [doesn'tExist]],
                                                                                    goodTestCase "one delegation, two targets" callReq $ \cid ->
                                                                                      withEd25519 [Just [cid, doesn'tExist]],
                                                                                    goodTestCase "one delegation, many targets" callReq $ \cid ->
                                                                                      withEd25519 [Just (cid : map wordToId' [0 .. 998])],
                                                                                    badTestCase "one delegation, too many targets" callReq code400 $ \cid ->
                                                                                      withEd25519 [Just (cid : map wordToId' [0 .. 999])],
                                                                                    goodTestCase "two delegations, two targets, webauthn ECDSA" callReq $ \cid ->
                                                                                      withWebAuthnECDSA [Just [cid, doesn'tExist], Just [cid, doesn'tExist]],
                                                                                    goodTestCase "two delegations, two targets, webauthn RSA" callReq $ \cid ->
                                                                                      withWebAuthnRSA [Just [cid, doesn'tExist], Just [cid, doesn'tExist]],
                                                                                    goodTestCase "one delegation, redundant targets" callReq $ \cid ->
                                                                                      withEd25519 [Just [cid, cid, doesn'tExist]],
                                                                                    goodTestCase "two delegations, singletons" callReq $ \cid ->
                                                                                      withEd25519 [Just [cid], Just [cid]],
                                                                                    goodTestCase "two delegations, first restricted" callReq $ \cid ->
                                                                                      withEd25519 [Just [cid], Nothing],
                                                                                    goodTestCase "two delegations, second restricted" callReq $ \cid ->
                                                                                      withEd25519 [Nothing, Just [cid]],
                                                                                    badTestCase "two delegations, empty intersection" callReq code403 $ \cid ->
                                                                                      withEd25519 [Just [cid], Just [doesn'tExist]],
                                                                                    badTestCase "two delegations, first empty target set" callReq code403 $ \cid ->
                                                                                      withEd25519 [Just [], Just [cid]],
                                                                                    badTestCase "two delegations, second empty target set" callReq code403 $ \cid ->
                                                                                      withEd25519 [Just [cid], Just []],
                                                                                    goodTestCase "20 delegations" callReq $ \cid ->
                                                                                      withEd25519 $ take 20 $ repeat $ Just [cid],
                                                                                    badTestCase "too many delegations" callReq code400 $ \cid ->
                                                                                      withEd25519 $ take 21 $ repeat $ Just [cid],
                                                                                    badTestCase "self-loop in delegations" callReq code400 $ \cid ->
                                                                                      withSelfLoop [Just [cid], Just [cid]],
                                                                                    badTestCase "cycle in delegations" callReq code400 $ \cid ->
                                                                                      withCycle [Just [cid], Just [cid], Just [cid]],
                                                                                    goodTestCase "management canister: correct target" mgmtReq $ \_cid ->
                                                                                      withEd25519 [Just [""]],
                                                                                    badTestCase "management canister: empty target set" mgmtReq code403 $ \_cid ->
                                                                                      withEd25519 [Just []],
                                                                                    badTestCase "management canister: bogus target" mgmtReq code403 $ \_cid ->
                                                                                      withEd25519 [Just [doesn'tExist]],
                                                                                    badTestCase "management canister: bogus target (using target canister)" mgmtReq code403 $ \cid ->
                                                                                      withEd25519 [Just [cid]]
                                                                                  ],
                                                                            testGroup "Authentication schemes" $
                                                                              let ed25519SK2 = createSecretKeyEd25519 "more keys"
                                                                                  ed25519SK3 = createSecretKeyEd25519 "yet more keys"
                                                                                  ed25519SK4 = createSecretKeyEd25519 "even more keys"
                                                                                  delEnv sks = delegationEnv otherSK (map (,Nothing) sks) -- no targets in these tests
                                                                               in flip
                                                                                    foldMap
                                                                                    [ ("Ed25519", otherUser, envelope otherSK),
                                                                                      ("ECDSA", ecdsaUser, envelope ecdsaSK),
                                                                                      ("secp256k1", secp256k1User, envelope secp256k1SK),
                                                                                      ("WebAuthn ECDSA", webAuthnECDSAUser, envelope webAuthnECDSASK),
                                                                                      ("WebAuthn RSA", webAuthnRSAUser, envelope webAuthnRSASK),
                                                                                      ("empty delegations", otherUser, delEnv []),
                                                                                      ("three delegations", otherUser, delEnv [ed25519SK2, ed25519SK3]),
                                                                                      ("four delegations", otherUser, delEnv [ed25519SK2, ed25519SK3, ed25519SK4]),
                                                                                      ("mixed delegations", otherUser, delEnv [defaultSK, webAuthnRSASK, ecdsaSK, secp256k1SK])
                                                                                    ]
                                                                                    $ \(name, user, env) ->
                                                                                      [ testCase (name ++ " in query") $ do
                                                                                          let cid = store_canister_id
                                                                                          let cbor =
                                                                                                rec
                                                                                                  [ "request_type" =: GText "query",
                                                                                                    "sender" =: GBlob user,
                                                                                                    "canister_id" =: GBlob cid,
                                                                                                    "method_name" =: GText "query",
                                                                                                    "arg" =: GBlob (run reply)
                                                                                                  ]
                                                                                          req <- addExpiry cbor
                                                                                          signed_req <- env req
                                                                                          postQueryCBOR cid signed_req >>= okCBOR >>= queryResponse >>= \res -> isQueryReply ecid (requestId req, res) >>= is "",
                                                                                        testCase (name ++ " in update") $ do
                                                                                          let cid = store_canister_id
                                                                                          req <-
                                                                                            addExpiry $
                                                                                              rec
                                                                                                [ "request_type" =: GText "call",
                                                                                                  "sender" =: GBlob user,
                                                                                                  "canister_id" =: GBlob cid,
                                                                                                  "method_name" =: GText "update",
                                                                                                  "arg" =: GBlob (run reply)
                                                                                                ]
                                                                                          signed_req <- env req
                                                                                          postCallCBOR cid signed_req >>= code2xx

                                                                                          awaitStatus (getRequestStatus' user cid (requestId req)) >>= isReply >>= is ""
                                                                                      ],
                                                                            testGroup "signature checking" $
                                                                              [ ("with bad signature", return . badEnvelope, id),
                                                                                ("with wrong key", envelope otherSK, id),
                                                                                ("with empty domain separator", noDomainSepEnv defaultSK, id),
                                                                                ("with no expiry", envelope defaultSK, noExpiryEnv),
                                                                                ("with expiry in the past", envelope defaultSK, pastExpiryEnv),
                                                                                ("with expiry in the future", envelope defaultSK, futureExpiryEnv)
                                                                              ]
                                                                                <&> \(name, env, mod_req) ->
                                                                                  testGroup
                                                                                    name
                                                                                    [ testCase "in query" $ do
                                                                                        let cid = store_canister_id
                                                                                        let good_cbor =
                                                                                              rec
                                                                                                [ "request_type" =: GText "query",
                                                                                                  "sender" =: GBlob defaultUser,
                                                                                                  "canister_id" =: GBlob cid,
                                                                                                  "method_name" =: GText "query",
                                                                                                  "arg" =: GBlob (run ((debugPrint $ i2b $ int 0) >>> reply))
                                                                                                ]
                                                                                        let bad_cbor =
                                                                                              rec
                                                                                                [ "request_type" =: GText "query",
                                                                                                  "sender" =: GBlob defaultUser,
                                                                                                  "canister_id" =: GBlob cid,
                                                                                                  "method_name" =: GText "query",
                                                                                                  "arg" =: GBlob (run ((debugPrint $ i2b $ int 1) >>> reply))
                                                                                                ]
                                                                                        good_req <- addNonce >=> addExpiry $ good_cbor
                                                                                        bad_req <- addNonce >=> addExpiry $ bad_cbor
                                                                                        (rid, res) <- queryCBOR cid good_req
                                                                                        res <- queryResponse res
                                                                                        isQueryReply ecid (rid, res) >>= is ""
                                                                                        env (mod_req bad_req) >>= postQueryCBOR cid >>= code4xx,
                                                                                      testCase "in empty read state request" $ do
                                                                                        let cid = store_canister_id
                                                                                        good_req <- addNonce >=> addExpiry $ readStateEmpty
                                                                                        envelope defaultSK good_req >>= postReadStateCBOR cid >>= code2xx
                                                                                        env (mod_req good_req) >>= postReadStateCBOR cid >>= code4xx,
                                                                                      testCase "in call" $ do
                                                                                        let cid = store_canister_id
                                                                                        let good_cbor =
                                                                                              rec
                                                                                                [ "request_type" =: GText "call",
                                                                                                  "sender" =: GBlob defaultUser,
                                                                                                  "canister_id" =: GBlob cid,
                                                                                                  "method_name" =: GText "query",
                                                                                                  "arg" =: GBlob (run ((debugPrint $ i2b $ int 0) >>> reply))
                                                                                                ]
                                                                                        let bad_cbor =
                                                                                              rec
                                                                                                [ "request_type" =: GText "call",
                                                                                                  "sender" =: GBlob defaultUser,
                                                                                                  "canister_id" =: GBlob cid,
                                                                                                  "method_name" =: GText "query",
                                                                                                  "arg" =: GBlob (run ((debugPrint $ i2b $ int 1) >>> reply))
                                                                                                ]
                                                                                        good_req <- addNonce >=> addExpiry $ good_cbor
                                                                                        bad_req <- addNonce >=> addExpiry $ bad_cbor
                                                                                        let req = mod_req bad_req
                                                                                        env req >>= postCallCBOR cid >>= code4xx

                                                                                        -- check that with a valid signature, this would have worked
                                                                                        awaitCall cid good_req >>= isReply >>= is ""

                                                                                        -- Also check that the request was not created
                                                                                        getRequestStatus defaultUser cid (requestId req) >>= is UnknownStatus
                                                                                    ],
                                                                            testGroup "Canister signatures" $
                                                                              let genId cid seed =
                                                                                    DER.encode DER.CanisterSig $ CanisterSig.genPublicKey (EntityId cid) seed

                                                                                  genSig cid seed msg = do
                                                                                    -- Create the tree
                                                                                    let tree =
                                                                                          construct $
                                                                                            SubTrees $
                                                                                              M.singleton "sig" $
                                                                                                SubTrees $
                                                                                                  M.singleton (sha256 seed) $
                                                                                                    SubTrees $
                                                                                                      M.singleton (sha256 msg) $
                                                                                                        Value ""
                                                                                    -- Store it as certified data
                                                                                    call_ cid (setCertifiedData (bytes (reconstruct tree)) >>> reply)
                                                                                    -- Get certificate
                                                                                    cert <- query cid (replyData getCertificate) >>= decodeCert'
                                                                                    -- double check it certifies
                                                                                    validateStateCert cid cert
                                                                                    certValue cert ["canister", cid, "certified_data"] >>= is (reconstruct tree)

                                                                                    return $ CanisterSig.genSig cert tree

                                                                                  exampleQuery cid userKey =
                                                                                    addExpiry $
                                                                                      rec
                                                                                        [ "request_type" =: GText "query",
                                                                                          "sender" =: GBlob (mkSelfAuthenticatingId userKey),
                                                                                          "canister_id" =: GBlob cid,
                                                                                          "method_name" =: GText "query",
                                                                                          "arg" =: GBlob (run (replyData "It works!"))
                                                                                        ]
                                                                                  simpleEnv userKey sig req delegations =
                                                                                    rec $
                                                                                      [ "sender_pubkey" =: GBlob userKey,
                                                                                        "sender_sig" =: GBlob sig,
                                                                                        "content" =: req
                                                                                      ]
                                                                                        ++ ["sender_delegation" =: GList delegations | not (null delegations)]
                                                                               in [ simpleTestCase "direct signature" ecid $ \cid -> do
                                                                                      let userKey = genId cid "Hello!"
                                                                                      req <- exampleQuery cid userKey
                                                                                      sig <- genSig cid "Hello!" $ "\x0Aic-request" <> requestId req
                                                                                      let env = simpleEnv userKey sig req []
                                                                                      postQueryCBOR cid env >>= okCBOR >>= queryResponse >>= \res -> isQueryReply ecid (requestId req, res) >>= is "It works!",
                                                                                    simpleTestCase "direct signature (empty seed)" ecid $ \cid -> do
                                                                                      let userKey = genId cid ""
                                                                                      req <- exampleQuery cid userKey
                                                                                      sig <- genSig cid "" $ "\x0Aic-request" <> requestId req
                                                                                      let env = simpleEnv userKey sig req []
                                                                                      postQueryCBOR cid env >>= okCBOR >>= queryResponse >>= \res -> isQueryReply ecid (requestId req, res) >>= is "It works!",
                                                                                    simpleTestCase "direct signature (wrong seed)" ecid $ \cid -> do
                                                                                      let userKey = genId cid "Hello"
                                                                                      req <- exampleQuery cid userKey
                                                                                      sig <- genSig cid "Hullo" $ "\x0Aic-request" <> requestId req
                                                                                      let env = simpleEnv userKey sig req []
                                                                                      postQueryCBOR cid env >>= code4xx,
                                                                                    simpleTestCase "direct signature (wrong cid)" ecid $ \cid -> do
                                                                                      let userKey = genId doesn'tExist "Hello"
                                                                                      req <- exampleQuery cid userKey
                                                                                      sig <- genSig cid "Hello" $ "\x0Aic-request" <> requestId req
                                                                                      let env = simpleEnv userKey sig req []
                                                                                      postQueryCBOR cid env >>= code4xx,
                                                                                    simpleTestCase "direct signature (wrong root key)" ecid $ \cid -> do
                                                                                      let seed = "Hello"
                                                                                      let userKey = genId cid seed
                                                                                      req <- exampleQuery cid userKey
                                                                                      let msg = "\x0Aic-request" <> requestId req
                                                                                      -- Create the tree
                                                                                      let tree =
                                                                                            construct $
                                                                                              SubTrees $
                                                                                                M.singleton "sig" $
                                                                                                  SubTrees $
                                                                                                    M.singleton (sha256 seed) $
                                                                                                      SubTrees $
                                                                                                        M.singleton (sha256 msg) $
                                                                                                          Value ""
                                                                                      -- Create a fake certificate
                                                                                      let cert_tree =
                                                                                            construct $
                                                                                              SubTrees $
                                                                                                M.singleton "canister" $
                                                                                                  SubTrees $
                                                                                                    M.singleton cid $
                                                                                                      SubTrees $
                                                                                                        M.singleton "certified_data" $
                                                                                                          Value (reconstruct tree)
                                                                                      let fake_root_key = createSecretKeyBLS "not the root key"
                                                                                      cert_sig <- sign "ic-state-root" fake_root_key (reconstruct cert_tree)
                                                                                      let cert = Certificate {cert_tree, cert_sig, cert_delegation = Nothing}
                                                                                      let sig = CanisterSig.genSig cert tree
                                                                                      let env = simpleEnv userKey sig req []
                                                                                      postQueryCBOR cid env >>= code4xx,
                                                                                    simpleTestCase "delegation to Ed25519" ecid $ \cid -> do
                                                                                      let userKey = genId cid "Hello!"

                                                                                      t <- getPOSIXTime
                                                                                      let expiry = round ((t + 3 * 60) * 1000_000_000)
                                                                                      let delegation =
                                                                                            rec
                                                                                              [ "pubkey" =: GBlob (toPublicKey otherSK),
                                                                                                "expiration" =: GNat expiry
                                                                                              ]
                                                                                      sig <- genSig cid "Hello!" $ "\x1Aic-request-auth-delegation" <> requestId delegation
                                                                                      let signed_delegation = rec ["delegation" =: delegation, "signature" =: GBlob sig]

                                                                                      req <- exampleQuery cid userKey
                                                                                      sig <- sign "ic-request" otherSK (requestId req)
                                                                                      let env = simpleEnv userKey sig req [signed_delegation]
                                                                                      postQueryCBOR cid env >>= okCBOR >>= queryResponse >>= \res -> isQueryReply ecid (requestId req, res) >>= is "It works!",
                                                                                    simpleTestCase "delegation from Ed25519" ecid $ \cid -> do
                                                                                      let userKey = genId cid "Hello!"

                                                                                      t <- getPOSIXTime
                                                                                      let expiry = round ((t + 3 * 60) * 1000_000_000)
                                                                                      let delegation =
                                                                                            rec
                                                                                              [ "pubkey" =: GBlob userKey,
                                                                                                "expiration" =: GNat expiry
                                                                                              ]
                                                                                      sig <- sign "ic-request-auth-delegation" otherSK (requestId delegation)
                                                                                      let signed_delegation = rec ["delegation" =: delegation, "signature" =: GBlob sig]

                                                                                      req <-
                                                                                        addExpiry $
                                                                                          rec
                                                                                            [ "request_type" =: GText "query",
                                                                                              "sender" =: GBlob otherUser,
                                                                                              "canister_id" =: GBlob cid,
                                                                                              "method_name" =: GText "query",
                                                                                              "arg" =: GBlob (run (replyData "It works!"))
                                                                                            ]
                                                                                      sig <- genSig cid "Hello!" $ "\x0Aic-request" <> requestId req
                                                                                      let env = simpleEnv (toPublicKey otherSK) sig req [signed_delegation]
                                                                                      postQueryCBOR cid env >>= okCBOR >>= queryResponse >>= \res -> isQueryReply ecid (requestId req, res) >>= is "It works!"
                                                                                  ]
                                                                          ]
                                                                      ]
