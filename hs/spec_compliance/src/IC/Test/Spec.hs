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
import IC.Test.Spec.CanisterHistory
import IC.Test.Spec.CanisterVersion
import IC.Test.Spec.HTTP
import IC.Test.Spec.Timer
import IC.Test.Spec.Utils
import IC.Test.Universal
import IC.Types (EntityId (..), SubnetType (..), TestSubnetConfig)
import Numeric.Natural
import Test.Tasty
import Test.Tasty.HUnit

-- * The test suite (see below for helper functions)

icTests :: TestSubnetConfig -> TestSubnetConfig -> AgentConfig -> TestTree
icTests my_sub other_sub =
  let (my_subnet_id_as_entity, my_type, my_nodes, my_ranges, _) = my_sub
   in let ((ecid_as_word64, last_canister_id_as_word64) : _) = my_ranges
       in let (_, last_canister_id_as_word64) = last my_ranges
           in let (other_subnet_id_as_entity, _, other_nodes, ((other_ecid_as_word64, _) : _), _) = other_sub
               in let my_subnet_id = rawEntityId my_subnet_id_as_entity
                   in let other_subnet_id = rawEntityId other_subnet_id_as_entity
                       in let my_is_root = isRootTestSubnet my_sub
                           in let ecid = rawEntityId $ wordToId ecid_as_word64
                               in let other_ecid = rawEntityId $ wordToId other_ecid_as_word64
                                   in let specified_canister_id = rawEntityId $ wordToId last_canister_id_as_word64
                                       in let unused_canister_id = rawEntityId $ wordToId (last_canister_id_as_word64 - 1)
                                           in let initial_cycles = case my_type of
                                                    System -> 0
                                                    _ -> (2 ^ (60 :: Int))
                                               in withAgentConfig $
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
                                                                            let ecid = rawEntityId $ wordToId n
                                                                            let specified_id = entityIdToPrincipal $ EntityId ecid
                                                                            cid <- ic_provisional_create ic00 ecid (Just specified_id) (Just cycles) Nothing
                                                                            assertBool "canister was not created at its specified ID" $ ecid == cid
                                                                            installAt cid prog
                                                                            return cid
                                                                       in [ testCase "NNS canisters" $ do
                                                                              registry <- install_with_cycles_at_id 0 initial_cycles noop
                                                                              governance <- install_with_cycles_at_id 1 initial_cycles noop
                                                                              ledger <- install_with_cycles_at_id 2 initial_cycles noop
                                                                              root <- install_with_cycles_at_id 3 initial_cycles noop
                                                                              cmc <- install_with_cycles_at_id 4 initial_cycles noop
                                                                              lifeline <- install_with_cycles_at_id 5 initial_cycles noop
                                                                              genesis <- install_with_cycles_at_id 6 initial_cycles noop
                                                                              sns <- install_with_cycles_at_id 7 initial_cycles noop
                                                                              identity <- install_with_cycles_at_id 8 initial_cycles noop
                                                                              ui <- install_with_cycles_at_id 9 initial_cycles noop

                                                                              cid <- install_with_cycles_at_id 10 initial_cycles noop

                                                                              let mint = replyData . i64tob . mintCycles . int64
                                                                              call' root (mint 0) >>= isReject [5]

                                                                              let transfer_args cycles =
                                                                                    defArgs
                                                                                      { other_side = (replyData $ i64tob $ acceptCycles $ int64 cycles),
                                                                                        cycles = cycles
                                                                                      }
                                                                              let mint_and_transfer cycles =
                                                                                    ( (ignore $ mintCycles $ int64 cycles)
                                                                                        >>> (inter_update cid (transfer_args cycles))
                                                                                    )

                                                                              when (isRootTestSubnet my_sub) $ do
                                                                                let transfer_cycles = (2 ^ (61 :: Int))
                                                                                call cmc (mint_and_transfer transfer_cycles) >>= isRelay >>= isReply >>= asWord64 >>= is transfer_cycles
                                                                          ]
                                                                            ++ [ after AllFinish "($0 ~ /NNS canisters/)" $
                                                                                   testGroup
                                                                                     "regular canisters"
                                                                                     [ simpleTestCase "create and install" ecid $ \_ ->
                                                                                         return (),
                                                                                       testCase "create_canister necessary" $
                                                                                         ic_install'' defaultUser (enum #install) doesn'tExist trivialWasmModule ""
                                                                                           >>= isErrOrReject [3, 5],
                                                                                       testGroup
                                                                                         "calls to a subnet ID"
                                                                                         [ let ic_install_subnet'' user subnet_id canister_id wasm_module arg =
                                                                                                 callICWithSubnet'' subnet_id user canister_id #install_code tmp
                                                                                                 where
                                                                                                   tmp :: InstallCodeArgs
                                                                                                   tmp =
                                                                                                     empty
                                                                                                       .+ #mode
                                                                                                       .== enum #install
                                                                                                       .+ #canister_id
                                                                                                       .== Principal canister_id
                                                                                                       .+ #wasm_module
                                                                                                       .== wasm_module
                                                                                                       .+ #arg
                                                                                                       .== arg
                                                                                                       .+ #sender_canister_version
                                                                                                       .== Nothing
                                                                                            in testCase "as user" $ do
                                                                                                 cid <- create ecid
                                                                                                 ic_install_subnet'' defaultUser my_subnet_id cid trivialWasmModule "" >>= isErrOrReject []
                                                                                                 ic_install_subnet'' defaultUser other_subnet_id cid trivialWasmModule "" >>= isErrOrReject [],
                                                                                           testCase "as canister to own subnet" $ do
                                                                                             cid <- install ecid noop
                                                                                             if my_is_root
                                                                                               then test_subnet_msg my_sub my_subnet_id other_subnet_id cid
                                                                                               else test_subnet_msg' my_sub my_subnet_id cid,
                                                                                           testCase "canister http outcalls to own subnet" $ do
                                                                                             cid <- install ecid noop
                                                                                             if my_is_root
                                                                                               then test_subnet_msg_canister_http my_sub my_subnet_id cid
                                                                                               else test_subnet_msg_canister_http' my_sub my_subnet_id cid,
                                                                                           testCase "as canister to other subnet" $ do
                                                                                             cid <- install ecid noop
                                                                                             if my_is_root
                                                                                               then test_subnet_msg other_sub other_subnet_id my_subnet_id cid
                                                                                               else test_subnet_msg' other_sub other_subnet_id cid,
                                                                                           testCase "canister http outcalls to other subnet" $ do
                                                                                             cid <- install ecid noop
                                                                                             if my_is_root
                                                                                               then test_subnet_msg_canister_http other_sub other_subnet_id cid
                                                                                               else test_subnet_msg_canister_http' other_sub other_subnet_id cid
                                                                                         ],
                                                                                       testGroup
                                                                                         "provisional_create_canister_with_cycles"
                                                                                         [ testCase "specified_id" $ do
                                                                                             let specified_id = entityIdToPrincipal $ EntityId specified_canister_id
                                                                                             ic_provisional_create ic00 ecid (Just specified_id) (Just (2 ^ (60 :: Int))) Nothing >>= is specified_canister_id,
                                                                                           simpleTestCase "specified_id already taken" ecid $ \cid -> do
                                                                                             let specified_id = entityIdToPrincipal $ EntityId cid
                                                                                             ic_provisional_create' ic00 ecid (Just specified_id) (Just (2 ^ (60 :: Int))) Nothing >>= isReject [5],
                                                                                           testCase "specified_id does not belong to the subnet's canister ranges" $ do
                                                                                             let specified_id = entityIdToPrincipal $ EntityId doesn'tExist
                                                                                             ic_provisional_create' ic00 ecid (Just specified_id) (Just (2 ^ (60 :: Int))) Nothing >>= isReject [4]
                                                                                         ],
                                                                                       let inst name = do
                                                                                             cid <- create ecid
                                                                                             wasm <- getTestWasm (name ++ ".wasm")
                                                                                             ic_install ic00 (enum #install) cid wasm ""
                                                                                             return cid
                                                                                        in let good name = testCase ("valid: " ++ name) $ void $ inst name
                                                                                            in let bad name = testCase ("invalid: " ++ name) $ do
                                                                                                     cid <- create ecid
                                                                                                     wasm <- getTestWasm (name ++ ".wasm")
                                                                                                     ic_install' ic00 (enum #install) cid wasm "" >>= isReject [5]
                                                                                                in let read cid m =
                                                                                                         ( awaitCall cid $
                                                                                                             rec
                                                                                                               [ "request_type" =: GText "call",
                                                                                                                 "sender" =: GBlob defaultUser,
                                                                                                                 "canister_id" =: GBlob cid,
                                                                                                                 "method_name" =: GText m,
                                                                                                                 "arg" =: GBlob ""
                                                                                                               ]
                                                                                                         )
                                                                                                           >>= isReply
                                                                                                           >>= asWord32
                                                                                                    in testGroup "WebAssembly module validation" $
                                                                                                         map good ["empty_custom_section_name", "large_custom_sections", "long_exported_function_names", "many_custom_sections", "many_exports", "many_functions", "many_globals", "valid_import"]
                                                                                                           ++ map bad ["duplicate_custom_section", "invalid_canister_composite_query_cq_reta", "invalid_canister_composite_query_cq_retb", "invalid_canister_export", "invalid_canister_global_timer_reta", "invalid_canister_global_timer_retb", "invalid_canister_heartbeat_reta", "invalid_canister_heartbeat_retb", "invalid_canister_init_reta", "invalid_canister_init_retb", "invalid_canister_inspect_message_reta", "invalid_canister_inspect_message_retb", "invalid_canister_post_upgrade_reta", "invalid_canister_post_upgrade_retb", "invalid_canister_pre_upgrade_reta", "invalid_canister_pre_upgrade_retb", "invalid_canister_query_que_reta", "invalid_canister_query_que_retb", "invalid_canister_update_upd_reta", "invalid_canister_update_upd_retb", "invalid_custom_section", "invalid_empty_custom_section_name", "invalid_empty_query_name", "invalid_import", "name_clash_query_composite_query", "name_clash_update_composite_query", "name_clash_update_query", "too_large_custom_sections", "too_long_exported_function_names", "too_many_custom_sections", "too_many_exports", "too_many_functions", "too_many_globals"]
                                                                                                           ++ [ testCase "(start) function" $ do
                                                                                                                  cid <- inst "start"
                                                                                                                  ctr <- read cid "read"
                                                                                                                  ctr @?= 4, -- (start) function was executed
                                                                                                                testCase "no (start) function" $ do
                                                                                                                  cid <- inst "no_start"
                                                                                                                  ctr <- read cid "read"
                                                                                                                  ctr @?= 0, -- no (start) function was executed
                                                                                                                testCase "empty query name" $ do
                                                                                                                  cid <- inst "empty_query_name"
                                                                                                                  void $ read cid "",
                                                                                                                testCase "query name with spaces" $ do
                                                                                                                  cid <- inst "query_name_with_spaces"
                                                                                                                  void $ read cid "name with spaces",
                                                                                                                testCase "empty custom section name" $ do
                                                                                                                  cid <- inst "empty_custom_section_name"
                                                                                                                  cert <- getStateCert otherUser cid [["canister", cid, "metadata", ""]]
                                                                                                                  lookupPath (cert_tree cert) ["canister", cid, "metadata", ""] @?= Found "a",
                                                                                                                testCase "custom section name with spaces" $ do
                                                                                                                  cid <- inst "custom_section_name_with_spaces"
                                                                                                                  cert <- getStateCert otherUser cid [["canister", cid, "metadata", "name with spaces"]]
                                                                                                                  lookupPath (cert_tree cert) ["canister", cid, "metadata", "name with spaces"] @?= Found "a"
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
                                                                                         universal_wasm <- getTestWasm "universal_canister.wasm.gz"
                                                                                         can_id <- ic_provisional_create (ic00via cid) ecid Nothing Nothing Nothing
                                                                                         ic_install (ic00via cid) (enum #install) can_id universal_wasm ""
                                                                                         do call can_id $ replyData "Hi"
                                                                                           >>= is "Hi",
                                                                                       simpleTestCase "randomness" ecid $ \cid -> do
                                                                                         r1 <- ic_raw_rand (ic00via cid) ecid
                                                                                         r2 <- ic_raw_rand (ic00via cid) ecid
                                                                                         BS.length r1 @?= 32
                                                                                         BS.length r2 @?= 32
                                                                                         assertBool "random blobs are different" $ r1 /= r2,
                                                                                       testGroup "canister http outcalls" $ canister_http_calls my_sub httpbin_proto,
                                                                                       testGroup
                                                                                         "large calls"
                                                                                         $ let arg n = BS.pack $ take n $ repeat 0
                                                                                            in let prog n = ignore (stableGrow (int 666)) >>> stableWrite (int 0) (bytes $ arg n) >>> replyData "ok"
                                                                                                in let callRec cid n =
                                                                                                         rec
                                                                                                           [ "request_type" =: GText "call",
                                                                                                             "canister_id" =: GBlob cid,
                                                                                                             "sender" =: GBlob anonymousUser,
                                                                                                             "method_name" =: GText "update",
                                                                                                             "arg" =: GBlob (run $ prog n)
                                                                                                           ]
                                                                                                    in let queryRec cid n =
                                                                                                             rec
                                                                                                               [ "request_type" =: GText "query",
                                                                                                                 "canister_id" =: GBlob cid,
                                                                                                                 "sender" =: GBlob anonymousUser,
                                                                                                                 "method_name" =: GText "query",
                                                                                                                 "arg" =: GBlob (run $ prog n)
                                                                                                               ]
                                                                                                        in [ simpleTestCase "Large update call" ecid $ \cid ->
                                                                                                               do
                                                                                                                 let size = case my_type of
                                                                                                                       System -> 3600000 -- registry setting for system subnets: 3.5MiB
                                                                                                                       _ -> 2000000 -- registry setting for app subnets: 2MiB
                                                                                                                 addNonceExpiryEnv (callRec cid size)
                                                                                                                   >>= postCallCBOR cid
                                                                                                                   >>= code202
                                                                                                                 call cid (prog size) >>= is "ok",
                                                                                                             simpleTestCase "Too large update call" ecid $ \cid ->
                                                                                                               do
                                                                                                                 let size = case my_type of
                                                                                                                       System -> 3700000
                                                                                                                       _ -> 2100000
                                                                                                                 addNonceExpiryEnv (callRec cid size)
                                                                                                                 >>= postCallCBOR cid
                                                                                                                 >>= code4xx,
                                                                                                             simpleTestCase "Large query call" ecid $ \cid -> do
                                                                                                               let size = 4100000 -- BN limits all requests to 4MiB
                                                                                                               addNonceExpiryEnv (queryRec cid size)
                                                                                                                 >>= postQueryCBOR cid
                                                                                                                 >>= code2xx
                                                                                                               query cid (prog size) >>= is "ok",
                                                                                                             simpleTestCase "Too large query call" ecid $ \cid ->
                                                                                                               addNonceExpiryEnv (queryRec cid 4200000)
                                                                                                                 >>= postQueryCBOR cid
                                                                                                                 >>= code4xx
                                                                                                           ],
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
                                                                                                   universal_wasm <- getTestWasm "universal_canister.wasm.gz"
                                                                                                   ic_install ic00 (enum #install) cid universal_wasm ""

                                                                                                   cs <- ic_canister_status (ic00via cid) cid
                                                                                                   assertBool "canister should not control itself in this test" $ not $ elem cid controllers
                                                                                                   Vec.toList (cs .! #settings .! #controllers) `isSet` map Principal controllers,
                                                                                                 testCase "Changing controllers" $ do
                                                                                                   let controllers = [defaultUser, otherUser]
                                                                                                   cid <- ic_provisional_create ic00 ecid Nothing Nothing Nothing
                                                                                                   ic_set_controllers ic00 cid controllers
                                                                                                   universal_wasm <- getTestWasm "universal_canister.wasm.gz"
                                                                                                   ic_install ic00 (enum #install) cid universal_wasm ""

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
                                                                                                   universal_wasm <- getTestWasm "universal_canister.wasm.gz"
                                                                                                   ic_install (ic00via cid) (enum #install) cid2 universal_wasm ""

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
                                                                                                   ic_create_with_controllers' (ic00viaWithCycles cid 20_000_000_000_000) ecid (replicate 11 cid) >>= isReject [3, 5]
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
                                                                                                                .== Just (2 ^ 48 + 1)
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
                                                                                         "anonymous user"
                                                                                         [ simpleTestCase "update, sender absent fails" ecid $ \cid ->
                                                                                             do
                                                                                               envelopeFor anonymousUser $
                                                                                                 rec
                                                                                                   [ "request_type" =: GText "call",
                                                                                                     "canister_id" =: GBlob cid,
                                                                                                     "method_name" =: GText "update",
                                                                                                     "arg" =: GBlob (run (replyData caller))
                                                                                                   ]
                                                                                               >>= postCallCBOR cid
                                                                                               >>= code4xx,
                                                                                           simpleTestCase "query, sender absent fails" ecid $ \cid ->
                                                                                             do
                                                                                               envelopeFor anonymousUser $
                                                                                                 rec
                                                                                                   [ "request_type" =: GText "query",
                                                                                                     "canister_id" =: GBlob cid,
                                                                                                     "method_name" =: GText "query",
                                                                                                     "arg" =: GBlob (run (replyData caller))
                                                                                                   ]
                                                                                               >>= postQueryCBOR cid
                                                                                               >>= code4xx,
                                                                                           simpleTestCase "update, sender explicit" ecid $ \cid ->
                                                                                             do
                                                                                               awaitCall cid $
                                                                                                 rec
                                                                                                   [ "request_type" =: GText "call",
                                                                                                     "canister_id" =: GBlob cid,
                                                                                                     "sender" =: GBlob anonymousUser,
                                                                                                     "method_name" =: GText "update",
                                                                                                     "arg" =: GBlob (run (replyData caller))
                                                                                                   ]
                                                                                               >>= isReply
                                                                                               >>= is anonymousUser,
                                                                                           simpleTestCase "query, sender explicit" ecid $ \cid ->
                                                                                             do
                                                                                               let cbor =
                                                                                                     rec
                                                                                                       [ "request_type" =: GText "query",
                                                                                                         "canister_id" =: GBlob cid,
                                                                                                         "sender" =: GBlob anonymousUser,
                                                                                                         "method_name" =: GText "query",
                                                                                                         "arg" =: GBlob (run (replyData caller))
                                                                                                       ]
                                                                                               (rid, res) <- queryCBOR cid cbor
                                                                                               res <- queryResponse res
                                                                                               isQueryReply ecid (rid, res) >>= is anonymousUser
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
                                                                                       simpleTestCase "self" ecid $ \cid ->
                                                                                         query cid (replyData self) >>= is cid,
                                                                                       testGroup
                                                                                         "wrong url path"
                                                                                         [ simpleTestCase "call request to query" ecid $ \cid -> do
                                                                                             let req =
                                                                                                   rec
                                                                                                     [ "request_type" =: GText "call",
                                                                                                       "sender" =: GBlob defaultUser,
                                                                                                       "canister_id" =: GBlob cid,
                                                                                                       "method_name" =: GText "update",
                                                                                                       "arg" =: GBlob (run reply)
                                                                                                     ]
                                                                                             addNonceExpiryEnv req >>= postQueryCBOR cid >>= code4xx,
                                                                                           simpleTestCase "query request to call" ecid $ \cid -> do
                                                                                             let req =
                                                                                                   rec
                                                                                                     [ "request_type" =: GText "query",
                                                                                                       "sender" =: GBlob defaultUser,
                                                                                                       "canister_id" =: GBlob cid,
                                                                                                       "method_name" =: GText "query",
                                                                                                       "arg" =: GBlob (run reply)
                                                                                                     ]
                                                                                             addNonceExpiryEnv req >>= postCallCBOR cid >>= code4xx,
                                                                                           simpleTestCase "query request to read_state" ecid $ \cid -> do
                                                                                             let req =
                                                                                                   rec
                                                                                                     [ "request_type" =: GText "query",
                                                                                                       "sender" =: GBlob defaultUser,
                                                                                                       "canister_id" =: GBlob cid,
                                                                                                       "method_name" =: GText "query",
                                                                                                       "arg" =: GBlob (run reply)
                                                                                                     ]
                                                                                             addNonceExpiryEnv req >>= postReadStateCBOR cid >>= code4xx,
                                                                                           simpleTestCase "read_state request to query" ecid $ \cid -> do
                                                                                             addNonceExpiryEnv readStateEmpty >>= postQueryCBOR cid >>= code4xx
                                                                                         ],
                                                                                       testGroup
                                                                                         "wrong effective canister id"
                                                                                         [ simpleTestCase "in call" ecid $ \cid1 -> do
                                                                                             cid2 <- create ecid
                                                                                             let req =
                                                                                                   rec
                                                                                                     [ "request_type" =: GText "call",
                                                                                                       "sender" =: GBlob defaultUser,
                                                                                                       "canister_id" =: GBlob cid1,
                                                                                                       "method_name" =: GText "update",
                                                                                                       "arg" =: GBlob (run reply)
                                                                                                     ]
                                                                                             addNonceExpiryEnv req >>= postCallCBOR cid2 >>= code4xx,
                                                                                           simpleTestCase "in query" ecid $ \cid1 -> do
                                                                                             cid2 <- create ecid
                                                                                             let req =
                                                                                                   rec
                                                                                                     [ "request_type" =: GText "query",
                                                                                                       "sender" =: GBlob defaultUser,
                                                                                                       "canister_id" =: GBlob cid1,
                                                                                                       "method_name" =: GText "query",
                                                                                                       "arg" =: GBlob (run reply)
                                                                                                     ]
                                                                                             addNonceExpiryEnv req >>= postQueryCBOR cid2 >>= code4xx,
                                                                                           simpleTestCase "in read_state" ecid $ \cid -> do
                                                                                             cid2 <- install ecid noop
                                                                                             getStateCert' defaultUser cid2 [["canisters", cid, "controllers"]] >>= isErr4xx,
                                                                                           -- read_state tested in read_state group
                                                                                           --
                                                                                           simpleTestCase "in management call" ecid $ \cid1 -> do
                                                                                             cid2 <- create ecid
                                                                                             let req =
                                                                                                   rec
                                                                                                     [ "request_type" =: GText "call",
                                                                                                       "sender" =: GBlob defaultUser,
                                                                                                       "canister_id" =: GBlob "",
                                                                                                       "method_name" =: GText "canister_status",
                                                                                                       "arg" =: GBlob (Candid.encode (#canister_id .== Principal cid1))
                                                                                                     ]
                                                                                             addNonceExpiryEnv req >>= postCallCBOR cid2 >>= code4xx,
                                                                                           simpleTestCase "non-existing (and likely invalid)" ecid $ \cid1 -> do
                                                                                             let req =
                                                                                                   rec
                                                                                                     [ "request_type" =: GText "call",
                                                                                                       "sender" =: GBlob defaultUser,
                                                                                                       "canister_id" =: GBlob cid1,
                                                                                                       "method_name" =: GText "update",
                                                                                                       "arg" =: GBlob (run reply)
                                                                                                     ]
                                                                                             addNonceExpiryEnv req >>= postCallCBOR "foobar" >>= code4xx,
                                                                                           simpleTestCase "invalid textual representation" ecid $ \cid1 -> do
                                                                                             let req =
                                                                                                   rec
                                                                                                     [ "request_type" =: GText "call",
                                                                                                       "sender" =: GBlob defaultUser,
                                                                                                       "canister_id" =: GBlob cid1,
                                                                                                       "method_name" =: GText "update",
                                                                                                       "arg" =: GBlob (run reply)
                                                                                                     ]
                                                                                             let path = "/api/v2/canister/" ++ filter (/= '-') (textual cid1) ++ "/call"
                                                                                             addNonceExpiryEnv req >>= postCBOR path >>= code4xx,
                                                                                           testCase "using management canister as effective canister id in update" $ do
                                                                                             let req =
                                                                                                   rec
                                                                                                     [ "request_type" =: GText "call",
                                                                                                       "sender" =: GBlob defaultUser,
                                                                                                       "canister_id" =: GBlob "",
                                                                                                       "method_name" =: GText "raw_rand",
                                                                                                       "arg" =: GBlob (Candid.encode ())
                                                                                                     ]
                                                                                             addNonceExpiryEnv req >>= postCallCBOR "" >>= code4xx,
                                                                                           testCase "using management canister as effective canister id in query" $ do
                                                                                             let req =
                                                                                                   rec
                                                                                                     [ "request_type" =: GText "query",
                                                                                                       "sender" =: GBlob defaultUser,
                                                                                                       "canister_id" =: GBlob "",
                                                                                                       "method_name" =: GText "raw_rand",
                                                                                                       "arg" =: GBlob (Candid.encode ())
                                                                                                     ]
                                                                                             addNonceExpiryEnv req >>= postQueryCBOR "" >>= code4xx,
                                                                                           testCase "using management canister as effective canister id in read_state" $ do
                                                                                             let req =
                                                                                                   rec
                                                                                                     [ "request_type" =: GText "read_state",
                                                                                                       "sender" =: GBlob defaultUser,
                                                                                                       "paths" =: GList [GList [GBlob "time"]]
                                                                                                     ]
                                                                                             addNonceExpiryEnv req >>= postReadStateCBOR "" >>= code4xx
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
                                                                                       testCaseSteps "stable memory" $ \step -> do
                                                                                         cid <- install ecid noop

                                                                                         step "Stable mem size is zero"
                                                                                         query cid (replyData (i2b stableSize)) >>= is "\x0\x0\x0\x0"

                                                                                         step "Writing stable memory (failing)"
                                                                                         call' cid (stableWrite (int 0) "FOO") >>= isReject [5]
                                                                                         step "Set stable mem (failing, query)"
                                                                                         query' cid (stableWrite (int 0) "FOO") >>= isQueryReject ecid [5]

                                                                                         step "Growing stable memory"
                                                                                         call cid (replyData (i2b (stableGrow (int 1)))) >>= is "\x0\x0\x0\x0"

                                                                                         step "Growing stable memory again"
                                                                                         call cid (replyData (i2b (stableGrow (int 1)))) >>= is "\x1\x0\x0\x0"

                                                                                         step "Growing stable memory in query"
                                                                                         query cid (replyData (i2b (stableGrow (int 1)))) >>= is "\x2\x0\x0\x0"

                                                                                         step "Stable mem size is two"
                                                                                         query cid (replyData (i2b stableSize)) >>= is "\x2\x0\x0\x0"

                                                                                         step "Try growing stable memory beyond 4GiB"
                                                                                         call cid (replyData (i2b (stableGrow (int 65535)))) >>= is "\xff\xff\xff\xff"

                                                                                         step "Writing stable memory"
                                                                                         call_ cid $ stableWrite (int 0) "FOO" >>> reply

                                                                                         step "Writing stable memory (query)"
                                                                                         query_ cid $ stableWrite (int 0) "BAR" >>> reply

                                                                                         step "Reading stable memory"
                                                                                         call cid (replyData (stableRead (int 0) (int 3))) >>= is "FOO",
                                                                                       testCaseSteps "64 bit stable memory" $ \step -> do
                                                                                         cid <- install ecid noop

                                                                                         step "Stable mem size is zero"
                                                                                         query cid (replyData (i64tob stable64Size)) >>= is "\x0\x0\x0\x0\x0\x0\x0\x0"

                                                                                         step "Writing stable memory (failing)"
                                                                                         call' cid (stable64Write (int64 0) "FOO") >>= isReject [5]

                                                                                         step "Set stable mem (failing, query)"
                                                                                         query' cid (stable64Write (int64 0) "FOO") >>= isQueryReject ecid [5]

                                                                                         step "Growing stable memory"
                                                                                         call cid (replyData (i64tob (stable64Grow (int64 1)))) >>= is "\x0\x0\x0\x0\x0\x0\x0\x0"

                                                                                         step "Growing stable memory again"
                                                                                         call cid (replyData (i64tob (stable64Grow (int64 1)))) >>= is "\x1\x0\x0\x0\x0\x0\x0\x0"

                                                                                         step "Growing stable memory in query"
                                                                                         query cid (replyData (i64tob (stable64Grow (int64 1)))) >>= is "\x2\x0\x0\x0\x0\x0\x0\x0"

                                                                                         step "Stable mem size is two"
                                                                                         query cid (replyData (i2b stableSize)) >>= is "\x2\x0\x0\x0"
                                                                                         query cid (replyData (i64tob stable64Size)) >>= is "\x2\x0\x0\x0\x0\x0\x0\x0"

                                                                                         step "Writing stable memory"
                                                                                         call_ cid $ stable64Write (int64 0) "FOO" >>> reply

                                                                                         step "Writing stable memory (query)"
                                                                                         query_ cid $ stable64Write (int64 0) "BAR" >>> reply

                                                                                         step "Reading stable memory"
                                                                                         call cid (replyData (stable64Read (int64 0) (int64 3))) >>= is "FOO"
                                                                                         call cid (replyData (stableRead (int 0) (int 3))) >>= is "FOO"

                                                                                         step "Writing in 32 bit mode"
                                                                                         call_ cid $ stableWrite (int 0) "BAR" >>> reply

                                                                                         step "Reading back in 64 bit mode"
                                                                                         call cid (replyData (stable64Read (int64 0) (int64 3))) >>= is "BAR"

                                                                                         step "Growing stable memory beyond 4GiB"
                                                                                         call cid (replyData (i64tob (stable64Grow (int64 65535)))) >>= is "\x2\x0\x0\x0\x0\x0\x0\x0"
                                                                                         query cid (replyData (i64tob stable64Size)) >>= is "\x01\x00\x01\x00\x0\x0\x0\x0"

                                                                                         step "Using 32 bit API with large stable memory"
                                                                                         query' cid (ignore stableSize) >>= isQueryReject ecid [5]
                                                                                         query' cid (ignore $ stableGrow (int 1)) >>= isQueryReject ecid [5]
                                                                                         query' cid (stableWrite (int 0) "BAZ") >>= isQueryReject ecid [5]
                                                                                         query' cid (ignore $ stableRead (int 0) (int 3)) >>= isQueryReject ecid [5]

                                                                                         step "Using 64 bit API with large stable memory"
                                                                                         call cid (replyData (i64tob (stable64Grow (int64 1)))) >>= is "\x01\x00\x01\x00\x0\x0\x0\x0"
                                                                                         query cid (replyData (i64tob stable64Size)) >>= is "\x02\x00\x01\x00\x0\x0\x0\x0"
                                                                                         call cid (replyData (stable64Read (int64 0) (int64 3))) >>= is "BAR"
                                                                                         call_ cid $ stable64Write (int64 0) "BAZ" >>> reply
                                                                                         call cid (replyData (stable64Read (int64 0) (int64 3))) >>= is "BAZ",
                                                                                       testGroup "time" $
                                                                                         let getTimeTwice = cat (i64tob getTime) (i64tob getTime)
                                                                                          in [ simpleTestCase "in query" ecid $ \cid ->
                                                                                                 query cid (replyData getTimeTwice) >>= as2Word64 >>= bothSame,
                                                                                               simpleTestCase "in update" ecid $ \cid ->
                                                                                                 call cid (replyData getTimeTwice) >>= as2Word64 >>= bothSame,
                                                                                               testCase "in install" $ do
                                                                                                 cid <- install ecid $ setGlobal getTimeTwice
                                                                                                 query cid (replyData getGlobal) >>= as2Word64 >>= bothSame,
                                                                                               testCase "in pre_upgrade" $ do
                                                                                                 cid <-
                                                                                                   install ecid $
                                                                                                     ignore (stableGrow (int 1))
                                                                                                       >>> onPreUpgrade (callback $ stableWrite (int 0) getTimeTwice)
                                                                                                 upgrade cid noop
                                                                                                 query cid (replyData (stableRead (int 0) (int (2 * 8)))) >>= as2Word64 >>= bothSame,
                                                                                               simpleTestCase "in post_upgrade" ecid $ \cid -> do
                                                                                                 upgrade cid $ setGlobal getTimeTwice
                                                                                                 query cid (replyData getGlobal) >>= as2Word64 >>= bothSame
                                                                                             ],
                                                                                       testGroup "canister global timer" $ canister_timer_tests ecid,
                                                                                       testGroup "canister version" $ canister_version_tests ecid,
                                                                                       testGroup "canister history" $ canister_history_tests ecid,
                                                                                       testGroup "is_controller system API" $
                                                                                         [ simpleTestCase "argument is controller" ecid $ \cid -> do
                                                                                             res <- query cid (replyData $ i2b $ isController (bytes defaultUser)) >>= asWord32
                                                                                             res @?= 1,
                                                                                           simpleTestCase "argument is not controller" ecid $ \cid -> do
                                                                                             res <- query cid (replyData $ i2b $ isController (bytes "")) >>= asWord32
                                                                                             res @?= 0,
                                                                                           simpleTestCase "argument is a valid principal" ecid $ \cid -> do
                                                                                             res <- query cid (replyData $ i2b $ isController (bytes $ BS.replicate 29 0)) >>= asWord32
                                                                                             res @?= 0,
                                                                                           simpleTestCase "argument is not a valid principal" ecid $ \cid -> do
                                                                                             query' cid (replyData $ i2b $ isController (bytes $ BS.replicate 30 0)) >>= isQueryReject ecid [5]
                                                                                         ],
                                                                                       testGroup "upgrades" $
                                                                                         let installForUpgrade on_pre_upgrade =
                                                                                               install ecid $
                                                                                                 setGlobal "FOO"
                                                                                                   >>> ignore (stableGrow (int 1))
                                                                                                   >>> stableWrite (int 0) "BAR______"
                                                                                                   >>> onPreUpgrade (callback on_pre_upgrade)

                                                                                             checkNoUpgrade cid = do
                                                                                               query cid (replyData getGlobal) >>= is "FOO"
                                                                                               query cid (replyData (stableRead (int 0) (int 9))) >>= is "BAR______"
                                                                                          in [ testCase "succeeding" $ do
                                                                                                 -- check that the pre-upgrade hook has access to the old state
                                                                                                 cid <- installForUpgrade $ stableWrite (int 3) getGlobal
                                                                                                 checkNoUpgrade cid

                                                                                                 upgrade cid $ stableWrite (int 6) (stableRead (int 0) (int 3))

                                                                                                 query cid (replyData getGlobal) >>= is ""
                                                                                                 query cid (replyData (stableRead (int 0) (int 9))) >>= is "BARFOOBAR",
                                                                                               testCase "trapping in pre-upgrade" $ do
                                                                                                 cid <- installForUpgrade $ trap "trap in pre-upgrade"
                                                                                                 checkNoUpgrade cid

                                                                                                 upgrade' cid noop >>= isReject [5]
                                                                                                 checkNoUpgrade cid,
                                                                                               testCase "trapping in pre-upgrade (by calling)" $ do
                                                                                                 cid <- installForUpgrade $ trap "trap in pre-upgrade"
                                                                                                 call_ cid $
                                                                                                   reply
                                                                                                     >>> onPreUpgrade
                                                                                                       ( callback
                                                                                                           ( inter_query cid defArgs {other_side = noop}
                                                                                                           )
                                                                                                       )
                                                                                                 checkNoUpgrade cid

                                                                                                 upgrade' cid noop >>= isReject [5]
                                                                                                 checkNoUpgrade cid,
                                                                                               testCase "trapping in pre-upgrade (by accessing arg)" $ do
                                                                                                 cid <- installForUpgrade $ ignore argData
                                                                                                 checkNoUpgrade cid

                                                                                                 upgrade' cid noop >>= isReject [5]
                                                                                                 checkNoUpgrade cid,
                                                                                               testCase "trapping in post-upgrade" $ do
                                                                                                 cid <- installForUpgrade $ stableWrite (int 3) getGlobal
                                                                                                 checkNoUpgrade cid

                                                                                                 upgrade' cid (trap "trap in post-upgrade") >>= isReject [5]
                                                                                                 checkNoUpgrade cid,
                                                                                               testCase "trapping in post-upgrade (by calling)" $ do
                                                                                                 cid <- installForUpgrade $ stableWrite (int 3) getGlobal
                                                                                                 checkNoUpgrade cid

                                                                                                 do upgrade' cid $ inter_query cid defArgs {other_side = noop}
                                                                                                   >>= isReject [5]
                                                                                                 checkNoUpgrade cid
                                                                                             ],
                                                                                       testGroup
                                                                                         "heartbeat"
                                                                                         [ testCase "called once for all canisters" $ do
                                                                                             cid <- install ecid $ onHeartbeat $ callback $ ignore (stableGrow (int 1)) >>> stableWrite (int 0) "FOO"
                                                                                             cid2 <- install ecid $ onHeartbeat $ callback $ ignore (stableGrow (int 1)) >>> stableWrite (int 0) "BAR"
                                                                                             -- Heartbeat cannot respond. Should be trapped.
                                                                                             cid3 <- install ecid $ onHeartbeat $ callback $ setGlobal "FIZZ" >>> replyData "FIZZ"

                                                                                             -- The spec currently gives no guarantee about when or how frequent heartbeats are executed.
                                                                                             -- But all implementations have the property: if update call B is submitted after call A is completed,
                                                                                             -- then a heartbeat runs before the execution of B.
                                                                                             -- We use this here to make sure that heartbeats have been attempted:
                                                                                             call_ cid reply
                                                                                             call_ cid reply

                                                                                             query cid (replyData (stableRead (int 0) (int 3))) >>= is "FOO"
                                                                                             query cid2 (replyData (stableRead (int 0) (int 3))) >>= is "BAR"
                                                                                             query cid3 (replyData getGlobal) >>= is ""
                                                                                         ],
                                                                                       testGroup
                                                                                         "reinstall"
                                                                                         [ testCase "succeeding" $ do
                                                                                             cid <-
                                                                                               install ecid $
                                                                                                 setGlobal "FOO"
                                                                                                   >>> ignore (stableGrow (int 1))
                                                                                                   >>> stableWrite (int 0) "FOO______"
                                                                                             query cid (replyData getGlobal) >>= is "FOO"
                                                                                             query cid (replyData (stableRead (int 0) (int 9))) >>= is "FOO______"
                                                                                             query cid (replyData (i2b stableSize)) >>= asWord32 >>= is 1

                                                                                             reinstall cid $
                                                                                               setGlobal "BAR"
                                                                                                 >>> ignore (stableGrow (int 2))
                                                                                                 >>> stableWrite (int 0) "BAR______"

                                                                                             query cid (replyData getGlobal) >>= is "BAR"
                                                                                             query cid (replyData (stableRead (int 0) (int 9))) >>= is "BAR______"
                                                                                             query cid (replyData (i2b stableSize)) >>= asWord32 >>= is 2

                                                                                             reinstall cid noop

                                                                                             query cid (replyData getGlobal) >>= is ""
                                                                                             query cid (replyData (i2b stableSize)) >>= asWord32 >>= is 0,
                                                                                           testCase "trapping" $ do
                                                                                             cid <-
                                                                                               install ecid $
                                                                                                 setGlobal "FOO"
                                                                                                   >>> ignore (stableGrow (int 1))
                                                                                                   >>> stableWrite (int 0) "FOO______"
                                                                                             query cid (replyData getGlobal) >>= is "FOO"
                                                                                             query cid (replyData (stableRead (int 0) (int 9))) >>= is "FOO______"
                                                                                             query cid (replyData (i2b stableSize)) >>= is "\1\0\0\0"

                                                                                             reinstall' cid (trap "Trapping the reinstallation") >>= isReject [5]

                                                                                             query cid (replyData getGlobal) >>= is "FOO"
                                                                                             query cid (replyData (stableRead (int 0) (int 9))) >>= is "FOO______"
                                                                                             query cid (replyData (i2b stableSize)) >>= is "\1\0\0\0"
                                                                                         ],
                                                                                       testGroup
                                                                                         "uninstall"
                                                                                         [ testCase "uninstall empty canister" $ do
                                                                                             cid <- create ecid
                                                                                             cs <- ic_canister_status ic00 cid
                                                                                             cs .! #status @?= enum #running
                                                                                             cs .! #settings .! #controllers @?= Vec.fromList [Principal defaultUser]
                                                                                             cs .! #module_hash @?= Nothing
                                                                                             ic_uninstall ic00 cid
                                                                                             cs <- ic_canister_status ic00 cid
                                                                                             cs .! #status @?= enum #running
                                                                                             cs .! #settings .! #controllers @?= Vec.fromList [Principal defaultUser]
                                                                                             cs .! #module_hash @?= Nothing,
                                                                                           testCase "uninstall as wrong user" $ do
                                                                                             cid <- create ecid
                                                                                             ic_uninstall'' otherUser cid >>= isErrOrReject [3, 5],
                                                                                           testCase "uninstall and reinstall wipes state" $ do
                                                                                             cid <- install ecid (setGlobal "FOO")
                                                                                             ic_uninstall ic00 cid
                                                                                             universal_wasm <- getTestWasm "universal_canister.wasm.gz"
                                                                                             ic_install ic00 (enum #install) cid universal_wasm (run (setGlobal "BAR"))
                                                                                             query cid (replyData getGlobal) >>= is "BAR",
                                                                                           testCase "uninstall and reinstall wipes stable memory" $ do
                                                                                             cid <- install ecid (ignore (stableGrow (int 1)) >>> stableWrite (int 0) "FOO")
                                                                                             ic_uninstall ic00 cid
                                                                                             universal_wasm <- getTestWasm "universal_canister.wasm.gz"
                                                                                             ic_install ic00 (enum #install) cid universal_wasm (run (setGlobal "BAR"))
                                                                                             query cid (replyData (i2b stableSize)) >>= asWord32 >>= is 0
                                                                                             do
                                                                                               query cid $
                                                                                                 ignore (stableGrow (int 1))
                                                                                                   >>> replyData (stableRead (int 0) (int 3))
                                                                                               >>= is "\0\0\0"
                                                                                             do
                                                                                               call cid $
                                                                                                 ignore (stableGrow (int 1))
                                                                                                   >>> replyData (stableRead (int 0) (int 3))
                                                                                               >>= is "\0\0\0",
                                                                                           testCase "uninstall and reinstall wipes certified data" $ do
                                                                                             cid <- install ecid $ setCertifiedData "FOO"
                                                                                             query cid (replyData getCertificate) >>= extractCertData cid >>= is "FOO"
                                                                                             ic_uninstall ic00 cid
                                                                                             universal_wasm <- getTestWasm "universal_canister.wasm.gz"
                                                                                             ic_install ic00 (enum #install) cid universal_wasm (run noop)
                                                                                             query cid (replyData getCertificate) >>= extractCertData cid >>= is "",
                                                                                           simpleTestCase "uninstalled rejects calls" ecid $ \cid -> do
                                                                                             call cid (replyData "Hi") >>= is "Hi"
                                                                                             query cid (replyData "Hi") >>= is "Hi"
                                                                                             ic_uninstall ic00 cid
                                                                                             -- should be http error, due to inspection
                                                                                             call'' cid (replyData "Hi") >>= isNoErrReject [5]
                                                                                             query' cid (replyData "Hi") >>= isQueryReject ecid [5],
                                                                                           testCaseSteps "open call contexts are rejected" $ \step -> do
                                                                                             cid <- install ecid noop

                                                                                             step "Create message hold"
                                                                                             (messageHold, release) <- createMessageHold ecid

                                                                                             step "Create long-running call"
                                                                                             grs1 <- submitCall cid $ callRequest cid messageHold
                                                                                             awaitKnown grs1 >>= isPendingOrProcessing

                                                                                             step "Uninstall"
                                                                                             ic_uninstall ic00 cid

                                                                                             step "Long-running call is rejected"
                                                                                             awaitStatus grs1 >>= isReject [4]

                                                                                             step "Now release"
                                                                                             release
                                                                                             awaitStatus grs1 >>= isReject [4], -- still a reject
                                                                                           testCaseSteps "deleted call contexts prevent stopping" $ \step -> do
                                                                                             cid <- install ecid noop

                                                                                             step "Create message hold"
                                                                                             (messageHold, release) <- createMessageHold ecid

                                                                                             step "Create long-running call"
                                                                                             grs1 <- submitCall cid $ callRequest cid messageHold
                                                                                             awaitKnown grs1 >>= isPendingOrProcessing

                                                                                             step "Uninstall"
                                                                                             ic_uninstall ic00 cid

                                                                                             step "Long-running call is rejected"
                                                                                             awaitStatus grs1 >>= isReject [4]

                                                                                             step "Stop"
                                                                                             grs2 <- submitCall cid $ stopRequest cid
                                                                                             awaitKnown grs2 >>= isPendingOrProcessing

                                                                                             step "Is stopping (via management)?"
                                                                                             cs <- ic_canister_status ic00 cid
                                                                                             cs .! #status @?= enum #stopping

                                                                                             step "Next stop waits, too"
                                                                                             grs3 <- submitCall cid $ stopRequest cid
                                                                                             awaitKnown grs3 >>= isPendingOrProcessing

                                                                                             step "Release the held message"
                                                                                             release

                                                                                             step "Wait for calls to complete"
                                                                                             awaitStatus grs1 >>= isReject [4] -- still a reject
                                                                                             awaitStatus grs2 >>= isReply >>= is (Candid.encode ())
                                                                                             awaitStatus grs3 >>= isReply >>= is (Candid.encode ())

                                                                                             step "Is stopped (via management)?"
                                                                                             cs <- ic_canister_status ic00 cid
                                                                                             cs .! #status @?= enum #stopped,
                                                                                           testCaseSteps "deleted call contexts are not delivered" $ \step -> do
                                                                                             -- This is a tricky one: We make one long-running call,
                                                                                             -- then uninstall (rejecting the call), then re-install fresh code,
                                                                                             -- make another long-running call, then release the first one. The system
                                                                                             -- should not confuse the two callbacks.
                                                                                             cid <- install ecid noop
                                                                                             helper <- install ecid noop

                                                                                             step "Create message holds"
                                                                                             (messageHold1, release1) <- createMessageHold ecid
                                                                                             (messageHold2, release2) <- createMessageHold ecid

                                                                                             step "Create first long-running call"
                                                                                             grs1 <-
                                                                                               submitCall cid $
                                                                                                 callRequest cid $
                                                                                                   inter_call
                                                                                                     helper
                                                                                                     "update"
                                                                                                     defArgs
                                                                                                       { other_side = messageHold1,
                                                                                                         on_reply = replyData "First"
                                                                                                       }
                                                                                             awaitKnown grs1 >>= isPendingOrProcessing

                                                                                             step "Uninstall"
                                                                                             ic_uninstall ic00 cid
                                                                                             awaitStatus grs1 >>= isReject [4]

                                                                                             step "Reinstall"
                                                                                             universal_wasm <- getTestWasm "universal_canister.wasm.gz"
                                                                                             ic_install ic00 (enum #install) cid universal_wasm (run (setGlobal "BAR"))

                                                                                             step "Create second long-running call"
                                                                                             grs2 <-
                                                                                               submitCall cid $
                                                                                                 callRequest cid $
                                                                                                   inter_call
                                                                                                     helper
                                                                                                     "update"
                                                                                                     defArgs
                                                                                                       { other_side = messageHold2,
                                                                                                         on_reply = replyData "Second"
                                                                                                       }
                                                                                             awaitStatus grs1 >>= isReject [4]
                                                                                             awaitKnown grs2 >>= isPendingOrProcessing

                                                                                             step "Release first call"
                                                                                             release1
                                                                                             awaitStatus grs1 >>= isReject [4]
                                                                                             awaitKnown grs2 >>= isPendingOrProcessing

                                                                                             step "Release second call"
                                                                                             release2
                                                                                             awaitStatus grs1 >>= isReject [4]
                                                                                             awaitStatus grs2 >>= isReply >>= is "Second"
                                                                                         ],
                                                                                       testGroup
                                                                                         "debug facilities"
                                                                                         [ simpleTestCase "Using debug_print" ecid $ \cid ->
                                                                                             call_ cid (debugPrint "ic-ref-test print" >>> reply),
                                                                                           simpleTestCase "Using debug_print (query)" ecid $ \cid ->
                                                                                             query_ cid $ debugPrint "ic-ref-test print" >>> reply,
                                                                                           simpleTestCase "Using debug_print with invalid bounds" ecid $ \cid ->
                                                                                             query_ cid $ badPrint >>> reply,
                                                                                           simpleTestCase "Explicit trap" ecid $ \cid ->
                                                                                             call' cid (trap "trapping") >>= isReject [5],
                                                                                           simpleTestCase "Explicit trap (query)" ecid $ \cid -> do
                                                                                             query' cid (trap "trapping") >>= isQueryReject ecid [5]
                                                                                         ],
                                                                                       testCase "caller (in init)" $ do
                                                                                         cid <- install ecid $ setGlobal caller
                                                                                         query cid (replyData getGlobal) >>= is defaultUser,
                                                                                       testCase "self (in init)" $ do
                                                                                         cid <- install ecid $ setGlobal self
                                                                                         query cid (replyData getGlobal) >>= is cid,
                                                                                       testGroup "trapping in init" $
                                                                                         let failInInit pgm = do
                                                                                               cid <- create ecid
                                                                                               install' cid pgm >>= isReject [5]
                                                                                               -- canister does not exist
                                                                                               query' cid noop >>= isQueryReject ecid [5]
                                                                                          in [ testCase "explicit trap" $ failInInit $ trap "trapping in install",
                                                                                               testCase "call" $ failInInit $ inter_query "dummy" defArgs,
                                                                                               testCase "reply" $ failInInit reply,
                                                                                               testCase "reject" $ failInInit $ reject "rejecting in init"
                                                                                             ],
                                                                                       testGroup
                                                                                         "query"
                                                                                         [ testGroup "required fields" $ do
                                                                                             -- TODO: Begin with a succeeding request to a real canister, to rule
                                                                                             -- out other causes of failure than missing fields
                                                                                             omitFields queryToNonExistent $ \req -> do
                                                                                               cid <- create ecid
                                                                                               addExpiry req >>= envelope defaultSK >>= postQueryCBOR cid >>= code4xx,
                                                                                           simpleTestCase "non-existing (deleted) canister" ecid $ \cid -> do
                                                                                             ic_stop_canister ic00 cid
                                                                                             ic_delete_canister ic00 cid
                                                                                             query' cid reply >>= isQueryReject ecid [3],
                                                                                           simpleTestCase "does not commit" ecid $ \cid -> do
                                                                                             call_ cid (setGlobal "FOO" >>> reply)
                                                                                             query cid (setGlobal "BAR" >>> replyData getGlobal) >>= is "BAR"
                                                                                             query cid (replyData getGlobal) >>= is "FOO"
                                                                                         ],
                                                                                       testGroup "read state" $
                                                                                         let ensure_request_exists cid user = do
                                                                                               req <-
                                                                                                 addNonce >=> addExpiry $
                                                                                                   rec
                                                                                                     [ "request_type" =: GText "call",
                                                                                                       "sender" =: GBlob user,
                                                                                                       "canister_id" =: GBlob cid,
                                                                                                       "method_name" =: GText "query",
                                                                                                       "arg" =: GBlob (run (replyData "\xff\xff"))
                                                                                                     ]
                                                                                               awaitCall cid req >>= isReply >>= is "\xff\xff"

                                                                                               -- check that the request is there
                                                                                               getRequestStatus user cid (requestId req) >>= is (Responded (Reply "\xff\xff"))

                                                                                               return (requestId req)
                                                                                             ensure_provisional_create_canister_request_exists ecid user = do
                                                                                               let arg :: ProvisionalCreateCanisterArgs =
                                                                                                     empty
                                                                                                       .+ #amount
                                                                                                       .== Just initial_cycles
                                                                                                       .+ #settings
                                                                                                       .== Nothing
                                                                                                       .+ #specified_id
                                                                                                       .== Nothing
                                                                                                       .+ #sender_canister_version
                                                                                                       .== Nothing
                                                                                               req <-
                                                                                                 addNonce >=> addExpiry $
                                                                                                   rec
                                                                                                     [ "request_type" =: GText "call",
                                                                                                       "sender" =: GBlob user,
                                                                                                       "canister_id" =: GBlob "",
                                                                                                       "method_name" =: GText "provisional_create_canister_with_cycles",
                                                                                                       "arg" =: GBlob (Candid.encode arg)
                                                                                                     ]
                                                                                               _ <- awaitCall ecid req >>= isReply

                                                                                               -- check that the request is there
                                                                                               getRequestStatus user ecid (requestId req) >>= isResponded

                                                                                               return (requestId req)
                                                                                          in [ testGroup "required fields" $
                                                                                                 omitFields readStateEmpty $ \req -> do
                                                                                                   cid <- create ecid
                                                                                                   addExpiry req >>= envelope defaultSK >>= postReadStateCBOR cid >>= code4xx,
                                                                                               simpleTestCase "certificate validates" ecid $ \cid -> do
                                                                                                 cert <- getStateCert defaultUser cid []
                                                                                                 validateStateCert cid cert,
                                                                                               simpleTestCase "certificate does not validate if canister range check fails" ecid $ \cid -> do
                                                                                                 unless my_is_root $ do
                                                                                                   cert <- getStateCert defaultUser cid []
                                                                                                   result <- try (validateStateCert other_ecid cert) :: IO (Either DelegationCanisterRangeCheck ())
                                                                                                   assertBool "certificate should not validate" $ isLeft result,
                                                                                               testCaseSteps "time is present" $ \step -> do
                                                                                                 cid <- create ecid
                                                                                                 cert <- getStateCert defaultUser cid []
                                                                                                 time <- certValue @Natural cert ["time"]
                                                                                                 step $ "Reported time: " ++ show time,
                                                                                               testCase "time can be asked for" $ do
                                                                                                 cid <- create ecid
                                                                                                 cert <- getStateCert defaultUser cid [["time"]]
                                                                                                 void $ certValue @Natural cert ["time"],
                                                                                               testCase "can ask for /subnet" $ do
                                                                                                 cert <- getStateCert defaultUser ecid [["subnet"]]
                                                                                                 void $ certValue @Blob cert ["subnet", my_subnet_id, "public_key"]
                                                                                                 void $ certValue @Blob cert ["subnet", my_subnet_id, "canister_ranges"]
                                                                                                 void $ certValue @Blob cert ["subnet", other_subnet_id, "public_key"]
                                                                                                 void $ certValue @Blob cert ["subnet", other_subnet_id, "canister_ranges"]
                                                                                                 void $ forM my_nodes $ \nid -> do
                                                                                                   void $ certValue @Blob cert ["subnet", my_subnet_id, "node", rawEntityId nid, "public_key"]
                                                                                                 void $ forM other_nodes $ \nid -> do
                                                                                                   certValueAbsent cert ["subnet", other_subnet_id, "node", rawEntityId nid, "public_key"],
                                                                                               testCase "controller of empty canister" $ do
                                                                                                 cid <- create ecid
                                                                                                 cert <- getStateCert defaultUser cid [["canister", cid, "controllers"]]
                                                                                                 certValue @Blob cert ["canister", cid, "controllers"] >>= asCBORBlobList >>= isSet [defaultUser],
                                                                                               testCase "module_hash of empty canister" $ do
                                                                                                 cid <- create ecid
                                                                                                 cert <- getStateCert defaultUser cid [["canister", cid, "module_hash"]]
                                                                                                 lookupPath (cert_tree cert) ["canister", cid, "module_hash"] @?= Absent,
                                                                                               testCase "single controller of installed canister" $ do
                                                                                                 cid <- install ecid noop
                                                                                                 -- also vary user, just for good measure
                                                                                                 cert <- getStateCert anonymousUser cid [["canister", cid, "controllers"]]
                                                                                                 certValue @Blob cert ["canister", cid, "controllers"] >>= asCBORBlobList >>= isSet [defaultUser],
                                                                                               testCase "multiple controllers of installed canister" $ do
                                                                                                 cid <- ic_provisional_create ic00 ecid Nothing Nothing Nothing
                                                                                                 ic_set_controllers ic00 cid [defaultUser, otherUser]
                                                                                                 cert <- getStateCert defaultUser cid [["canister", cid, "controllers"]]
                                                                                                 certValue @Blob cert ["canister", cid, "controllers"] >>= asCBORBlobList >>= isSet [defaultUser, otherUser],
                                                                                               testCase "zero controllers of installed canister" $ do
                                                                                                 cid <- ic_provisional_create ic00 ecid Nothing Nothing Nothing
                                                                                                 ic_set_controllers ic00 cid []
                                                                                                 cert <- getStateCert defaultUser cid [["canister", cid, "controllers"]]
                                                                                                 certValue @Blob cert ["canister", cid, "controllers"] >>= asCBORBlobList >>= isSet [],
                                                                                               testCase "module_hash of universal canister" $ do
                                                                                                 cid <- install ecid noop
                                                                                                 universal_wasm <- getTestWasm "universal_canister.wasm.gz"
                                                                                                 cert <- getStateCert anonymousUser cid [["canister", cid, "module_hash"]]
                                                                                                 certValue @Blob cert ["canister", cid, "module_hash"] >>= is (sha256 universal_wasm),
                                                                                               testGroup
                                                                                                 "malformed request id"
                                                                                                 [ simpleTestCase ("rid \"" ++ shorten 8 (asHex rid) ++ "\"") ecid $ \cid -> do
                                                                                                     getStateCert' defaultUser cid [["request_status", rid]] >>= isErr4xx
                                                                                                   | rid <- ["", "foo"]
                                                                                                 ],
                                                                                               testGroup
                                                                                                 "non-existence proofs for non-existing request id"
                                                                                                 [ simpleTestCase ("rid \"" ++ shorten 8 (asHex rid) ++ "\"") ecid $ \cid -> do
                                                                                                     cert <- getStateCert defaultUser cid [["request_status", rid]]
                                                                                                     certValueAbsent cert ["request_status", rid, "status"]
                                                                                                   | rid <- [BS.replicate 32 0, BS.replicate 32 8, BS.replicate 32 255]
                                                                                                 ],
                                                                                               simpleTestCase "can ask for portion of request status" ecid $ \cid -> do
                                                                                                 rid <- ensure_request_exists cid defaultUser
                                                                                                 cert <- getStateCert defaultUser cid [["request_status", rid, "status"], ["request_status", rid, "reply"]]
                                                                                                 void $ certValue @T.Text cert ["request_status", rid, "status"]
                                                                                                 void $ certValue @Blob cert ["request_status", rid, "reply"],
                                                                                               simpleTestCase "access denied for other users request" ecid $ \cid -> do
                                                                                                 rid <- ensure_request_exists cid defaultUser
                                                                                                 getStateCert' otherUser cid [["request_status", rid]] >>= isErr4xx,
                                                                                               simpleTestCase "reading two statuses to same canister in one go" ecid $ \cid -> do
                                                                                                 rid1 <- ensure_request_exists cid defaultUser
                                                                                                 rid2 <- ensure_request_exists cid defaultUser
                                                                                                 getStateCert' defaultUser cid [["request_status", rid1], ["request_status", rid2]] >>= isErr4xx,
                                                                                               simpleTestCase "access denied for other users request (mixed request)" ecid $ \cid -> do
                                                                                                 rid1 <- ensure_request_exists cid defaultUser
                                                                                                 rid2 <- ensure_request_exists cid otherUser
                                                                                                 getStateCert' defaultUser cid [["request_status", rid1], ["request_status", rid2]] >>= isErr4xx,
                                                                                               simpleTestCase "access denied for two statuses to different canisters" ecid $ \cid -> do
                                                                                                 cid2 <- install ecid noop
                                                                                                 rid1 <- ensure_request_exists cid defaultUser
                                                                                                 rid2 <- ensure_request_exists cid2 defaultUser
                                                                                                 getStateCert' defaultUser cid [["request_status", rid1], ["request_status", rid2]] >>= isErr4xx,
                                                                                               simpleTestCase "access denied with different effective canister id" ecid $ \cid -> do
                                                                                                 cid2 <- install ecid noop
                                                                                                 rid <- ensure_provisional_create_canister_request_exists cid defaultUser
                                                                                                 getStateCert' defaultUser cid2 [["request_status", rid]] >>= isErr4xx,
                                                                                               simpleTestCase "access denied for bogus path" ecid $ \cid -> do
                                                                                                 getStateCert' otherUser cid [["hello", "world"]] >>= isErr4xx,
                                                                                               simpleTestCase "access denied for fetching full state tree" ecid $ \cid -> do
                                                                                                 getStateCert' otherUser cid [[]] >>= isErr4xx,
                                                                                               testGroup "metadata" $
                                                                                                 let withCustomSection mod (name, content) = mod <> BS.singleton 0 <> sized (sized name <> content)
                                                                                                       where
                                                                                                         sized x = BS.fromStrict (toLEB128 @Natural (fromIntegral (BS.length x))) <> x
                                                                                                     withSections xs = foldl withCustomSection trivialWasmModule xs
                                                                                                  in [ simpleTestCase "absent" ecid $ \cid -> do
                                                                                                         cert <- getStateCert defaultUser cid [["canister", cid, "metadata", "foo"]]
                                                                                                         lookupPath (cert_tree cert) ["canister", cid, "metadata", "foo"] @?= Absent,
                                                                                                       testCase "public" $ do
                                                                                                         let mod = withSections [("icp:public test", "bar")]
                                                                                                         cid <- create ecid
                                                                                                         ic_install ic00 (enum #install) cid mod ""
                                                                                                         cert <- getStateCert otherUser cid [["canister", cid, "metadata", "test"]]
                                                                                                         lookupPath (cert_tree cert) ["canister", cid, "metadata", "test"] @?= Found "bar"
                                                                                                         cert <- getStateCert anonymousUser cid [["canister", cid, "metadata", "test"]]
                                                                                                         lookupPath (cert_tree cert) ["canister", cid, "metadata", "test"] @?= Found "bar",
                                                                                                       testCase "private" $ do
                                                                                                         let mod = withSections [("icp:private test", "bar")]
                                                                                                         cid <- create ecid
                                                                                                         ic_install ic00 (enum #install) cid mod ""
                                                                                                         getStateCert' otherUser cid [["canister", cid, "metadata", "test"]] >>= isErr4xx
                                                                                                         getStateCert' anonymousUser cid [["canister", cid, "metadata", "test"]] >>= isErr4xx
                                                                                                         cert <- getStateCert defaultUser cid [["canister", cid, "metadata", "test"]]
                                                                                                         lookupPath (cert_tree cert) ["canister", cid, "metadata", "test"] @?= Found "bar",
                                                                                                       testCase "duplicate public" $ do
                                                                                                         let mod = withSections [("icp:public test", "bar"), ("icp:public test", "baz")]
                                                                                                         cid <- create ecid
                                                                                                         ic_install' ic00 (enum #install) cid mod "" >>= isReject [5],
                                                                                                       testCase "duplicate private" $ do
                                                                                                         let mod = withSections [("icp:private test", "bar"), ("icp:private test", "baz")]
                                                                                                         cid <- create ecid
                                                                                                         ic_install' ic00 (enum #install) cid mod "" >>= isReject [5],
                                                                                                       testCase "duplicate mixed" $ do
                                                                                                         let mod = withSections [("icp:private test", "bar"), ("icp:public test", "baz")]
                                                                                                         cid <- create ecid
                                                                                                         ic_install' ic00 (enum #install) cid mod "" >>= isReject [5],
                                                                                                       testCase "invalid utf8 in module" $ do
                                                                                                         let mod = withSections [("icp:public \xe2\x28\xa1", "baz")]
                                                                                                         cid <- create ecid
                                                                                                         ic_install' ic00 (enum #install) cid mod "" >>= isReject [5],
                                                                                                       simpleTestCase "invalid utf8 in read_state" ecid $ \cid -> do
                                                                                                         getStateCert' defaultUser cid [["canister", cid, "metadata", "\xe2\x28\xa1"]] >>= isErr4xx,
                                                                                                       testCase "unicode metadata name" $ do
                                                                                                         let mod = withSections [("icp:public ☃️", "bar")]
                                                                                                         cid <- create ecid
                                                                                                         ic_install ic00 (enum #install) cid mod ""
                                                                                                         cert <- getStateCert anonymousUser cid [["canister", cid, "metadata", "☃️"]]
                                                                                                         lookupPath (cert_tree cert) ["canister", cid, "metadata", "☃️"] @?= Found "bar",
                                                                                                       testCase "zero-length metadata name" $ do
                                                                                                         let mod = withSections [("icp:public ", "bar")]
                                                                                                         cid <- create ecid
                                                                                                         ic_install ic00 (enum #install) cid mod ""
                                                                                                         cert <- getStateCert anonymousUser cid [["canister", cid, "metadata", ""]]
                                                                                                         lookupPath (cert_tree cert) ["canister", cid, "metadata", ""] @?= Found "bar",
                                                                                                       testCase "metadata section name with spaces" $ do
                                                                                                         let mod = withSections [("icp:public metadata section name with spaces", "bar")]
                                                                                                         cid <- create ecid
                                                                                                         ic_install ic00 (enum #install) cid mod ""
                                                                                                         cert <- getStateCert anonymousUser cid [["canister", cid, "metadata", "metadata section name with spaces"]]
                                                                                                         lookupPath (cert_tree cert) ["canister", cid, "metadata", "metadata section name with spaces"] @?= Found "bar"
                                                                                                     ]
                                                                                             ],
                                                                                       testGroup
                                                                                         "certified variables"
                                                                                         [ simpleTestCase "initially empty" ecid $ \cid -> do
                                                                                             query cid (replyData getCertificate) >>= extractCertData cid >>= is "",
                                                                                           simpleTestCase "validates" ecid $ \cid -> do
                                                                                             query cid (replyData getCertificate)
                                                                                               >>= decodeCert'
                                                                                               >>= validateStateCert cid,
                                                                                           simpleTestCase "present in query method (query call)" ecid $ \cid -> do
                                                                                             query cid (replyData (i2b getCertificatePresent))
                                                                                               >>= is "\1\0\0\0",
                                                                                           simpleTestCase "not present in query method (update call)" ecid $ \cid -> do
                                                                                             callToQuery'' cid (replyData (i2b getCertificatePresent))
                                                                                               >>= is2xx
                                                                                               >>= isReply
                                                                                               >>= is "\0\0\0\0",
                                                                                           simpleTestCase "not present in query method (inter-canister call)" ecid $ \cid -> do
                                                                                             do
                                                                                               call cid $
                                                                                                 inter_call
                                                                                                   cid
                                                                                                   "query"
                                                                                                   defArgs
                                                                                                     { other_side = replyData (i2b getCertificatePresent)
                                                                                                     }
                                                                                               >>= isRelay
                                                                                               >>= isReply
                                                                                               >>= is "\0\0\0\0",
                                                                                           simpleTestCase "not present in update method" ecid $ \cid -> do
                                                                                             call cid (replyData (i2b getCertificatePresent))
                                                                                               >>= is "\0\0\0\0",
                                                                                           simpleTestCase "set and get" ecid $ \cid -> do
                                                                                             call_ cid $ setCertifiedData "FOO" >>> reply
                                                                                             query cid (replyData getCertificate) >>= extractCertData cid >>= is "FOO",
                                                                                           simpleTestCase "set twice" ecid $ \cid -> do
                                                                                             call_ cid $ setCertifiedData "FOO" >>> setCertifiedData "BAR" >>> reply
                                                                                             query cid (replyData getCertificate) >>= extractCertData cid >>= is "BAR",
                                                                                           simpleTestCase "set then trap" ecid $ \cid -> do
                                                                                             call_ cid $ setCertifiedData "FOO" >>> reply
                                                                                             call' cid (setCertifiedData "BAR" >>> trap "Trapped") >>= isReject [5]
                                                                                             query cid (replyData getCertificate) >>= extractCertData cid >>= is "FOO",
                                                                                           simpleTestCase "too large traps, old value retained" ecid $ \cid -> do
                                                                                             call_ cid $ setCertifiedData "FOO" >>> reply
                                                                                             call' cid (setCertifiedData (bytes (BS.replicate 33 0x42)) >>> reply)
                                                                                               >>= isReject [5]
                                                                                             query cid (replyData getCertificate) >>= extractCertData cid >>= is "FOO",
                                                                                           testCase "set in init" $ do
                                                                                             cid <- install ecid $ setCertifiedData "FOO"
                                                                                             query cid (replyData getCertificate) >>= extractCertData cid >>= is "FOO",
                                                                                           testCase "set in pre-upgrade" $ do
                                                                                             cid <- install ecid $ onPreUpgrade (callback $ setCertifiedData "FOO")
                                                                                             upgrade cid noop
                                                                                             query cid (replyData getCertificate) >>= extractCertData cid >>= is "FOO",
                                                                                           simpleTestCase "set in post-upgrade" ecid $ \cid -> do
                                                                                             upgrade cid $ setCertifiedData "FOO"
                                                                                             query cid (replyData getCertificate) >>= extractCertData cid >>= is "FOO",
                                                                                           simpleTestCase "cleared in reinstall" ecid $ \cid -> do
                                                                                             call_ cid $ setCertifiedData "FOO" >>> reply
                                                                                             query cid (replyData getCertificate) >>= extractCertData cid >>= is "FOO"
                                                                                             reinstall cid noop
                                                                                             query cid (replyData getCertificate) >>= extractCertData cid >>= is "",
                                                                                           simpleTestCase "cleared in uninstall" ecid $ \cid -> do
                                                                                             call_ cid $ setCertifiedData "FOO" >>> reply
                                                                                             query cid (replyData getCertificate) >>= extractCertData cid >>= is "FOO"
                                                                                             ic_uninstall ic00 cid
                                                                                             installAt cid noop
                                                                                             query cid (replyData getCertificate) >>= extractCertData cid >>= is ""
                                                                                         ],
                                                                                       testGroup "cycles" $
                                                                                         let replyBalance = replyData (i64tob getBalance)
                                                                                             replyBalance128 = replyData getBalance128
                                                                                             replyBalanceBalance128 = replyDataAppend (i64tob getBalance) >>> replyDataAppend getBalance128 >>> reply
                                                                                             rememberBalance =
                                                                                               ignore (stableGrow (int 1))
                                                                                                 >>> stableWrite (int 0) (i64tob getBalance)
                                                                                             recallBalance = replyData (stableRead (int 0) (int 8))
                                                                                             acceptAll = ignore (acceptCycles getAvailableCycles)
                                                                                             queryBalance cid = query cid replyBalance >>= asWord64
                                                                                             queryBalance128 cid = query cid replyBalance128 >>= asWord128
                                                                                             queryBalanceBalance128 cid = query cid replyBalanceBalance128 >>= asWord64Word128

                                                                                             -- At the time of writing, creating a canister needs at least 1T
                                                                                             -- and the freezing limit is 5T
                                                                                             -- (At some point, the max was 100T, but that is no longer the case)
                                                                                             -- So lets try to stay away from these limits.
                                                                                             -- The lowest denomination we deal with below is def_cycles`div`4
                                                                                             def_cycles = 80_000_000_000_000 :: Word64

                                                                                             -- The system burns cycles at unspecified rates. To cater for such behaviour,
                                                                                             -- we make the assumption that no test burns more than the following epsilon.
                                                                                             --
                                                                                             -- The biggest fee we currently deal with is the system deducing 1T
                                                                                             -- upon canister creation. So our epsilon needs to allow that and then
                                                                                             -- some more.
                                                                                             eps = 3_000_000_000_000 :: Integer

                                                                                             isRoughly :: (HasCallStack, Show a, Num a, Integral a, Show b, Num b, Integral b) => a -> b -> Assertion
                                                                                             isRoughly exp act =
                                                                                               assertBool
                                                                                                 (show act ++ " not near " ++ show exp)
                                                                                                 (abs (fromIntegral exp - fromIntegral act) < eps)

                                                                                             create prog = do
                                                                                               cid <- ic_provisional_create ic00 ecid Nothing (Just (fromIntegral def_cycles)) Nothing
                                                                                               installAt cid prog
                                                                                               return cid
                                                                                             create_via cid initial_cycles = do
                                                                                               cid2 <- ic_create (ic00viaWithCycles cid initial_cycles) ecid Nothing
                                                                                               universal_wasm <- getTestWasm "universal_canister.wasm.gz"
                                                                                               ic_install (ic00via cid) (enum #install) cid2 universal_wasm (run noop)
                                                                                               return cid2
                                                                                          in [ testGroup "cycles API - backward compatibility" $
                                                                                                 [ simpleTestCase "canister_cycle_balance = canister_cycle_balance128 for numbers fitting in 64 bits" ecid $ \cid -> do
                                                                                                     (a, b) <- queryBalanceBalance128 cid
                                                                                                     bothSame (a, fromIntegral b),
                                                                                                   testCase "legacy API traps when a result is too big" $ do
                                                                                                     cid <- create noop
                                                                                                     let large = 2 ^ (65 :: Int)
                                                                                                     ic_top_up ic00 cid large
                                                                                                     query' cid replyBalance >>= isQueryReject ecid [5]
                                                                                                     queryBalance128 cid >>= isRoughly (large + fromIntegral def_cycles)
                                                                                                 ],
                                                                                               testGroup "can use balance API" $
                                                                                                 let getBalanceTwice = join cat (i64tob getBalance)
                                                                                                     test = replyData getBalanceTwice
                                                                                                  in [ simpleTestCase "in query" ecid $ \cid ->
                                                                                                         query cid test >>= as2Word64 >>= bothSame,
                                                                                                       simpleTestCase "in update" ecid $ \cid ->
                                                                                                         call cid test >>= as2Word64 >>= bothSame,
                                                                                                       testCase "in init" $ do
                                                                                                         cid <- install ecid (setGlobal getBalanceTwice)
                                                                                                         query cid (replyData getGlobal) >>= as2Word64 >>= bothSame,
                                                                                                       simpleTestCase "in callback" ecid $ \cid ->
                                                                                                         call cid (inter_query cid defArgs {on_reply = test}) >>= as2Word64 >>= bothSame
                                                                                                     ],
                                                                                               testGroup "can use available cycles API" $
                                                                                                 let getAvailableCyclesTwice = join cat (i64tob getAvailableCycles)
                                                                                                     test = replyData getAvailableCyclesTwice
                                                                                                  in [ simpleTestCase "in update" ecid $ \cid ->
                                                                                                         call cid test >>= as2Word64 >>= bothSame,
                                                                                                       simpleTestCase "in callback" ecid $ \cid ->
                                                                                                         call cid (inter_query cid defArgs {on_reply = test}) >>= as2Word64 >>= bothSame
                                                                                                     ],
                                                                                               simpleTestCase "can accept zero cycles" ecid $ \cid ->
                                                                                                 call cid (replyData (i64tob (acceptCycles (int64 0)))) >>= asWord64 >>= is 0,
                                                                                               simpleTestCase "can accept more than available cycles" ecid $ \cid ->
                                                                                                 call cid (replyData (i64tob (acceptCycles (int64 1)))) >>= asWord64 >>= is 0,
                                                                                               simpleTestCase "can accept absurd amount of cycles" ecid $ \cid ->
                                                                                                 call cid (replyData (acceptCycles128 (int64 maxBound) (int64 maxBound))) >>= asWord128 >>= is 0,
                                                                                               testGroup
                                                                                                 "provisional_create_canister_with_cycles"
                                                                                                 [ testCase "balance as expected" $ do
                                                                                                     cid <- create noop
                                                                                                     queryBalance cid >>= isRoughly def_cycles,
                                                                                                   testCaseSteps "default (i.e. max) balance" $ \step -> do
                                                                                                     cid <- ic_provisional_create ic00 ecid Nothing Nothing Nothing
                                                                                                     installAt cid noop
                                                                                                     cycles <- queryBalance128 cid
                                                                                                     step $ "Cycle balance now at " ++ show cycles,
                                                                                                   testCaseSteps "> 2^128 succeeds" $ \step -> do
                                                                                                     cid <- ic_provisional_create ic00 ecid Nothing (Just (10 * 2 ^ (128 :: Int))) Nothing
                                                                                                     installAt cid noop
                                                                                                     cycles <- queryBalance128 cid
                                                                                                     step $ "Cycle balance now at " ++ show cycles
                                                                                                 ],
                                                                                               testCase "cycles in canister_status" $ do
                                                                                                 cid <- create noop
                                                                                                 cs <- ic_canister_status ic00 cid
                                                                                                 isRoughly def_cycles (cs .! #cycles),
                                                                                               testGroup
                                                                                                 "cycle balance"
                                                                                                 [ testCase "install" $ do
                                                                                                     cid <- create rememberBalance
                                                                                                     query cid recallBalance >>= asWord64 >>= isRoughly def_cycles,
                                                                                                   testCase "update" $ do
                                                                                                     cid <- create noop
                                                                                                     call cid replyBalance >>= asWord64 >>= isRoughly def_cycles,
                                                                                                   testCase "query" $ do
                                                                                                     cid <- create noop
                                                                                                     query cid replyBalance >>= asWord64 >>= isRoughly def_cycles,
                                                                                                   testCase "in pre_upgrade" $ do
                                                                                                     cid <- create $ onPreUpgrade (callback rememberBalance)
                                                                                                     upgrade cid noop
                                                                                                     query cid recallBalance >>= asWord64 >>= isRoughly def_cycles,
                                                                                                   testCase "in post_upgrade" $ do
                                                                                                     cid <- create noop
                                                                                                     upgrade cid rememberBalance
                                                                                                     query cid recallBalance >>= asWord64 >>= isRoughly def_cycles
                                                                                                     queryBalance cid >>= isRoughly def_cycles
                                                                                                 ],
                                                                                               testCase "can send cycles" $ do
                                                                                                 cid1 <- create noop
                                                                                                 cid2 <- create noop
                                                                                                 do
                                                                                                   call cid1 $
                                                                                                     inter_call
                                                                                                       cid2
                                                                                                       "update"
                                                                                                       defArgs
                                                                                                         { other_side =
                                                                                                             replyDataAppend (i64tob getAvailableCycles)
                                                                                                               >>> acceptAll
                                                                                                               >>> reply,
                                                                                                           cycles = def_cycles `div` 4
                                                                                                         }
                                                                                                   >>= isRelay
                                                                                                   >>= isReply
                                                                                                   >>= asWord64
                                                                                                   >>= isRoughly (def_cycles `div` 4)
                                                                                                 queryBalance cid1 >>= isRoughly (def_cycles - def_cycles `div` 4)
                                                                                                 queryBalance cid2 >>= isRoughly (def_cycles + def_cycles `div` 4),
                                                                                               testCase "sending more cycles than in balance traps" $ do
                                                                                                 cid <- create noop
                                                                                                 cycles <- queryBalance cid
                                                                                                 call' cid (inter_call cid cid defArgs {cycles = cycles + 1000_000})
                                                                                                   >>= isReject [5],
                                                                                               testCase "relay cycles before accept traps" $ do
                                                                                                 cid1 <- create noop
                                                                                                 cid2 <- create noop
                                                                                                 cid3 <- create noop
                                                                                                 do
                                                                                                   call cid1 $
                                                                                                     inter_call
                                                                                                       cid2
                                                                                                       "update"
                                                                                                       defArgs
                                                                                                         { cycles = def_cycles `div` 2,
                                                                                                           other_side =
                                                                                                             inter_call
                                                                                                               cid3
                                                                                                               "update"
                                                                                                               defArgs
                                                                                                                 { other_side = acceptAll >>> reply,
                                                                                                                   cycles = def_cycles + def_cycles `div` 4,
                                                                                                                   on_reply = noop -- must not double reply
                                                                                                                 }
                                                                                                               >>> acceptAll
                                                                                                               >>> reply,
                                                                                                           on_reply = trap "unexpected reply",
                                                                                                           on_reject = replyData (i64tob getRefund)
                                                                                                         }
                                                                                                   >>= asWord64
                                                                                                   >>= isRoughly (def_cycles `div` 2)
                                                                                                 queryBalance cid1 >>= isRoughly def_cycles
                                                                                                 queryBalance cid2 >>= isRoughly def_cycles
                                                                                                 queryBalance cid3 >>= isRoughly def_cycles,
                                                                                               testCase "relay cycles after accept works" $ do
                                                                                                 cid1 <- create noop
                                                                                                 cid2 <- create noop
                                                                                                 cid3 <- create noop
                                                                                                 do
                                                                                                   call cid1 $
                                                                                                     inter_call
                                                                                                       cid2
                                                                                                       "update"
                                                                                                       defArgs
                                                                                                         { cycles = def_cycles `div` 2,
                                                                                                           other_side =
                                                                                                             acceptAll
                                                                                                               >>> inter_call
                                                                                                                 cid3
                                                                                                                 "update"
                                                                                                                 defArgs
                                                                                                                   { other_side = acceptAll >>> reply,
                                                                                                                     cycles = def_cycles + def_cycles `div` 4
                                                                                                                   },
                                                                                                           on_reply = replyData (i64tob getRefund),
                                                                                                           on_reject = trap "unexpected reject"
                                                                                                         }
                                                                                                   >>= asWord64
                                                                                                   >>= isRoughly (0 :: Word64)
                                                                                                 queryBalance cid1 >>= isRoughly (def_cycles `div` 2)
                                                                                                 queryBalance cid2 >>= isRoughly (def_cycles `div` 4)
                                                                                                 queryBalance cid3 >>= isRoughly (2 * def_cycles + def_cycles `div` 4),
                                                                                               testCase "aborting call resets balance" $ do
                                                                                                 cid <- create noop
                                                                                                 (a, b) <-
                                                                                                   do
                                                                                                     call cid $
                                                                                                       callNew "Foo" "Bar" "baz" "quux"
                                                                                                         >>> callCyclesAdd (int64 (def_cycles `div` 2))
                                                                                                         >>> replyDataAppend (i64tob getBalance)
                                                                                                         >>> callNew "Foo" "Bar" "baz" "quux"
                                                                                                         >>> replyDataAppend (i64tob getBalance)
                                                                                                         >>> reply
                                                                                                     >>= as2Word64
                                                                                                 isRoughly (def_cycles `div` 2) a
                                                                                                 isRoughly def_cycles b,
                                                                                               testCase "partial refund" $ do
                                                                                                 cid1 <- create noop
                                                                                                 cid2 <- create noop
                                                                                                 do
                                                                                                   call cid1 $
                                                                                                     inter_call
                                                                                                       cid2
                                                                                                       "update"
                                                                                                       defArgs
                                                                                                         { cycles = def_cycles `div` 2,
                                                                                                           other_side = ignore (acceptCycles (int64 (def_cycles `div` 4))) >>> reply,
                                                                                                           on_reply = replyData (i64tob getRefund),
                                                                                                           on_reject = trap "unexpected reject"
                                                                                                         }
                                                                                                   >>= asWord64
                                                                                                   >>= isRoughly (def_cycles `div` 4)
                                                                                                 queryBalance cid1 >>= isRoughly (def_cycles - def_cycles `div` 4)
                                                                                                 queryBalance cid2 >>= isRoughly (def_cycles + def_cycles `div` 4),
                                                                                               testCase "cycles not in balance while in transit" $ do
                                                                                                 cid1 <- create noop
                                                                                                 do
                                                                                                   call cid1 $
                                                                                                     inter_call
                                                                                                       cid1
                                                                                                       "update"
                                                                                                       defArgs
                                                                                                         { cycles = def_cycles `div` 4,
                                                                                                           other_side = replyBalance,
                                                                                                           on_reject = trap "unexpected reject"
                                                                                                         }
                                                                                                   >>= isRelay
                                                                                                   >>= isReply
                                                                                                   >>= asWord64
                                                                                                   >>= isRoughly (def_cycles - def_cycles `div` 4)
                                                                                                 queryBalance cid1 >>= isRoughly def_cycles,
                                                                                               testCase "create and delete canister with cycles" $ do
                                                                                                 cid1 <- create noop
                                                                                                 cid2 <- create_via cid1 (def_cycles `div` 2)
                                                                                                 queryBalance cid1 >>= isRoughly (def_cycles `div` 2)
                                                                                                 queryBalance cid2 >>= isRoughly (def_cycles `div` 2)
                                                                                                 ic_stop_canister (ic00via cid1) cid2
                                                                                                 -- We load some cycles on the deletion call, just to check that they are refunded
                                                                                                 ic_delete_canister (ic00viaWithCycles cid1 (def_cycles `div` 4)) cid2
                                                                                                 queryBalance cid1 >>= isRoughly (def_cycles `div` 2),
                                                                                               testGroup
                                                                                                 "deposit_cycles"
                                                                                                 [ testCase "as controller" $ do
                                                                                                     cid1 <- create noop
                                                                                                     cid2 <- create_via cid1 (def_cycles `div` 2)
                                                                                                     queryBalance cid1 >>= isRoughly (def_cycles `div` 2)
                                                                                                     queryBalance cid2 >>= isRoughly (def_cycles `div` 2)
                                                                                                     ic_deposit_cycles (ic00viaWithCycles cid1 (def_cycles `div` 4)) cid2
                                                                                                     queryBalance cid1 >>= isRoughly (def_cycles `div` 4)
                                                                                                     queryBalance cid2 >>= isRoughly (def_cycles - def_cycles `div` 4),
                                                                                                   testCase "as other non-controlling canister" $ do
                                                                                                     cid1 <- create noop
                                                                                                     cid2 <- create_via cid1 (def_cycles `div` 2)
                                                                                                     queryBalance cid1 >>= isRoughly (def_cycles `div` 2)
                                                                                                     queryBalance cid2 >>= isRoughly (def_cycles `div` 2)
                                                                                                     ic_deposit_cycles (ic00viaWithCycles cid2 (def_cycles `div` 4)) cid1
                                                                                                     queryBalance cid1 >>= isRoughly (def_cycles - def_cycles `div` 4)
                                                                                                     queryBalance cid2 >>= isRoughly (def_cycles `div` 4),
                                                                                                   testCase "to non-existing canister" $ do
                                                                                                     cid1 <- create noop
                                                                                                     queryBalance cid1 >>= isRoughly def_cycles
                                                                                                     ic_deposit_cycles' (ic00viaWithCycles cid1 (def_cycles `div` 4)) doesn'tExist
                                                                                                       >>= isReject [3, 4, 5]
                                                                                                     queryBalance cid1 >>= isRoughly def_cycles
                                                                                                 ],
                                                                                               testCase "two-step-refund" $ do
                                                                                                 cid1 <- create noop
                                                                                                 do
                                                                                                   call cid1 $
                                                                                                     inter_call
                                                                                                       cid1
                                                                                                       "update"
                                                                                                       defArgs
                                                                                                         { cycles = 10,
                                                                                                           other_side =
                                                                                                             inter_call
                                                                                                               cid1
                                                                                                               "update"
                                                                                                               defArgs
                                                                                                                 { cycles = 5,
                                                                                                                   other_side = reply, -- no accept
                                                                                                                   on_reply =
                                                                                                                     -- remember refund
                                                                                                                     replyDataAppend (i64tob getRefund)
                                                                                                                       >>> reply,
                                                                                                                   on_reject = trap "unexpected reject"
                                                                                                                 },
                                                                                                           on_reply =
                                                                                                             -- remember the refund above and this refund
                                                                                                             replyDataAppend argData
                                                                                                               >>> replyDataAppend (i64tob getRefund)
                                                                                                               >>> reply,
                                                                                                           on_reject = trap "unexpected reject"
                                                                                                         }
                                                                                                   >>= as2Word64
                                                                                                   >>= is (5, 10)
                                                                                                 queryBalance cid1 >>= isRoughly def_cycles, -- nothing lost?
                                                                                               testGroup
                                                                                                 "provisional top up"
                                                                                                 [ testCase "as user" $ do
                                                                                                     cid <- create noop
                                                                                                     queryBalance cid >>= isRoughly def_cycles
                                                                                                     ic_top_up ic00 cid (fromIntegral def_cycles)
                                                                                                     queryBalance cid >>= isRoughly (2 * def_cycles),
                                                                                                   testCase "as self" $ do
                                                                                                     cid <- create noop
                                                                                                     queryBalance cid >>= isRoughly def_cycles
                                                                                                     ic_top_up (ic00via cid) cid (fromIntegral def_cycles)
                                                                                                     queryBalance cid >>= isRoughly (2 * def_cycles),
                                                                                                   testCase "as other canister" $ do
                                                                                                     cid <- create noop
                                                                                                     cid2 <- create noop
                                                                                                     queryBalance cid >>= isRoughly def_cycles
                                                                                                     ic_top_up (ic00via cid2) cid (fromIntegral def_cycles)
                                                                                                     queryBalance cid >>= isRoughly (2 * def_cycles),
                                                                                                   testCaseSteps "more than 2^128" $ \step -> do
                                                                                                     cid <- create noop
                                                                                                     ic_top_up ic00 cid (10 * 2 ^ (128 :: Int))
                                                                                                     cycles <- queryBalance128 cid
                                                                                                     step $ "Cycle balance now at " ++ show cycles,
                                                                                                   testCase "nonexisting canister" $ do
                                                                                                     ic_top_up''' ic00' unused_canister_id (fromIntegral def_cycles)
                                                                                                       >>= isErrOrReject [3, 5]
                                                                                                 ]
                                                                                             ],
                                                                                       testGroup
                                                                                         "canister_inspect_message"
                                                                                         [ testCase "empty canister" $ do
                                                                                             cid <- create ecid
                                                                                             call'' cid reply >>= isNoErrReject [5]
                                                                                             callToQuery'' cid reply >>= isNoErrReject [5],
                                                                                           testCase "accept all" $ do
                                                                                             cid <- install ecid $ onInspectMessage $ callback acceptMessage
                                                                                             call_ cid reply
                                                                                             callToQuery'' cid reply >>= is2xx >>= isReply >>= is "",
                                                                                           testCase "no accept_message" $ do
                                                                                             cid <- install ecid $ onInspectMessage $ callback noop
                                                                                             call'' cid reply >>= isNoErrReject [4]
                                                                                             callToQuery'' cid reply >>= isNoErrReject [4]
                                                                                             -- check that inter-canister calls still work
                                                                                             cid2 <- install ecid noop
                                                                                             call cid2 (inter_update cid defArgs)
                                                                                               >>= isRelay
                                                                                               >>= isReply
                                                                                               >>= is ("Hello " <> cid2 <> " this is " <> cid),
                                                                                           testCase "two calls to accept_message" $ do
                                                                                             cid <- install ecid $ onInspectMessage $ callback $ acceptMessage >>> acceptMessage
                                                                                             call'' cid reply >>= isNoErrReject [5]
                                                                                             callToQuery'' cid reply >>= isNoErrReject [5],
                                                                                           testCase "trap" $ do
                                                                                             cid <- install ecid $ onInspectMessage $ callback $ trap "no no no"
                                                                                             call'' cid reply >>= isNoErrReject [5]
                                                                                             callToQuery'' cid reply >>= isNoErrReject [5],
                                                                                           testCase "method_name correct" $ do
                                                                                             cid <-
                                                                                               install ecid $
                                                                                                 onInspectMessage $
                                                                                                   callback $
                                                                                                     trapIfEq methodName "update" "no no no" >>> acceptMessage

                                                                                             call'' cid reply >>= isNoErrReject [5]
                                                                                             callToQuery'' cid reply >>= is2xx >>= isReply >>= is "",
                                                                                           testCase "caller correct" $ do
                                                                                             cid <-
                                                                                               install ecid $
                                                                                                 onInspectMessage $
                                                                                                   callback $
                                                                                                     trapIfEq caller (bytes defaultUser) "no no no" >>> acceptMessage

                                                                                             call'' cid reply >>= isNoErrReject [5]
                                                                                             callToQuery'' cid reply >>= isNoErrReject [5]

                                                                                             awaitCall' cid (callRequestAs otherUser cid reply)
                                                                                               >>= is2xx
                                                                                               >>= isReply
                                                                                               >>= is ""
                                                                                             awaitCall' cid (callToQueryRequestAs otherUser cid reply)
                                                                                               >>= is2xx
                                                                                               >>= isReply
                                                                                               >>= is "",
                                                                                           testCase "arg correct" $ do
                                                                                             cid <-
                                                                                               install ecid $
                                                                                                 onInspectMessage $
                                                                                                   callback $
                                                                                                     trapIfEq argData (callback reply) "no no no" >>> acceptMessage

                                                                                             call'' cid reply >>= isNoErrReject [5]
                                                                                             callToQuery'' cid reply >>= isNoErrReject [5]

                                                                                             call cid (replyData "foo") >>= is "foo"
                                                                                             callToQuery'' cid (replyData "foo") >>= is2xx >>= isReply >>= is "foo",
                                                                                           testCase "management canister: raw_rand not accepted" $ do
                                                                                             ic_raw_rand'' defaultUser ecid >>= isNoErrReject [4],
                                                                                           testCase "management canister: http_request not accepted" $ do
                                                                                             ic_http_get_request'' defaultUser ecid httpbin_proto >>= isNoErrReject [4],
                                                                                           testCase "management canister: ecdsa_public_key not accepted" $ do
                                                                                             ic_ecdsa_public_key'' defaultUser ecid >>= isNoErrReject [4],
                                                                                           testCase "management canister: sign_with_ecdsa not accepted" $ do
                                                                                             ic_sign_with_ecdsa'' defaultUser ecid (sha256 "dummy") >>= isNoErrReject [4],
                                                                                           simpleTestCase "management canister: deposit_cycles not accepted" ecid $ \cid -> do
                                                                                             ic_deposit_cycles'' defaultUser cid >>= isNoErrReject [4],
                                                                                           simpleTestCase "management canister: wrong sender not accepted" ecid $ \cid -> do
                                                                                             ic_canister_status'' otherUser cid >>= isNoErrReject [5]
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
                                                                                               delegationEnv defaultSK dels req >>= postCallCBOR cid >>= code403

                                                                                             badRead cid req dels = do
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
                                                                                               delegationEnv defaultSK dels sreq >>= postReadStateCBOR cid >>= void . code403

                                                                                             badQuery cid req dels = do
                                                                                               req <- addExpiry req
                                                                                               -- sign request with delegations (should fail)
                                                                                               delegationEnv defaultSK dels req >>= postQueryCBOR cid >>= code403

                                                                                             goodTestCase name mkReq mkDels =
                                                                                               simpleTestCase name ecid $ \cid -> good cid (fst $ mkReq cid) (snd $ mkReq cid) (mkDels cid)

                                                                                             badTestCase name mkReq mkDels =
                                                                                               testGroup
                                                                                                 name
                                                                                                 [ simpleTestCase "in submit" ecid $ \cid -> badSubmit cid (fst $ mkReq cid) (mkDels cid),
                                                                                                   simpleTestCase "in read_state" ecid $ \cid -> badRead cid (fst $ mkReq cid) (mkDels cid),
                                                                                                   simpleTestCase "in query" ecid $ \cid -> badQuery cid (snd $ mkReq cid) (mkDels cid)
                                                                                                 ]

                                                                                             withEd25519 = zip [createSecretKeyEd25519 (BS.singleton n) | n <- [0 ..]]
                                                                                             withWebAuthnECDSA = zip [createSecretKeyWebAuthnECDSA (BS.singleton n) | n <- [0 ..]]
                                                                                             withWebAuthnRSA = zip [createSecretKeyWebAuthnRSA (BS.singleton n) | n <- [0 ..]]
                                                                                             withSelfLoop = zip [createSecretKeyEd25519 (BS.singleton n) | n <- repeat 0]
                                                                                             withCycle = zip [createSecretKeyEd25519 (BS.singleton n) | n <- [y | _ <- [(0 :: Integer) ..], y <- [0, 1]]]
                                                                                          in [ goodTestCase "one delegation, singleton target" callReq $ \cid ->
                                                                                                 withEd25519 [Just [cid]],
                                                                                               badTestCase "one delegation, wrong singleton target" callReq $ \_cid ->
                                                                                                 withEd25519 [Just [doesn'tExist]],
                                                                                               goodTestCase "one delegation, two targets" callReq $ \cid ->
                                                                                                 withEd25519 [Just [cid, doesn'tExist]],
                                                                                               goodTestCase "one delegation, many targets" callReq $ \cid ->
                                                                                                 withEd25519 [Just (cid : map wordToId' [0 .. 998])],
                                                                                               badTestCase "one delegation, too many targets" callReq $ \cid ->
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
                                                                                               badTestCase "two delegations, empty intersection" callReq $ \cid ->
                                                                                                 withEd25519 [Just [cid], Just [doesn'tExist]],
                                                                                               badTestCase "two delegations, first empty target set" callReq $ \cid ->
                                                                                                 withEd25519 [Just [], Just [cid]],
                                                                                               badTestCase "two delegations, second empty target set" callReq $ \cid ->
                                                                                                 withEd25519 [Just [cid], Just []],
                                                                                               goodTestCase "20 delegations" callReq $ \cid ->
                                                                                                 withEd25519 $ take 20 $ repeat $ Just [cid],
                                                                                               badTestCase "too many delegations" callReq $ \cid ->
                                                                                                 withEd25519 $ take 21 $ repeat $ Just [cid],
                                                                                               badTestCase "self-loop in delegations" callReq $ \cid ->
                                                                                                 withSelfLoop [Just [cid], Just [cid]],
                                                                                               badTestCase "cycle in delegations" callReq $ \cid ->
                                                                                                 withCycle [Just [cid], Just [cid], Just [cid]],
                                                                                               goodTestCase "management canister: correct target" mgmtReq $ \_cid ->
                                                                                                 withEd25519 [Just [""]],
                                                                                               badTestCase "management canister: empty target set" mgmtReq $ \_cid ->
                                                                                                 withEd25519 [Just []],
                                                                                               badTestCase "management canister: bogus target" mgmtReq $ \_cid ->
                                                                                                 withEd25519 [Just [doesn'tExist]],
                                                                                               badTestCase "management canister: bogus target (using target canister)" mgmtReq $ \cid ->
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
                                                                                                 [ simpleTestCase (name ++ " in query") ecid $ \cid -> do
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
                                                                                                   simpleTestCase (name ++ " in update") ecid $ \cid -> do
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
                                                                                               [ simpleTestCase "in query" ecid $ \cid -> do
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
                                                                                                 simpleTestCase "in empty read state request" ecid $ \cid -> do
                                                                                                   good_req <- addNonce >=> addExpiry $ readStateEmpty
                                                                                                   envelope defaultSK good_req >>= postReadStateCBOR cid >>= code2xx
                                                                                                   env (mod_req good_req) >>= postReadStateCBOR cid >>= code4xx,
                                                                                                 simpleTestCase "in call" ecid $ \cid -> do
                                                                                                   good_req <-
                                                                                                     addNonce >=> addExpiry $
                                                                                                       rec
                                                                                                         [ "request_type" =: GText "call",
                                                                                                           "sender" =: GBlob defaultUser,
                                                                                                           "canister_id" =: GBlob cid,
                                                                                                           "method_name" =: GText "query",
                                                                                                           "arg" =: GBlob (run reply)
                                                                                                         ]
                                                                                                   let req = mod_req good_req
                                                                                                   env req >>= postCallCBOR cid >>= code202_or_4xx

                                                                                                   -- Also check that the request was not created
                                                                                                   ingressDelay
                                                                                                   getRequestStatus defaultUser cid (requestId req) >>= is UnknownStatus

                                                                                                   -- check that with a valid signature, this would have worked
                                                                                                   awaitCall cid good_req >>= isReply >>= is ""
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
                                                                                                 let expiry = round ((t + 5 * 60) * 1000_000_000)
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
                                                                                                 let expiry = round ((t + 5 * 60) * 1000_000_000)
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
