{-# LANGUAGE ExplicitNamespaces #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedLabels #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TupleSections #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

-- |
--
-- This module contains a test suite for the Internet Computer
module IC.Test.Spec.CanisterHistory (canister_history_tests) where

import Codec.Candid
import Control.Monad
import Data.Row ((.!), (.+), (.==))
import qualified Data.Row as R
import qualified Data.Vector as Vec
import IC.Hash
import IC.Management
import IC.Test.Agent
import IC.Test.Agent.SafeCalls
import IC.Test.Agent.UnsafeCalls
import IC.Test.Agent.UserCalls
import IC.Test.Spec.Utils
import IC.Test.Universal
import IC.Types hiding (Blob)
import Test.Tasty
import Test.Tasty.HUnit

-- * The test suite

canister_history_tests :: (HasAgentConfig) => Blob -> [TestTree]
canister_history_tests ecid =
  let no_heartbeat = onHeartbeat (callback $ trap $ bytes "")
   in let get_canister_info cid canister_id num_requested_changes = ic_canister_info (ic00via cid) canister_id num_requested_changes
       in let check_history resp total cs = do
                (resp .! #total_num_changes) @?= total
                Vec.length (resp .! #recent_changes) @?= length cs
                forM (zip (Vec.toList $ resp .! #recent_changes) cs) $
                  \(c, (v, o, d)) -> do
                    c .! #canister_version @?= v
                    c .! #origin @?= mapChangeOrigin o
                    c .! #details @?= mapChangeDetails d
           in [ simpleTestCase "after creation and code deployments" ecid $ \unican -> do
                  universal_wasm <- getTestWasm "universal_canister.wasm.gz"

                  cid <- ic_provisional_create ic00 ecid Nothing Nothing Nothing
                  info <- get_canister_info unican cid (Just 1)
                  void $ check_history info 1 [(0, ChangeFromUser (EntityId defaultUser), Creation [(EntityId defaultUser)])]

                  ic_install ic00 (enum #install) cid universal_wasm (run no_heartbeat)
                  info <- get_canister_info unican cid (Just 1)
                  void $ check_history info 2 [(1, ChangeFromUser (EntityId defaultUser), CodeDeployment Install (sha256 universal_wasm))]

                  ic_install_with_sender_canister_version ic00 (enum #reinstall) cid trivialWasmModule "" (Just 666) -- sender_canister_version in ingress message is ignored
                  info <- get_canister_info unican cid (Just 1)
                  void $ check_history info 3 [(2, ChangeFromUser (EntityId defaultUser), CodeDeployment Reinstall (sha256 trivialWasmModule))]

                  ic_install ic00 (enumNothing #upgrade) cid universal_wasm (run no_heartbeat)
                  info <- get_canister_info unican cid (Just 1)
                  void $ check_history info 4 [(3, ChangeFromUser (EntityId defaultUser), CodeDeployment Upgrade (sha256 universal_wasm))]

                  return (),
                simpleTestCase "after uninstall" ecid $ \unican -> do
                  cid <- install ecid no_heartbeat

                  ic_uninstall ic00 cid
                  info <- get_canister_info unican cid (Just 1)
                  void $ check_history info 3 [(2, ChangeFromUser (EntityId defaultUser), CodeUninstall)],
                simpleTestCase "after changing controllers" ecid $ \unican -> do
                  cid <- create ecid

                  ic_set_controllers ic00 cid [otherUser, defaultUser, defaultUser]
                  info <- get_canister_info unican cid (Just 1)
                  void $ check_history info 2 [(1, ChangeFromUser (EntityId defaultUser), ControllersChange [EntityId otherUser, EntityId defaultUser])]

                  ic_set_controllers ic00 cid [defaultUser, otherUser, defaultUser]
                  info <- get_canister_info unican cid (Just 1)
                  void $ check_history info 3 [(2, ChangeFromUser (EntityId defaultUser), ControllersChange [EntityId otherUser, EntityId defaultUser])]

                  return (),
                simpleTestCase "after many changes" ecid $ \unican -> do
                  cid <- create ecid

                  void $ forM [1 .. 22] $ \_ -> ic_set_controllers ic00 cid [defaultUser]
                  info <- get_canister_info unican cid (Just 20)
                  let hist =
                        reverse $
                          take 20 $
                            reverse $
                              (0, ChangeFromUser (EntityId defaultUser), Creation [(EntityId defaultUser)])
                                : map (\i -> (i, ChangeFromUser (EntityId defaultUser), ControllersChange [EntityId defaultUser])) [1 .. 22]
                  void $ check_history info 23 hist

                  return (),
                testCase "changes from canister" $ do
                  unican <- install ecid no_heartbeat

                  cid <- ic_create_with_controllers (ic00viaWithCycles unican 20_000_000_000_000) ecid [unican, defaultUser]
                  info <- get_canister_info unican cid (Just 1)
                  void $ check_history info 1 [(0, ChangeFromCanister (EntityId unican) Nothing, Creation [EntityId unican, EntityId defaultUser])]

                  ic_install_with_sender_canister_version (ic00via unican) (enum #install) cid trivialWasmModule "" (Just 5)
                  info <- get_canister_info unican cid (Just 1)
                  void $ check_history info 2 [(1, ChangeFromCanister (EntityId unican) (Just 5), CodeDeployment Install (sha256 trivialWasmModule))]

                  return (),
                simpleTestCase "does not track all update_settings calls" ecid $ \unican -> do
                  cid <- ic_provisional_create ic00 ecid Nothing Nothing Nothing
                  ic_set_freezing_threshold ic00 cid (2 ^ 10) -- not stored in canister history; canister version still bumped
                  ic_install ic00 (enum #install) cid trivialWasmModule ""

                  info <- get_canister_info unican cid (Just 2)
                  void $
                    check_history
                      info
                      2
                      [ (0, ChangeFromUser (EntityId defaultUser), Creation [(EntityId defaultUser)]),
                        (2, ChangeFromUser (EntityId defaultUser), CodeDeployment Install (sha256 trivialWasmModule))
                      ],
                testCase "incorrect sender_canister_version" $ do
                  unican <- install ecid no_heartbeat
                  ic_create_with_sender_canister_version' (ic00via unican) ecid (Just 666) Nothing >>= isReject [5],
                simpleTestCase "user call to canister_info" ecid $ \cid ->
                  ic_canister_info'' defaultUser cid Nothing >>= is2xx >>= isReject [4],
                simpleTestCase "calling canister_info" ecid $ \unican -> do
                  universal_wasm <- getTestWasm "universal_canister.wasm.gz"

                  cid <- ic_provisional_create ic00 ecid Nothing Nothing Nothing
                  ic_install ic00 (enum #install) cid trivialWasmModule ""
                  ic_install ic00 (enum #reinstall) cid universal_wasm (run no_heartbeat)

                  info <- get_canister_info unican cid Nothing
                  info .! #controllers @?= (Vec.fromList [Principal defaultUser])
                  info .! #module_hash @?= (Just $ sha256 universal_wasm)

                  ic_install ic00 (enumNothing #upgrade) cid trivialWasmModule ""

                  info <- get_canister_info unican cid Nothing
                  info .! #controllers @?= (Vec.fromList [Principal defaultUser])
                  info .! #module_hash @?= (Just $ sha256 trivialWasmModule)

                  ic_uninstall ic00 cid
                  ic_set_controllers ic00 cid [defaultUser, otherUser, defaultUser]

                  info <- get_canister_info unican cid Nothing
                  void $ check_history info 6 []
                  info .! #controllers @?= (Vec.fromList [Principal otherUser, Principal defaultUser])
                  info .! #module_hash @?= Nothing

                  let hist =
                        [ (0, ChangeFromUser (EntityId defaultUser), Creation [(EntityId defaultUser)]),
                          (1, ChangeFromUser (EntityId defaultUser), CodeDeployment Install (sha256 trivialWasmModule)),
                          (2, ChangeFromUser (EntityId defaultUser), CodeDeployment Reinstall (sha256 universal_wasm)),
                          (3, ChangeFromUser (EntityId defaultUser), CodeDeployment Upgrade (sha256 trivialWasmModule)),
                          (4, ChangeFromUser (EntityId defaultUser), CodeUninstall),
                          (5, ChangeFromUser (EntityId defaultUser), ControllersChange [EntityId otherUser, EntityId defaultUser])
                        ]

                  info <- get_canister_info unican cid (Just 0)
                  void $ check_history info 6 []

                  info <- get_canister_info unican cid (Just 1)
                  void $ check_history info 6 [last hist]

                  info <- get_canister_info unican cid (Just 2)
                  void $ check_history info 6 (reverse $ take 2 $ reverse hist)

                  info <- get_canister_info unican cid (Just 6)
                  void $ check_history info 6 hist

                  info <- get_canister_info unican cid (Just 20)
                  void $ check_history info 6 hist

                  info <- get_canister_info unican cid (Just 200)
                  void $ check_history info 6 hist
              ]
