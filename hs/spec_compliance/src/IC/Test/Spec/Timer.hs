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
module IC.Test.Spec.Timer (canister_timer_tests) where

import Codec.Candid (Principal (..))
import qualified Codec.Candid as Candid
import Data.ByteString.Builder
import Data.Row as R
import Data.Time.Clock.POSIX
import qualified Data.Vector as Vec
import IC.Management (InstallMode)
import IC.Test.Agent
import IC.Test.Agent.UnsafeCalls
import IC.Test.Spec.Utils
import IC.Test.Universal
import Test.Tasty
import Test.Tasty.HUnit

-- * The test suite (see below for helper functions)

canister_timer_tests :: (HasAgentConfig) => Blob -> [TestTree]
canister_timer_tests ecid =
  let on_timer_prog n = onGlobalTimer $ callback ((ignore $ stableGrow $ int 1) >>> (stableWrite (int 0) $ i64tob $ int64 $ fromIntegral n))
   in let set_timer_prog time = ((ignore $ stableGrow $ int 1) >>> (stableWrite (int 0) $ i64tob $ apiGlobalTimerSet $ int64 time))
       in let install_canister_with_global_timer n = install ecid $ on_timer_prog n
           in let reset_stable cid = call cid ((ignore $ stableGrow $ int 1) >>> (stableWrite (int 0) $ i64tob $ int64 42) >>> replyData "")
               in let get_stable cid = call cid (replyData $ stableRead (int 0) (int 8))
                   in let get_far_past_time = return 1
                       in let get_current_time = floor . (* 1e9) <$> getPOSIXTime
                           in let get_far_future_time = floor . (* 1e9) <$> (+) 100000 <$> getPOSIXTime
                               in let get_far_far_future_time = floor . (* 1e9) <$> (+) 1000000 <$> getPOSIXTime
                                   in let set_timer cid time = call cid (replyData $ i64tob $ apiGlobalTimerSet $ int64 time)
                                       in let blob = toLazyByteString . word64LE . fromIntegral
                                           in let wait_for_timer cid n = waitFor $ (\b -> return $ if b then Just () else Nothing) <$> (blob n ==) <$> get_stable cid
                                               in [ testCase "in update" $ do
                                                      cid <- install_canister_with_global_timer (2 :: Int)
                                                      _ <- reset_stable cid
                                                      far_future_time <- get_far_future_time
                                                      timer1 <- set_timer cid far_future_time
                                                      timer2 <- set_timer cid far_future_time
                                                      ctr <- get_stable cid
                                                      timer1 @?= blob 0
                                                      timer2 @?= blob far_future_time
                                                      ctr @?= blob 42,
                                                    testCase "in init" $ do
                                                      far_future_time <- get_far_future_time
                                                      cid <- install ecid $ on_timer_prog (2 :: Int) >>> set_timer_prog far_future_time
                                                      timer1 <- get_stable cid
                                                      timer2 <- set_timer cid far_future_time
                                                      timer1 @?= blob 0
                                                      timer2 @?= blob far_future_time,
                                                    testCase "in pre-upgrade" $ do
                                                      far_past_time <- get_far_past_time
                                                      far_future_time <- get_far_future_time
                                                      cid <- install ecid $ (on_timer_prog (2 :: Int) >>> onPreUpgrade (callback $ set_timer_prog far_past_time))
                                                      _ <- reset_stable cid
                                                      upgrade cid noop
                                                      timer1 <- get_stable cid
                                                      timer2 <- set_timer cid far_future_time
                                                      timer1 @?= blob 0
                                                      timer2 @?= blob 0,
                                                    testCase "in post-upgrade" $ do
                                                      cid <- install_canister_with_global_timer (2 :: Int)
                                                      _ <- reset_stable cid
                                                      far_future_time <- get_far_future_time
                                                      timer1 <- set_timer cid far_future_time
                                                      far_far_future_time <- get_far_far_future_time
                                                      upgrade cid (set_timer_prog far_far_future_time)
                                                      timer2 <- get_stable cid
                                                      timer3 <- set_timer cid far_future_time
                                                      timer1 @?= blob 0
                                                      timer2 @?= blob 0
                                                      timer3 @?= blob far_far_future_time,
                                                    testCase "in post-upgrade on stopped canister" $ do
                                                      cid <- install_canister_with_global_timer (2 :: Int)
                                                      _ <- reset_stable cid
                                                      far_future_time <- get_far_future_time
                                                      timer1 <- set_timer cid far_future_time
                                                      past_time <- get_far_past_time
                                                      _ <- ic_stop_canister ic00 cid
                                                      waitFor $ do
                                                        cs <- ic_canister_status ic00 cid
                                                        if cs .! #status == enum #stopped
                                                          then return $ Just ()
                                                          else return Nothing
                                                      upgrade cid (on_timer_prog (2 :: Int) >>> set_timer_prog past_time)
                                                      _ <- ic_start_canister ic00 cid
                                                      wait_for_timer cid 2
                                                      timer2 <- set_timer cid far_future_time
                                                      timer1 @?= blob 0
                                                      timer2 @?= blob 0,
                                                    testCase "in post-upgrade on stopping canister" $ do
                                                      let Just store_canister_id = tc_store_canister_id agentConfig
                                                      let Just ucan_chunk_hash = tc_ucan_chunk_hash agentConfig
                                                      cid <- install_canister_with_global_timer (2 :: Int)
                                                      _ <- reset_stable cid
                                                      far_future_time <- get_far_future_time
                                                      timer1 <- set_timer cid far_future_time
                                                      ic_set_controllers ic00 cid [defaultUser, store_canister_id]
                                                      past_time <- get_far_past_time
                                                      let upgrade =
                                                            update_call "" "install_chunked_code" $
                                                              defUpdateArgs
                                                                { uc_arg =
                                                                    Candid.encode $
                                                                      empty
                                                                        .+ #mode
                                                                        .== ((enumNothing #upgrade) :: InstallMode)
                                                                        .+ #target_canister
                                                                        .== Principal cid
                                                                        .+ #store_canister
                                                                        .== Principal store_canister_id
                                                                        .+ #chunk_hashes_list
                                                                        .== Vec.fromList [empty .+ #hash .== ucan_chunk_hash]
                                                                        .+ #wasm_module_hash
                                                                        .== ucan_chunk_hash
                                                                        .+ #arg
                                                                        .== (run $ on_timer_prog (2 :: Int) >>> set_timer_prog past_time)
                                                                }
                                                      let stop_and_upgrade =
                                                            ( oneway_call "" "stop_canister" $
                                                                defOneWayArgs
                                                                  { ow_arg = Candid.encode $ empty .+ #canister_id .== Principal cid
                                                                  }
                                                            )
                                                              >>> upgrade
                                                      let relay =
                                                            oneway_call store_canister_id "update" $
                                                              defOneWayArgs
                                                                { ow_arg = run stop_and_upgrade
                                                                }
                                                      call' cid relay >>= isReject [5] -- we get an error here because, to keep the canister stopping, we cannot reply after performing the one-way call
                                                      ic_start_canister ic00 cid
                                                      wait_for_timer cid 2
                                                      timer2 <- set_timer cid far_future_time
                                                      timer1 @?= blob 0
                                                      timer2 @?= blob 0,
                                                    testCase "in timer callback" $ do
                                                      past_time <- get_far_past_time
                                                      far_future_time <- get_far_future_time
                                                      cid <- install ecid $ onGlobalTimer $ callback $ set_timer_prog far_future_time -- the timer callback sets timer to far_future_time and stores the previous value of timer to stable memory
                                                      _ <- reset_stable cid -- stores 42 to stable memory
                                                      timer1 <- set_timer cid past_time -- sets timer to 1 and returns previous value of timer (0)
                                                      wait_for_timer cid 0 -- wait until stable memory stores 0 (previous value of timer assigned to stable memory by the timer callback)
                                                      timer2 <- set_timer cid far_future_time -- sets timer to far_future_time and returns previous value of timer (far_future_time set by the timer callback)
                                                      timer1 @?= blob 0
                                                      timer2 @?= blob far_future_time,
                                                    testCase "deactivate timer" $ do
                                                      cid <- install_canister_with_global_timer (2 :: Int)
                                                      _ <- reset_stable cid
                                                      far_future_time <- get_far_future_time
                                                      timer1 <- set_timer cid far_future_time
                                                      timer2 <- set_timer cid 0
                                                      timer3 <- set_timer cid far_future_time
                                                      ctr <- get_stable cid
                                                      timer1 @?= blob 0
                                                      timer2 @?= blob far_future_time
                                                      timer3 @?= blob 0
                                                      ctr @?= blob 42,
                                                    testCase "set timer far in the past" $ do
                                                      cid <- install_canister_with_global_timer (2 :: Int)
                                                      _ <- reset_stable cid
                                                      past_time <- get_far_past_time
                                                      timer1 <- set_timer cid past_time
                                                      wait_for_timer cid 2
                                                      future_time <- get_far_future_time
                                                      timer2 <- set_timer cid future_time
                                                      timer1 @?= blob 0
                                                      timer2 @?= blob 0,
                                                    testCase "set timer at current time" $ do
                                                      cid <- install_canister_with_global_timer (2 :: Int)
                                                      _ <- reset_stable cid
                                                      current_time <- get_current_time
                                                      timer1 <- set_timer cid current_time
                                                      wait_for_timer cid 2
                                                      future_time <- get_far_future_time
                                                      timer2 <- set_timer cid future_time
                                                      timer1 @?= blob 0
                                                      timer2 @?= blob 0,
                                                    testCase "stop and start canister" $ do
                                                      cid <- install_canister_with_global_timer (2 :: Int)
                                                      _ <- reset_stable cid
                                                      far_future_time <- get_far_future_time
                                                      timer1 <- set_timer cid far_future_time
                                                      timer2 <- set_timer cid far_future_time
                                                      _ <- ic_stop_canister ic00 cid
                                                      _ <- ic_start_canister ic00 cid
                                                      timer3 <- set_timer cid far_future_time
                                                      ctr <- get_stable cid
                                                      timer1 @?= blob 0
                                                      timer2 @?= blob far_future_time
                                                      timer3 @?= blob far_future_time
                                                      ctr @?= blob 42,
                                                    testCase "uninstall and install canister" $ do
                                                      cid <- install_canister_with_global_timer (2 :: Int)
                                                      _ <- reset_stable cid
                                                      far_future_time <- get_far_future_time
                                                      timer1 <- set_timer cid far_future_time
                                                      timer2 <- set_timer cid far_future_time
                                                      _ <- ic_uninstall ic00 cid
                                                      installAt cid (on_timer_prog (2 :: Int))
                                                      timer3 <- set_timer cid far_future_time
                                                      timer1 @?= blob 0
                                                      timer2 @?= blob far_future_time
                                                      timer3 @?= blob 0,
                                                    testCase "upgrade canister" $ do
                                                      cid <- install_canister_with_global_timer (2 :: Int)
                                                      _ <- reset_stable cid
                                                      far_future_time <- get_far_future_time
                                                      timer1 <- set_timer cid far_future_time
                                                      timer2 <- set_timer cid far_future_time
                                                      upgrade cid (on_timer_prog (2 :: Int))
                                                      timer3 <- set_timer cid far_future_time
                                                      timer1 @?= blob 0
                                                      timer2 @?= blob far_future_time
                                                      timer3 @?= blob 0,
                                                    testCase "reinstall canister" $ do
                                                      cid <- install_canister_with_global_timer (2 :: Int)
                                                      _ <- reset_stable cid
                                                      far_future_time <- get_far_future_time
                                                      timer1 <- set_timer cid far_future_time
                                                      timer2 <- set_timer cid far_future_time
                                                      reinstall cid (on_timer_prog (2 :: Int))
                                                      timer3 <- set_timer cid far_future_time
                                                      timer1 @?= blob 0
                                                      timer2 @?= blob far_future_time
                                                      timer3 @?= blob 0
                                                  ]
