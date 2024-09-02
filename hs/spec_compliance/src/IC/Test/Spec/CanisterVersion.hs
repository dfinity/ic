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
module IC.Test.Spec.CanisterVersion (canister_version_tests) where

import Data.ByteString.Builder
import Data.Row as R
import IC.Test.Agent
import IC.Test.Agent.SafeCalls
import IC.Test.Agent.UnsafeCalls
import IC.Test.Agent.UserCalls
import IC.Test.Spec.Utils
import IC.Test.Universal
import Test.Tasty
import Test.Tasty.HUnit

-- * The test suite

canister_version_tests :: (HasAgentConfig) => Blob -> [TestTree]
canister_version_tests ecid =
  let canister_version = i64tob canisterVersion
   in let no_heartbeat = onHeartbeat (callback $ trap $ bytes "")
       in let simpleTestCase name ecid act = testCase name $ install ecid no_heartbeat >>= act
           in let get_global cid = query cid $ replyData getGlobal
               in let blob = toLazyByteString . word64LE . fromIntegral
                   in let wait_for_global cid n = waitFor $ (\b -> return $ if b then Just () else Nothing) <$> (blob n ==) <$> get_global cid
                       in [ simpleTestCase "in query" ecid $ \cid -> do
                              ctr <- query cid (replyData canister_version) >>= asWord64
                              ctr @?= 1
                              ctr <- query cid (replyData canister_version) >>= asWord64
                              ctr @?= 1
                              ctr <- query cid (replyData canister_version) >>= asWord64
                              ctr @?= 1,
                            simpleTestCase "in replicated query" ecid $ \cid -> do
                              ctr <- callToQuery'' cid (replyData canister_version) >>= is2xx >>= isReply >>= asWord64
                              ctr @?= 1
                              ctr <- callToQuery'' cid (replyData canister_version) >>= is2xx >>= isReply >>= asWord64
                              ctr @?= 1
                              ctr <- callToQuery'' cid (replyData canister_version) >>= is2xx >>= isReply >>= asWord64
                              ctr @?= 1,
                            simpleTestCase "in update" ecid $ \cid -> do
                              ctr <- call cid (replyData canister_version) >>= asWord64
                              ctr @?= 1
                              ctr <- call cid (replyData canister_version) >>= asWord64
                              ctr @?= 2
                              ctr <- call cid (replyData canister_version) >>= asWord64
                              ctr @?= 3,
                            testCase "in install" $ do
                              cid <- install ecid $ no_heartbeat >>> setGlobal canister_version
                              ctr1 <- query cid (replyData getGlobal) >>= asWord64
                              ctr2 <- query cid (replyData canister_version) >>= asWord64
                              ctr1 @?= 1
                              ctr2 @?= 1,
                            simpleTestCase "in reinstall" ecid $ \cid -> do
                              ctr1 <- query cid (replyData canister_version) >>= asWord64
                              _ <- reinstall cid $ no_heartbeat >>> setGlobal canister_version
                              ctr2 <- query cid (replyData getGlobal) >>= asWord64
                              ctr3 <- query cid (replyData canister_version) >>= asWord64
                              ctr1 @?= 1
                              ctr2 @?= 2
                              ctr3 @?= 2,
                            testCase "in pre_upgrade" $ do
                              cid <-
                                install ecid $
                                  no_heartbeat
                                    >>> ignore (stableGrow (int 1))
                                    >>> onPreUpgrade (callback $ stableWrite (int 0) canister_version)
                              ctr1 <- query cid (replyData canister_version) >>= asWord64
                              upgrade cid no_heartbeat
                              ctr2 <- query cid (replyData (stableRead (int 0) (int 8))) >>= asWord64
                              ctr3 <- query cid (replyData canister_version) >>= asWord64
                              ctr1 @?= 1
                              ctr2 @?= 1
                              ctr3 @?= 2,
                            simpleTestCase "in post_upgrade" ecid $ \cid -> do
                              ctr1 <- query cid (replyData canister_version) >>= asWord64
                              upgrade cid $ no_heartbeat >>> setGlobal canister_version
                              ctr2 <- query cid (replyData getGlobal) >>= asWord64
                              ctr3 <- query cid (replyData canister_version) >>= asWord64
                              ctr1 @?= 1
                              ctr2 @?= 2
                              ctr3 @?= 2,
                            testCase "in heartbeat" $ do
                              cid <-
                                install ecid $
                                  onHeartbeat (callback $ trapIfNeq canister_version (i64tob $ int64 1) "" >>> setGlobal canister_version)
                              wait_for_global cid (1 :: Int)
                              ctr1 <- query cid (replyData getGlobal) >>= asWord64
                              ctr2 <- query cid (replyData canister_version) >>= asWord64
                              ctr1 @?= 1
                              ctr2 @?= 2,
                            testCase "in global timer" $ do
                              cid <-
                                install ecid $
                                  no_heartbeat
                                    >>> onGlobalTimer (callback $ setGlobal canister_version)
                                    >>> ignore (apiGlobalTimerSet $ int64 1)
                              wait_for_global cid (1 :: Int)
                              ctr1 <- query cid (replyData getGlobal) >>= asWord64
                              ctr2 <- query cid (replyData canister_version) >>= asWord64
                              ctr1 @?= 1
                              ctr2 @?= 2,
                            simpleTestCase "in reply callback" ecid $ \cid -> do
                              cid2 <- install ecid noop
                              ctr1 <- query cid (replyData canister_version) >>= asWord64
                              ctr2 <-
                                call
                                  cid
                                  ( inter_call
                                      cid2
                                      "update"
                                      defArgs
                                        { on_reply = replyData canister_version,
                                          on_reject = trap $ bytes "" -- make test fail if reject callback was executed
                                        }
                                  )
                                  >>= asWord64
                              ctr3 <- query cid (replyData canister_version) >>= asWord64
                              ctr1 @?= 1
                              ctr2 @?= 2
                              ctr3 @?= 3,
                            simpleTestCase "in reject callback" ecid $ \cid -> do
                              cid2 <- install ecid noop
                              ctr1 <- query cid (replyData canister_version) >>= asWord64
                              ctr2 <-
                                call
                                  cid
                                  ( inter_call
                                      cid2
                                      "update"
                                      defArgs
                                        { on_reply = trap $ bytes "", -- make test fail if reply callback was executed
                                          on_reject = replyData canister_version,
                                          other_side = trap $ bytes "" -- other side traps which triggers reject callback
                                        }
                                  )
                                  >>= asWord64
                              ctr3 <- query cid (replyData canister_version) >>= asWord64
                              ctr1 @?= 1
                              ctr2 @?= 2
                              ctr3 @?= 3,
                            simpleTestCase "in cleanup" ecid $ \cid -> do
                              cid2 <- install ecid noop
                              ctr1 <- query cid (replyData canister_version) >>= asWord64
                              call'
                                cid
                                ( inter_call
                                    cid2
                                    "update"
                                    defArgs
                                      { on_reply = trap $ bytes "",
                                        on_reject = trap $ bytes "", -- make test fail if reject callback was executed
                                        on_cleanup = Just $ (setGlobal canister_version)
                                      }
                                )
                                >>= isReject [5]
                              ctr2 <- query cid (replyData getGlobal) >>= asWord64
                              ctr3 <- query cid (replyData canister_version) >>= asWord64
                              ctr1 @?= 1
                              ctr2 @?= 2
                              ctr3 @?= 3,
                            simpleTestCase "after uninstall" ecid $ \cid -> do
                              ctr1 <- query cid (replyData canister_version) >>= asWord64
                              ic_uninstall ic00 cid
                              installAt cid no_heartbeat
                              ctr2 <- query cid (replyData canister_version) >>= asWord64
                              ctr1 @?= 1
                              ctr2 @?= 3, -- code uninstalled and installed since the last query
                            simpleTestCase "after setting controllers" ecid $ \cid -> do
                              ctr1 <- query cid (replyData canister_version) >>= asWord64
                              ic_set_controllers ic00 cid [otherUser]
                              ctr2 <- query cid (replyData canister_version) >>= asWord64
                              ctr1 @?= 1
                              ctr2 @?= 2,
                            simpleTestCase "after setting freezing threshold" ecid $ \cid -> do
                              ctr1 <- query cid (replyData canister_version) >>= asWord64
                              ic_set_freezing_threshold ic00 cid (2 ^ 20)
                              ctr2 <- query cid (replyData canister_version) >>= asWord64
                              ctr1 @?= 1
                              ctr2 @?= 2,
                            simpleTestCase "after failed query" ecid $ \cid -> do
                              ctr1 <- query cid (replyData canister_version) >>= asWord64
                              query' cid (trap "") >>= isQueryReject ecid [5]
                              ctr2 <- query cid (replyData canister_version) >>= asWord64
                              ctr1 @?= 1
                              ctr2 @?= 1,
                            simpleTestCase "after failed update" ecid $ \cid -> do
                              ctr1 <- query cid (replyData canister_version) >>= asWord64
                              call' cid (trap "") >>= isReject [5]
                              ctr2 <- query cid (replyData canister_version) >>= asWord64
                              ctr1 @?= 1
                              ctr2 @?= 1,
                            simpleTestCase "after failed install" ecid $ \cid -> do
                              ctr1 <- query cid (replyData canister_version) >>= asWord64
                              ic_install' ic00 (enum #install) cid "" "" >>= isReject [5]
                              ctr2 <- query cid (replyData canister_version) >>= asWord64
                              ctr1 @?= 1
                              ctr2 @?= 1,
                            testCase "after failed init in install" $ do
                              cid <- create ecid
                              install' cid (trap $ bytes "") >>= isReject [5]
                              _ <- installAt cid $ no_heartbeat
                              ctr <- query cid (replyData canister_version) >>= asWord64
                              ctr @?= 1,
                            simpleTestCase "after failed reinstall" ecid $ \cid -> do
                              ctr1 <- query cid (replyData canister_version) >>= asWord64
                              ic_install' ic00 (enum #reinstall) cid "" "" >>= isReject [5]
                              ctr2 <- query cid (replyData canister_version) >>= asWord64
                              ctr1 @?= 1
                              ctr2 @?= 1,
                            simpleTestCase "after failed init in reinstall" ecid $ \cid -> do
                              ctr1 <- query cid (replyData canister_version) >>= asWord64
                              reinstall' cid (trap $ bytes "") >>= isReject [5]
                              ctr2 <- query cid (replyData canister_version) >>= asWord64
                              ctr1 @?= 1
                              ctr2 @?= 1,
                            simpleTestCase "after failed upgrade" ecid $ \cid -> do
                              ctr1 <- query cid (replyData canister_version) >>= asWord64
                              ic_install' ic00 (enumNothing #upgrade) cid "" "" >>= isReject [5]
                              ctr2 <- query cid (replyData canister_version) >>= asWord64
                              ctr1 @?= 1
                              ctr2 @?= 1,
                            testCase "after failed pre_upgrade" $ do
                              cid <-
                                install ecid $
                                  no_heartbeat
                                    >>> onPreUpgrade (callback $ trap $ bytes "")
                              ctr1 <- query cid (replyData canister_version) >>= asWord64
                              upgrade' cid no_heartbeat >>= isReject [5]
                              ctr2 <- query cid (replyData canister_version) >>= asWord64
                              ctr1 @?= 1
                              ctr2 @?= 1,
                            simpleTestCase "after failed post_upgrade" ecid $ \cid -> do
                              ctr1 <- query cid (replyData canister_version) >>= asWord64
                              upgrade' cid (trap $ bytes "") >>= isReject [5]
                              ctr2 <- query cid (replyData canister_version) >>= asWord64
                              ctr1 @?= 1
                              ctr2 @?= 1,
                            testCase "after failed heartbeat" $ do
                              cid <- install ecid $ onHeartbeat (callback $ trap $ bytes "")
                              ctr1 <- query cid (replyData canister_version) >>= asWord64
                              -- The spec currently gives no guarantee about when or how frequent heartbeats are executed.
                              -- But all implementations have the property: if update call B is submitted after call A is completed,
                              -- then a heartbeat runs before the execution of B.
                              -- We use this here to make sure that heartbeats have been attempted:
                              call_ cid reply
                              call_ cid reply
                              ctr2 <- query cid (replyData canister_version) >>= asWord64
                              ctr1 @?= 1
                              ctr2 @?= 3, -- only two update calls have been executed, but no heartbeats
                            testCase "after failed global timer" $ do
                              cid <-
                                install ecid $
                                  no_heartbeat
                                    >>> onGlobalTimer (callback $ trap $ bytes "")
                                    >>> ignore (apiGlobalTimerSet $ int64 1)
                              ctr1 <- query cid (replyData canister_version) >>= asWord64
                              -- The spec currently gives no guarantee about when or how frequent global timers are executed.
                              -- But all implementations have the property: if update call B is submitted after call A is completed,
                              -- then a global timer runs before the execution of B.
                              -- We use this here to make sure that global timers have been attempted:
                              call_ cid reply
                              call_ cid reply
                              ctr2 <- query cid (replyData canister_version) >>= asWord64
                              ctr1 @?= 1
                              ctr2 @?= 3, -- only two update calls have been executed, but no global timers
                            simpleTestCase "after failed reply callback" ecid $ \cid -> do
                              cid2 <- install ecid noop
                              ctr1 <- query cid (replyData canister_version) >>= asWord64
                              call'
                                cid
                                ( inter_call
                                    cid2
                                    "update"
                                    defArgs
                                      { on_reply = trap $ bytes "",
                                        on_reject = replyData "" -- make test fail if reject callback was executed
                                      }
                                )
                                >>= isReject [5]
                              ctr2 <- query cid (replyData canister_version) >>= asWord64
                              ctr1 @?= 1
                              ctr2 @?= 2, -- update was executed, but callback trapped and no cleanup was provided
                            simpleTestCase "after failed reject callback" ecid $ \cid -> do
                              cid2 <- install ecid noop
                              ctr1 <- query cid (replyData canister_version) >>= asWord64
                              call'
                                cid
                                ( inter_call
                                    cid2
                                    "update"
                                    defArgs
                                      { on_reply = replyData "", -- make test fail if reply callback was executed
                                        on_reject = trap $ bytes "",
                                        other_side = trap $ bytes "" -- other side traps which triggers reject callback
                                      }
                                )
                                >>= isReject [5]
                              ctr2 <- query cid (replyData canister_version) >>= asWord64
                              ctr1 @?= 1
                              ctr2 @?= 2, -- update was executed, but callback trapped and no cleanup was provided
                            simpleTestCase "after failed cleanup" ecid $ \cid -> do
                              cid2 <- install ecid noop
                              ctr1 <- query cid (replyData canister_version) >>= asWord64
                              call'
                                cid
                                ( inter_call
                                    cid2
                                    "update"
                                    defArgs
                                      { on_reply = trap $ bytes "",
                                        on_reject = replyData "", -- make test fail if reject callback was executed
                                        on_cleanup = Just $ trap $ bytes ""
                                      }
                                )
                                >>= isReject [5]
                              ctr2 <- query cid (replyData canister_version) >>= asWord64
                              ctr1 @?= 1
                              ctr2 @?= 2, -- update was executed, but callback and cleanup both trapped
                            simpleTestCase "after failed uninstall" ecid $ \cid -> do
                              ctr1 <- query cid (replyData canister_version) >>= asWord64
                              ic_uninstall'' otherUser cid >>= isErrOrReject [5]
                              ctr2 <- query cid (replyData canister_version) >>= asWord64
                              ctr1 @?= 1
                              ctr2 @?= 1,
                            simpleTestCase "after failed change of settings" ecid $ \cid -> do
                              ctr1 <- query cid (replyData canister_version) >>= asWord64
                              ic_set_freezing_threshold' ic00 cid (2 ^ 70) >>= isReject [5]
                              ctr2 <- query cid (replyData canister_version) >>= asWord64
                              ctr1 @?= 1
                              ctr2 @?= 1
                          ]
