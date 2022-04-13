{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Analyzer.Ekg (getRules, getLog, Log (..)) where

import Analyzer.Types
import Data.Aeson
import Data.Fixed
import Data.List
import Data.Time.Clock
import LTL

getRules :: EKGRule -> [LTL Observation]
getRules MaliciouslyProposeEquivocatingBlocks = [maliciousBehaviour 6]
getRules MaliciouslyProposeEmptyBlock = [maliciousBehaviour 7]
getRules MaliciouslyFinalizeAll = [maliciousBehaviour 8]
getRules MaliciouslyNotarizeAll = [maliciousBehaviour 9]
getRules MaliciouslyCorruptOwnStateAtHeight = [maliciousBehaviour 14]
getRules NoChildDied = [noChildDied]
getRules NoErrorLogMessage = [noErrorLogMessage]
getRules FinalizedHashesAgree = [finalizedHashesAgree]
getRules (FinalizedHeightWithin t) = [finalizedHeightWithin t]
getRules BasicMonitoring = [noChildDied, noErrorLogMessage, finalizedHeightWithin 80, finalizedHashesAgree]
getRules DivergedReplicaEventuallyConsistent = [divergedReplicaEventuallyConsistent]

noChildDied :: LTL Observation
noChildDied = always $
  examine $ \o -> case getExited o of
    Nothing -> top
    Just e ->
      bottomUnless (exStatus e == 0) $
        "child exited with status code: " ++ show (exStatus e)

data Exited = Exited
  { exStatus :: !Int
  }
  deriving (Show)

instance FromJSON Exited where
  parseJSON = withObject "Exited" $ \obj ->
    Exited
      <$> obj .: "status"

getExited :: Observation -> Maybe Exited
getExited Observation {obKind = ObKindNode, obSubkind = "Exited", obEvent = ExternalEvent v} = resultToMaybe $ fromJSON v
getExited _ = Nothing

noErrorLogMessage :: LTL Observation
noErrorLogMessage =
  always $
    examine $ \o -> case getLog o of
      Nothing -> top
      Just l ->
        bottomWhen (errOrCrit l && nonBoot l) $
          "unexpected log message: [" ++ logLevel l ++ "] " ++ logMessage l
  where
    errOrCrit l = logLevel l `elem` ["CRITICAL", "ERROR"]
    -- in legacy system tests, we have to ignore such messages
    nonBoot l = not $ "Could not confirm the boot" `isInfixOf` logMessage l

data Log = Log
  { logLevel :: !String,
    logMessage :: !String,
    logNodeId :: !String
  }
  deriving (Show)

instance FromJSON Log where
  parseJSON = withObject "Log" $ \obj -> do
    entry <- obj .: "log_entry"
    Log
      <$> (entry .: "level")
      <*> (entry .: "message")
      <*> (entry .: "node_id")

getLog :: Observation -> Maybe Log
getLog Observation {obKind = ObKindNode, obSubkind = "Log", obEvent = ExternalEvent v} = resultToMaybe $ fromJSON v
getLog _ = Nothing

maliciousBehaviour :: Int -> LTL Observation
maliciousBehaviour c = eventually $
  examine $ \o ->
    case getMaliciousBehaviour o of
      Nothing -> bottom "not a malicious behaviour"
      Just (MaliciousBehaviour mb) ->
        bottomUnless (mb == c) $
          "malicious behaviour " ++ show mb ++ " expected, but not found"

data MaliciousBehaviour = MaliciousBehaviour Int deriving (Show)

instance FromJSON MaliciousBehaviour where
  parseJSON = withObject "MaliciousBehaviour" $ \obj ->
    fmap MaliciousBehaviour $ obj .: "log_entry" >>= (.: "malicious_behaviour") >>= (.: "malicious_behaviour")

getMaliciousBehaviour :: Observation -> Maybe MaliciousBehaviour
getMaliciousBehaviour Observation {obKind = ObKindNode, obSubkind = "Log", obEvent = ExternalEvent v} = resultToMaybe $ fromJSON v
getMaliciousBehaviour _ = Nothing

finalizedHeightWithin :: Pico -> LTL Observation
finalizedHeightWithin timelimit = always $ examine step
  where
    step :: Observation -> LTL Observation
    step o = case getFinalizationEvent o of
      Nothing -> top
      Just fe -> next $
        always $
          examine $ \nextO -> case getFinalizationEvent nextO of
            Nothing -> top
            Just nextFe ->
              if consecutive fe nextFe
                then
                  bottomUnless (closerThan (feTimestamp fe) (feTimestamp nextFe) timelimit) $
                    "finalization took too long: " ++ show fe ++ " -> " ++ show nextFe
                else top

    closerThan :: UTCTime -> UTCTime -> Pico -> Bool
    closerThan t1 t2 maxGap = diffUTCTime t2 t1 <= secondsToNominalDiffTime maxGap

    consecutive :: FinalizationEvent -> FinalizationEvent -> Bool
    consecutive before after =
      (succ (feHeight before) == feHeight after)
        && (feSubnetId before == feSubnetId after)

finalizedHashesAgree :: LTL Observation
finalizedHashesAgree = always $ examine step
  where
    step :: Observation -> LTL Observation
    step o = case getFinalizationEvent o of
      Nothing -> top
      Just fe -> next $
        always $
          examine $ \nextO -> case getFinalizationEvent nextO of
            Nothing -> top
            Just nextFe ->
              if sameHeightAndSubnet fe nextFe
                then
                  bottomUnless (feHash fe == feHash nextFe) $
                    "finalized hashes do not match: " ++ show fe ++ " != " ++ show nextFe
                else top

    sameHeightAndSubnet :: FinalizationEvent -> FinalizationEvent -> Bool
    sameHeightAndSubnet fe1 fe2 =
      (feHeight fe1 == feHeight fe2)
        && (feSubnetId fe1 == feSubnetId fe2)

data FinalizationEvent = FinalizationEvent
  { feHeight :: !Int,
    feHash :: !String,
    feSubnetId :: !String,
    feTimestamp :: !UTCTime
  }
  deriving (Show)

instance FromJSON FinalizationEvent where
  parseJSON = withObject "FinalizationEvent" $ \obj -> do
    entry <- obj .: "log_entry"
    consensus <- entry .: "consensus"
    FinalizationEvent
      <$> (consensus .: "height")
      <*> (consensus .: "hash")
      <*> (entry .: "subnet_id")
      <*> (entry .: "utc_time")

getFinalizationEvent :: Observation -> Maybe FinalizationEvent
getFinalizationEvent Observation {obKind = ObKindNode, obSubkind = "Log", obEvent = ExternalEvent v} = resultToMaybe $ fromJSON v
getFinalizationEvent _ = Nothing

resultToMaybe :: Result a -> Maybe a
resultToMaybe (Data.Aeson.Error _) = Nothing
resultToMaybe (Data.Aeson.Success r) = Just r

divergedReplicaEventuallyConsistent :: LTL Observation
divergedReplicaEventuallyConsistent = eventually $ examine step
  where
    step :: Observation -> LTL Observation
    step o = case getLog o of
      Nothing -> bottom "not a log event"
      Just fe ->
        if divergence fe
          then next $
            eventually $
              examine $ \nextO -> case getLog nextO of
                Nothing -> bottom "not a log event"
                Just nextFe ->
                  bottomUnless (cup nextFe && logNodeId fe == logNodeId nextFe) $
                    "missing a CUP for node" ++ show (logNodeId nextFe)
          else bottom $ "divergence event not found for node: " ++ show (logNodeId fe)

    check msg l = isPrefixOf msg (logMessage l)
    divergence = check "Replica diverged"
    cup = check "Proposing a CatchUpPackageShare"

bottomUnless :: Bool -> String -> LTL Observation
bottomUnless condition errMsg
  | condition = top
  | otherwise = bottom errMsg

bottomWhen :: Bool -> String -> LTL Observation
bottomWhen condition errMsg = bottomUnless (not condition) errMsg
