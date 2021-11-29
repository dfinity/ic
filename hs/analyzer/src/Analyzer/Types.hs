{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE RecordWildCards #-}

module Analyzer.Types where

import Control.Lens
import Data.Aeson
import Data.Fixed
import Data.Time
import LTL
import Pipes

data Observation = Observation
  { obKind :: ObservationKind,
    obSubkind :: String,
    obTime :: Maybe UTCTime,
    obEvent :: Event
  }
  deriving (Show)

instance FromJSON Observation where
  parseJSON = withObject "Observation" $ \o -> do
    let obKind = ObKindNode
    obSubkind <- o .: "type"
    entry <- (o .: "event") >>= (.:? "log_entry")
    obTime <- case entry of
      Nothing -> pure Nothing
      Just p -> p .:? "utc_time"
    mcontent <- o .:? "_content"
    obEvent <- case mcontent of
      Nothing -> ExternalEvent . Object <$> o .: "event"
      Just c -> pure $ ExternalEvent . String $ c
    pure Observation {..}

data ObservationKind
  = ObKindOS
  | ObKindFramework
  | ObKindTest
  | ObKindFarm
  | ObKindNode
  | ObKindAnalyzer
  deriving (Show)

instance FromJSON ObservationKind where
  parseJSON (String s) = case s of
    "OS" -> pure ObKindOS
    "Framework" -> pure ObKindFramework
    "Test" -> pure ObKindTest
    "Farm" -> pure ObKindFarm
    "Node" -> pure ObKindNode
    "Analyzer" -> pure ObKindNode
    v -> fail $ "Unexpected ObservationKind: " ++ show v
  parseJSON v = fail $ "Unexpected ObservationKind: " ++ show v

data LogLevel
  = TraceLevel
  | DebugLevel
  | InfoLevel
  | WarnLevel
  | ErrorLevel
  | FatalLevel
  deriving (Show)

data AnalyzerEvent
  = Message LogLevel String
  | Stop
  deriving (Show)

data Event
  = AnalyzerEvent AnalyzerEvent
  | ExternalEvent Value
  deriving (Show)

-- At the very least an AnalysisRule is quantified over a Monad and the final
-- result is simply ignored. AnalyzerEvent's should be used to communicate
-- results down to the reporting consumer. If stronger capabilities are
-- required, such as keeping state, use mtl-style, such as @MonadState s m =>
-- Rule m@.
type AnalysisRule m = Monad m => Pipe Observation Observation m ()

class MonadTime m where
  getTime :: m UTCTime

class Has a b where
  hasLens :: Lens' a b

data EKGRule
  = NoChildDied
  | MaliciouslyProposeEquivocatingBlocks
  | MaliciouslyProposeEmptyBlock
  | MaliciouslyFinalizeAll
  | MaliciouslyNotarizeAll
  | MaliciouslyCorruptOwnStateAtHeight
  | BasicMonitoring
  | FinalizedHashesAgree
  | FinalizedHeightWithin Pico
  | NoErrorLogMessage
  | DivergedReplicaEventuallyConsistent
  deriving (Show)

data Pot = Pot
  { potName :: String,
    potObservations :: Producer Observation IO (),
    potLTLRules :: [LTL Observation]
  }
