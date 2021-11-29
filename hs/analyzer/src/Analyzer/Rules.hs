{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TemplateHaskell #-}

module Analyzer.Rules where

import Analyzer.Types
import Control.Monad.IO.Class
import Data.Time.Clock
import LTL
import Pipes

-- If a Fatal message comes through, trigger a Stop event.
hardenFatalMessages :: AnalysisRule m
hardenFatalMessages = do
  ob@Observation {} <- await
  yield ob
  case obEvent ob of
    AnalyzerEvent (Message FatalLevel _) ->
      yield ob {obEvent = AnalyzerEvent Stop}
    _ -> hardenFatalMessages

-- Given an LTL expression, turn it into an analysis rule over streams of
-- observations.
forallEvents :: MonadIO m => LTL Observation -> AnalysisRule m
forallEvents = go
  where
    go rule = do
      ob <- await
      yield ob
      case ob of
        Observation {obKind = ObKindFramework, obSubkind = "StreamEnd"} -> case step rule Nothing of
          Continue _ -> report $ HitBottom "failed to determine formula by end of stream"
          Success -> pure ()
          Failure reason -> report reason
          Abort reason -> report reason
        _ -> case step rule (Just ob) of
          Continue cont -> go cont
          Success -> go top
          Failure reason -> do
            report reason
            go top
          Abort reason -> do
            report reason
            go top
    report reason = do
      now <- liftIO getCurrentTime
      yield
        Observation
          { obKind = ObKindAnalyzer,
            obSubkind = "RuleError",
            obTime = Just now,
            obEvent = AnalyzerEvent (Message ErrorLevel (prettyPrintReason reason 0))
          }

createAnalysisRule :: MonadIO m => [LTL Observation] -> AnalysisRule m
createAnalysisRule [] = forallEvents top
createAnalysisRule rules = foldl1 (>->) (map forallEvents rules)

prettyPrintReason :: Reason a -> Int -> String
prettyPrintReason (HitBottom s) indent = (replicate indent '*') ++ " " ++ s
prettyPrintReason (Rejected _) indent = (replicate indent '*') ++ " Rejected"
prettyPrintReason (BothFailed l r) indent = (prettyPrintReason l (indent + 1)) ++ "\n" ++ (prettyPrintReason r (indent + 1))
prettyPrintReason (LeftFailed l) indent = prettyPrintReason l indent
prettyPrintReason (RightFailed r) indent = prettyPrintReason r indent
