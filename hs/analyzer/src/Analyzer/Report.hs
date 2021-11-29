{-# LANGUAGE FlexibleContexts #-}

module Analyzer.Report where

import Analyzer.Ekg
import Analyzer.Types
import Control.Monad (forever)
import Data.Map
import Pipes
import qualified Pipes.Prelude as P

newtype Statistics = Statistics (Map String Int)

instance Show Statistics where
  show (Statistics m) = foldlWithKey (\prev n c -> prev ++ " * " ++ n ++ ": " ++ show c ++ "\n") "Logs statistics:\n" m

countLogs :: (MonadIO m) => Producer Observation m () -> m Statistics
countLogs = P.fold (\stats ob -> updateStats (getLog ob) stats) (Statistics empty) id
  where
    updateStats :: Maybe Log -> Statistics -> Statistics
    updateStats (Just (Log t _ _)) (Statistics s) = Statistics $ insertWith (+) t 1 s
    updateStats _ s = s

printAnalyzerEvents :: (MonadIO m) => Consumer Observation m ()
printAnalyzerEvents = forever $ do
  ob <- await
  case ob of
    Observation {obEvent = AnalyzerEvent (Message lvl msg)} -> liftIO $ putStrLn $ "[" ++ show lvl ++ "]\n" ++ msg
    _ -> pure ()
