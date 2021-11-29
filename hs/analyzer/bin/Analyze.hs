{-# LANGUAGE DeriveGeneric #-}

module Main where

import Analyzer.Ekg
import Analyzer.Event
import qualified Analyzer.Multiplex as AM
import Analyzer.Report
import Analyzer.Rules
import Analyzer.Types
import Control.Monad.Reader
import Data.Either
import qualified Data.Map as M
import GHC.Generics
import Pipes
import Pipes.Lift
import qualified Pipes.Prelude as PP
import System.Environment
import System.Exit

data PotResult = Success | Failure deriving (Eq, Show)

evalPot :: Pot -> IO PotResult
evalPot p = do
  putStrLn $ "Running " ++ (potName p) ++ "..."
  let outputStream = potObservations p >-> (createAnalysisRule $ potLTLRules p)
  stats <- countLogs outputStream
  putStrLn $ show stats
  res <- PP.any erroneousEvent outputStream
  case res of
    False -> do
      putStrLn "Pot succeeded!\n"
      return Success
    True -> do
      putStrLn "Analyzer events: "
      runEffect $ outputStream >-> printAnalyzerEvents
      putStrLn "\nPot failed!\n"
      return Failure

summarizeResults :: [PotResult] -> IO ()
summarizeResults rs = do
  putStrLn $ "Pots summary: " ++ show s ++ " succeeded and " ++ show f ++ " failed\n"
  if f > 0 then exitFailure else exitSuccess
  where
    s = length $ filter (== Success) rs
    f = length $ filter (== Failure) rs

main :: IO ()
main = do
  args <- getArgs
  case args of
    (logsBaseDir : _) -> do
      pots <- runReaderT AM.run $ AM.Context logsBaseDir
      results <- mapM evalPot pots
      summarizeResults results
    _ -> putStrLn "Usage: ./analyze logs_base_dir"
