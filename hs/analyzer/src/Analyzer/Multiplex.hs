module Analyzer.Multiplex where

import Analyzer.Ekg
import Analyzer.Event
import Analyzer.Types
import Control.Monad.Reader
import Data.Either
import Data.List
import Pipes
import System.Directory
import System.FilePath.Posix

data Context = Context
  { contextObservationBaseDir :: FilePath
  }

type Multiplexer m = ReaderT Context m

run :: Multiplexer IO [Pot]
run = do
  ctx <- ask
  let baseDir = contextObservationBaseDir ctx
  potNames <- liftIO $ listDirectory baseDir
  mapM processPot potNames

-- TODO(VER-1262): enable activating rules for pots through sending activation events
-- and remove the hardcoded mapping below.
potToRules :: String -> [EKGRule]
potToRules = nameToRules . getPotName
  where
    nameToRules "consensus_liveness_with_equivocation_pot" = [MaliciouslyProposeEquivocatingBlocks]
    nameToRules "consensus_safety_pot" = [BasicMonitoring, MaliciouslyProposeEmptyBlock, MaliciouslyNotarizeAll, MaliciouslyFinalizeAll]
    nameToRules "replica_determinism_pot" = [NoChildDied, FinalizedHashesAgree, MaliciouslyCorruptOwnStateAtHeight, DivergedReplicaEventuallyConsistent]
    nameToRules "cow_safety_test" = [FinalizedHashesAgree, FinalizedHeightWithin 180]
    nameToRules "fwd_back_upgrade_pot" = []
    nameToRules "simple_self_upgrade_pot" = []
    nameToRules _ = [BasicMonitoring]

    getPotName = takeWhile (/= ':')

processPot :: String -> Multiplexer IO Pot
processPot name = do
  ctx <- ask
  let baseDir = contextObservationBaseDir ctx
  let potPath = joinPath [baseDir, name]
  testNames <- liftIO $ listDirectory potPath
  let producers = map readLogFile $ map (\t -> joinPath [potPath, t]) testNames
  let p = mergeOrdered (\x y -> compare (obTime x) (obTime y)) producers
  return $ Pot name p $ concatMap getRules $ potToRules name

mergeOrdered :: (Monad m) => (a -> a -> Ordering) -> [Producer a m ()] -> Producer a m ()
mergeOrdered _ [] = return ()
mergeOrdered cmp ps = do
  l <- mapM (\p -> lift $ next p) ps
  merge cmp $ rights l

merge :: (Monad m) => (a -> a -> Ordering) -> [(a, Producer a m ())] -> Producer a m ()
merge _ [] = return ()
merge cmp l = do
  case getMinElement cmp l of
    (Nothing, _) -> return ()
    (Just (nextEl, prod), prods) -> do
      yield nextEl
      e <- lift $ next prod
      case e of
        Left _ -> merge cmp prods
        Right p -> merge cmp $ prods ++ [p]

getMinElement :: (a -> a -> Ordering) -> [(a, b)] -> (Maybe (a, b), [(a, b)])
getMinElement cmp l = (Just $ head ascL, tail ascL)
  where
    ascL = sortBy (\x y -> cmp (fst x) (fst y)) l
