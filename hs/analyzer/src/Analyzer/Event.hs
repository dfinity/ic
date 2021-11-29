module Analyzer.Event where

import Analyzer.Types
import Control.Monad
import Data.Aeson
import Data.ByteString
import Data.Time
import Pipes
import System.IO hiding (hGetLine)

readLogFile :: MonadIO m => FilePath -> Producer Observation m ()
readLogFile path = do
  h <- liftIO $ openFile path ReadMode
  stdinLines h
  now <- liftIO $ getCurrentTime
  yield
    Observation
      { obKind = ObKindFramework,
        obSubkind = "StreamEnd",
        obTime = Just now,
        obEvent = AnalyzerEvent (Message InfoLevel "end of observations stream")
      }
  where
    stdinLines :: MonadIO m => Handle -> Producer Observation m ()
    stdinLines h = do
      eof <- liftIO $ hIsEOF h
      unless eof $ do
        line <- liftIO $ hGetLine h
        obs <- return $ decodeStrict' line
        case obs of
          Nothing -> pure ()
          Just o -> yield o
        stdinLines h

erroneousEvent :: Observation -> Bool
erroneousEvent Observation {obEvent = AnalyzerEvent (Message ErrorLevel _)} = True
erroneousEvent Observation {obEvent = AnalyzerEvent (Message FatalLevel _)} = True
erroneousEvent _ = False
