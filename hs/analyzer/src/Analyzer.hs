module Analyzer where

import Control.Monad
import Pipes

foo :: Monad m => Pipe Int Int m ()
foo = forever $ do
  ev <- await
  yield ev
