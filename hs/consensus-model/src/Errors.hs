module Errors where

import Control.Exception (Exception, throwIO)
import Control.Monad
import Control.Monad.IO.Class
import Data.Function
import Data.List.Safe as Safe
import Data.Typeable
import Test.HUnit.Lang (FailureReason (..))
import Test.Tasty.HUnit hiding (assert)
import Text.Show.Pretty
import Prelude hiding (round)

------------------------------------------------------------------------------
-- MORE ATTRACTIVE ERROR REPORTING
------------------------------------------------------------------------------

data MockFailure = MockFailure FailureReason
  deriving (Eq, Typeable)

instance Show MockFailure where
  show (MockFailure (Reason msg)) = msg
  show (MockFailure (ExpectedButGot preface expected actual)) = msg
    where
      msg =
        (case preface of Just str -> str ++ "\n"; Nothing -> "")
          ++ "\n----------------------------------------\n"
          ++ "expected:\n"
          ++ expected
          ++ "\n----------------------------------------\n"
          ++ "but got:\n"
          ++ actual

instance Exception MockFailure

assertEq' ::
  (PrettyVal a, HasCallStack) =>
  (a -> a -> Bool) ->
  -- | The message prefix
  String ->
  -- | The expected value
  a ->
  -- | The actual value
  a ->
  Assertion
assertEq' cmp preface expected actual =
  unless (cmp actual expected) $ do
    throwIO
      ( MockFailure
          ( ExpectedButGot
              ( if Prelude.null preface
                  then Nothing
                  else Just preface
              )
              (dumpStr expected)
              (dumpStr actual)
          )
      )

infix 1 @?==

(@?==) :: (MonadIO m, Eq a, PrettyVal a, HasCallStack) => a -> a -> m ()
actual @?== expected = liftIO $ assertEq' (==) "" expected actual
