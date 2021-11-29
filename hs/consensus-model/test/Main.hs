module Main where

import Basic
import Data.Function
import Genesis
import Test.Tasty
import Test.Tasty.HUnit hiding (assert)
import Prelude hiding (round)

main :: IO ()
main =
  defaultMain $
    testGroup
      "reference"
      [ testCase "initial_pool" test_initial_pool,
        testCase "on_state_change" test_on_state_change
      ]
