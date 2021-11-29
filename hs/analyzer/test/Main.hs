module Main where

import Basic
import Test.Tasty
import Test.Tasty.HUnit hiding (assert)

main :: IO ()
main =
  defaultMain $
    testGroup
      "multiplex"
      [testCase "merge_ordered" test_merge_ordered]
