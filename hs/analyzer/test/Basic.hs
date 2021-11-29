module Basic where

import Analyzer.Multiplex
import Control.Monad
import Pipes
import qualified Pipes.Prelude as P
import Test.Tasty.HUnit hiding (assert)

test_merge_ordered :: Assertion
test_merge_ordered = do
  assertEqual
    "integer streams with the default comparator"
    ([1, 2, 1, 3, 4, 5, 1])
    (P.toList $ mergeOrdered compare [each [1, 2, 1], each [5, 1], each [3, 4]])

  assertEqual
    "string streams with the custom comparator"
    (["x", "aa", "yyy"])
    (P.toList $ mergeOrdered (\x y -> compare (length x) (length y)) [each ["x", "yyy"], each ["aa"]])

  assertEqual
    "empty streams"
    ([])
    (P.toList $ mergeOrdered compare [each ([] :: [Int]), each ([] :: [Int])])
