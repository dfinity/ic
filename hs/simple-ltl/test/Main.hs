module Main where

import Data.List hiding (and, or)
import LTL
import Test.Tasty
import Test.Tasty.HUnit
import Prelude hiding (and, or, until)

assertFormula :: [Int] -> LTL Int -> Assertion
assertFormula xs formula = case run formula xs of
  Failed e -> assertFailure $ "Failed: " ++ show e
  _ -> return ()

assertFormulaFailed :: [Int] -> LTL Int -> Assertion
assertFormulaFailed xs formula = case run formula xs of
  Failed _ -> return ()
  _ -> assertFailure "Failed"

main :: IO ()
main =
  defaultMain $
    testGroup
      "LTL tests"
      [ testCase "even or odd/1" $
          assertFormula [1 .. 100] $
            always (test odd `or` (test even `and` weak next (test odd))),
        testCase "even or odd/2" $
          assertFormula [1 .. 100] $
            always (test odd `until` test even),
        testCase "eventually >10" $
          assertFormula [1 .. 100] $
            eventually (test (> 10)),
        testCase "eventually >100" $
          assertFormulaFailed [1 .. 100] $
            eventually (test (> 100)),
        -- @weak eventually@ is a useless statement, since it inefficiently
        -- verifies that p is either true or not true. This test just checks
        -- the 'weak' combinator.
        testCase "weak eventually >100" $
          assertFormula [1 .. 100] $
            weak eventually (test (> 100)),
        testCase "always <100" $
          assertFormula [1 .. 99] $
            always (test (< 100)),
        testCase "even or odd/3" $
          assertFormula [1 .. 2] $
            neg $ test even `and` next (test odd),
        testCase "subsequent" $
          assertFormula [1 .. 100] $
            always (examine (\n -> weak next (eq (succ n)))),
        testCase "strongRelease" $
          assertFormulaFailed [1 .. 100] $
            strongRelease (bottom "always") (examine (\n -> next (eq (succ n))))
      ]
