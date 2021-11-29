module Main where

import Criterion.Main
import Data.List hiding (and, or)
import LTL
import Prelude hiding (and, or)

formula1 :: LTL Int
formula1 = always (is odd `or` (is even `and` next (is odd)))

formula2 :: LTL Int
formula2 = always (is odd `LTL.until` is even)

runIt :: LTL Int -> Int -> Answer Int
runIt f n = run f (take n ([1 ..] :: [Int]))

grIt :: Int -> Bool
grIt n = all (> 0) (take n ([1 ..] :: [Int]))

main :: IO ()
main =
  defaultMain
    [ bgroup
        "just numbers"
        [ bench "all (<0)" $ whnf grIt 1000000,
          bench "formula1" $ whnf (runIt formula1) 1000000,
          bench "formula2" $ whnf (runIt formula2) 1000000
        ]
    ]
