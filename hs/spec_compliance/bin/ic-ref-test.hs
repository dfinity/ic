{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module Main (main) where

import IC.Constants
import qualified IC.Crypto.BLS as BLS
import IC.Test.Agent (preFlight)
import IC.Test.Options
import IC.Test.Spec
import Test.Tasty
import Test.Tasty.Ingredients
import Test.Tasty.Ingredients.Basic
import Test.Tasty.Ingredients.Rerun
import Test.Tasty.Options (lookupOption)
import Test.Tasty.Runners
import Test.Tasty.Runners.AntXML
import Test.Tasty.Runners.Html

main :: IO ()
main = do
  BLS.init
  os <- parseOptions ingredients (testGroup "dummy" [])
  ac <- preFlight os
  let TestSubnet my_sub = lookupOption os
  let PeerSubnet other_sub = lookupOption os
  defaultMainWithIngredients ingredients (icTests my_sub other_sub ac)
  where
    ingredients =
      [ rerunningTests
          [ listingTests,
            includingOptions [endpointOption],
            includingOptions [httpbinProtoOption],
            includingOptions [httpbinOption],
            includingOptions [polltimeoutOption],
            includingOptions [testSubnetOption],
            includingOptions [peerSubnetOption],
            includingOptions [allowSelfSignedCertsOption],
            antXMLRunner `composeReporters` htmlRunner `composeReporters` consoleTestReporter
          ]
      ]
