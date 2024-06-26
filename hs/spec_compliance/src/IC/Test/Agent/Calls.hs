{-# LANGUAGE BlockArguments #-}
{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE ImplicitParams #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedLabels #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}

module IC.Test.Agent.Calls where

import Codec.Candid (Principal (..))
import qualified Codec.Candid as Candid
import Data.Row
import qualified Data.Row.Dictionaries as R
import qualified Data.Row.Internal as R
import qualified Data.Row.Records as R
import qualified Data.Text as T
import IC.Id.Forms
import IC.Management
import IC.Test.Agent

httpbin_proto :: (HasAgentConfig) => String
httpbin_proto = tc_httpbin_proto agentConfig

httpbin :: (HasAgentConfig) => String
httpbin = tc_httpbin agentConfig

toTransformFn :: Maybe (String, a) -> Blob -> Maybe (Rec ('R.R '["context" 'R.:-> a, "function" 'R.:-> Candid.FuncRef r]))
toTransformFn arg cid = fmap (\(n, c) -> empty .+ #function .== (Candid.FuncRef (Principal cid) (T.pack n)) .+ #context .== c) arg

-- The following line noise is me getting out of my way
-- to be able to use `ic_create` etc. by passing a record that contains
-- a subset of settings, without Maybe
type family UnRec r where
  UnRec (R.Rec r) = r

type PartialSettings r = (R.Forall r R.Unconstrained1, R.Map Maybe r .// UnRec Settings ≈ UnRec Settings)

fromPartialSettings :: (PartialSettings r) => R.Rec r -> Settings
fromPartialSettings r =
  R.map' Just r
    .// R.default' @(R.IsA R.Unconstrained1 Maybe) @(UnRec Settings) d
  where
    d :: forall a. (R.IsA R.Unconstrained1 Maybe a) => a
    d = case R.as @R.Unconstrained1 @Maybe @a of R.As -> Nothing
