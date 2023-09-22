{-# LANGUAGE OverloadedStrings #-}

module IC.Version where

import Data.Text
import SourceId

specVersion, implVersion :: Text
specVersion = "0.18.0"
implVersion = pack SourceId.id
