-- |
-- This module describe a type for our “generic request (or response)” format. It
-- can be seen as a simplified (and more abstract) AST for CBOR data.
--
-- The following operations can be done on generic requests
--  * Parsing from CBOR
--  * Encoding to CBOR
--  * Request ID calculation
--  * Thus: Signing and signature checking
module IC.HTTP.GenR where

import Data.ByteString.Lazy
import Data.HashMap.Lazy
import Data.Text
import Numeric.Natural

data GenR
  = GBool Bool
  | GNat Natural
  | GText Text
  | GBlob ByteString
  | GRec (HashMap Text GenR)
  | GList [GenR]
  deriving (Show)

emptyR :: GenR
emptyR = GRec Data.HashMap.Lazy.empty

-- For assembling generic records
(=:) :: Text -> v -> HashMap Text v
(=:) = Data.HashMap.Lazy.singleton

rec :: [HashMap Text GenR] -> GenR
rec = GRec . mconcat
