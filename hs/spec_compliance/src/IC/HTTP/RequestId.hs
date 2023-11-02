module IC.HTTP.RequestId (requestId) where

import qualified Data.ByteString.Lazy as BS
import qualified Data.HashMap.Lazy as HM
import Data.List (sort)
import Data.Serialize.LEB128
import qualified Data.Text as T
import IC.HTTP.GenR
import IC.Hash
import IC.Utils
import Numeric.Natural

type RequestId = BS.ByteString

requestId :: GenR -> RequestId
requestId (GRec hm) = sha256 $ BS.concat $ sort $ map encodeKV $ HM.toList hm
requestId _ = error "requestID: expected a record"

encodeKV :: (T.Text, GenR) -> BS.ByteString
encodeKV (k, v) = sha256 (toUtf8 k) <> sha256 (encodeVal v)

encodeVal :: GenR -> BS.ByteString
encodeVal (GBlob b) = b
encodeVal (GText t) = toUtf8 t
encodeVal (GNat n) = encodeNat n
encodeVal (GRec _) = error "requestID: Nested record"
encodeVal (GList vs) = BS.concat $ map (sha256 . encodeVal) vs

encodeNat :: Natural -> BS.ByteString
encodeNat = BS.fromStrict . toLEB128
