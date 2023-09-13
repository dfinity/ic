module IC.Id.Fresh where

import Data.ByteString.Builder
import Data.Word
import IC.Id.Forms hiding (Blob)
import IC.Types

-- Not particularly efficient, but this is a reference implementation, right?
freshId :: [(Word64, Word64)] -> [EntityId] -> Maybe EntityId
freshId ranges ids =
  case filter (`notElem` ids) $ map wordToId $ concatMap (\(a, b) -> [a .. b]) ranges of
    [] -> Nothing
    (x : _) -> Just x

wordToId' :: Word64 -> Blob
wordToId' = mkOpaqueId . toLazyByteString . word64BE

wordToId :: Word64 -> EntityId
wordToId = EntityId . wordToId'

checkCanisterIdInRanges' :: [(Blob, Blob)] -> Blob -> Bool
checkCanisterIdInRanges' ranges cid = any (\(a, b) -> a <= cid && cid <= b) ranges

checkCanisterIdInRanges :: [(Word64, Word64)] -> CanisterId -> Bool
checkCanisterIdInRanges ranges cid = checkCanisterIdInRanges' (map (\(a, b) -> (wordToId' a, wordToId' b)) ranges) (rawEntityId cid)

isRootTestSubnet :: TestSubnetConfig -> Bool
isRootTestSubnet (_, _, _, ranges, _) = checkCanisterIdInRanges ranges nns_canister_id
  where
    nns_canister_id = wordToId 0
