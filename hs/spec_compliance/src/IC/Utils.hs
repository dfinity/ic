{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE ExplicitNamespaces #-}
{-# LANGUAGE ImplicitParams #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedLabels #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}

-- |
-- Generic utilities related to standard or imported data structures that we do
-- don’t want to see in non-plumbing code.
module IC.Utils where

import qualified Codec.Candid as Candid
import qualified Data.ByteString.Lazy as BS
import qualified Data.Map as M
import Data.Row ((.!), type (.!))
import qualified Data.Row as R
import qualified Data.Set as S
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import qualified Data.Vector as Vec
import qualified Data.Word as W
import qualified Data.X509 as C
import IC.Constants
import IC.Management
import IC.Types

freshKey :: M.Map Int a -> Int
freshKey m
  | M.null m = 0
  | otherwise = fst (M.findMax m) + 1

repeatWhileTrue :: (Monad m) => m Bool -> m ()
repeatWhileTrue act =
  act >>= \case
    True -> repeatWhileTrue act
    False -> return ()

duplicates :: (Ord a) => [a] -> [a]
duplicates = go S.empty
  where
    go _s [] = []
    go s (x : xs)
      | x `S.member` s = x : go s' xs
      | otherwise = go s' xs
      where
        s' = S.insert x s

-- Wrappers to hide strict/lazy conversion from view
toUtf8 :: T.Text -> BS.ByteString
toUtf8 = BS.fromStrict . T.encodeUtf8

fromUtf8 :: BS.ByteString -> Maybe T.Text
fromUtf8 b = case T.decodeUtf8' (BS.toStrict b) of
  Left _ -> Nothing
  Right t -> Just t

-- Compute UTF-8 length of Text
utf8_length :: T.Text -> W.Word64
utf8_length = fromIntegral . BS.length . toUtf8

-- ic-ref config
data RefConfig = RefConfig
  { tc_root_certs :: [C.SignedCertificate]
  }

makeRefConfig :: [C.SignedCertificate] -> IO RefConfig
makeRefConfig root_certs = do
  return
    RefConfig
      { tc_root_certs = root_certs
      }

type HasRefConfig = (?refConfig :: RefConfig)

withRefConfig :: RefConfig -> (forall. (HasRefConfig) => a) -> a
withRefConfig tc act = let ?refConfig = tc in act

refConfig :: (HasRefConfig) => RefConfig
refConfig = ?refConfig

getRootCerts :: (HasRefConfig) => [C.SignedCertificate]
getRootCerts = tc_root_certs refConfig

-- Canister http_request
max_response_size :: HttpRequest -> W.Word64
max_response_size r = aux $ fmap fromIntegral $ r .! #max_response_bytes
  where
    aux Nothing = max_response_bytes_limit
    aux (Just w) = w

http_request_fee :: HttpRequest -> (SubnetType, W.Word64) -> W.Word64
http_request_fee r (subnet_type, subnet_size) = normalized_fee * subnet_size + quadratic_per_node_fee * subnet_size * subnet_size
  where
    base_fee = getHttpRequestBaseFee subnet_type
    quadratic_per_node_fee = getHttpRequestPerSubnetSizeFee subnet_type
    per_request_byte_fee = getHttpRequestPerRequestByteFee subnet_type
    per_response_byte_fee = getHttpRequestPerResponseByteFee subnet_type
    response_size Nothing = max_response_bytes_limit
    response_size (Just max_response_size) = max_response_size
    transform_fee Nothing = 0
    transform_fee (Just t) = dec_var (t .! #function) + (fromIntegral $ BS.length (t .! #context))
    dec_var (Candid.FuncRef _ t) = utf8_length t
    body_fee Nothing = 0
    body_fee (Just t) = BS.length t
    request_size =
      (fromIntegral $ utf8_length $ r .! #url)
        + (fromIntegral $ sum $ map (\h -> utf8_length (h .! #name) + utf8_length (h .! #value)) $ Vec.toList $ r .! #headers)
        + (fromIntegral $ body_fee $ r .! #body)
        + (fromIntegral $ transform_fee $ r .! #transform)
    request_fee = per_request_byte_fee * request_size
    response_fee = per_response_byte_fee * response_size (fmap fromIntegral $ r .! #max_response_bytes)
    normalized_fee = base_fee + request_fee + response_fee

http_request_headers_total_size :: (Integral c) => HttpRequest -> c
http_request_headers_total_size r = fromIntegral $ sum $ map (\h -> utf8_length (h .! #name) + utf8_length (h .! #value)) $ Vec.toList $ r .! #headers

check_http_request_headers_number :: HttpRequest -> Bool
check_http_request_headers_number r = length (Vec.toList $ r .! #headers) <= http_headers_max_number

check_http_request_headers_name_length :: HttpRequest -> Bool
check_http_request_headers_name_length r = all (\h -> utf8_length (h .! #name) <= http_headers_max_name_value_length) (Vec.toList $ r .! #headers)

check_http_request_headers_value_length :: HttpRequest -> Bool
check_http_request_headers_value_length r = all (\h -> utf8_length (h .! #value) <= http_headers_max_name_value_length) (Vec.toList $ r .! #headers)

check_http_request_headers_total_size :: HttpRequest -> Bool
check_http_request_headers_total_size r = http_request_headers_total_size r <= http_headers_max_total_size

http_request_size :: (Integral c) => HttpRequest -> c
http_request_size r = http_request_headers_total_size r + body_size (r .! #body)
  where
    body_size Nothing = 0
    body_size (Just b) = fromIntegral $ BS.length b

http_response_headers :: HttpResponse -> [(T.Text, T.Text)]
http_response_headers r = map (\h -> (h .! #name, h .! #value)) $ Vec.toList $ r .! #headers

http_response_headers_total_size :: (Integral c) => HttpResponse -> c
http_response_headers_total_size r = fromIntegral $ sum $ map (\h -> utf8_length (h .! #name) + utf8_length (h .! #value)) $ Vec.toList $ r .! #headers

check_http_response_headers_number :: HttpResponse -> Bool
check_http_response_headers_number r = length (Vec.toList $ r .! #headers) <= http_headers_max_number

check_http_response_headers_name_length :: HttpResponse -> Bool
check_http_response_headers_name_length r = all (\h -> utf8_length (h .! #name) <= http_headers_max_name_value_length) (Vec.toList $ r .! #headers)

check_http_response_headers_value_length :: HttpResponse -> Bool
check_http_response_headers_value_length r = all (\h -> utf8_length (h .! #value) <= http_headers_max_name_value_length) (Vec.toList $ r .! #headers)

check_http_response_headers_total_size :: HttpResponse -> Bool
check_http_response_headers_total_size r = http_response_headers_total_size r <= http_headers_max_total_size

http_response_size :: HttpResponse -> W.Word64
http_response_size r = http_response_headers_total_size r + body_size
  where
    body_size = fromIntegral (BS.length (r .! #body))
