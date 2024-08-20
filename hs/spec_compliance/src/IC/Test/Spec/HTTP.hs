{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedLabels #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TupleSections #-}
{-# LANGUAGE TypeApplications #-}

-- |
--
-- This module contains a test suite for the Internet Computer
module IC.Test.Spec.HTTP (canister_http_calls) where

import qualified Codec.Candid as Candid
import Data.Aeson
import qualified Data.Aeson.Key as K
import qualified Data.Aeson.KeyMap as KM
import qualified Data.ByteString.Lazy as BS
import qualified Data.ByteString.Lazy.UTF8 as BLU
import Data.Char
import Data.List
import Data.Maybe
import Data.Row as R
import qualified Data.Text as T
import qualified Data.Vector as Vec
import Data.Word
import IC.Constants
import IC.Id.Fresh
import IC.Management (HttpHeader, HttpResponse)
import IC.Test.Agent
import IC.Test.Agent.SafeCalls
import IC.Test.Agent.UnsafeCalls
import IC.Test.Spec.Utils
import IC.Test.Universal
import IC.Types (EntityId (..), TestSubnetConfig)
import IC.Utils
import Test.Tasty
import Test.Tasty.HUnit

-- * Helpers

charFromInt :: Int -> Char
charFromInt n = chr $ n + ord 'a'

-- * Canister http calls

check_distinct_headers :: Vec.Vector HttpHeader -> Bool
check_distinct_headers v = length xs == length (nub xs)
  where
    xs = map (\r -> T.toLower $ r .! #name) $ Vec.toList v

http_headers_to_map :: Vec.Vector HttpHeader -> T.Text -> Maybe T.Text
http_headers_to_map v n = lookup n $ map_to_lower $ map (\r -> (r .! #name, r .! #value)) $ Vec.toList v

map_to_lower :: [(T.Text, T.Text)] -> [(T.Text, T.Text)]
map_to_lower = map (\(n, v) -> (T.toLower n, v))

check_http_response :: HttpResponse -> IO ()
check_http_response resp = do
  assertBool "HTTP response header names must be distinct" $ check_distinct_headers (resp .! #headers)
  assertBool "HTTP header \"content-length\" must contain the length of the body" $
    case h (T.pack "content-length") of
      Nothing -> False
      Just l -> l == (T.pack $ show $ BS.length $ resp .! #body)
  where
    h = http_headers_to_map $ resp .! #headers

newtype HttpRequestHeaders = HttpRequestHeaders [(T.Text, T.Text)]

newtype HttpRequestBody = HttpRequestBody BS.ByteString
  deriving (Eq)

data HttpRequest = HttpRequest
  { method :: T.Text,
    headers :: HttpRequestHeaders,
    body :: HttpRequestBody
  }

instance FromJSON HttpRequest where
  parseJSON (Object v) =
    HttpRequest
      <$> v
      .: "method"
      <*> v
      .: "headers"
      <*> v
      .: "data"
  parseJSON _ = error "unsupported"

instance FromJSON HttpRequestHeaders where
  parseJSON (Object v) =
    do
      let r =
            foldr
              ( \(k, v) r -> case v of
                  String s -> fmap (\hs -> (K.toText k, s) : hs) r
                  _ -> Nothing
              )
              (Just [])
              (KM.toList v)
      case r of
        Nothing -> error "unsupported"
        Just hs -> return $ HttpRequestHeaders hs
  parseJSON _ = error "unsupported"

instance FromJSON HttpRequestBody where
  parseJSON (String s) = return $ HttpRequestBody $ toUtf8 s
  parseJSON _ = error "unsupported"

list_subset :: (Eq a) => [a] -> [a] -> Bool
list_subset xs ys = all (\x -> elem x ys) xs

headers_match :: [(T.Text, T.Text)] -> [(T.Text, T.Text)] -> Bool
headers_match xs ys = all (\x -> elem x ys) xs && all (\(n, v) -> elem (n, v) xs || n == "host" || n == "content-length" || n == "accept-encoding" || n == "user-agent" && v == "ic/1.0") ys

check_http_json :: String -> [(T.Text, T.Text)] -> BS.ByteString -> Maybe HttpRequest -> Assertion
check_http_json _ _ _ Nothing = assertFailure "Could not parse the original HttpRequest from the response"
check_http_json m hs b (Just req) = do
  assertBool "Wrong HTTP method" $ T.pack m == method req
  assertBool "Headers were not properly included in the HTTP request" $ headers_match (map_to_lower hs) (case headers req of HttpRequestHeaders hs -> map_to_lower hs)
  assertBool "Body was not properly included in the HTTP request" $ HttpRequestBody b == body req

check_http_body :: BS.ByteString -> Bool
check_http_body = aux . fromUtf8
  where
    aux Nothing = False
    aux (Just s) = all ((==) 'x') $ T.unpack s

canister_http_calls :: (HasAgentConfig) => TestSubnetConfig -> String -> [TestTree]
canister_http_calls sub httpbin_proto =
  let (_, _, _, ((ecid_as_word64, _) : _), _) = sub
   in let ecid = rawEntityId $ wordToId ecid_as_word64
       in [ -- Corner cases

            simpleTestCase "invalid domain name" ecid $ \cid ->
              ic_http_invalid_address_request' (ic00viaWithCyclesRefund 0 cid) sub "https://" "xwWPqqbNqxxHmLXdguF4DN9xGq22nczV.com" Nothing Nothing cid >>= isReject [2],
            simpleTestCase "invalid IP address" ecid $ \cid ->
              ic_http_invalid_address_request' (ic00viaWithCyclesRefund 0 cid) sub "https://" "240.0.0.0" Nothing Nothing cid >>= isReject [2],
            -- "Currently, the GET, HEAD, and POST methods are supported for HTTP requests."

            simpleTestCase "GET call" ecid $ \cid -> do
              let s = "hello_world"
              resp <- ic_http_get_request (ic00viaWithCyclesRefund 0 cid) sub httpbin_proto ("ascii/" ++ s) (Just 666) Nothing cid
              (resp .! #status) @?= 200
              (resp .! #body) @?= BLU.fromString s
              check_http_response resp,
            simpleTestCase "POST call" ecid $ \cid -> do
              let b = toUtf8 $ T.pack $ "Hello, world!"
              let hs = [(T.pack "name1", T.pack "value1"), (T.pack "name2", T.pack "value2")]
              resp <- ic_http_post_request (ic00viaWithCyclesRefund 0 cid) sub httpbin_proto "anything" (Just 666) (Just b) (vec_header_from_list_text hs) Nothing cid
              (resp .! #status) @?= 200
              check_http_response resp
              check_http_json "POST" hs b $ (decode (resp .! #body) :: Maybe HttpRequest),
            simpleTestCase "HEAD call" ecid $ \cid -> do
              let n = 6666
              let b = toUtf8 $ T.pack $ replicate n 'x'
              let hs = [(T.pack "name1", T.pack "value1"), (T.pack "name2", T.pack "value2")]
              resp <- ic_http_head_request (ic00viaWithCyclesRefund 0 cid) sub httpbin_proto "anything" (Just 666) (Just b) (vec_header_from_list_text hs) Nothing cid
              (resp .! #status) @?= 200
              (resp .! #body) @?= (toUtf8 $ T.pack "")
              assertBool "HTTP response header names must be distinct" $ check_distinct_headers (resp .! #headers)
              let h = http_headers_to_map (resp .! #headers) "content-length"
              assertBool ("content-length must be present and at least " ++ show n) $
                case h of
                  Nothing -> False
                  Just l -> (read (T.unpack l) :: Int) >= n,
            -- "For security reasons, only HTTPS connections are allowed (URLs must start with https://)."

            testCase "url must start with https://" $ do
              let s = "hello_world"
              cid <- install ecid noop
              ic_http_get_request' (ic00viaWithCyclesRefund 0 cid) sub "http://" ("ascii/" ++ s) Nothing Nothing cid >>= isReject [1],
            -- "The size of an HTTP request from the canister is the total number of bytes representing the names and values of HTTP headers and the HTTP body. The maximal size for the request from the canister is 2MB (2,000,000B)."

            simpleTestCase "maximum possible request size" ecid $ \cid -> do
              let hs = [(T.pack "name1", T.pack "value1"), (T.pack "name2", T.pack "value2"), (T.pack "content-type", T.pack "text/html; charset=utf-8")]
              let len_hs = sum $ map (\(n, v) -> utf8_length n + utf8_length v) hs
              let b = toUtf8 $ T.pack $ replicate (fromIntegral $ max_request_bytes_limit - len_hs) 'x'
              resp <- ic_http_post_request (ic00viaWithCyclesRefund 0 cid) sub httpbin_proto "request_size" Nothing (Just b) (vec_header_from_list_text hs) Nothing cid
              (resp .! #status) @?= 200
              check_http_response resp
              let n = read (T.unpack $ fromJust $ fromUtf8 (resp .! #body)) :: Word64
              assertBool ("Request size must be at least (the HTTP client can add more headers) " ++ show max_request_bytes_limit) $ n >= len_hs + fromIntegral (BS.length b),
            simpleTestCase "maximum possible request size exceeded" ecid $ \cid -> do
              let hs = [(T.pack "name1", T.pack "value1"), (T.pack "name2", T.pack "value2"), (T.pack "content-type", T.pack "text/html; charset=utf-8")]
              let len_hs = sum $ map (\(n, v) -> utf8_length n + utf8_length v) hs
              let b = toUtf8 $ T.pack $ replicate (fromIntegral $ max_request_bytes_limit - len_hs + 1) 'x'
              ic_http_post_request' (\fee -> ic00viaWithCyclesRefund fee cid fee) sub httpbin_proto "request_size" Nothing (Just b) (vec_header_from_list_text hs) Nothing cid >>= isReject [4],
            -- "The size of an HTTP response from the remote server is the total number of bytes representing the names and values of HTTP headers and the HTTP body. Each request can specify a maximal size for the response from the remote HTTP server."

            simpleTestCase "small maximum possible response size" ecid $ \cid -> do
              let s = "hello_world"
              {- Response headers (size: 158)
                  date: Jan 1 1970 00:00:00 GMT
                  content-type: application/octet-stream
                  content-length: 11
                  connection: close
                  access-control-allow-origin: *
                  access-control-allow-credentials: true
              -}
              let header_size = 158
              resp <- ic_http_get_request (ic00viaWithCyclesRefund 0 cid) sub httpbin_proto ("ascii/" ++ s) (Just $ fromIntegral $ length s + header_size) Nothing cid
              (resp .! #status) @?= 200
              (resp .! #body) @?= BLU.fromString s
              check_http_response resp,
            simpleTestCase "small maximum possible response size exceeded" ecid $ \cid -> do
              let s = "hello_world"
              {- Response headers (size: 158)
                  date: Jan 1 1970 00:00:00 GMT
                  content-type: application/octet-stream
                  content-length: 11
                  connection: close
                  access-control-allow-origin: *
                  access-control-allow-credentials: true
              -}
              let header_size = 158
              ic_http_get_request' (ic00viaWithCyclesRefund 0 cid) sub httpbin_proto ("ascii/" ++ s) (Just $ fromIntegral $ length s + header_size - 1) Nothing cid >>= isReject [1],
            simpleTestCase "small maximum possible response size (only headers)" ecid $ \cid -> do
              {- Response headers (size: 157)
                  date: Jan 1 1970 00:00:00 GMT
                  content-type: application/octet-stream
                  content-length: 0
                  connection: close
                  access-control-allow-origin: *
                  access-control-allow-credentials: true
              -}
              let header_size = 157
              resp <- ic_http_get_request (ic00viaWithCyclesRefund 0 cid) sub httpbin_proto ("equal_bytes/0") (Just header_size) Nothing cid
              (resp .! #status) @?= 200
              (resp .! #body) @?= BS.empty
              check_http_response resp,
            simpleTestCase "small maximum possible response size (only headers) exceeded" ecid $ \cid -> do
              {- Response headers (size: 157)
                  date: Jan 1 1970 00:00:00 GMT
                  content-type: application/octet-stream
                  content-length: 0
                  connection: close
                  access-control-allow-origin: *
                  access-control-allow-credentials: true
              -}
              let header_size = 157
              ic_http_get_request' (ic00viaWithCyclesRefund 0 cid) sub httpbin_proto ("equal_bytes/0") (Just $ header_size - 1) Nothing cid >>= isReject [1],
            -- "The upper limit on the maximal size for the response is 2MB (2,000,000B) and this value also applies if no maximal size value is specified."

            testCase "large maximum possible response size" $ do
              {- Response headers (size: 163)
                  date: Jan 1 1970 00:00:00 GMT
                  content-type: application/octet-stream
                  content-length: 1999837
                  connection: close
                  access-control-allow-origin: *
                  access-control-allow-credentials: true
              -}
              let header_size = 163
              cid <- install ecid (onTransform (callback (replyData (bytes (Candid.encode dummyResponse)))))
              resp <- ic_http_get_request (ic00viaWithCyclesRefund 0 cid) sub httpbin_proto ("equal_bytes/" ++ show (max_response_bytes_limit - header_size)) Nothing (Just ("transform", "")) cid
              (resp .! #status) @?= 202
              (resp .! #body) @?= "Dummy!"
              check_http_response resp,
            testCase "large maximum possible response size exceeded" $ do
              {- Response headers (size: 163)
                  date: Jan 1 1970 00:00:00 GMT
                  content-type: application/octet-stream
                  content-length: 1999838
                  connection: close
                  access-control-allow-origin: *
                  access-control-allow-credentials: true
              -}
              let header_size = 163
              cid <- install ecid (onTransform (callback (replyData (bytes (Candid.encode dummyResponse)))))
              ic_http_get_request' (ic00viaWithCyclesRefund 0 cid) sub httpbin_proto ("equal_bytes/" ++ show (max_response_bytes_limit - header_size + 1)) Nothing (Just ("transform", "")) cid >>= isReject [1],
            -- "The URL must be valid according to RFC-3986 and its length must not exceed 8192."

            simpleTestCase "non-ascii URL" ecid $ \cid -> do
              ic_http_get_request' (ic00viaWithCyclesRefund 0 cid) sub httpbin_proto "ascii/안녕하세요" Nothing Nothing cid >>= isReject [1],
            simpleTestCase "maximum possible url size" ecid $ \cid -> do
              resp <- ic_long_url_http_request (ic00viaWithCyclesRefund 0 cid) sub httpbin_proto max_http_request_url_length Nothing cid
              (resp .! #status) @?= 200
              assertBool "HTTP response body is malformed" $ check_http_body $ resp .! #body
              check_http_response resp,
            simpleTestCase "maximum possible url size exceeded" ecid $ \cid -> do
              ic_long_url_http_request' (\fee -> ic00viaWithCyclesRefund fee cid fee) sub httpbin_proto (max_http_request_url_length + 1) Nothing cid >>= isReject [4],
            -- "max_response_bytes - If provided, the value must not exceed 2MB (2,000,000B)."

            simpleTestCase "maximum possible value of max_response_bytes" ecid $ \cid -> do
              let s = "hello_world"
              resp <- ic_http_get_request (ic00viaWithCyclesRefund 0 cid) sub httpbin_proto ("ascii/" ++ s) (Just max_response_bytes_limit) Nothing cid
              (resp .! #status) @?= 200
              (resp .! #body) @?= BLU.fromString s
              check_http_response resp,
            simpleTestCase "maximum possible value of max_response_bytes exceeded" ecid $ \cid -> do
              let s = "hello_world"
              ic_http_get_request' (\fee -> ic00viaWithCyclesRefund fee cid fee) sub httpbin_proto ("ascii/" ++ s) (Just $ max_response_bytes_limit + 1) Nothing cid >>= isReject [4],
            -- "transform - an optional record that includes a function that transforms raw responses to sanitized responses, and a byte-encoded context that is provided to the function upon invocation, along with the response to be sanitized."

            testCase "call with simple transform" $ do
              let b = toUtf8 $ T.pack $ "Hello, world!"
              let hs = vec_header_from_list_text [(T.pack "name1", T.pack "value1"), (T.pack "name2", T.pack "value2")]
              cid <- install ecid (onTransform (callback (replyData (bytes (Candid.encode dummyResponse)))))
              resp <- ic_http_post_request (ic00viaWithCyclesRefund 0 cid) sub httpbin_proto "anything" (Just 666) (Just b) hs (Just ("transform", "")) cid
              (resp .! #status) @?= 202
              (resp .! #body) @?= "Dummy!"
              check_http_response resp,
            testCase "reflect transform context" $ do
              let s = "hello_world"
              cid <- install ecid (onTransform (callback (replyData (getHttpReplyWithBody (getHttpTransformContext argData)))))
              resp <- ic_http_get_request (ic00viaWithCyclesRefund 0 cid) sub httpbin_proto ("ascii/" ++ s) Nothing (Just ("transform", "asdf")) cid
              (resp .! #status) @?= 200
              (resp .! #body) @?= "asdf",
            -- "If provided, the calling canister itself must export this (transform) function."

            testCase "non-existent transform function" $ do
              let s = "hello_world"
              cid <- install ecid noop
              ic_http_get_request' (ic00viaWithCyclesRefund 0 cid) sub httpbin_proto ("ascii/" ++ s) Nothing (Just ("nonExistent", "")) cid >>= isReject [5],
            testCase "reference to a transform function exposed by another canister" $ do
              let s = "hello_world"
              cid <- install ecid noop
              cid2 <- install ecid (onTransform (callback (replyData (bytes (Candid.encode dummyResponse)))))
              ic_http_get_request' (\fee -> ic00viaWithCyclesRefund fee cid fee) sub httpbin_proto ("ascii/" ++ s) Nothing (Just ("transform", "")) cid2 >>= isReject [4],
            -- "The maximal number of bytes representing the response produced by the transform function is 2MB (2,000,000B)."

            testCase "maximum possible canister response size" $ do
              {- Response headers (size: 163)
                  date: Jan 1 1970 00:00:00 GMT
                  content-type: application/octet-stream
                  content-length: 1999837
                  connection: close
                  access-control-allow-origin: *
                  access-control-allow-credentials: true
              -}
              let header_size = 163
              let size = maximumSizeResponseBodySize
              let new_pages = int $ size `div` (64 * 1024) + 1
              let max_size = int $ size
              cid <- install ecid (onTransform (callback (ignore (stableGrow new_pages) >>> stableFill (int 0) (int 120) max_size >>> replyData (getHttpReplyWithBody (stableRead (int 0) max_size)))))
              resp <- ic_http_get_request (ic00viaWithCyclesRefund 0 cid) sub httpbin_proto ("equal_bytes/" ++ show (max_response_bytes_limit - header_size)) Nothing (Just ("transform", "")) cid
              (resp .! #status) @?= 200
              (resp .! #body) @?= bodyOfSize maximumSizeResponseBodySize,
            testCase "maximum possible canister response size exceeded" $ do
              {- Response headers (size: 163)
                  date: Jan 1 1970 00:00:00 GMT
                  content-type: application/octet-stream
                  content-length: 1999837
                  connection: close
                  access-control-allow-origin: *
                  access-control-allow-credentials: true
              -}
              let header_size = 163
              let size = maximumSizeResponseBodySize + 1
              let new_pages = int $ size `div` (64 * 1024) + 1
              let max_size = int $ size
              cid <- install ecid (onTransform (callback (ignore (stableGrow new_pages) >>> stableFill (int 0) (int 120) max_size >>> replyData (getHttpReplyWithBody (stableRead (int 0) max_size)))))
              ic_http_get_request' (ic00viaWithCyclesRefund 0 cid) sub httpbin_proto ("equal_bytes/" ++ show (max_response_bytes_limit - header_size)) Nothing (Just ("transform", "")) cid >>= isReject [1],
            -- "When the transform function is invoked by the system due to a canister HTTP request, the caller's identity is the principal of the management canister."

            testCase "check caller of transform" $ do
              let s = "hello_world"
              cid <- install ecid (onTransform (callback (replyData (getHttpReplyWithBody (parsePrincipal caller)))))
              resp <- ic_http_get_request (ic00viaWithCyclesRefund 0 cid) sub httpbin_proto ("ascii/" ++ s) Nothing (Just ("transform", "caller")) cid
              (resp .! #status) @?= 200
              (resp .! #body) @?= "aaaaa-aa",
            -- "The following additional limits apply to HTTP requests and HTTP responses from the remote sever: the number of headers must not exceed 64."

            simpleTestCase "maximum number of request headers" ecid $ \cid -> do
              let b = toUtf8 $ T.pack $ "Hello, world!"
              let hs = [(T.pack ("name" ++ show i), T.pack ("value" ++ show i)) | i <- [0 .. http_headers_max_number - 1]]
              resp <- ic_http_post_request (ic00viaWithCyclesRefund 0 cid) sub httpbin_proto "anything" Nothing (Just b) (vec_header_from_list_text hs) Nothing cid
              (resp .! #status) @?= 200
              check_http_response resp
              check_http_json "POST" hs b $ (decode (resp .! #body) :: Maybe HttpRequest),
            simpleTestCase "maximum number of request headers exceeded" ecid $ \cid -> do
              let b = toUtf8 $ T.pack $ "Hello, world!"
              let hs = [(T.pack ("name" ++ show i), T.pack ("value" ++ show i)) | i <- [0 .. http_headers_max_number]]
              ic_http_post_request' (\fee -> ic00viaWithCyclesRefund fee cid fee) sub httpbin_proto "anything" Nothing (Just b) (vec_header_from_list_text hs) Nothing cid >>= isReject [4],
            simpleTestCase "maximum number of response headers" ecid $ \cid -> do
              {- These 6 response headers are always included:
                  date: Jan 1 1970 00:00:00 GMT
                  content-type: text/plain; charset=utf-8
                  content-length: 0
                  connection: close
                  access-control-allow-origin: *
                  access-control-allow-credentials: true
              -}
              let n = http_headers_max_number - 6
              let hs = [(T.pack ("name" ++ show i), T.pack ("value" ++ show i)) | i <- [0 .. n - 1]]
              resp <- ic_http_get_request (ic00viaWithCyclesRefund 0 cid) sub httpbin_proto ("many_response_headers/" ++ show n) Nothing Nothing cid
              (resp .! #status) @?= 200
              assertBool "Response HTTP headers have not been received properly." $ list_subset (map_to_lower hs) (map_to_lower $ http_response_headers resp)
              check_http_response resp,
            simpleTestCase "maximum number of response headers exceeded" ecid $ \cid -> do
              {- These 6 response headers are always included:
                  date: Jan 1 1970 00:00:00 GMT
                  content-type: text/plain; charset=utf-8
                  content-length: 0
                  connection: close
                  access-control-allow-origin: *
                  access-control-allow-credentials: true
              -}
              let n = http_headers_max_number - 6 + 1
              ic_http_get_request' (ic00viaWithCyclesRefund 0 cid) sub httpbin_proto ("many_response_headers/" ++ show n) Nothing Nothing cid >>= isReject [1],
            -- "The following additional limits apply to HTTP requests and HTTP responses from the remote sever: the number of bytes representing a header name must not exceed 8KiB."

            simpleTestCase "maximum request header name length" ecid $ \cid -> do
              let b = toUtf8 $ T.pack $ "Hello, world!"
              let hs = [(T.pack (replicate (fromIntegral http_headers_max_name_value_length) 'x'), T.pack ("value"))]
              resp <- ic_http_post_request (ic00viaWithCyclesRefund 0 cid) sub httpbin_proto "anything" Nothing (Just b) (vec_header_from_list_text hs) Nothing cid
              (resp .! #status) @?= 200
              check_http_response resp
              check_http_json "POST" hs b $ (decode (resp .! #body) :: Maybe HttpRequest),
            simpleTestCase "maximum request header name length exceeded" ecid $ \cid -> do
              let b = toUtf8 $ T.pack $ "Hello, world!"
              let hs = [(T.pack (replicate (fromIntegral $ http_headers_max_name_value_length + 1) 'x'), T.pack ("value"))]
              ic_http_post_request' (\fee -> ic00viaWithCyclesRefund fee cid fee) sub httpbin_proto "anything" Nothing (Just b) (vec_header_from_list_text hs) Nothing cid >>= isReject [4],
            simpleTestCase "maximum response header name length" ecid $ \cid -> do
              let n = http_headers_max_name_value_length
              let hs = [(T.pack $ replicate (fromIntegral n) 'x', T.pack "value")]
              resp <- ic_http_get_request (ic00viaWithCyclesRefund 0 cid) sub httpbin_proto ("long_response_header_name/" ++ show n) Nothing Nothing cid
              (resp .! #status) @?= 200
              assertBool "Response HTTP headers have not been received properly." $ list_subset (map_to_lower hs) (map_to_lower $ http_response_headers resp)
              check_http_response resp,
            simpleTestCase "maximum response header name length exceeded" ecid $ \cid -> do
              let n = http_headers_max_name_value_length + 1
              ic_http_get_request' (ic00viaWithCyclesRefund 0 cid) sub httpbin_proto ("long_response_header_name/" ++ show n) Nothing Nothing cid >>= isReject [1],
            -- "The following additional limits apply to HTTP requests and HTTP responses from the remote sever: the number of bytes representing a header value must not exceed 8KiB."

            simpleTestCase "maximum request header value length" ecid $ \cid -> do
              let b = toUtf8 $ T.pack $ "Hello, world!"
              let hs = [(T.pack "name", T.pack (replicate (fromIntegral http_headers_max_name_value_length) 'x'))]
              resp <- ic_http_post_request (ic00viaWithCyclesRefund 0 cid) sub httpbin_proto "anything" Nothing (Just b) (vec_header_from_list_text hs) Nothing cid
              (resp .! #status) @?= 200
              check_http_response resp
              check_http_json "POST" hs b $ (decode (resp .! #body) :: Maybe HttpRequest),
            simpleTestCase "maximum request header value length exceeded" ecid $ \cid -> do
              let b = toUtf8 $ T.pack $ "Hello, world!"
              let hs = [(T.pack "name", T.pack (replicate (fromIntegral $ http_headers_max_name_value_length + 1) 'x'))]
              ic_http_post_request' (\fee -> ic00viaWithCyclesRefund fee cid fee) sub httpbin_proto "anything" Nothing (Just b) (vec_header_from_list_text hs) Nothing cid >>= isReject [4],
            simpleTestCase "maximum response header value length" ecid $ \cid -> do
              let n = http_headers_max_name_value_length
              let hs = [(T.pack "name", T.pack $ replicate (fromIntegral n) 'x')]
              resp <- ic_http_get_request (ic00viaWithCyclesRefund 0 cid) sub httpbin_proto ("long_response_header_value/" ++ show n) Nothing Nothing cid
              (resp .! #status) @?= 200
              assertBool "Response HTTP headers have not been received properly." $ list_subset (map_to_lower hs) (map_to_lower $ http_response_headers resp)
              check_http_response resp,
            simpleTestCase "maximum response header value length exceeded" ecid $ \cid -> do
              let n = http_headers_max_name_value_length + 1
              ic_http_get_request' (ic00viaWithCyclesRefund 0 cid) sub httpbin_proto ("long_response_header_value/" ++ show n) Nothing Nothing cid >>= isReject [1],
            -- "The following additional limits apply to HTTP requests and HTTP responses from the remote sever: the total number of bytes representing the header names and values must not exceed 48KiB."

            simpleTestCase "maximum request total header size" ecid $ \cid -> do
              let chunk = http_headers_max_name_value_length
              assertBool ("Maximum number of bytes to represent all request header names and value is not divisible by " ++ show (2 * chunk)) (http_headers_max_total_size `mod` (2 * chunk) == 0)
              assertBool ("Maximum number of bytes to represent all request header names and value exceeds " ++ show (2 * chunk * 26)) (http_headers_max_total_size `div` (2 * chunk) <= fromIntegral (min 26 http_headers_max_number))
              let n = http_headers_max_total_size `div` (2 * chunk)
              let b = toUtf8 $ T.pack $ "Hello, world!"
              let hs = [(T.pack $ [charFromInt i] ++ replicate (fromIntegral chunk - 1) 'x', T.pack $ replicate (fromIntegral chunk) 'x') | i <- [0 .. fromIntegral n - 1]]
              resp <- ic_http_post_request (ic00viaWithCyclesRefund 0 cid) sub httpbin_proto "anything" Nothing (Just b) (vec_header_from_list_text hs) Nothing cid
              (resp .! #status) @?= 200
              check_http_response resp
              check_http_json "POST" hs b $ (decode (resp .! #body) :: Maybe HttpRequest),
            simpleTestCase "maximum request total header size exceeded" ecid $ \cid -> do
              let chunk = http_headers_max_name_value_length
              assertBool ("Maximum number of bytes to represent all request header names and value is not divisible by " ++ show (2 * chunk)) (http_headers_max_total_size `mod` (2 * chunk) == 0)
              assertBool ("Maximum number of bytes to represent all request header names and value exceeds " ++ show (2 * chunk * 26)) (http_headers_max_total_size `div` (2 * chunk) <= fromIntegral (min 26 http_headers_max_number))
              let n = http_headers_max_total_size `div` (2 * chunk)
              let b = toUtf8 $ T.pack $ "Hello, world!"
              let hs = (T.pack "x", T.empty) : [(T.pack $ [charFromInt i] ++ replicate (fromIntegral chunk - 1) 'x', T.pack $ replicate (fromIntegral chunk) 'x') | i <- [0 .. fromIntegral n - 1]]
              ic_http_post_request' (\fee -> ic00viaWithCyclesRefund fee cid fee) sub httpbin_proto "anything" Nothing (Just b) (vec_header_from_list_text hs) Nothing cid >>= isReject [4],
            simpleTestCase "maximum response total header size" ecid $ \cid -> do
              let n = http_headers_max_total_size
              resp <- ic_http_get_request (ic00viaWithCyclesRefund 0 cid) sub httpbin_proto ("large_response_total_header_size/" ++ show http_headers_max_name_value_length ++ "/" ++ show n) Nothing Nothing cid
              (resp .! #status) @?= 200
              assertBool ("Total header size is not equal to " ++ show n) $ http_response_headers_total_size resp == n
              check_http_response resp,
            simpleTestCase "maximum response total header size exceeded" ecid $ \cid -> do
              let n = http_headers_max_total_size + 1
              ic_http_get_request' (ic00viaWithCyclesRefund 0 cid) sub httpbin_proto ("large_response_total_header_size/" ++ show http_headers_max_name_value_length ++ "/" ++ show n) Nothing Nothing cid >>= isReject [1]
          ]
