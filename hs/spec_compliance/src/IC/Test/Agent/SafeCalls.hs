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

module IC.Test.Agent.SafeCalls
  ( ic_create',
    ic_create_with_controllers',
    ic_create_with_sender_canister_version',
    ic_delete_canister',
    ic_deposit_cycles',
    ic_http_invalid_address_request',
    ic_http_get_request',
    ic_http_post_request',
    ic_http_head_request',
    ic_long_url_http_request',
    ic_install',
    ic_install_with_sender_canister_version',
    ic_provisional_create',
    ic_provisional_create_with_sender_canister_version',
    ic_raw_rand',
    ic_set_controllers',
    ic_set_controllers_with_sender_canister_version',
    ic_set_freezing_threshold',
    ic_top_up',
    ic_update_settings',
    ic_update_settings_with_sender_canister_version',
  )
where

import Codec.Candid (Principal (..))
import qualified Data.ByteString.Lazy as BS
import Data.Row
import qualified Data.Text as T
import qualified Data.Vector as Vec
import qualified Data.Word as W
import IC.Id.Forms
import IC.Management
import IC.Test.Agent
import IC.Test.Agent.Calls
import IC.Types (TestSubnetConfig)
import IC.Utils
import Numeric.Natural
import Test.Tasty.HUnit

ic_create_with_sender_canister_version' ::
  (HasCallStack, HasAgentConfig) =>
  IC00 ->
  Blob ->
  Maybe W.Word64 ->
  Maybe CanisterSettings ->
  IO ReqResponse
ic_create_with_sender_canister_version' ic00 ecid sender_canister_version ps = do
  callIC' ic00 ecid #create_canister arg
  where
    arg :: CreateCanisterArgs
    arg =
      empty
        .+ #settings
        .== ps
        .+ #sender_canister_version
        .== sender_canister_version

ic_create' ::
  (HasCallStack, HasAgentConfig) =>
  IC00 ->
  Blob ->
  Maybe CanisterSettings ->
  IO ReqResponse
ic_create' ic00 ecid ps = ic_create_with_sender_canister_version' ic00 ecid Nothing ps

ic_create_with_controllers' ::
  (HasCallStack, HasAgentConfig) =>
  IC00 ->
  Blob ->
  [Blob] ->
  IO ReqResponse
ic_create_with_controllers' ic00 ecid new_controllers = ic_create_with_sender_canister_version' ic00 ecid Nothing (Just settings)
  where
    settings =
      empty
        .+ #controllers
        .== Just (Vec.fromList (map Principal new_controllers))
        .+ #compute_allocation
        .== Nothing
        .+ #memory_allocation
        .== Nothing
        .+ #freezing_threshold
        .== Nothing
        .+ #reserved_cycles_limit
        .== Nothing
        .+ #log_visibility
        .== Nothing
        .+ #wasm_memory_limit
        .== Nothing

ic_provisional_create_with_sender_canister_version' ::
  (HasCallStack, HasAgentConfig) =>
  IC00 ->
  Blob ->
  Maybe Principal ->
  Maybe Natural ->
  Maybe W.Word64 ->
  Maybe CanisterSettings ->
  IO ReqResponse
ic_provisional_create_with_sender_canister_version' ic00 ecid specified_id cycles sender_canister_version ps = do
  callIC' ic00 ecid #provisional_create_canister_with_cycles arg
  where
    arg :: ProvisionalCreateCanisterArgs
    arg =
      empty
        .+ #amount
        .== cycles
        .+ #settings
        .== ps
        .+ #specified_id
        .== specified_id
        .+ #sender_canister_version
        .== sender_canister_version

ic_provisional_create' ::
  (HasCallStack, HasAgentConfig) =>
  IC00 ->
  Blob ->
  Maybe Principal ->
  Maybe Natural ->
  Maybe CanisterSettings ->
  IO ReqResponse
ic_provisional_create' ic00 ecid specified_id cycles ps = ic_provisional_create_with_sender_canister_version' ic00 ecid specified_id cycles Nothing ps

ic_install_with_sender_canister_version' :: (HasAgentConfig) => IC00 -> InstallMode -> Blob -> Blob -> Blob -> Maybe W.Word64 -> IO ReqResponse
ic_install_with_sender_canister_version' ic00 mode canister_id wasm_module arg sender_canister_version =
  callIC' ic00 canister_id #install_code tmp
  where
    tmp :: InstallCodeArgs
    tmp =
      empty
        .+ #mode
        .== mode
        .+ #canister_id
        .== Principal canister_id
        .+ #wasm_module
        .== wasm_module
        .+ #arg
        .== arg
        .+ #sender_canister_version
        .== sender_canister_version

ic_install' :: (HasAgentConfig) => IC00 -> InstallMode -> Blob -> Blob -> Blob -> IO ReqResponse
ic_install' ic00 mode canister_id wasm_module arg = ic_install_with_sender_canister_version' ic00 mode canister_id wasm_module arg Nothing

ic_update_settings_with_sender_canister_version' :: (HasAgentConfig) => IC00 -> Blob -> Maybe W.Word64 -> CanisterSettings -> IO ReqResponse
ic_update_settings_with_sender_canister_version' ic00 canister_id sender_canister_version r = do
  callIC' ic00 canister_id #update_settings arg
  where
    arg :: UpdateSettingsArgs
    arg =
      empty
        .+ #canister_id
        .== Principal canister_id
        .+ #settings
        .== r
        .+ #sender_canister_version
        .== sender_canister_version

ic_update_settings' :: (HasAgentConfig) => IC00 -> Blob -> CanisterSettings -> IO ReqResponse
ic_update_settings' ic00 canister_id r = ic_update_settings_with_sender_canister_version' ic00 canister_id Nothing r

ic_set_controllers_with_sender_canister_version' :: (HasAgentConfig) => IC00 -> Blob -> Maybe W.Word64 -> [Blob] -> IO ReqResponse
ic_set_controllers_with_sender_canister_version' ic00 canister_id sender_canister_version new_controllers = do
  ic_update_settings_with_sender_canister_version' ic00 canister_id sender_canister_version settings
  where
    settings =
      empty
        .+ #controllers
        .== Just (Vec.fromList (map Principal new_controllers))
        .+ #compute_allocation
        .== Nothing
        .+ #memory_allocation
        .== Nothing
        .+ #freezing_threshold
        .== Nothing
        .+ #reserved_cycles_limit
        .== Nothing
        .+ #log_visibility
        .== Nothing
        .+ #wasm_memory_limit
        .== Nothing

ic_set_controllers' :: (HasAgentConfig) => IC00 -> Blob -> [Blob] -> IO ReqResponse
ic_set_controllers' ic00 canister_id new_controllers = ic_set_controllers_with_sender_canister_version' ic00 canister_id Nothing new_controllers

ic_set_freezing_threshold' :: (HasAgentConfig) => IC00 -> Blob -> Natural -> IO ReqResponse
ic_set_freezing_threshold' ic00 canister_id ft = do
  ic_update_settings_with_sender_canister_version' ic00 canister_id Nothing settings
  where
    settings =
      empty
        .+ #controllers
        .== Nothing
        .+ #compute_allocation
        .== Nothing
        .+ #memory_allocation
        .== Nothing
        .+ #freezing_threshold
        .== Just ft
        .+ #reserved_cycles_limit
        .== Nothing
        .+ #log_visibility
        .== Nothing
        .+ #wasm_memory_limit
        .== Nothing

ic_delete_canister' :: (HasAgentConfig) => IC00 -> Blob -> IO ReqResponse
ic_delete_canister' ic00 canister_id = do
  callIC' ic00 canister_id #delete_canister arg
  where
    arg :: CanisterIdRecord
    arg =
      empty
        .+ #canister_id
        .== Principal canister_id

ic_raw_rand' :: (HasAgentConfig) => IC00 -> Blob -> IO ReqResponse
ic_raw_rand' ic00 ecid =
  callIC' ic00 ecid #raw_rand ()

ic_deposit_cycles' :: (HasAgentConfig) => IC00 -> Blob -> IO ReqResponse
ic_deposit_cycles' ic00 canister_id = do
  callIC' ic00 canister_id #deposit_cycles arg
  where
    arg :: CanisterIdRecord
    arg =
      empty
        .+ #canister_id
        .== Principal canister_id

ic_top_up' :: (HasAgentConfig) => IC00 -> Blob -> Natural -> IO ReqResponse
ic_top_up' ic00 canister_id amount = do
  callIC' ic00 canister_id #provisional_top_up_canister arg
  where
    arg :: ProvisionalTopUpArgs
    arg =
      empty
        .+ #canister_id
        .== Principal canister_id
        .+ #amount
        .== amount

ic_http_invalid_address_request' :: (HasAgentConfig) => IC00WithCycles -> TestSubnetConfig -> String -> String -> Maybe W.Word64 -> Maybe (String, Blob) -> Blob -> IO ReqResponse
ic_http_invalid_address_request' ic00 (_, subnet_type, subnet_nodes, _, _) proto httpbin max_response_bytes transform canister_id =
  callIC' (ic00 $ http_request_fee request (subnet_type, fromIntegral $ length subnet_nodes)) "" #http_request request
  where
    request :: HttpRequest
    request =
      empty
        .+ #url
        .== (T.pack $ proto ++ httpbin ++ "/")
        .+ #max_response_bytes
        .== max_response_bytes
        .+ #method
        .== enum #get
        .+ #headers
        .== Vec.empty
        .+ #body
        .== Nothing
        .+ #transform
        .== (toTransformFn transform canister_id)

ic_http_get_request' :: (HasAgentConfig) => IC00WithCycles -> TestSubnetConfig -> String -> String -> Maybe W.Word64 -> Maybe (String, Blob) -> Blob -> IO ReqResponse
ic_http_get_request' ic00 (_, subnet_type, subnet_nodes, _, _) proto path max_response_bytes transform canister_id =
  callIC' (ic00 $ http_request_fee request (subnet_type, fromIntegral $ length subnet_nodes)) "" #http_request request
  where
    request :: HttpRequest
    request =
      empty
        .+ #url
        .== (T.pack $ proto ++ httpbin ++ "/" ++ path)
        .+ #max_response_bytes
        .== max_response_bytes
        .+ #method
        .== enum #get
        .+ #headers
        .== Vec.empty
        .+ #body
        .== Nothing
        .+ #transform
        .== (toTransformFn transform canister_id)

ic_http_post_request' :: (HasAgentConfig) => IC00WithCycles -> TestSubnetConfig -> String -> String -> Maybe W.Word64 -> Maybe BS.ByteString -> Vec.Vector HttpHeader -> Maybe (String, Blob) -> Blob -> IO ReqResponse
ic_http_post_request' ic00 (_, subnet_type, subnet_nodes, _, _) proto path max_response_bytes body headers transform canister_id =
  callIC' (ic00 $ http_request_fee request (subnet_type, fromIntegral $ length subnet_nodes)) "" #http_request request
  where
    request :: HttpRequest
    request =
      empty
        .+ #url
        .== (T.pack $ proto ++ httpbin ++ "/" ++ path)
        .+ #max_response_bytes
        .== max_response_bytes
        .+ #method
        .== enum #post
        .+ #headers
        .== headers
        .+ #body
        .== body
        .+ #transform
        .== (toTransformFn transform canister_id)

ic_http_head_request' :: (HasAgentConfig) => IC00WithCycles -> TestSubnetConfig -> String -> String -> Maybe W.Word64 -> Maybe BS.ByteString -> Vec.Vector HttpHeader -> Maybe (String, Blob) -> Blob -> IO ReqResponse
ic_http_head_request' ic00 (_, subnet_type, subnet_nodes, _, _) proto path max_response_bytes body headers transform canister_id =
  callIC' (ic00 $ http_request_fee request (subnet_type, fromIntegral $ length subnet_nodes)) "" #http_request request
  where
    request :: HttpRequest
    request =
      empty
        .+ #url
        .== (T.pack $ proto ++ httpbin ++ "/" ++ path)
        .+ #max_response_bytes
        .== max_response_bytes
        .+ #method
        .== enum #head
        .+ #headers
        .== headers
        .+ #body
        .== body
        .+ #transform
        .== (toTransformFn transform canister_id)

ic_long_url_http_request' :: (HasAgentConfig) => IC00WithCycles -> TestSubnetConfig -> String -> W.Word64 -> Maybe (String, Blob) -> Blob -> IO ReqResponse
ic_long_url_http_request' ic00 (_, subnet_type, subnet_nodes, _, _) proto len transform canister_id =
  callIC' (ic00 $ http_request_fee request (subnet_type, fromIntegral $ length subnet_nodes)) "" #http_request request
  where
    l = fromIntegral len - (length $ proto ++ httpbin ++ "/ascii/")
    path = take l $ repeat 'x'
    request :: HttpRequest
    request =
      empty
        .+ #url
        .== (T.pack $ proto ++ httpbin ++ "/ascii/" ++ path)
        .+ #max_response_bytes
        .== Nothing
        .+ #method
        .== enum #get
        .+ #headers
        .== Vec.empty
        .+ #body
        .== Nothing
        .+ #transform
        .== (toTransformFn transform canister_id)
