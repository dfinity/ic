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

module IC.Test.Agent.UserCalls
  ( ic_canister_status'',
    ic_canister_info'',
    ic_delete_canister'',
    ic_deposit_cycles'',
    ic_ecdsa_public_key'',
    ic_http_get_request'',
    ic_install'',
    ic_raw_rand'',
    ic_set_controllers'',
    ic_sign_with_ecdsa'',
    ic_start_canister'',
    ic_stop_canister'',
    ic_top_up''',
    ic_uninstall'',
  )
where

import Codec.Candid (Principal (..))
import Data.Row
import qualified Data.Text as T
import qualified Data.Vector as Vec
import qualified Data.Word as W
import IC.Id.Forms
import IC.Management
import IC.Test.Agent
import IC.Test.Agent.Calls
import Numeric.Natural
import Test.Tasty.HUnit

ic_install'' :: (HasCallStack, HasAgentConfig) => Blob -> InstallMode -> Blob -> Blob -> Blob -> IO (HTTPErrOr ReqResponse)
ic_install'' user mode canister_id wasm_module arg =
  callIC'' user canister_id #install_code tmp
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
        .== Nothing

ic_uninstall'' :: (HasAgentConfig) => Blob -> Blob -> IO (HTTPErrOr ReqResponse)
ic_uninstall'' user canister_id =
  callIC'' user canister_id #uninstall_code arg
  where
    arg :: ExtendedCanisterIdRecord
    arg =
      empty
        .+ #canister_id
        .== Principal canister_id
        .+ #sender_canister_version
        .== Nothing

ic_set_controllers'' :: (HasAgentConfig) => Blob -> Blob -> [Blob] -> IO (HTTPErrOr ReqResponse)
ic_set_controllers'' user canister_id new_controllers = do
  callIC'' user canister_id #update_settings arg
  where
    arg :: UpdateSettingsArgs
    arg =
      empty
        .+ #canister_id
        .== Principal canister_id
        .+ #settings
        .== settings
        .+ #sender_canister_version
        .== Nothing
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

ic_start_canister'' :: (HasAgentConfig) => Blob -> Blob -> IO (HTTPErrOr ReqResponse)
ic_start_canister'' user canister_id = do
  callIC'' user canister_id #start_canister arg
  where
    arg :: CanisterIdRecord
    arg =
      empty
        .+ #canister_id
        .== Principal canister_id

ic_stop_canister'' :: (HasAgentConfig) => Blob -> Blob -> IO (HTTPErrOr ReqResponse)
ic_stop_canister'' user canister_id = do
  callIC'' user canister_id #stop_canister arg
  where
    arg :: CanisterIdRecord
    arg =
      empty
        .+ #canister_id
        .== Principal canister_id

ic_canister_status'' :: (HasAgentConfig) => Blob -> Blob -> IO (HTTPErrOr ReqResponse)
ic_canister_status'' user canister_id = do
  callIC'' user canister_id #canister_status arg
  where
    arg :: CanisterIdRecord
    arg =
      empty
        .+ #canister_id
        .== Principal canister_id

ic_canister_info'' :: (HasAgentConfig) => Blob -> Blob -> Maybe W.Word64 -> IO (HTTPErrOr ReqResponse)
ic_canister_info'' user canister_id num_requested_changes = do
  callIC'' user canister_id #canister_info arg
  where
    arg :: CanisterInfoArgs
    arg =
      empty
        .+ #canister_id
        .== Principal canister_id
        .+ #num_requested_changes
        .== num_requested_changes

ic_delete_canister'' :: (HasAgentConfig) => Blob -> Blob -> IO (HTTPErrOr ReqResponse)
ic_delete_canister'' user canister_id = do
  callIC'' user canister_id #delete_canister arg
  where
    arg :: CanisterIdRecord
    arg =
      empty
        .+ #canister_id
        .== Principal canister_id

ic_deposit_cycles'' :: (HasAgentConfig) => Blob -> Blob -> IO (HTTPErrOr ReqResponse)
ic_deposit_cycles'' user canister_id = do
  callIC'' user canister_id #deposit_cycles arg
  where
    arg :: CanisterIdRecord
    arg =
      empty
        .+ #canister_id
        .== Principal canister_id

ic_raw_rand'' :: (HasAgentConfig) => Blob -> Blob -> IO (HTTPErrOr ReqResponse)
ic_raw_rand'' user ecid = do
  callIC'' user ecid #raw_rand ()

ic_http_get_request'' :: (HasAgentConfig) => Blob -> Blob -> String -> IO (HTTPErrOr ReqResponse)
ic_http_get_request'' user ecid proto =
  callIC'' user ecid #http_request arg
  where
    arg :: HttpRequest
    arg =
      empty
        .+ #url
        .== (T.pack $ proto ++ httpbin)
        .+ #max_response_bytes
        .== Nothing
        .+ #method
        .== enum #get
        .+ #headers
        .== Vec.empty
        .+ #body
        .== Nothing
        .+ #transform
        .== Nothing

ic_ecdsa_public_key'' :: (HasAgentConfig) => Blob -> Blob -> IO (HTTPErrOr ReqResponse)
ic_ecdsa_public_key'' user ecid =
  callIC'' user ecid #ecdsa_public_key arg
  where
    arg :: EcdsaPublicKeyArgs
    arg =
      empty
        .+ #derivation_path
        .== Vec.empty
        .+ #canister_id
        .== Nothing
        .+ #key_id
        .== ( empty
                .+ #curve
                .== enum #secp256k1
                .+ #name
                .== (T.pack "0")
            )

ic_sign_with_ecdsa'' :: (HasAgentConfig) => Blob -> Blob -> Blob -> IO (HTTPErrOr ReqResponse)
ic_sign_with_ecdsa'' user ecid msg =
  callIC'' user ecid #sign_with_ecdsa arg
  where
    arg :: SignWithEcdsaArgs
    arg =
      empty
        .+ #derivation_path
        .== Vec.empty
        .+ #message_hash
        .== msg
        .+ #key_id
        .== ( empty
                .+ #curve
                .== enum #secp256k1
                .+ #name
                .== (T.pack "0")
            )

ic_top_up''' :: (HasAgentConfig) => IC00' -> Blob -> Natural -> IO (HTTPErrOr ReqResponse)
ic_top_up''' ic00' canister_id amount = do
  callIC''' ic00' canister_id #provisional_top_up_canister arg
  where
    arg :: ProvisionalTopUpArgs
    arg =
      empty
        .+ #canister_id
        .== Principal canister_id
        .+ #amount
        .== amount
