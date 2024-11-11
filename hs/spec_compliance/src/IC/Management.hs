{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedLabels #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE TypeApplications #-}
{-
Plumbing related to Candid and the management canister.
-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE UndecidableInstances #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module IC.Management where

import Codec.Candid
import Data.Row ((.+), (.==))
import qualified Data.Row as R
import qualified Data.Row.Internal as R
import qualified Data.Row.Variants as V
import qualified Data.Text as T
import qualified Data.Vector as Vec
import qualified Data.Word as W
import IC.Types
import Numeric.Natural

-- This needs cleaning up
principalToEntityId :: Principal -> EntityId
principalToEntityId = EntityId . rawPrincipal

entityIdToPrincipal :: EntityId -> Principal
entityIdToPrincipal = Principal . rawEntityId

-- Canister creation

type CreateCanisterArgs = R.Rec ("settings" R..== Maybe CanisterSettings R..+ "sender_canister_version" R..== Maybe W.Word64)

-- Canister settings

type LogVisibility = V.Var ("controllers" R..== () R..+ "public" R..== ())

type CanisterSettings = R.Rec ("controllers" R..== Maybe (Vec.Vector Principal) R..+ "compute_allocation" R..== Maybe Natural R..+ "memory_allocation" R..== Maybe Natural R..+ "freezing_threshold" R..== Maybe Natural R..+ "reserved_cycles_limit" R..== Maybe Natural R..+ "log_visibility" R..== Maybe LogVisibility R..+ "wasm_memory_limit" R..== Maybe Natural)

type DefiniteCanisterSettings = R.Rec ("controllers" R..== Vec.Vector Principal R..+ "compute_allocation" R..== Natural R..+ "memory_allocation" R..== Natural R..+ "freezing_threshold" R..== Natural R..+ "reserved_cycles_limit" R..== Natural R..+ "log_visibility" R..== LogVisibility R..+ "wasm_memory_limit" R..== Natural)

type UpdateSettingsArgs = R.Rec ("canister_id" R..== Principal R..+ "settings" R..== CanisterSettings R..+ "sender_canister_version" R..== Maybe W.Word64)

-- Canister status

type RunState = V.Var ("running" R..== () R..+ "stopping" R..== () R..+ "stopped" R..== ())

type QueryStats = R.Rec ("num_calls_total" R..== Natural R..+ "num_instructions_total" R..== Natural R..+ "request_payload_bytes_total" R..== Natural R..+ "response_payload_bytes_total" R..== Natural)

type CanisterStatus = R.Rec ("status" R..== RunState R..+ "settings" R..== DefiniteCanisterSettings R..+ "module_hash" R..== Maybe Blob R..+ "memory_size" R..== Natural R..+ "cycles" R..== Natural R..+ "reserved_cycles" R..== Natural R..+ "idle_cycles_burned_per_day" R..== Natural R..+ "query_stats" R..== QueryStats)

-- Canister installation

type WasmMemoryPersistence = V.Var ("keep" R..== () R..+ "replace" R..== ())

type UpgradeArgs = R.Rec ("skip_pre_upgrade" R..== Maybe Bool R..+ "wasm_memory_persistence" R..== Maybe WasmMemoryPersistence)

type InstallMode = V.Var ("install" R..== () R..+ "reinstall" R..== () R..+ "upgrade" R..== Maybe UpgradeArgs)

type InstallCodeArgs = R.Rec ("mode" R..== InstallMode R..+ "canister_id" R..== Principal R..+ "wasm_module" R..== Blob R..+ "arg" R..== Blob R..+ "sender_canister_version" R..== Maybe W.Word64)

-- Canister history

type CandidChangeFromUser = R.Rec ("user_id" R..== Principal)

type CandidChangeFromCanister = R.Rec ("canister_id" R..== Principal R..+ "canister_version" R..== Maybe W.Word64)

type CandidChangeOrigin = V.Var ("from_user" R..== CandidChangeFromUser R..+ "from_canister" R..== CandidChangeFromCanister)

type CandidChangeCreation = R.Rec ("controllers" R..== Vec.Vector Principal)

type CandidChangeCodeDeploymentMode = V.Var ("install" R..== () R..+ "reinstall" R..== () R..+ "upgrade" R..== ())

type CandidChangeCodeDeployment = R.Rec ("mode" R..== CandidChangeCodeDeploymentMode R..+ "module_hash" R..== Blob)

type CandidChangeControllersChange = R.Rec ("controllers" R..== Vec.Vector Principal)

type CandidChangeDetails = V.Var ("creation" R..== CandidChangeCreation R..+ "code_uninstall" R..== () R..+ "code_deployment" R..== CandidChangeCodeDeployment R..+ "controllers_change" R..== CandidChangeControllersChange)

type CanisterChange = R.Rec ("timestamp_nanos" R..== W.Word64 R..+ "canister_version" R..== W.Word64 R..+ "origin" R..== CandidChangeOrigin R..+ "details" R..== CandidChangeDetails)

type CanisterInfoArgs = R.Rec ("canister_id" R..== Principal R..+ "num_requested_changes" R..== Maybe W.Word64)

type CanisterInfo = R.Rec ("total_num_changes" R..== W.Word64 R..+ "recent_changes" R..== Vec.Vector CanisterChange R..+ "module_hash" R..== Maybe Blob R..+ "controllers" R..== Vec.Vector Principal)

-- Canister HTTP outcalls

type HttpMethod = V.Var ("get" R..== () R..+ "head" R..== () R..+ "post" R..== ())

type HttpHeader = R.Rec ("name" R..== T.Text R..+ "value" R..== T.Text)

type HttpTransformArgs = R.Rec ("response" R..== HttpResponse R..+ "context" R..== Blob)

type HttpTransform = R.Rec ("function" R..== FuncRef (HttpTransformArgs, Unary HttpResponse, AnnTrue, AnnFalse, AnnFalse) R..+ "context" R..== Blob)

type HttpRequest = R.Rec ("url" R..== T.Text R..+ "max_response_bytes" R..== Maybe W.Word64 R..+ "method" R..== HttpMethod R..+ "headers" R..== Vec.Vector HttpHeader R..+ "body" R..== Maybe Blob R..+ "transform" R..== Maybe HttpTransform)

type HttpResponse = R.Rec ("status" R..== Natural R..+ "headers" R..== Vec.Vector HttpHeader R..+ "body" R..== Blob)

-- ECDSA API

type EcdsaCurve = V.Var ("secp256k1" R..== ())

type EcdsaKeyId = R.Rec ("curve" R..== EcdsaCurve R..+ "name" R..== T.Text)

type EcdsaPublicKeyArgs = R.Rec ("canister_id" R..== Maybe Principal R..+ "derivation_path" R..== Vec.Vector Blob R..+ "key_id" R..== EcdsaKeyId)

type SignWithEcdsaArgs = R.Rec ("message_hash" R..== Blob R..+ "derivation_path" R..== Vec.Vector Blob R..+ "key_id" R..== EcdsaKeyId)

-- Generic input args used by several APIs

type CanisterIdRecord = R.Rec ("canister_id" R..== Principal)

type ExtendedCanisterIdRecord = R.Rec ("canister_id" R..== Principal R..+ "sender_canister_version" R..== Maybe W.Word64)

-- Provisional API

type ProvisionalCreateCanisterArgs = R.Rec ("amount" R..== Maybe Natural R..+ "settings" R..== Maybe CanisterSettings R..+ "specified_id" R..== Maybe Principal R..+ "sender_canister_version" R..== Maybe W.Word64)

type ProvisionalTopUpArgs = R.Rec ("canister_id" R..== Principal R..+ "amount" R..== Natural)

mapChangeOrigin :: ChangeOrigin -> CandidChangeOrigin
mapChangeOrigin (ChangeFromUser user_id) =
  V.IsJust #from_user $
    R.empty
      .+ #user_id
      .== entityIdToPrincipal user_id
mapChangeOrigin (ChangeFromCanister canister_id canister_version) =
  V.IsJust #from_canister $
    R.empty
      .+ #canister_id
      .== entityIdToPrincipal canister_id
      .+ #canister_version
      .== canister_version

mapChangeDetails :: ChangeDetails -> CandidChangeDetails
mapChangeDetails (Creation controllers) =
  V.IsJust #creation $
    R.empty
      .+ #controllers
      .== Vec.fromList (map entityIdToPrincipal controllers)
mapChangeDetails CodeUninstall = V.IsJust #code_uninstall ()
mapChangeDetails (CodeDeployment mode module_hash) =
  V.IsJust #code_deployment $
    R.empty
      .+ #mode
      .== mapInstallMode mode
      .+ #module_hash
      .== module_hash
  where
    mapInstallMode Reinstall = V.IsJust #reinstall ()
    mapInstallMode Install = V.IsJust #install ()
    mapInstallMode Upgrade = V.IsJust #upgrade ()
mapChangeDetails (ControllersChange controllers) =
  V.IsJust #controllers_change $
    R.empty
      .+ #controllers
      .== Vec.fromList (map entityIdToPrincipal controllers)
