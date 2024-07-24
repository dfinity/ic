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

type SenderCanisterVersion = R.Rec (R.R '["sender_canister_version" R.:-> W.Word64])

type WasmMemoryPersistence = V.Var (R.R '["keep" R.:-> (), "replace" R.:-> ()])

type UpgradeArgs = R.Rec (R.R '["skip_pre_upgrade" R.:-> Maybe Bool, "wasm_memory_persistence" R.:-> Maybe WasmMemoryPersistence])

type InstallMode = V.Var (R.R '["install" R.:-> (), "reinstall" R.:-> (), "upgrade" R.:-> Maybe UpgradeArgs])

type RunState = V.Var (R.R '["running" R.:-> (), "stopping" R.:-> (), "stopped" R.:-> ()])

type Settings = R.Rec (R.R '["controllers" R.:-> Maybe (Vec.Vector Principal), "compute_allocation" R.:-> Maybe Natural, "memory_allocation" R.:-> Maybe Natural, "freezing_threshold" R.:-> Maybe Natural])

type HttpMethod = V.Var (R.R '["get" R.:-> (), "head" R.:-> (), "post" R.:-> ()])

type HttpHeader = R.Rec (R.R '["name" R.:-> T.Text, "value" R.:-> T.Text])

type HttpTransformArgs = R.Rec (R.R '["response" R.:-> HttpResponse, "context" R.:-> Blob])

type HttpTransform = R.Rec (R.R '["function" R.:-> FuncRef (HttpTransformArgs, Unary HttpResponse, AnnTrue, AnnFalse, AnnFalse), "context" R.:-> Blob])

type HttpRequest = R.Rec (R.R '["url" R.:-> T.Text, "max_response_bytes" R.:-> Maybe W.Word64, "method" R.:-> HttpMethod, "headers" R.:-> Vec.Vector HttpHeader, "body" R.:-> Maybe Blob, "transform" R.:-> Maybe HttpTransform])

type HttpResponse = R.Rec (R.R '["status" R.:-> Natural, "headers" R.:-> Vec.Vector HttpHeader, "body" R.:-> Blob])

type CandidChangeFromUser = R.Rec (R.R '["user_id" R.:-> Principal])

type CandidChangeFromCanister = R.Rec (R.R '["canister_id" R.:-> Principal, "canister_version" R.:-> Maybe W.Word64])

type CandidChangeOrigin = V.Var (R.R '["from_user" R.:-> CandidChangeFromUser, "from_canister" R.:-> CandidChangeFromCanister])

type CandidChangeCreation = R.Rec (R.R '["controllers" R.:-> Vec.Vector Principal])

type CandidChangeCodeDeploymentMode = V.Var (R.R '["install" R.:-> (), "reinstall" R.:-> (), "upgrade" R.:-> ()])

type CandidChangeCodeDeployment = R.Rec (R.R '["mode" R.:-> CandidChangeCodeDeploymentMode, "module_hash" R.:-> Blob])

type CandidChangeControllersChange = R.Rec (R.R '["controllers" R.:-> Vec.Vector Principal])

type CandidChangeDetails = V.Var (R.R '["creation" R.:-> CandidChangeCreation, "code_uninstall" R.:-> (), "code_deployment" R.:-> CandidChangeCodeDeployment, "controllers_change" R.:-> CandidChangeControllersChange])

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
