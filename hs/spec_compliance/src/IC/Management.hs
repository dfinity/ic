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
import qualified Data.Vector as Vec
import IC.Types

-- This needs cleaning up
principalToEntityId :: Principal -> EntityId
principalToEntityId = EntityId . rawPrincipal

entityIdToPrincipal :: EntityId -> Principal
entityIdToPrincipal = Principal . rawEntityId

type SenderCanisterVersion =
  [candidType|
    record {
      sender_canister_version : opt nat64;
    }
  |]

type InstallMode =
  [candidType|
    variant {
      install : null; 
      reinstall : null; 
      upgrade : opt record {
        skip_pre_upgrade : opt bool;
        wasm_memory_persistence : opt variant {
          keep;
          replace;
        };
      };
    }
  |]

type RunState =
  [candidType|
    variant { running; stopping; stopped }
  |]

type Settings =
  [candidType|
    record {
      controllers : opt vec principal;
      compute_allocation : opt nat;
      memory_allocation : opt nat;
      freezing_threshold : opt nat;
    }
  |]

type HttpHeader =
  [candidType|
    record { name: text; value: text }
  |]

type HttpResponse =
  [candidType|
    record {
      status: nat;
      headers: vec record { name : text; value : text };
      body: blob;
    }
  |]

type CandidChangeOrigin =
  [candidType|
    variant {
      from_user : record {
        user_id : principal;
      };
      from_canister : record {
        canister_id : principal;
        canister_version : opt nat64;
      };
    }
  |]

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

type CandidChangeDetails =
  [candidType|
    variant {
        creation : record {
        controllers : vec principal;
      };
      code_uninstall;
      code_deployment : record {
        mode : variant {install; reinstall; upgrade};
        module_hash : blob;
      };
      controllers_change : record {
        controllers : vec principal;
      };
    }
  |]

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

type ICManagement m = [candidFile|hs/spec_compliance/ic.did|]

managementMethods :: [String]
managementMethods = R.labels @(ICManagement IO) @R.Unconstrained1
