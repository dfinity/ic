use std::{cell::RefCell, rc::Rc};

use ic_asset_certification::{Asset, AssetConfig, AssetFallbackConfig, AssetRouter};
use ic_cdk::api::{data_certificate, set_certified_data};
use ic_http_certification::{HeaderField, HttpCertificationTree, HttpRequest, HttpResponse};

use crate::{
    metrics::{export_metrics_as_http_response, with_metrics_registry},
    state::with_canister_state,
};

thread_local! {
    static HTTP_TREE: Rc<RefCell<HttpCertificationTree>> = Default::default();

    // initializing the asset router with an HTTP certification tree is optional.
    // if direct access to the HTTP certification tree is not needed for certifying
    // requests and responses outside of the asset router, then this step can be skipped.
    static ASSET_ROUTER: RefCell<AssetRouter<'static>> = Default::default();
}

// Handlers
pub fn serve_asset(request: &HttpRequest<'static>) -> HttpResponse<'static> {
    let path = match request.get_path() {
        Ok(path) => path,
        Err(err) => {
            return HttpResponse::builder()
                .with_status_code(400)
                .with_body(
                    format!("Malformed request: {:?}", err.to_string())
                        .as_bytes()
                        .to_vec(),
                )
                .build()
        }
    };

    match path.as_str() {
        // Serve non-certified metrics
        "/metrics" => with_canister_state(|state| {
            with_metrics_registry(|registry| export_metrics_as_http_response(registry, state))
        }),
        // Serve all other certified assets
        _ => ASSET_ROUTER.with_borrow(|asset_router| match data_certificate() {
            Some(certificate) => match asset_router.serve_asset(certificate.as_slice(), request) {
                Ok(response) => response,
                Err(err) => HttpResponse::builder()
                    .with_status_code(500)
                    .with_body(
                        format!(
                            "Failed to serve asset for path {}: {:?}",
                            path.as_str(),
                            err
                        )
                        .as_bytes()
                        .to_vec(),
                    )
                    .build(),
            },
            None => HttpResponse::builder()
                .with_status_code(500)
                .with_body(b"No data certificate available".to_vec())
                .build(),
        }),
    }
}

pub fn certify_assets(assets: Vec<Asset<'static, 'static>>) {
    let asset_configs = vec![
        AssetConfig::File {
            path: "/configs".to_string(),
            content_type: Some("text/plain".to_string()),
            headers: get_asset_headers(vec![(
                "cache-control".to_string(),
                "public, no-cache, no-store".to_string(),
            )]),
            fallback_for: vec![],
            aliased_by: vec![],
            encodings: vec![],
        },
        AssetConfig::File {
            path: "/rules".to_string(),
            content_type: Some("text/plain".to_string()),
            headers: get_asset_headers(vec![(
                "cache-control".to_string(),
                "public, no-cache, no-store".to_string(),
            )]),
            fallback_for: vec![],
            aliased_by: vec![],
            encodings: vec![],
        },
        AssetConfig::File {
            path: "/incidents".to_string(),
            content_type: Some("text/plain".to_string()),
            headers: get_asset_headers(vec![(
                "cache-control".to_string(),
                "public, no-cache, no-store".to_string(),
            )]),
            fallback_for: vec![],
            aliased_by: vec![],
            encodings: vec![],
        },
        AssetConfig::File {
            path: "/404".to_string(),
            content_type: Some("text/plain".to_string()),
            headers: get_asset_headers(vec![(
                "cache-control".to_string(),
                "public, no-cache, no-store".to_string(),
            )]),
            fallback_for: vec![AssetFallbackConfig {
                scope: "/".to_string(),
            }],
            aliased_by: vec![],
            encodings: vec![],
        },
        AssetConfig::File {
            path: "/403".to_string(),
            content_type: Some("text/plain".to_string()),
            headers: get_asset_headers(vec![(
                "cache-control".to_string(),
                "public, no-cache, no-store".to_string(),
            )]),
            fallback_for: vec![AssetFallbackConfig {
                scope: "/rules".to_string(),
            }],
            aliased_by: vec![],
            encodings: vec![],
        },
    ];

    // Add 404 and 403 paths to assets
    let mut assets = assets;
    assets.push(Asset::new("/404", "404 Not Found".as_bytes().to_owned()));
    assets.push(Asset::new("/403", "403 Forbidden".as_bytes().to_owned()));

    // We need to keep only one response for each asset, hence we:
    // - first delete all assets
    // - certify all assets
    ASSET_ROUTER.with_borrow_mut(|asset_router| {
        let _ = asset_router.delete_assets(assets.clone(), asset_configs.clone());
    });

    // Certify all the assets
    ASSET_ROUTER.with_borrow_mut(|asset_router| {
        if let Err(err) = asset_router.certify_assets(assets, asset_configs) {
            ic_cdk::trap(&format!("Failed to certify assets: {}", err));
        }

        // Set the canister's certified data.
        set_certified_data(&asset_router.root_hash());
    });
}

fn get_asset_headers(additional_headers: Vec<HeaderField>) -> Vec<HeaderField> {
    // Set up the default headers and include additional headers provided by the caller
    let mut headers = vec![
        ("strict-transport-security".to_string(), "max-age=31536000; includeSubDomains".to_string()),
        ("x-frame-options".to_string(), "DENY".to_string()),
        ("x-content-type-options".to_string(), "nosniff".to_string()),
        ("content-security-policy".to_string(), "default-src 'self'; form-action 'self'; object-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests; block-all-mixed-content".to_string()),
        ("referrer-policy".to_string(), "no-referrer".to_string()),
        ("permissions-policy".to_string(), "accelerometer=(),ambient-light-sensor=(),autoplay=(),battery=(),camera=(),display-capture=(),document-domain=(),encrypted-media=(),fullscreen=(),gamepad=(),geolocation=(),gyroscope=(),layout-animations=(self),legacy-image-formats=(self),magnetometer=(),microphone=(),midi=(),oversized-images=(self),payment=(),picture-in-picture=(),publickey-credentials-get=(),speaker-selection=(),sync-xhr=(self),unoptimized-images=(self),unsized-media=(self),usb=(),screen-wake-lock=(),web-share=(),xr-spatial-tracking=()".to_string()),
        ("cross-origin-embedder-policy".to_string(), "require-corp".to_string()),
        ("cross-origin-opener-policy".to_string(), "same-origin".to_string()),
    ];
    headers.extend(additional_headers);

    headers
}
