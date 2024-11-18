use anyhow::Result;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use kube::api::DynamicObject;
use kube::api::{Patch, PatchParams};
use kube::Api;
use strum_macros::AsRefStr;
use tracing::*;

static DV_URL_TEMPLATE: &str = r#"
apiVersion: cdi.kubevirt.io/v1beta1
kind: DataVolume
metadata:
  name: {name}
  annotations:
    cdi.kubevirt.io/storage.usePopulator: "false"
spec:
  contentType: {type}
  pvc:
    accessModes:
    - ReadWriteOnce
    resources:
      requests:
        storage: {quantity}
  source:
    http:
      url: {url}
"#;

static DV_PVC_TEMPLATE: &str = r#"
apiVersion: cdi.kubevirt.io/v1beta1
kind: DataVolume
metadata:
  name: {name}
  annotations:
    cdi.kubevirt.io/storage.usePopulator: "false"
spec:
  contentType: {type}
  pvc:
    accessModes:
    - ReadWriteOnce
    resources:
      requests:
        storage: {quantity}
  source:
    pvc:
      name: {pvc_name}
      namespace: {pvc_namespace}
"#;

#[derive(Debug, AsRefStr)]
#[strum(serialize_all = "lowercase")]
pub enum DataVolumeContentType {
    Kubevirt,
    Archive,
}

#[derive(Clone, Debug)]
pub enum DvSource {
    URL(String),
    PVC(String, String),
}

impl DvSource {
    pub fn url(url: String) -> Self {
        DvSource::URL(url)
    }
    pub fn pvc(pvc_name: String, pvc_namespace: String) -> Self {
        DvSource::PVC(pvc_name, pvc_namespace)
    }
}

pub struct DvInfo {
    name: String,
    source: DvSource,
    content_type: DataVolumeContentType,
    quantity: String,
}

impl DvInfo {
    pub fn new(
        name: &str,
        source: DvSource,
        content_type: DataVolumeContentType,
        quantity: &str,
    ) -> DvInfo {
        DvInfo {
            name: name.to_string(),
            source,
            content_type,
            quantity: quantity.to_string(),
        }
    }
}

pub async fn create_datavolume(
    api: &Api<DynamicObject>,
    dvinfo: &DvInfo,
    owner: OwnerReference,
) -> Result<()> {
    let DvInfo {
        name,
        source,
        content_type,
        quantity,
    } = dvinfo;

    info!("Creating data volume {}", name);
    let yaml = match source {
        DvSource::URL(url) => DV_URL_TEMPLATE.replace("{url}", url),
        DvSource::PVC(pvc_name, pvc_namespace) => DV_PVC_TEMPLATE
            .replace("{pvc_name}", pvc_name)
            .replace("{pvc_namespace}", pvc_namespace),
    };
    let yaml = yaml
        .replace("{name}", name)
        .replace("{type}", content_type.as_ref())
        .replace("{quantity}", quantity);

    let mut data: DynamicObject = serde_yaml::from_str(&yaml)?;
    data.metadata.owner_references = vec![owner].into();
    let response = api
        .patch(name, &PatchParams::apply("tnet"), &Patch::Apply(data))
        .await?;
    debug!("Creating data volume response: {:?}", response);
    info!("Creating data volume {} complete", name);

    Ok(())
}
