#[allow(clippy::all)]
#[path = "../gen/ic_sns_root.pb.v1.rs"]
pub mod v1;

impl TryFrom<v1::LogVisibility> for ic_nervous_system_clients::update_settings::LogVisibility {
    type Error = String;

    fn try_from(log_visibility: v1::LogVisibility) -> Result<Self, Self::Error> {
        match log_visibility {
            v1::LogVisibility::Unspecified => Err("Unspecified log visibility".to_string()),
            v1::LogVisibility::Controllers => Ok(Self::Controllers),
            v1::LogVisibility::Public => Ok(Self::Public),
        }
    }
}

impl TryFrom<v1::SnapshotVisibility>
    for ic_nervous_system_clients::update_settings::SnapshotVisibility
{
    type Error = String;

    fn try_from(snapshot_visibility: v1::SnapshotVisibility) -> Result<Self, Self::Error> {
        match snapshot_visibility {
            v1::SnapshotVisibility::Unspecified => {
                Err("Unspecified snapshot visibility".to_string())
            }
            v1::SnapshotVisibility::Controllers => Ok(Self::Controllers),
            v1::SnapshotVisibility::Public => Ok(Self::Public),
        }
    }
}
