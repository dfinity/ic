use std::path::Path;

use crate::util::block_on;
use slog::{error, info, Logger};
use std::time::Duration;
use url::Url;

pub struct NotificationClient {
    pub push_metrics: bool,
    pub metrics_urls: Vec<Url>,
    pub network_name: String,
    pub backup_instance: String,
    pub slack_token: String,
    pub subnet: String,
    pub log: Logger,
}

impl NotificationClient {
    fn http_post_request(&self, url: String, content_type: String, data_str: String) {
        block_on(async {
            let client = reqwest::Client::new();
            match client
                .post(url)
                .timeout(Duration::from_secs(60))
                .header(reqwest::header::CONTENT_TYPE, content_type)
                .body(data_str)
                .send()
                .await
            {
                Ok(_) => {}
                Err(err) => error!(self.log, "Http POST failed: {}", err),
            }
        });
    }

    pub fn message_slack(&self, message: String) {
        info!(self.log, "{}", message);
        let url = format!(
            "https://hooks.slack.com/services/T43F9UHS5/B027BHAQ1HQ/{}",
            self.slack_token
        );
        let data_str = format!(
            "{{\"text\":\"[{}, *{}*] {}\"}}",
            self.backup_instance,
            &self.subnet[0..5],
            message
        );
        let content_type = "Content-type: application/json".to_string();
        self.http_post_request(url, content_type, data_str)
    }

    pub fn report_failure_slack(&self, message: String) {
        self.message_slack(format!("<!channel> ❌ {}", message))
    }

    pub fn report_warning_slack(&self, message: String) {
        self.message_slack(format!("⚠️ {}", message))
    }

    fn push_metrics(&self, message: String) {
        if !self.push_metrics {
            return;
        }
        for url in &self.metrics_urls {
            let url_str = format!(
                "{}metrics/job/backup-pod/instance/{}/ic_subnet/{}",
                url.as_str(),
                self.backup_instance,
                self.subnet
            );
            let content_type = "Content-type: application/octet-stream".to_string();
            self.http_post_request(url_str, content_type, message.clone());
        }
    }

    pub fn push_metrics_restored_height(&self, height: u64) {
        let message = format!(
            "# TYPE backup_last_restored_height gauge\n\
            # HELP backup_last_restored_height The height of the last restored state on a backup pod.\n\
            backup_last_restored_height{{ic=\"{}\"}} {}\n",
            self.network_name,
            height
        );
        self.push_metrics(message)
    }

    pub fn push_metrics_synced_height(&self, height: u64) {
        let message = format!(
            "# TYPE backup_last_synced_height gauge\n\
            # HELP backup_last_synced_height The height of the last synchronized state on a backup pod.\n\
            backup_last_synced_height{{ic=\"{}\"}} {}\n",
            self.network_name, height
        );
        self.push_metrics(message)
    }

    pub fn push_metrics_replay_time(&self, minutes: u64) {
        let message = format!(
            "# TYPE backup_replay_time_minutes gauge\n\
            # HELP backup_replay_time_minutes Time spent on a replay.\n\
            backup_replay_time_minutes{{ic=\"{}\"}} {}\n",
            self.network_name, minutes
        );
        self.push_metrics(message)
    }

    pub fn push_metrics_sync_time(&self, minutes: u64) {
        let message = format!(
            "# TYPE backup_sync_minutes gauge\n\
            # HELP backup_sync_minutes The time it took a backup pod to sync artifacts from NNS nodes.\n\
            backup_sync_minutes{{ic=\"{}\"}} {}\n",
            self.network_name, minutes
        );
        self.push_metrics(message)
    }

    pub fn push_metrics_disk_stats(
        &self,
        stats: &[(
            &Path,
            /*space % usage*/ u32,
            /*inodes % usage*/ u32,
            /*storage type*/ &str,
        )],
    ) {
        let message = format!(
            "# TYPE backup_disk_usage gauge\n\
             # HELP backup_disk_usage The allocation percentage of some resource on a backup pod.\n\
             {}",
            stats
                .iter()
                .map(|(dir, space, inodes, storage_type)| {
                    format!(
                        "backup_disk_usage{{ic=\"{0}\", dir=\"{1}\", resource=\"space\", storage_type=\"{4}\"}} {2}\n\
                         backup_disk_usage{{ic=\"{0}\", dir=\"{1}\", resource=\"inodes\", storage_type=\"{4}\"}} {3}\n",
                        self.network_name,
                        dir.to_str().unwrap_or_default(),
                        space,
                        inodes,
                        storage_type
                    )
                })
                .collect::<Vec<_>>()
                .join("\n")
        );
        self.push_metrics(message)
    }

    pub fn push_metrics_version(&self) {
        // Convert semantic version to a single number, e.g.
        // 3.23.56 => 3*1000_000 + 23 * 1000 + 56 => 3_023_056.
        let major = env!("CARGO_PKG_VERSION_MAJOR");
        let minor = env!("CARGO_PKG_VERSION_MINOR");
        let patch = env!("CARGO_PKG_VERSION_PATCH");
        let version = major.parse::<u32>().unwrap_or_default() * 1_000_000
            + minor.parse::<u32>().unwrap_or_default() * 1000
            + patch.parse::<u32>().unwrap_or_default();
        let message = format!(
            "# TYPE backup_version_number gauge\n\
            # HELP backup_version_number The current version of the ic-backup tool that is running on this pod.\n\
            backup_version_number{{ic=\"{}\"}} {}\n",
            self.network_name, version
        );
        self.push_metrics(message)
    }
}
