use crate::util::block_on;
use slog::{error, info, Logger};

pub struct NotificationClient {
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
        self.message_slack(format!("⚠️  {}", message))
    }

    fn push_metrics(&self, message: String) {
        let url = format!(
            "http://prometheus.mainnet.dfinity.network:9091/metrics/job/backup-pod/instance/{}",
            self.backup_instance
        );
        let content_type = "Content-type: application/octet-stream".to_string();

        self.http_post_request(url, content_type, message);
    }

    pub fn push_metrics_restored_height(&self, height: u64) {
        let message = format!(
            "# TYPE backup_last_restored_height gauge\n\
            # HELP backup_last_restored_height The height of the last restored state on a backup pod.\n\
            backup_last_restored_height{{ic=\"{}\", ic_subnet=\"{}\"}} {}\n",
            self.backup_instance,
            self.subnet,
            height,
        );
        self.push_metrics(message)
    }

    pub fn push_metrics_replay_time(&self, minutes: u64) {
        let message = format!(
            "# TYPE backup_replay_time_minutes gauge\n\
            # HELP backup_replay_time_minutes Time spent on a replay.\n\
            backup_replay_time_minutes{{ic=\"{}\", ic_subnet=\"{}\"}} {}\n",
            self.backup_instance, self.subnet, minutes,
        );
        self.push_metrics(message)
    }

    pub fn push_metrics_sync_time(&self, minutes: u64) {
        let message = format!(
            "# TYPE backup_sync_minutes gauge\n\
            # HELP backup_sync_minutes The time it took a backup pod to sync artifacts from NNS nodes.\n\
            backup_sync_minutes{{ic=\"{}\", ic_subnet=\"{}\"}} {}\n",
            self.backup_instance,
            self.subnet,
            minutes,
        );
        self.push_metrics(message)
    }
}
