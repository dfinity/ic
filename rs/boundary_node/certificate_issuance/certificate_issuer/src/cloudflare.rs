use anyhow::{Context, Error, anyhow};
use async_trait::async_trait;
use cloudflare::{
    endpoints::{
        dns::{
            CreateDnsRecord, CreateDnsRecordParams, DeleteDnsRecord, DnsContent, ListDnsRecords,
            ListDnsRecordsParams, UpdateDnsRecord, UpdateDnsRecordParams,
        },
        zone::{ListZones, ListZonesParams, Zone},
    },
    framework::{Environment, HttpApiClientConfig, async_api::Client, auth::Credentials},
};

use crate::dns::{Create, Delete, Record};

impl TryFrom<DnsContent> for Record {
    type Error = Error;

    fn try_from(value: DnsContent) -> Result<Self, Self::Error> {
        match value {
            DnsContent::TXT { content } => Ok(Record::Txt(content)),
            _ => Err(anyhow!("not supported")),
        }
    }
}

pub struct Cloudflare {
    client: Client,
}

impl Cloudflare {
    pub fn new(url: &str, key: &str) -> Result<Self, Error> {
        let credentials = Credentials::UserAuthToken {
            token: key.to_owned(),
        };

        let client = Client::new(
            credentials,
            HttpApiClientConfig::default(),
            Environment::Custom(url.try_into().context("invalid api url")?),
        )
        .context("failed to initialize cloudflare api client")?;

        Ok(Self { client })
    }
}

#[async_trait]
impl Create for Cloudflare {
    async fn create(&self, zone: &str, name: &str, record: Record) -> Result<(), Error> {
        // Search zone
        let resp = self
            .client
            .request(&ListZones {
                params: ListZonesParams {
                    name: Some(zone.into()),
                    status: None,
                    page: None,
                    per_page: None,
                    order: None,
                    direction: None,
                    search_match: None,
                },
            })
            .await?;

        let zone_id = match resp.result.first() {
            Some(Zone { id, .. }) => id,
            None => return Err(anyhow!("missing zone")),
        };

        // Check for existence
        let resp = self
            .client
            .request(&ListDnsRecords {
                zone_identifier: zone_id,
                params: ListDnsRecordsParams {
                    record_type: None,
                    name: Some(format!("{name}.{zone}")),
                    page: None,
                    per_page: None,
                    order: None,
                    direction: None,
                    search_match: None,
                },
            })
            .await?;

        enum Command {
            Create,
            Update(String),
        }

        let cmd = match resp.result.first() {
            Some(r) => {
                if record != r.content.to_owned().try_into()? {
                    Some(Command::Update(r.id.to_owned()))
                } else {
                    None
                }
            }
            _ => Some(Command::Create),
        };

        // Create/Update record
        let content = match record {
            Record::Txt(content) => DnsContent::TXT { content },
        };

        match cmd {
            Some(Command::Create) => {
                self.client
                    .request(&CreateDnsRecord {
                        zone_identifier: zone_id,
                        params: CreateDnsRecordParams {
                            ttl: None,
                            priority: None,
                            proxied: None,
                            name,
                            content,
                        },
                    })
                    .await?
            }
            Some(Command::Update(id)) => {
                self.client
                    .request(&UpdateDnsRecord {
                        zone_identifier: zone_id,
                        identifier: &id,
                        params: UpdateDnsRecordParams {
                            ttl: None,
                            proxied: None,
                            name,
                            content,
                        },
                    })
                    .await?
            }
            None => {
                return Ok(());
            }
        };

        Ok(())
    }
}

#[async_trait]
impl Delete for Cloudflare {
    async fn delete(&self, zone: &str, name: &str) -> Result<(), Error> {
        // Search zone
        let resp = self
            .client
            .request(&ListZones {
                params: ListZonesParams {
                    name: Some(zone.into()),
                    status: None,
                    page: None,
                    per_page: None,
                    order: None,
                    direction: None,
                    search_match: None,
                },
            })
            .await?;

        let zone_id = match resp.result.first() {
            Some(Zone { id, .. }) => id,
            None => return Err(anyhow!("missing zone")),
        };

        // Check for existence
        let resp = self
            .client
            .request(&ListDnsRecords {
                zone_identifier: zone_id,
                params: ListDnsRecordsParams {
                    record_type: None,
                    name: Some(format!("{name}.{zone}")),
                    page: None,
                    per_page: None,
                    order: None,
                    direction: None,
                    search_match: None,
                },
            })
            .await?;

        let record = match resp.result.first() {
            Some(r) => r,
            None => return Ok(()),
        };

        // Delete
        self.client
            .request(&DeleteDnsRecord {
                zone_identifier: zone_id,
                identifier: &record.id,
            })
            .await?;

        Ok(())
    }
}
