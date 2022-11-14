use std::sync::Arc;

use anyhow::{Context, Error};
use async_trait::async_trait;
use itertools::Itertools;
use redis::{AsyncCommands, ErrorKind, FromRedisValue, RedisResult, Value};
use serde::Serialize;
use tokio::sync::Mutex;

pub struct Pair(
    pub String, // Certificate Chain
    pub String, // Private Key
);

#[async_trait]
pub trait Upload: Sync + Send {
    async fn upload(&self, id: &str, pair: &Pair) -> Result<(), Error>;
}

#[derive(Serialize)]
pub struct Package {
    domain: String,
    canister: String,
    crt: String,
    key: String,
}

impl FromRedisValue for Package {
    fn from_redis_value(v: &Value) -> RedisResult<Package> {
        match *v {
            Value::Bulk(ref vs) => {
                let p = String::from_redis_values(vs)
                    .map_err(|_| (ErrorKind::TypeError, "failed to deserialize package"))?;

                let (domain, canister, crt, key) = p
                    .into_iter()
                    .collect_tuple()
                    .ok_or((ErrorKind::TypeError, "failed to collect package values"))?;

                Ok(Package {
                    domain,
                    canister,
                    crt,
                    key,
                })
            }
            _ => Err((ErrorKind::ResponseError, "response is type-incompatible").into()),
        }
    }
}

#[async_trait]
pub trait Export: Sync + Send {
    async fn export(&self) -> Result<Vec<Package>, Error>;
}

pub struct RedisUploader<T>(pub Arc<Mutex<T>>);

#[async_trait]
impl<T> Upload for RedisUploader<T>
where
    T: AsyncCommands + Clone + Send + Sync,
{
    async fn upload(&self, id: &str, pair: &Pair) -> Result<(), Error> {
        let Pair(certificate_chain, private_key) = pair;

        // Construct Query
        let q = redis::pipe()
            .set(format!("registration:{id}:crt"), &certificate_chain)
            .set(format!("registration:{id}:key"), &private_key)
            .to_owned();

        // Execute Query
        q.query_async(&mut self.0.lock().await.clone())
            .await
            .context("failed to write certificates to redis")?;

        Ok(())
    }
}

pub struct RedisExporter<T>(pub Arc<Mutex<T>>);

#[async_trait]
impl<T> Export for RedisExporter<T>
where
    T: AsyncCommands + Clone + Send + Sync,
{
    async fn export(&self) -> Result<Vec<Package>, Error> {
        let script = redis::Script::new(
            r"
            local pkgs = {}
            local cursor = '0'

            while true do
                local resp = redis.call(
                    'SCAN', cursor,
                    'MATCH', 'domain:*'
                )

                local cursor = resp[1]
                local keys   = resp[2]

                for _, k in ipairs(keys) do
                    local id  = redis.call('GET', k)
                    local reg = redis.call('GET', 'registration:' .. id)
                    local reg = cjson.decode(reg)

                    if reg['state'] == 'Available' then
                        local domain   = reg['domain']
                        local canister = reg['canister']
                        local crt      = redis.call('GET', 'registration:' .. domain .. ':crt')
                        local pkey     = redis.call('GET', 'registration:' .. domain .. ':key')

                        table.insert(pkgs, {
                            domain,
                            canister,
                            crt,
                            pkey
                        })
                    end
                end

                if cursor == '0' then
                    break
                end
            end

            return pkgs
        ",
        );

        let pkgs: Vec<Package> = script
            .prepare_invoke()
            .invoke_async(&mut self.0.lock().await.clone())
            .await
            .context("failed to retrieve certificate packages")?;

        Ok(pkgs)
    }
}
