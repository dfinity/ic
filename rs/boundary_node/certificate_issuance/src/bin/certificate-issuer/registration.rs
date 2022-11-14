use std::{str::FromStr, sync::Arc};

use anyhow::Context;
use async_trait::async_trait;
use candid::Principal;
use redis::{
    AsyncCommands, ErrorKind, FromRedisValue, RedisResult, RedisWrite, ToRedisArgs, Value,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::work::ProcessError;

const PENDING_REGISTRATION_TTL: u32 = 3600; // 1 Hour

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum State {
    Failed(String),
    PendingOrder,
    PendingChallengeResponse,
    PendingAcmeApproval,
    Available,
}

impl ToString for State {
    fn to_string(&self) -> String {
        serde_json::ser::to_string(self).unwrap_or_else(|_| "N/A".into())
    }
}

impl From<ProcessError> for State {
    fn from(e: ProcessError) -> Self {
        match e {
            ProcessError::AwaitingDnsPropogation => State::PendingChallengeResponse,
            ProcessError::AwaitingAcmeOrderReady => State::PendingAcmeApproval,
            ProcessError::UnexpectedError(_) => State::Failed(e.to_string()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Registration {
    pub domain: String,
    pub canister: Principal,
    pub state: State,
}

#[derive(Debug, thiserror::Error)]
pub enum CreateError {
    #[error("Registration '{0}' already exists")]
    Duplicate(Uuid),
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

#[async_trait]
pub trait Create: Send + Sync {
    async fn create(&self, domain: &str, canister: &Principal) -> Result<Uuid, CreateError>;
}

#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    #[error("Registration '{0}' not found")]
    NotFound(Uuid),
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

#[async_trait]
pub trait Update: Send + Sync {
    async fn update(&self, id: &Uuid, state: &State) -> Result<(), UpdateError>;
}

#[derive(Debug, thiserror::Error)]
pub enum GetError {
    #[error("Registration '{0}' not found")]
    NotFound(Uuid),
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}

#[async_trait]
pub trait Get: Send + Sync {
    async fn get(&self, id: &Uuid) -> Result<Registration, GetError>;
}

impl ToRedisArgs for Registration {
    fn write_redis_args<W>(&self, out: &mut W)
    where
        W: ?Sized + RedisWrite,
    {
        out.write_arg(&serde_json::ser::to_vec(self).unwrap())
    }
}

impl FromRedisValue for Registration {
    fn from_redis_value(v: &Value) -> RedisResult<Registration> {
        match *v {
            Value::Data(ref bytes) => serde_json::de::from_slice::<Registration>(bytes)
                .map_err(|_| (ErrorKind::TypeError, "failed to deserialize response").into()),
            _ => Err((ErrorKind::ResponseError, "response is type-incompatible").into()),
        }
    }
}

pub struct RedisCreator<T>(pub Arc<Mutex<T>>);

#[async_trait]
impl<T> Create for RedisCreator<T>
where
    T: AsyncCommands + Clone + Send + Sync,
{
    async fn create(&self, domain: &str, canister: &Principal) -> Result<Uuid, CreateError> {
        let script = redis::Script::new(
            r"
            local domain = KEYS[1]

            -- CHECK EXISTING
            local id = redis.call('GET', 'domain:' .. domain)
            if id then
                return id
            end

            local id  = KEYS[2]
            local reg = ARGV[1]
            local ttl = ARGV[2]

            -- CREATE NEW
            redis.call('SET', 'registration:' .. id, reg, 'EX', ttl)
            redis.call('SET', 'domain:' .. domain, id, 'EX', ttl)

            return id
        ",
        );

        let _id = Uuid::new_v4();
        let id: String = script
            .key(domain)
            .key(_id.to_string()) // Suggested ID
            .arg(&Registration {
                domain: domain.to_owned(),
                canister: canister.to_owned(),
                state: State::PendingOrder,
            })
            .arg(PENDING_REGISTRATION_TTL)
            .invoke_async(&mut self.0.lock().await.clone())
            .await
            .context("failed to create registration")?;

        let id = Uuid::from_str(&id).context("failed to parse id")?;
        if _id != id {
            return Err(CreateError::Duplicate(id));
        }

        Ok(id)
    }
}

pub struct RedisUpdater<T>(pub Arc<Mutex<T>>);

#[async_trait]
impl<T> Update for RedisUpdater<T>
where
    T: AsyncCommands + Clone + Send + Sync,
{
    async fn update(&self, id: &Uuid, state: &State) -> Result<(), UpdateError> {
        let reg: Option<Registration> = self
            .0
            .lock()
            .await
            .clone()
            .get(format!("registration:{id}"))
            .await
            .context("failed to get registration")?;

        // Check record exists
        let Registration {
            domain, canister, ..
        } = reg.ok_or_else(|| UpdateError::NotFound(id.to_owned()))?;

        let mut q = redis::pipe()
            .atomic()
            // Op 1
            .cmd("set")
            .arg(format!("registration:{id}"))
            .arg(&Registration {
                domain: domain.to_owned(),
                canister: canister.to_owned(),
                state: state.to_owned(),
            })
            .to_owned();

        // persist records if state is "Available"
        let mut q = match state {
            State::Failed(_)
            | State::PendingOrder
            | State::PendingChallengeResponse
            | State::PendingAcmeApproval => q.arg("keepttl").to_owned(),
            State::Available => q,
        };

        let q = match state {
            State::Available => q.cmd("persist").arg(format!("domain:{domain}")).to_owned(),
            _ => q,
        };

        // Execute
        q.query_async(&mut self.0.lock().await.clone())
            .await
            .context("failed to create registration")?;

        Ok(())
    }
}

pub struct RedisGetter<T>(pub Arc<Mutex<T>>);

#[async_trait]
impl<T> Get for RedisGetter<T>
where
    T: AsyncCommands + Clone + Send + Sync,
{
    async fn get(&self, id: &Uuid) -> Result<Registration, GetError> {
        let reg: Option<Registration> = self
            .0
            .lock()
            .await
            .clone()
            .get(format!("registration:{id}"))
            .await
            .context("failed to get registration")?;

        // Check record exists
        let reg = reg.ok_or_else(|| GetError::NotFound(id.to_owned()))?;

        Ok(reg)
    }
}
