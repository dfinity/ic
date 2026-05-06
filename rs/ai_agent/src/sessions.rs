//! In-memory chat session store.
//!
//! `/v1/agent/chat` is multi-turn: callers send only the new user
//! prompt plus a `session_id`, and the server is responsible for
//! correlating turns. We cache the conversation transcript
//! (`Vec<Message>`) per session id; the rig `Agent` itself is rebuilt
//! per turn (it's cheap — just struct construction and tool wiring)
//! so that re-keying via `POST /v1/config` and per-request preamble
//! changes naturally take effect.
//!
//! Bounding rules (so a misbehaving client can't OOM the process):
//!
//! * `LruCache<SessionId, Session>` capped at a configurable count
//!   (default [`DEFAULT_MAX_SESSIONS`]).
//! * Per-session idle TTL ([`DEFAULT_IDLE_TTL`] default). Idle entries
//!   are swept lazily on every access — no background task required.
//!
//! Reset semantics:
//!
//! * `DELETE /v1/agent/sessions/:id` and `DELETE /v1/agent/sessions`
//!   call into [`SessionStore::remove`] / [`SessionStore::clear`].
//! * `POST /v1/config` clears all sessions, because per-session
//!   transcripts under a different model/key tend to confuse the
//!   model on continuation.

use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

use lru::LruCache;
use rig::completion::message::Message;
use uuid::Uuid;

/// Default cap on concurrently-cached sessions. ~256 chat threads
/// covers any realistic AI-node operator workload; raise via
/// `--max-sessions` if you actually need more.
pub const DEFAULT_MAX_SESSIONS: usize = 256;

/// Default idle TTL. A session that hasn't received a turn in this
/// long is dropped on the next access.
pub const DEFAULT_IDLE_TTL: Duration = Duration::from_secs(60 * 60);

/// One cached chat thread.
pub struct Session {
    /// Conversation transcript. Replayed verbatim into the next
    /// `agent.prompt(...).with_history(history)` call. After each
    /// turn we extend this with the `messages` list that rig returns
    /// in its `PromptResponse` — that list contains the new user
    /// prompt, any tool-call/tool-result interleavings, and the final
    /// assistant reply, in the right order for the next turn.
    pub history: Vec<Message>,

    /// Provider name + model snapshot, copied for the response so
    /// callers can verify which model handled their turn.
    pub provider_name: &'static str,
    pub model: String,

    /// Last-touched timestamp for idle-eviction.
    pub last_activity: Instant,
}

/// Thread-safe LRU + TTL session store. Wraps a `Mutex<LruCache>` —
/// the critical section is a hashmap lookup + clone of the history
/// `Vec<Message>` and is never held across an `.await`.
pub struct SessionStore {
    inner: Mutex<LruCache<String, Session>>,
    idle_ttl: Duration,
}

impl SessionStore {
    pub fn new(max_sessions: usize, idle_ttl: Duration) -> Self {
        let cap = max_sessions.max(1);
        Self {
            inner: Mutex::new(LruCache::new(cap)),
            idle_ttl,
        }
    }

    /// Generate a fresh, server-side session id. UUIDv4 keeps
    /// collisions a non-issue and matches what most chat APIs use.
    pub fn fresh_id() -> String {
        Uuid::new_v4().to_string()
    }

    /// Returns a snapshot of the cached session for `id`, refreshing
    /// its `last_activity`. Returns `None` if the session does not
    /// exist or has expired (in which case the entry is also evicted).
    ///
    /// The returned [`SessionSnapshot`] holds an owned clone of the
    /// transcript; the caller can `await` on the LLM without keeping
    /// the store mutex.
    pub fn get(&self, id: &str) -> Option<SessionSnapshot> {
        let mut cache = self.inner.lock().unwrap();

        // Lazy idle-TTL sweep on the requested entry. We don't sweep
        // the whole cache — capacity is bounded so stragglers will be
        // pushed out by the LRU on their own.
        if let Some(s) = cache.peek(id)
            && s.last_activity.elapsed() > self.idle_ttl
        {
            cache.pop(id);
            return None;
        }

        let session = cache.get_mut(id)?;
        session.last_activity = Instant::now();
        Some(SessionSnapshot {
            history: session.history.clone(),
            provider_name: session.provider_name,
            model: session.model.clone(),
        })
    }

    /// Insert (or replace) a session. Returns the id we keyed it
    /// under, which may be a freshly-minted UUID if the caller
    /// passed `None`.
    pub fn put(
        &self,
        id: Option<String>,
        history: Vec<Message>,
        provider_name: &'static str,
        model: String,
    ) -> String {
        let id = id.unwrap_or_else(Self::fresh_id);
        let mut cache = self.inner.lock().unwrap();
        cache.put(
            id.clone(),
            Session {
                history,
                provider_name,
                model,
                last_activity: Instant::now(),
            },
        );
        id
    }

    /// Replace the cached transcript for `id` after a turn completes.
    ///
    /// If the session was evicted between the snapshot read and this
    /// write (eviction races: another concurrent request, or LRU
    /// pressure from a different session id) we silently no-op rather
    /// than re-creating the entry — the user's intent was to update
    /// an existing session, not to resurrect one that was just told
    /// to go away. The next turn will then start fresh under the
    /// same id (or a new one) without surprising history.
    pub fn update_history(&self, id: &str, history: Vec<Message>) {
        let mut cache = self.inner.lock().unwrap();
        if let Some(session) = cache.get_mut(id) {
            session.history = history;
            session.last_activity = Instant::now();
        }
    }

    /// Remove one session by id. Returns `true` if it was present.
    pub fn remove(&self, id: &str) -> bool {
        self.inner.lock().unwrap().pop(id).is_some()
    }

    /// Drop every session. Used by `DELETE /v1/agent/sessions` and on
    /// every `POST /v1/config` (because mixing transcripts across
    /// model/credential changes is more confusing than helpful).
    pub fn clear(&self) -> usize {
        let mut cache = self.inner.lock().unwrap();
        let n = cache.len();
        cache.clear();
        n
    }

    /// Number of cached sessions. Intended for diagnostics / tests.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }

    /// Whether the cache currently has no sessions. Paired with
    /// [`SessionStore::len`] to satisfy `clippy::len_without_is_empty`.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.inner.lock().unwrap().is_empty()
    }
}

/// Read snapshot of a session. The transcript is owned (cloned out
/// of the LRU) so handlers can drop the store mutex before issuing
/// the LLM call.
pub struct SessionSnapshot {
    pub history: Vec<Message>,
    pub provider_name: &'static str,
    pub model: String,
}
