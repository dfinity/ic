use maplit::btreeset;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::time::Duration;

#[derive(Clone, PartialEq, Eq)]
enum ForumPost {
    ApplicationCanisterManagement { title: String, body: String },
}

impl ForumPost {
    fn title(&self) -> &String {
        match self {
            ForumPost::ApplicationCanisterManagement { title, .. } => title,
        }
    }

    fn body(&self) -> &String {
        match self {
            ForumPost::ApplicationCanisterManagement { body, .. } => body,
        }
    }

    fn category(&self) -> u64 {
        match &self {
            ForumPost::ApplicationCanisterManagement { .. } => {
                // Category "NNS proposal discussions"
                // https://forum.dfinity.org/c/governance/nns-proposal-discussions/76
                76
            }
        }
    }

    fn tags(&self) -> BTreeSet<Tag> {
        btreeset! {Tag::ApplicationCanisterMgmt}
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Tag {
    ApplicationCanisterMgmt,
}

impl Tag {
    fn id(&self) -> &'static str {
        match self {
            Tag::ApplicationCanisterMgmt => "Application-canister-mgmt",
        }
    }
}

/// Create a new topic (first forum post in a thread)
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct CreateTopicRequest {
    title: String,
    raw: String,
    category: u64,
    tags: Vec<String>,
}

/// Response returned upon successful creation of a new topic.
#[derive(Clone, PartialEq, Eq, Deserialize)]
pub struct CreateTopicResponse {
    pub id: u64,
    pub topic_id: u64,
    pub topic_slug: String,
    pub post_url: String,
}

pub struct DiscourseClient {
    client: reqwest::Client,
    forum_url: String,
    api_user: String,
    api_key: String,
}

impl DiscourseClient {
    pub fn new(url: String, api_user: String, api_key: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("ERROR: Failed to create client");

        Self {
            client,
            forum_url: url,
            api_key,
            api_user,
        }
    }

    pub async fn create_topic<T: Into<CreateTopicRequest>>(
        &self,
        request: T,
    ) -> Result<CreateTopicResponse, String> {
        let request = request.into();
        self.post_request("posts.json?skip_validations=true", request)
            .await
    }

    async fn post_request<Request: Serialize, Response: DeserializeOwned>(
        &self,
        path: &str,
        request: Request,
    ) -> Result<Response, String> {
        self.client
            .post(format!("{}/{}", self.forum_url, path))
            .json(&request)
            .header("Api-Key", &self.api_key)
            .header("Api-Username", &self.api_user)
            .send()
            .await
            .map_err(|e| e.to_string())?
            .json()
            .await
            .map_err(|e| e.to_string())
    }
}
