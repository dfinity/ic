use maplit::btreeset;
use std::collections::BTreeSet;

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
