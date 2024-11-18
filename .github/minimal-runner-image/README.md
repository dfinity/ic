# Minimal Runner Image

We maintain a minimal image that can be used for all self-hosted runners across dfinity. The reason why it is stored in the `ic` repo, is because GHCR can only create public images from a repo that is public. It is also a central repo that many developers use and can easily refer to. This is an alternative to using the full `ic-build` image which is much larger.
