# HTTP Utilities

**Crates**: `ic-http-utils`, `httpbin-rs`

## Requirements

### Requirement: File Downloader

The HTTP utilities crate provides a file downloader for fetching large files over HTTP.

#### Scenario: File download
- **WHEN** a file download is initiated with a URL
- **THEN** the file is downloaded via HTTP GET
- **AND** the response body is written to the specified destination

#### Scenario: Large file download
- **WHEN** a large file is being downloaded
- **THEN** the download streams the content incrementally
- **AND** the download can handle files larger than available memory
