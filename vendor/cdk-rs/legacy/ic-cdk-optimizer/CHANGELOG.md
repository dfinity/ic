# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.5] - 2022-09-15
This is the final release of this deprecated tool.

### Added
- Specifying `-` as the input or output argument refers to stdin or stdout respectively (#230)

### Changed
- Update clap to 3.1 (#209)
- The output argument defaults to the input argument if unspecified (#230)

## [0.3.4] - 2022-02-07
### Fixed
- Actually print version with --version (#196)
