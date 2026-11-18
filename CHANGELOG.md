# Changelog

All notable changes to PromptHound are documented here. Format based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning per
[SemVer](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026
### Added
- `gen` — hidden-payload document generator: pure-Python PDF writer (invisible /
  tiny / white / off-page hide modes) plus HTML/SVG/TXT carriers and
  invoice/report/resume/blank decoys.
- `probe` — generic direct-injection HTTP prober with `{{PAYLOAD}}` templating,
  JSON `--response-path` extraction, canary detection, and Burp/ZAP proxy support.
- `payloads` — categorized injection library (instruction-override,
  provenance-forgery, data-exfil-output, tool-abuse, prompt-leak, cross-context)
  with unique canary templating.
- Packaging, CLI entry point (`prompthound`), CI, SECURITY and CONTRIBUTING docs.
