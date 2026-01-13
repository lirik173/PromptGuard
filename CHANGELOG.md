# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- `IOptions<PromptShieldOptions>` support for standard .NET configuration patterns
- `AddPromptShield(IConfiguration)` overload for appsettings.json binding
- Configurable heuristic thresholds via `HeuristicOptions`:
  - `LengthThresholdRatio` - control prompt length sensitivity
  - `AlphanumericRatioThreshold` - control special character detection
  - `PunctuationDensityThreshold` - control delimiter injection detection
  - `MinDirectiveKeywords` - control directive language sensitivity

### Fixed
- Memory leak in ASP.NET Core middleware when handling large request bodies
- Content length now checked before enabling request buffering

### Changed
- Heuristic analyzer now uses configurable thresholds instead of hardcoded values

---

## [1.0.0] - 2026-01-13

### Added

#### Core Detection Engine
- Multi-layer detection pipeline with cascading execution
- Pattern Matching layer with regex-based threat detection
- Heuristic Analysis layer with behavioral signal detection
- ML Classification layer support (ONNX runtime)
- Semantic Analysis layer support (opt-in, requires LLM endpoint)
- Early exit optimization for definitive results
- Configurable thresholds per layer and globally

#### Built-in Patterns
- Jailbreak detection patterns (DAN, STAN, etc.)
- Role impersonation detection
- Instruction override detection
- System prompt extraction detection
- Encoding obfuscation detection (Base64, hex, Unicode)
- Delimiter injection detection

#### Heuristic Signals
- Instruction override indicators
- Role impersonation signals
- Encoding anomaly detection
- Delimiter abuse detection
- Prompt length anomalies
- Special character density analysis

#### Integrations
- **Semantic Kernel**: `IPromptRenderFilter` integration via `.AddPromptShield()`
- **ASP.NET Core**: Request middleware with path filtering and JSON path extraction
- **Direct API**: `IPromptAnalyzer` for custom integration scenarios

#### Configuration
- Code-first configuration with fluent API
- File-based configuration via `appsettings.json`
- Per-layer enable/disable toggles
- Configurable thresholds and timeouts
- Fail-closed/fail-open behavior options

#### Observability
- OpenTelemetry metrics support
- Distributed tracing support
- Structured logging with configurable levels
- Privacy-conscious logging options (disable prompt content logging)

#### Extensibility
- `IPatternProvider` for custom detection patterns
- `IHeuristicAnalyzer` for custom heuristic signals
- `IPromptShieldEventHandler` for custom event handling
- `IDynamicPatternProvider` for runtime pattern updates

#### Analysis Results
- Threat detection status and confidence score
- OWASP LLM Top 10 category mapping
- Detailed breakdown by detection layer
- User-facing safe error messages
- Technical explanations for security teams

### Security
- Fail-closed default behavior
- Input validation (null, empty, length limits)
- Regex timeout protection against ReDoS
- No prompt content in logs by default
- Safe user-facing messages that don't leak internals

### Performance
- Sub-millisecond latency for clean prompts (p95)
- Compiled regex patterns for pattern matching
- Early exit on definitive results
- Thread-safe singleton components

---

## Version History

| Version | Date | Highlights |
|---------|------|------------|
| 1.0.0 | 2026-01-13 | Initial release |

---

## Migration Guides

### Upgrading to 1.x

This is the initial release. No migration required.

---

## Links

- [Full Documentation](README.md)
- [API Reference](docs/api-reference.md)
- [GitHub Releases](https://github.com/promptshield/promptshield/releases)
