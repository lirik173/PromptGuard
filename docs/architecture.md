# PromptShield Architecture

This document describes the high-level architecture of PromptShield and the design decisions behind it.

---

## Table of Contents

- [Overview](#overview)
- [System Architecture](#system-architecture)
- [Detection Pipeline](#detection-pipeline)
- [Package Structure](#package-structure)
- [Key Components](#key-components)
- [Design Decisions](#design-decisions)

---

## Overview

PromptShield is designed as a multi-layer prompt injection detection system that provides defense-in-depth against various attack vectors. The architecture follows these core principles:

1. **Modularity** — Each detection layer is independent and can be enabled/disabled
2. **Extensibility** — Custom patterns and analyzers can be added without modifying core code
3. **Performance** — Fast-path execution for clean prompts, expensive operations only when needed
4. **Security** — Fail-closed by default, safe user-facing messages

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Client Applications                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   ┌──────────────────┐   ┌──────────────────┐   ┌──────────────────┐       │
│   │  Semantic Kernel │   │   ASP.NET Core   │   │    Direct API    │       │
│   │   Integration    │   │    Middleware    │   │      Usage       │       │
│   │                  │   │                  │   │                  │       │
│   │ .AddPromptShield │   │ .UsePromptShield │   │ IPromptAnalyzer  │       │
│   └────────┬─────────┘   └────────┬─────────┘   └────────┬─────────┘       │
│            │                      │                      │                  │
│            └──────────────────────┼──────────────────────┘                  │
│                                   │                                         │
│                                   ▼                                         │
│   ┌─────────────────────────────────────────────────────────────────┐      │
│   │                        PromptShield.Core                         │      │
│   │  ┌─────────────────────────────────────────────────────────┐    │      │
│   │  │                    IPromptAnalyzer                       │    │      │
│   │  │                    (PromptAnalyzer)                      │    │      │
│   │  └───────────────────────────┬─────────────────────────────┘    │      │
│   │                              │                                   │      │
│   │                              ▼                                   │      │
│   │  ┌─────────────────────────────────────────────────────────┐    │      │
│   │  │                  PipelineOrchestrator                    │    │      │
│   │  │         (Coordinates multi-layer detection)              │    │      │
│   │  └───────────────────────────┬─────────────────────────────┘    │      │
│   │                              │                                   │      │
│   │      ┌───────────────────────┼───────────────────────┐          │      │
│   │      │                       │                       │          │      │
│   │      ▼                       ▼                       ▼          │      │
│   │  ┌────────────┐      ┌─────────────┐      ┌──────────────┐     │      │
│   │  │  Pattern   │─────▶│  Heuristic  │─────▶│      ML      │     │      │
│   │  │  Matching  │      │  Analysis   │      │Classification│     │      │
│   │  │   Layer    │      │    Layer    │      │    Layer     │     │      │
│   │  └────────────┘      └─────────────┘      └──────────────┘     │      │
│   │                                                                  │      │
│   └─────────────────────────────────────────────────────────────────┘      │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Detection Pipeline

The detection pipeline executes layers in a specific order, with early exit capabilities:

### Pipeline Flow

```
                    ┌────────────────┐
                    │AnalysisRequest │
                    │   (Input)      │
                    └───────┬────────┘
                            │
                            ▼
                    ┌───────────────┐
                    │  Validation   │──────▶ ValidationException
                    │               │        (if invalid)
                    └───────┬───────┘
                            │
                            ▼
            ┌───────────────────────────────┐
            │      Pattern Matching Layer    │
            │                               │
            │  • Regex-based detection      │
            │  • Built-in + custom patterns │
            │  • Timeout protection (100ms) │
            └───────────────┬───────────────┘
                            │
                    ┌───────┴───────┐
                    │ Early Exit?   │
                    │ (≥0.9 conf)   │
                    └───────┬───────┘
                            │ No
                            ▼
            ┌───────────────────────────────┐
            │      Heuristic Analysis       │
            │                               │
            │  • Behavioral signals         │
            │  • Structural anomalies       │
            │  • Multiple analyzers         │
            └───────────────┬───────────────┘
                            │
                    ┌───────┴───────┐
                    │ Definitive?   │
                    │ (≥0.85 / ≤0.15)│
                    └───────┬───────┘
                            │ No
                            ▼
            ┌───────────────────────────────┐
            │       ML Classification       │
            │                               │
            │  • ONNX model inference       │
            │  • Neural network classifier  │
            │  • Confidence scoring         │
            └───────────────┬───────────────┘
                            │
                            ▼
            ┌───────────────────────────────┐
            │         Aggregation           │
            │                               │
            │  • Combine layer results      │
            │  • Apply global threshold     │
            │  • Generate final decision    │
            └───────────────┬───────────────┘
                            │
                            ▼
                    ┌───────────────┐
                    │AnalysisResult │
                    │   (Output)    │
                    └───────────────┘
```

### Layer Execution Rules

| Layer | Condition to Execute | Early Exit Condition |
|-------|---------------------|---------------------|
| Pattern Matching | Always (if enabled) | Confidence ≥ 0.9 |
| Heuristic Analysis | Previous layer didn't early-exit | Confidence ≥ 0.85 or ≤ 0.15 |
| ML Classification | Elevated risk from previous layers | Confidence ≥ 0.8 |
| Semantic Analysis | User-enabled and elevated risk | N/A (final layer) |

---

## Package Structure

```
PromptShield/
├── src/
│   ├── PromptShield.Abstractions/     # Interfaces, models, contracts
│   │   ├── Analysis/                  # AnalysisRequest, AnalysisResult, etc.
│   │   ├── Configuration/             # Options classes
│   │   ├── Detection/                 # DetectionPattern
│   │   ├── Events/                    # Event types
│   │   ├── Exceptions/                # Custom exceptions
│   │   ├── I*.cs                      # Core interfaces
│   │   └── *.cs                       # Base classes, helpers
│   │
│   ├── PromptShield.Core/             # Core detection engine
│   │   ├── Layers/                    # Detection layer implementations
│   │   │   ├── PatternMatchingLayer.cs
│   │   │   ├── HeuristicLayer.cs
│   │   │   └── BuiltInHeuristicAnalyzer.cs
│   │   ├── Patterns/                  # Pattern providers
│   │   │   └── BuiltInPatternProvider.cs
│   │   ├── Pipeline/                  # Orchestration
│   │   │   └── PipelineOrchestrator.cs
│   │   ├── Validation/                # Input validation
│   │   │   └── AnalysisRequestValidator.cs
│   │   ├── PromptAnalyzer.cs          # Main analyzer
│   │   └── ServiceCollectionExtensions.cs
│   │
│   ├── PromptShield.SemanticKernel/   # Semantic Kernel integration
│   │   ├── KernelBuilderExtensions.cs
│   │   ├── PromptShieldFilter.cs
│   │   └── PromptInjectionDetectedException.cs
│   │
│   └── PromptShield.AspNetCore/       # ASP.NET Core integration
│       ├── ApplicationBuilderExtensions.cs
│       ├── PromptShieldMiddleware.cs
│       └── PromptShieldMiddlewareOptions.cs
│
└── tests/
    ├── PromptShield.Core.Tests/
    ├── PromptShield.SemanticKernel.Tests/
    ├── PromptShield.AspNetCore.Tests/
    └── PromptShield.Benchmarks/
```

### Package Dependencies

```
┌─────────────────────────────┐
│PromptShield.SemanticKernel  │───────┐
└─────────────────────────────┘       │
                                      │
┌─────────────────────────────┐       │
│PromptShield.AspNetCore      │───────┼───▶ ┌─────────────────────┐
└─────────────────────────────┘       │     │PromptShield.Core    │
                                      │     └──────────┬──────────┘
                                      │                │
                                      │                ▼
                                      │     ┌─────────────────────────┐
                                      └────▶│PromptShield.Abstractions│
                                            └─────────────────────────┘
```

---

## Key Components

### IPromptAnalyzer

The main entry point for prompt analysis:

```csharp
public interface IPromptAnalyzer
{
    Task<AnalysisResult> AnalyzeAsync(string prompt, CancellationToken ct = default);
    Task<AnalysisResult> AnalyzeAsync(AnalysisRequest request, CancellationToken ct = default);
}
```

### PipelineOrchestrator

Coordinates layer execution with early exit logic:

```csharp
internal class PipelineOrchestrator
{
    private readonly PatternMatchingLayer _patternLayer;
    private readonly HeuristicLayer _heuristicLayer;
    private readonly PromptShieldOptions _options;

    public async Task<PipelineResult> ExecuteAsync(AnalysisRequest request, CancellationToken ct)
    {
        // 1. Execute pattern matching
        var patternResult = await _patternLayer.ExecuteAsync(request, ct);
        if (patternResult.Confidence >= _options.PatternMatching.EarlyExitThreshold)
            return CreateResult(patternResult, "PatternMatching");

        // 2. Execute heuristics
        var heuristicResult = await _heuristicLayer.ExecuteAsync(request, ct);
        if (heuristicResult.IsDefinitive)
            return CreateResult(heuristicResult, "Heuristics");

        // 3. Continue to ML if elevated risk...
    }
}
```

### Detection Layers

Each layer implements a consistent interface:

```csharp
internal interface IDetectionLayer
{
    string LayerName { get; }
    Task<LayerResult> ExecuteAsync(AnalysisRequest request, CancellationToken ct);
}
```

### Extensibility Points

| Interface | Purpose | Registration |
|-----------|---------|--------------|
| `IPatternProvider` | Custom detection patterns | `AddPatternProvider<T>()` |
| `IHeuristicAnalyzer` | Custom heuristic signals | `AddHeuristicAnalyzer<T>()` |
| `IPromptShieldEventHandler` | Event callbacks | `AddEventHandler<T>()` |
| `IDynamicPatternProvider` | Runtime pattern updates | `AddDynamicPatternProvider<T>()` |

---

## Design Decisions

### Why Multi-Layer Detection?

**Problem**: Single-layer detection is easily bypassed. Attackers can craft prompts that evade pattern matching or fool ML models.

**Solution**: Defense-in-depth with multiple complementary layers:

| Layer | Strengths | Weaknesses |
|-------|-----------|------------|
| Pattern Matching | Fast, precise, explainable | Easily bypassed with variations |
| Heuristics | Catches behavioral anomalies | May miss novel attacks |
| ML Classification | Generalizes to variations | Black box, requires training |
| Semantic Analysis | Deep understanding | Slow, expensive, recursive risk |

### Why Cascading Execution?

**Problem**: Running all layers for every prompt is wasteful and slow.

**Solution**: Early exit when definitive results are reached:

```
Clean Prompt Path:     Pattern(0.1) → Heuristic(0.05) → Done (skip ML)
Obvious Attack Path:   Pattern(0.95) → Done (early exit)
Uncertain Prompt Path: Pattern(0.5) → Heuristic(0.6) → ML(0.85) → Done
```

### Why Fail-Closed by Default?

**Problem**: Security systems that fail-open create vulnerabilities during failures.

**Solution**: Default to denying prompts when analysis fails:

```csharp
// Default configuration
options.OnAnalysisError = FailureBehavior.FailClosed;
```

This ensures that system errors don't become attack vectors.

### Why Separate Abstractions Package?

**Problem**: Integration packages need to reference types without depending on implementation.

**Solution**: Extract interfaces and models to `PromptShield.Abstractions`:

- Integration packages have minimal dependencies
- Implementation can be swapped without breaking contracts
- Clear separation between API and implementation

### Why Regex with Timeouts?

**Problem**: Complex regex patterns can cause catastrophic backtracking (ReDoS).

**Solution**: All regex execution is wrapped with configurable timeouts:

```csharp
try
{
    var match = Regex.Match(input, pattern, RegexOptions.None, TimeSpan.FromMilliseconds(100));
}
catch (RegexMatchTimeoutException)
{
    _logger.LogWarning("Pattern {PatternName} timed out", pattern.Name);
    // Skip this pattern, continue with others
}
```

---

## Data Flow

### Analysis Request Flow

```
User Input
    │
    ▼
┌─────────────────────────────────────────┐
│           AnalysisRequest                │
│  ┌─────────────────────────────────┐    │
│  │ Prompt: string                   │    │
│  │ SystemPrompt: string?            │    │
│  │ ConversationHistory: Message[]?  │    │
│  │ Metadata: AnalysisMetadata?      │    │
│  └─────────────────────────────────┘    │
└───────────────────┬─────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────┐
│           Input Validation               │
│  • Null/empty check                     │
│  • Length validation                    │
│  • Character validation                 │
└───────────────────┬─────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────┐
│           Pipeline Execution             │
│  • Pattern Matching                     │
│  • Heuristic Analysis                   │
│  • ML Classification (if needed)        │
└───────────────────┬─────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────┐
│           AnalysisResult                 │
│  ┌─────────────────────────────────┐    │
│  │ IsThreat: bool                   │    │
│  │ Confidence: double               │    │
│  │ ThreatInfo: ThreatInfo?          │    │
│  │ Breakdown: DetectionBreakdown?   │    │
│  │ DecisionLayer: string            │    │
│  │ Duration: TimeSpan               │    │
│  │ AnalysisId: Guid                 │    │
│  └─────────────────────────────────┘    │
└─────────────────────────────────────────┘
```

### Event Flow

```
Analysis Start
    │
    ├──▶ IPromptShieldEventHandler.OnAnalysisStartedAsync()
    │
    ▼
Pipeline Execution
    │
    ├──▶ (if threat) IPromptShieldEventHandler.OnThreatDetectedAsync()
    │
    ▼
Analysis Complete
    │
    └──▶ IPromptShieldEventHandler.OnAnalysisCompletedAsync()
```

---

## Thread Safety

All public components are designed for concurrent use:

| Component | Thread Safety | Notes |
|-----------|---------------|-------|
| `IPromptAnalyzer` | Thread-safe | Stateless, DI singleton |
| `PipelineOrchestrator` | Thread-safe | Stateless coordinator |
| Detection Layers | Thread-safe | Compiled regex, immutable state |
| `IPatternProvider` | Must be thread-safe | Custom implementations must handle concurrency |

---

## Performance Characteristics

| Operation | Typical Latency | Notes |
|-----------|-----------------|-------|
| Input validation | < 0.01ms | Simple checks |
| Pattern matching | 0.1 - 0.5ms | Depends on pattern count |
| Heuristic analysis | 0.2 - 0.5ms | Multiple signal checks |
| ML classification | 2 - 5ms | ONNX inference |
| Clean prompt total | 0.3 - 1ms | Fast path |
| Threat prompt total | 0.5 - 8ms | Full pipeline |

---

## Future Considerations

### Planned Enhancements

1. **Pre-trained ML Model** — Embedded in NuGet package
2. **Pattern Feed** — Dynamic pattern updates from threat intelligence
3. **Distributed Caching** — Cache analysis results for identical prompts
4. **Adaptive Thresholds** — Learn from false positive/negative feedback

### Extension Points Reserved

- `ISemanticAnalyzer` — For semantic layer implementation
- `IResultCache` — For caching integration
- `IThreatIntelligenceProvider` — For real-time threat feeds
