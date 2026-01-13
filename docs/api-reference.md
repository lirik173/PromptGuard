# API Reference

This document provides detailed API documentation for PromptShield.

---

## Table of Contents

- [Core Interfaces](#core-interfaces)
- [Analysis Types](#analysis-types)
- [Configuration Types](#configuration-types)
- [Exception Types](#exception-types)
- [Event Types](#event-types)
- [Extension Methods](#extension-methods)

---

## Core Interfaces

### IPromptAnalyzer

The main entry point for prompt analysis.

**Namespace:** `PromptShield.Abstractions`

```csharp
public interface IPromptAnalyzer
{
    /// <summary>
    /// Analyzes a prompt for potential injection attacks.
    /// </summary>
    Task<AnalysisResult> AnalyzeAsync(
        string prompt, 
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Analyzes a prompt with full context (system prompt, history, metadata).
    /// </summary>
    Task<AnalysisResult> AnalyzeAsync(
        AnalysisRequest request, 
        CancellationToken cancellationToken = default);
}
```

**Usage:**

```csharp
var analyzer = services.GetRequiredService<IPromptAnalyzer>();

// Simple analysis
var result = await analyzer.AnalyzeAsync("What is the weather?");

// Full context analysis
var request = new AnalysisRequest 
{ 
    Prompt = "What is the weather?",
    SystemPrompt = "You are a weather assistant"
};
var result = await analyzer.AnalyzeAsync(request);
```

---

### IPatternProvider

Interface for providing custom detection patterns.

**Namespace:** `PromptShield.Abstractions`

```csharp
public interface IPatternProvider
{
    /// <summary>
    /// Name of this pattern provider.
    /// </summary>
    string ProviderName { get; }

    /// <summary>
    /// Returns all detection patterns from this provider.
    /// </summary>
    IEnumerable<DetectionPattern> GetPatterns();
}
```

**Usage:**

```csharp
public class CustomPatternProvider : IPatternProvider
{
    public string ProviderName => "Custom Patterns";

    public IEnumerable<DetectionPattern> GetPatterns()
    {
        yield return new DetectionPattern
        {
            Id = "custom-001",
            Name = "Custom Attack Pattern",
            Pattern = @"(?i)\bmy\s+custom\s+pattern\b",
            OwaspCategory = "LLM01",
            Severity = ThreatSeverity.High
        };
    }
}

// Registration
services.AddPromptShield().AddPatternProvider<CustomPatternProvider>();
```

---

### IHeuristicAnalyzer

Interface for providing custom heuristic analysis signals.

**Namespace:** `PromptShield.Abstractions`

```csharp
public interface IHeuristicAnalyzer
{
    /// <summary>
    /// Name of this analyzer.
    /// </summary>
    string AnalyzerName { get; }

    /// <summary>
    /// Analyzes the prompt and returns heuristic signals.
    /// </summary>
    Task<HeuristicResult> AnalyzeAsync(
        AnalysisRequest request, 
        CancellationToken cancellationToken = default);
}
```

**Usage:**

```csharp
public class CustomHeuristicAnalyzer : IHeuristicAnalyzer
{
    public string AnalyzerName => "Custom Heuristics";

    public Task<HeuristicResult> AnalyzeAsync(
        AnalysisRequest request, 
        CancellationToken ct)
    {
        var signals = new List<HeuristicSignal>();
        
        // Custom analysis logic
        if (request.Prompt.Contains("suspicious"))
        {
            signals.Add(new HeuristicSignal
            {
                Name = "SuspiciousKeyword",
                Score = 0.6,
                Description = "Contains suspicious keyword"
            });
        }

        return Task.FromResult(new HeuristicResult { Signals = signals });
    }
}

// Registration
services.AddPromptShield().AddHeuristicAnalyzer<CustomHeuristicAnalyzer>();
```

---

### IPromptShieldEventHandler

Interface for handling PromptShield events.

**Namespace:** `PromptShield.Abstractions`

```csharp
public interface IPromptShieldEventHandler
{
    Task OnAnalysisStartedAsync(
        AnalysisStartedEvent @event, 
        CancellationToken cancellationToken = default);
    
    Task OnThreatDetectedAsync(
        ThreatDetectedEvent @event, 
        CancellationToken cancellationToken = default);
    
    Task OnAnalysisCompletedAsync(
        AnalysisCompletedEvent @event, 
        CancellationToken cancellationToken = default);
}
```

**Base class for convenience:**

```csharp
public abstract class PromptShieldEventHandlerBase : IPromptShieldEventHandler
{
    public virtual Task OnAnalysisStartedAsync(
        AnalysisStartedEvent @event, 
        CancellationToken ct = default) 
        => Task.CompletedTask;
    
    public virtual Task OnThreatDetectedAsync(
        ThreatDetectedEvent @event, 
        CancellationToken ct = default) 
        => Task.CompletedTask;
    
    public virtual Task OnAnalysisCompletedAsync(
        AnalysisCompletedEvent @event, 
        CancellationToken ct = default) 
        => Task.CompletedTask;
}
```

---

## Analysis Types

### AnalysisRequest

Input model for prompt analysis.

**Namespace:** `PromptShield.Abstractions.Analysis`

```csharp
public sealed class AnalysisRequest
{
    /// <summary>
    /// The prompt text to analyze. Required.
    /// </summary>
    public required string Prompt { get; init; }

    /// <summary>
    /// Optional system prompt for context.
    /// </summary>
    public string? SystemPrompt { get; init; }

    /// <summary>
    /// Optional conversation history for context.
    /// </summary>
    public IReadOnlyList<ConversationMessage>? ConversationHistory { get; init; }

    /// <summary>
    /// Optional metadata for logging and correlation.
    /// </summary>
    public AnalysisMetadata? Metadata { get; init; }
}
```

### AnalysisResult

Output model containing analysis results.

**Namespace:** `PromptShield.Abstractions.Analysis`

```csharp
public sealed class AnalysisResult
{
    /// <summary>
    /// Unique identifier for this analysis.
    /// </summary>
    public required Guid AnalysisId { get; init; }

    /// <summary>
    /// Indicates whether a threat was detected.
    /// </summary>
    public required bool IsThreat { get; init; }

    /// <summary>
    /// Overall confidence score (0.0 = safe, 1.0 = threat).
    /// </summary>
    public required double Confidence { get; init; }

    /// <summary>
    /// Threat details if detected; null otherwise.
    /// </summary>
    public ThreatInfo? ThreatInfo { get; init; }

    /// <summary>
    /// Per-layer breakdown (if IncludeBreakdown enabled).
    /// </summary>
    public DetectionBreakdown? Breakdown { get; init; }

    /// <summary>
    /// Which layer made the final decision.
    /// </summary>
    public required string DecisionLayer { get; init; }

    /// <summary>
    /// Total analysis duration.
    /// </summary>
    public required TimeSpan Duration { get; init; }

    /// <summary>
    /// Timestamp of analysis.
    /// </summary>
    public required DateTimeOffset Timestamp { get; init; }
}
```

### ThreatInfo

Detailed information about a detected threat.

**Namespace:** `PromptShield.Abstractions.Analysis`

```csharp
public sealed class ThreatInfo
{
    /// <summary>
    /// OWASP LLM Top 10 category (e.g., "LLM01").
    /// </summary>
    public required string OwaspCategory { get; init; }
    
    /// <summary>
    /// Human-readable threat type name.
    /// </summary>
    public required string ThreatType { get; init; }
    
    /// <summary>
    /// Technical explanation for security engineers.
    /// </summary>
    public required string Explanation { get; init; }
    
    /// <summary>
    /// Safe message for end users.
    /// </summary>
    public required string UserFacingMessage { get; init; }
    
    /// <summary>
    /// Severity level.
    /// </summary>
    public required ThreatSeverity Severity { get; init; }
    
    /// <summary>
    /// Detection sources that flagged this threat.
    /// </summary>
    public required IReadOnlyList<string> DetectionSources { get; init; }
    
    /// <summary>
    /// Matched pattern names, if any.
    /// </summary>
    public IReadOnlyList<string>? MatchedPatterns { get; init; }
}
```

### ThreatSeverity

Enumeration of threat severity levels.

**Namespace:** `PromptShield.Abstractions`

```csharp
public enum ThreatSeverity
{
    /// <summary>
    /// Low severity - informational.
    /// </summary>
    Low = 0,
    
    /// <summary>
    /// Medium severity - warrants attention.
    /// </summary>
    Medium = 1,
    
    /// <summary>
    /// High severity - significant risk.
    /// </summary>
    High = 2,
    
    /// <summary>
    /// Critical severity - immediate action required.
    /// </summary>
    Critical = 3
}
```

### DetectionBreakdown

Detailed breakdown of results from each detection layer.

**Namespace:** `PromptShield.Abstractions.Analysis`

```csharp
public sealed class DetectionBreakdown
{
    /// <summary>
    /// List of layers that were executed.
    /// </summary>
    public required IReadOnlyList<string> ExecutedLayers { get; init; }

    /// <summary>
    /// Results from pattern matching layer.
    /// </summary>
    public LayerResult? PatternMatching { get; init; }

    /// <summary>
    /// Results from heuristic analysis layer.
    /// </summary>
    public LayerResult? Heuristics { get; init; }

    /// <summary>
    /// Results from ML classification layer.
    /// </summary>
    public LayerResult? MLClassification { get; init; }

    /// <summary>
    /// Results from semantic analysis layer.
    /// </summary>
    public LayerResult? SemanticAnalysis { get; init; }
}
```

---

## Configuration Types

### PromptShieldOptions

Root configuration options.

**Namespace:** `PromptShield.Abstractions.Configuration`

```csharp
public sealed class PromptShieldOptions
{
    public const string SectionName = "PromptShield";
    
    public double ThreatThreshold { get; set; } = 0.75;
    public int MaxPromptLength { get; set; } = 50_000;
    public bool IncludeBreakdown { get; set; } = true;
    public FailureBehavior OnAnalysisError { get; set; } = FailureBehavior.FailClosed;
    
    public PatternMatchingOptions PatternMatching { get; set; } = new();
    public HeuristicOptions Heuristics { get; set; } = new();
    public MLClassificationOptions ML { get; set; } = new();
    public SemanticAnalysisOptions SemanticAnalysis { get; set; } = new();
    public SemanticKernelIntegrationOptions SemanticKernel { get; set; } = new();
    public TelemetryOptions Telemetry { get; set; } = new();
}
```

### FailureBehavior

Behavior when analysis encounters an error.

**Namespace:** `PromptShield.Abstractions.Configuration`

```csharp
public enum FailureBehavior
{
    /// <summary>
    /// Treat as threat on error (secure default).
    /// </summary>
    FailClosed = 0,
    
    /// <summary>
    /// Allow through on error (NOT recommended).
    /// </summary>
    FailOpen = 1
}
```

---

## Exception Types

### ValidationException

Thrown when input validation fails.

**Namespace:** `PromptShield.Abstractions.Exceptions`

```csharp
public class ValidationException : PromptShieldException
{
    public string PropertyName { get; }
    public object? AttemptedValue { get; }
}
```

**Thrown when:**
- Prompt is null or empty
- Prompt exceeds `MaxPromptLength`
- Invalid characters detected

### PromptShieldException

Base exception for PromptShield errors.

**Namespace:** `PromptShield.Abstractions.Exceptions`

```csharp
public class PromptShieldException : Exception
{
    public string ErrorCode { get; }
}
```

### PromptInjectionDetectedException

Thrown when a prompt injection threat is detected (Semantic Kernel integration).

**Namespace:** `PromptShield.SemanticKernel`

```csharp
public class PromptInjectionDetectedException : PromptShieldException
{
    /// <summary>
    /// The full analysis result.
    /// </summary>
    public AnalysisResult Result { get; }
}
```

---

## Event Types

### AnalysisStartedEvent

Fired when analysis begins.

```csharp
public sealed class AnalysisStartedEvent
{
    public Guid AnalysisId { get; init; }
    public AnalysisRequest Request { get; init; }
    public DateTimeOffset Timestamp { get; init; }
}
```

### ThreatDetectedEvent

Fired when a threat is detected.

```csharp
public sealed class ThreatDetectedEvent
{
    public Guid AnalysisId { get; init; }
    public AnalysisRequest Request { get; init; }
    public ThreatInfo ThreatInfo { get; init; }
    public double Confidence { get; init; }
    public string DetectionLayer { get; init; }
    public DateTimeOffset Timestamp { get; init; }
}
```

### AnalysisCompletedEvent

Fired when analysis completes.

```csharp
public sealed class AnalysisCompletedEvent
{
    public Guid AnalysisId { get; init; }
    public AnalysisRequest Request { get; init; }
    public AnalysisResult Result { get; init; }
    public DateTimeOffset Timestamp { get; init; }
}
```

---

## Extension Methods

### ServiceCollectionExtensions

**Namespace:** `PromptShield.Core`

```csharp
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds PromptShield services with default configuration.
    /// </summary>
    public static IServiceCollection AddPromptShield(
        this IServiceCollection services);

    /// <summary>
    /// Adds PromptShield services with custom configuration.
    /// </summary>
    public static IServiceCollection AddPromptShield(
        this IServiceCollection services,
        Action<PromptShieldOptions> configure);

    /// <summary>
    /// Adds a custom pattern provider.
    /// </summary>
    public static IServiceCollection AddPatternProvider<TProvider>(
        this IServiceCollection services)
        where TProvider : class, IPatternProvider;

    /// <summary>
    /// Adds a custom heuristic analyzer.
    /// </summary>
    public static IServiceCollection AddHeuristicAnalyzer<TAnalyzer>(
        this IServiceCollection services)
        where TAnalyzer : class, IHeuristicAnalyzer;

    /// <summary>
    /// Adds a custom event handler.
    /// </summary>
    public static IServiceCollection AddEventHandler<THandler>(
        this IServiceCollection services)
        where THandler : class, IPromptShieldEventHandler;
}
```

### KernelBuilderExtensions

**Namespace:** `PromptShield.SemanticKernel`

```csharp
public static class KernelBuilderExtensions
{
    /// <summary>
    /// Adds PromptShield protection to Semantic Kernel.
    /// </summary>
    public static IKernelBuilder AddPromptShield(
        this IKernelBuilder builder);

    /// <summary>
    /// Adds PromptShield protection with custom configuration.
    /// </summary>
    public static IKernelBuilder AddPromptShield(
        this IKernelBuilder builder,
        Action<PromptShieldOptions> configure);
}
```

### ApplicationBuilderExtensions

**Namespace:** `PromptShield.AspNetCore`

```csharp
public static class ApplicationBuilderExtensions
{
    /// <summary>
    /// Adds PromptShield middleware to the pipeline.
    /// </summary>
    public static IApplicationBuilder UsePromptShield(
        this IApplicationBuilder app);

    /// <summary>
    /// Adds PromptShield middleware with custom options.
    /// </summary>
    public static IApplicationBuilder UsePromptShield(
        this IApplicationBuilder app,
        Action<PromptShieldMiddlewareOptions> configure);
}
```

---

## OpenTelemetry Metrics

| Metric Name | Type | Tags | Description |
|-------------|------|------|-------------|
| `promptshield.analysis.total` | Counter | - | Total analyses |
| `promptshield.threats.detected` | Counter | `owasp_category`, `severity` | Threats detected |
| `promptshield.analysis.latency` | Histogram | `layer`, `is_threat` | Analysis latency (ms) |
| `promptshield.layer.executed` | Counter | `layer` | Layer executions |

---

## OpenTelemetry Traces

**Activity Source:** `PromptShield`

| Span Name | Tags |
|-----------|------|
| `PromptShield.Analyze` | `prompt.length`, `is_threat`, `confidence`, `decision_layer` |
| `PromptShield.PatternMatching` | `patterns_checked`, `patterns_matched` |
| `PromptShield.Heuristics` | `signals_detected`, `score` |
| `PromptShield.MLClassification` | `model`, `inference_time` |
