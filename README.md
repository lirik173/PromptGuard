<p align="center">
  <img src="docs/assets/logo.svg" alt="PromptShield Logo" width="200"/>
</p>

<h1 align="center">PromptShield</h1>

<p align="center">
  <strong>Enterprise-grade Prompt Injection Firewall for .NET</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#documentation">Documentation</a> •
  <a href="#contributing">Contributing</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/.NET-8.0+-512BD4?style=flat-square&logo=dotnet" alt=".NET 8+"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="MIT License"/>
  <img src="https://img.shields.io/badge/OWASP-LLM%20Top%2010-orange?style=flat-square" alt="OWASP LLM Top 10"/>
</p>

---

## Overview

**PromptShield** is a multi-layer prompt injection detection engine designed to protect .NET applications that integrate Large Language Models (LLMs). It provides defense-in-depth against prompt injection attacks with minimal performance impact and seamless integration with [Semantic Kernel](https://github.com/microsoft/semantic-kernel) and ASP.NET Core.

### Why PromptShield?

- **One-Line Integration** — Add protection to Semantic Kernel with `.AddPromptShield()`
- **Multi-Layer Defense** — Pattern Matching, Heuristics, ML Classification, and Semantic Analysis
- **Enterprise Ready** — OpenTelemetry support, extensible architecture, fail-closed security defaults
- **High Performance** — Sub-millisecond latency for 95% of clean prompts
- **OWASP Aligned** — All threats mapped to [OWASP LLM Top 10 (2025)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)

---

## Features

### 🛡️ Multi-Layer Detection Pipeline

| Layer | Description | Latency |
|-------|-------------|---------|
| **Pattern Matching** | Regex-based detection of known attack patterns | < 0.1ms |
| **Heuristic Analysis** | Behavioral signals and structural anomaly detection | < 0.5ms |
| **ML Classification** | ONNX-based neural network classifier | < 5ms |
| **Semantic Analysis** | LLM-powered deep content analysis (opt-in) | < 50ms |

### 🔌 Seamless Integrations

- **Semantic Kernel** — `IPromptRenderFilter` integration
- **ASP.NET Core** — Request middleware for API protection
- **Direct API** — Use `IPromptAnalyzer` anywhere in your code

### 📊 Observability

- OpenTelemetry metrics, traces, and structured logging
- Detailed analysis breakdown for security investigations
- Configurable telemetry levels

### 🔧 Extensibility

- Custom pattern providers via `IPatternProvider`
- Custom heuristic analyzers via `IHeuristicAnalyzer`
- Event hooks via `IPromptShieldEventHandler`

---

## Installation

```bash
# Core library (required)
dotnet add package PromptShield.Core

# Semantic Kernel integration (optional)
dotnet add package PromptShield.SemanticKernel

# ASP.NET Core middleware (optional)
dotnet add package PromptShield.AspNetCore
```

### Requirements

- .NET 8.0 or later
- Microsoft.SemanticKernel 1.x (for Semantic Kernel integration)

---

## Quick Start

### Semantic Kernel Integration

The simplest way to add prompt protection — just one line of code:

```csharp
using Microsoft.SemanticKernel;
using PromptShield.SemanticKernel;

var kernel = Kernel.CreateBuilder()
    .AddAzureOpenAIChatCompletion(
        deploymentName: "gpt-4",
        endpoint: "https://your-resource.openai.azure.com/",
        apiKey: "your-api-key")
    .AddPromptShield()  // ← One line to enable protection
    .Build();

// Use the kernel normally - prompts are automatically analyzed
var result = await kernel.InvokePromptAsync("What is the weather in Seattle?");
```

### ASP.NET Core Middleware

Protect your API endpoints automatically:

```csharp
using PromptShield.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

// Add PromptShield services
builder.Services.AddPromptShield(options =>
{
    options.ThreatThreshold = 0.75;
});

var app = builder.Build();

// Add middleware to pipeline
app.UsePromptShield(options =>
{
    options.ExcludedPaths.Add("/health");
    options.PromptJsonPath = "$.message";
});

app.MapPost("/api/chat", async (ChatRequest request) =>
{
    // Request is already validated by middleware
    return Results.Ok(new { response = "Hello!" });
});

app.Run();
```

### Direct Analyzer Usage

For full control over the analysis process:

```csharp
using PromptShield.Core;
using PromptShield.Abstractions;

var services = new ServiceCollection();
services.AddPromptShield();
var provider = services.BuildServiceProvider();
var analyzer = provider.GetRequiredService<IPromptAnalyzer>();

// Simple analysis
var result = await analyzer.AnalyzeAsync("What is the capital of France?");

if (result.IsThreat)
{
    Console.WriteLine($"🚨 Threat detected: {result.ThreatInfo?.ThreatType}");
    Console.WriteLine($"   OWASP Category: {result.ThreatInfo?.OwaspCategory}");
    Console.WriteLine($"   Confidence: {result.Confidence:P0}");
    Console.WriteLine($"   Decision by: {result.DecisionLayer}");
}
else
{
    Console.WriteLine("✅ Prompt is safe");
}
```

### Analysis with Full Context

```csharp
var request = new AnalysisRequest
{
    Prompt = "Tell me about the weather",
    SystemPrompt = "You are a helpful weather assistant.",
    ConversationHistory = new[]
    {
        new ConversationMessage { Role = "user", Content = "Hello" },
        new ConversationMessage { Role = "assistant", Content = "Hi! How can I help?" }
    },
    Metadata = new AnalysisMetadata
    {
        UserId = "user-123",
        ConversationId = "conv-456",
        Source = "web-chat"
    }
};

var result = await analyzer.AnalyzeAsync(request);

// Access detailed breakdown
foreach (var layer in result.Breakdown?.ExecutedLayers ?? [])
{
    Console.WriteLine($"  Layer: {layer}");
}
```

---

## Configuration

### Code-First Configuration

```csharp
builder.Services.AddPromptShield(options =>
{
    // Global settings
    options.ThreatThreshold = 0.75;          // 0.0 - 1.0
    options.MaxPromptLength = 50_000;
    options.IncludeBreakdown = true;
    options.OnAnalysisError = FailureBehavior.FailClosed;  // Secure default
    
    // Pattern Matching
    options.PatternMatching.Enabled = true;
    options.PatternMatching.TimeoutMs = 100;
    options.PatternMatching.EarlyExitThreshold = 0.9;
    options.PatternMatching.IncludeBuiltInPatterns = true;
    
    // Heuristics
    options.Heuristics.Enabled = true;
    options.Heuristics.DefinitiveThreatThreshold = 0.85;
    options.Heuristics.DefinitiveSafeThreshold = 0.15;
    
    // ML Classification (requires ONNX model)
    options.ML.Enabled = true;
    options.ML.Threshold = 0.8;
    
    // Telemetry
    options.Telemetry.EnableMetrics = true;
    options.Telemetry.EnableTracing = true;
    options.Telemetry.LogPromptContent = false;  // Privacy
});
```

### Configuration via appsettings.json

```json
{
  "PromptShield": {
    "ThreatThreshold": 0.75,
    "MaxPromptLength": 50000,
    "IncludeBreakdown": true,
    
    "PatternMatching": {
      "Enabled": true,
      "TimeoutMs": 100,
      "EarlyExitThreshold": 0.9,
      "IncludeBuiltInPatterns": true
    },
    
    "Heuristics": {
      "Enabled": true,
      "DefinitiveThreatThreshold": 0.85,
      "DefinitiveSafeThreshold": 0.15
    },
    
    "ML": {
      "Enabled": true,
      "Threshold": 0.8
    },
    
    "Telemetry": {
      "EnableMetrics": true,
      "EnableTracing": true,
      "EnableLogging": true,
      "LogPromptContent": false
    }
  }
}
```

---

## Extensibility

### Custom Pattern Provider

```csharp
public class EnterprisePatternProvider : IPatternProvider
{
    public string ProviderName => "Enterprise Patterns";

    public IEnumerable<DetectionPattern> GetPatterns()
    {
        yield return new DetectionPattern
        {
            Id = "enterprise-001",
            Name = "Project Codename Extraction",
            Pattern = @"(?i)\b(reveal|tell|show).*project\s*(titan|phoenix)\b",
            OwaspCategory = "LLM01",
            Severity = ThreatSeverity.Critical,
            Description = "Attempts to extract confidential project codenames"
        };
    }
}

// Registration
builder.Services.AddPromptShield()
    .AddPatternProvider<EnterprisePatternProvider>();
```

### Custom Event Handler

```csharp
public class SecurityAuditHandler : PromptShieldEventHandlerBase
{
    private readonly ILogger<SecurityAuditHandler> _logger;

    public SecurityAuditHandler(ILogger<SecurityAuditHandler> logger)
    {
        _logger = logger;
    }

    public override Task OnThreatDetectedAsync(
        ThreatDetectedEvent @event,
        CancellationToken cancellationToken = default)
    {
        _logger.LogWarning(
            "Threat detected: AnalysisId={AnalysisId}, Type={ThreatType}, OWASP={OwaspCategory}",
            @event.AnalysisId,
            @event.ThreatInfo.ThreatType,
            @event.ThreatInfo.OwaspCategory);

        return Task.CompletedTask;
    }
}

// Registration
builder.Services.AddPromptShield()
    .AddEventHandler<SecurityAuditHandler>();
```

---

## OpenTelemetry Integration

```csharp
builder.Services.AddOpenTelemetry()
    .WithMetrics(metrics =>
    {
        metrics.AddMeter("PromptShield");
        metrics.AddPrometheusExporter();
    })
    .WithTracing(tracing =>
    {
        tracing.AddSource("PromptShield");
        tracing.AddOtlpExporter();
    });
```

### Available Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `promptshield.analysis.total` | Counter | Total analyses performed |
| `promptshield.threats.detected` | Counter | Total threats detected |
| `promptshield.analysis.latency` | Histogram | Analysis latency (ms) |
| `promptshield.layer.executed` | Counter | Layer execution counts |

---

## Error Handling

```csharp
try
{
    var result = await analyzer.AnalyzeAsync(prompt);
}
catch (ValidationException ex)
{
    // Prompt validation failed (null, empty, too long)
    Console.WriteLine($"Validation error: {ex.Message}");
}
catch (PromptShieldException ex)
{
    // Other PromptShield errors
    Console.WriteLine($"Analysis error: {ex.Message}");
}
```

### Handling Threats in Semantic Kernel

```csharp
try
{
    var result = await kernel.InvokePromptAsync(userPrompt);
}
catch (PromptInjectionDetectedException ex)
{
    // Prompt was blocked by PromptShield
    Console.WriteLine($"Blocked: {ex.Result.ThreatInfo?.UserFacingMessage}");
    
    // Return safe response to user
    return "I'm sorry, but I cannot process that request.";
}
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                       PromptShield Pipeline                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐        │
│  │   Pattern    │──▶│  Heuristic   │──▶│     ML       │──▶ ... │
│  │  Matching    │   │  Analysis    │   │Classification│        │
│  └──────────────┘   └──────────────┘   └──────────────┘        │
│         │                  │                  │                  │
│         ▼                  ▼                  ▼                  │
│  ┌─────────────────────────────────────────────────────┐       │
│  │              Early Exit on Definitive Result         │       │
│  └─────────────────────────────────────────────────────┘       │
│                            │                                    │
│                            ▼                                    │
│  ┌─────────────────────────────────────────────────────┐       │
│  │                   AnalysisResult                     │       │
│  │  - IsThreat, Confidence, ThreatInfo, Breakdown      │       │
│  └─────────────────────────────────────────────────────┘       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/architecture.md) | System design and layer details |
| [Configuration](docs/configuration.md) | All configuration options |
| [API Reference](docs/api-reference.md) | Full API documentation |
| [Security](SECURITY.md) | Security policy and reporting |
| [Contributing](CONTRIBUTING.md) | Contribution guidelines |
| [Changelog](CHANGELOG.md) | Version history |

---

## Performance

PromptShield is optimized for high-throughput scenarios:

| Scenario | p50 | p95 | p99 |
|----------|-----|-----|-----|
| Clean prompt (fast path) | 0.2ms | 0.8ms | 1.2ms |
| Pattern match only | 0.1ms | 0.3ms | 0.5ms |
| Full pipeline (no ML) | 0.5ms | 1.5ms | 2.5ms |
| With ML classification | 2ms | 5ms | 8ms |

*Benchmarks run on Intel i7-12700K, .NET 8.0*

---

## Roadmap

- [ ] Pre-trained ML model in NuGet package
- [ ] Real-time pattern updates via feed
- [ ] Additional language support (Python, JavaScript)
- [ ] Dashboard for threat analytics
- [ ] Integration with Azure AI Content Safety

---

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

---

## Security

For security vulnerabilities, please see our [Security Policy](SECURITY.md). **Do not** create public issues for security vulnerabilities.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/) for threat categorization framework
- [Microsoft Semantic Kernel](https://github.com/microsoft/semantic-kernel) for the excellent AI orchestration framework
- The .NET community for continuous feedback and contributions

---

<p align="center">
  Made with ❤️ for secure AI applications
</p>
