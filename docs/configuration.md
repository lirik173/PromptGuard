# Configuration Guide

This document provides comprehensive documentation for all configuration options available in PromptShield.

---

## Table of Contents

- [Overview](#overview)
- [Configuration Methods](#configuration-methods)
- [Global Options](#global-options)
- [Pattern Matching Options](#pattern-matching-options)
- [Heuristic Options](#heuristic-options)
- [ML Classification Options](#ml-classification-options)
- [Semantic Analysis Options](#semantic-analysis-options)
- [Telemetry Options](#telemetry-options)
- [Semantic Kernel Options](#semantic-kernel-options)
- [Complete Configuration Example](#complete-configuration-example)

---

## Overview

PromptShield uses hierarchical configuration with sensible defaults. Configuration can be provided through:

1. **Code-first** — Fluent API with strongly-typed options
2. **File-based** — `appsettings.json` with `IConfiguration` binding
3. **Hybrid** — Base configuration from files, overrides in code

### Configuration Hierarchy

```
appsettings.json (base)
    └── appsettings.{Environment}.json (environment override)
        └── Code configuration (runtime override)
```

---

## Configuration Methods

### Code-First Configuration

```csharp
builder.Services.AddPromptShield(options =>
{
    options.ThreatThreshold = 0.75;
    options.PatternMatching.Enabled = true;
    // ... more options
});
```

### File-Based Configuration

```json
// appsettings.json
{
  "PromptShield": {
    "ThreatThreshold": 0.75,
    "PatternMatching": {
      "Enabled": true
    }
  }
}
```

```csharp
// Program.cs
builder.Services.AddPromptShield();
builder.Services.Configure<PromptShieldOptions>(
    builder.Configuration.GetSection("PromptShield"));
```

### Hybrid Configuration

```csharp
// Load from configuration, then override specific values
builder.Services.AddPromptShield(options =>
{
    builder.Configuration.GetSection("PromptShield").Bind(options);
    
    // Override for this environment
    if (builder.Environment.IsDevelopment())
    {
        options.Telemetry.LogPromptContent = true;
    }
});
```

---

## Global Options

### PromptShieldOptions

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `ThreatThreshold` | `double` | `0.75` | Global confidence threshold for threat detection (0.0 - 1.0) |
| `MaxPromptLength` | `int` | `50000` | Maximum allowed prompt length in characters |
| `IncludeBreakdown` | `bool` | `true` | Include detailed layer-by-layer breakdown in results |
| `OnAnalysisError` | `FailureBehavior` | `FailClosed` | Behavior when analysis encounters an error |

### ThreatThreshold

The global confidence threshold determines when a prompt is classified as a threat:

```csharp
options.ThreatThreshold = 0.75; // Default - balanced
options.ThreatThreshold = 0.5;  // More sensitive - catches more, more false positives
options.ThreatThreshold = 0.9;  // Less sensitive - fewer false positives, may miss attacks
```

**Recommendations:**

| Environment | Threshold | Rationale |
|-------------|-----------|-----------|
| Development | 0.5 - 0.6 | Catch more potential issues early |
| Staging | 0.7 - 0.75 | Balance detection and false positives |
| Production | 0.75 - 0.85 | Minimize false positives |
| High Security | 0.6 - 0.7 | Prioritize security over convenience |

### MaxPromptLength

Prevents DoS attacks via extremely large prompts:

```csharp
options.MaxPromptLength = 50_000;  // Default
options.MaxPromptLength = 10_000;  // More restrictive
options.MaxPromptLength = 100_000; // For applications with longer prompts
```

### OnAnalysisError

Determines behavior when analysis fails:

```csharp
// FailClosed (default, recommended) - treat as threat on error
options.OnAnalysisError = FailureBehavior.FailClosed;

// FailOpen - allow prompt through on error (NOT recommended)
options.OnAnalysisError = FailureBehavior.FailOpen;
```

**Security Warning:** `FailOpen` should only be used when availability is more critical than security.

---

## Pattern Matching Options

### PatternMatchingOptions

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `Enabled` | `bool` | `true` | Enable/disable pattern matching layer |
| `TimeoutMs` | `int` | `100` | Regex execution timeout (ms) |
| `EarlyExitThreshold` | `double` | `0.9` | Confidence threshold for early pipeline exit |
| `IncludeBuiltInPatterns` | `bool` | `true` | Include built-in detection patterns |
| `MaxPatternsPerProvider` | `int` | `1000` | Maximum patterns per provider |

### Usage

```csharp
options.PatternMatching.Enabled = true;
options.PatternMatching.TimeoutMs = 100;
options.PatternMatching.EarlyExitThreshold = 0.9;
options.PatternMatching.IncludeBuiltInPatterns = true;
```

### TimeoutMs

Protects against ReDoS (Regular Expression Denial of Service):

```csharp
// Short timeout - faster but may skip complex patterns
options.PatternMatching.TimeoutMs = 50;

// Default timeout - balanced
options.PatternMatching.TimeoutMs = 100;

// Longer timeout - more thorough but slower
options.PatternMatching.TimeoutMs = 200;
```

### EarlyExitThreshold

When pattern matching achieves this confidence level, skip remaining layers:

```csharp
// High threshold - only exit early on very confident matches
options.PatternMatching.EarlyExitThreshold = 0.95;

// Default - exit early on confident matches
options.PatternMatching.EarlyExitThreshold = 0.9;

// Lower threshold - exit early more often (faster, less thorough)
options.PatternMatching.EarlyExitThreshold = 0.85;
```

### JSON Configuration

```json
{
  "PromptShield": {
    "PatternMatching": {
      "Enabled": true,
      "TimeoutMs": 100,
      "EarlyExitThreshold": 0.9,
      "IncludeBuiltInPatterns": true,
      "MaxPatternsPerProvider": 1000
    }
  }
}
```

---

## Heuristic Options

### HeuristicOptions

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `Enabled` | `bool` | `true` | Enable/disable heuristic analysis layer |
| `DefinitiveThreatThreshold` | `double` | `0.85` | Score above which prompt is definitely a threat |
| `DefinitiveSafeThreshold` | `double` | `0.15` | Score below which prompt is definitely safe |

### Usage

```csharp
options.Heuristics.Enabled = true;
options.Heuristics.DefinitiveThreatThreshold = 0.85;
options.Heuristics.DefinitiveSafeThreshold = 0.15;
```

### Definitive Thresholds

These thresholds determine when heuristic analysis can make a definitive decision without invoking subsequent layers:

```
0.0 ────────────────────────────────────────────────────── 1.0
 │                                                         │
 │   SAFE ZONE         UNCERTAIN ZONE        THREAT ZONE   │
 │  (skip ML)        (continue to ML)        (skip ML)     │
 │                                                         │
 └──────────┴────────────────────────────────┴─────────────┘
          0.15                             0.85
```

### JSON Configuration

```json
{
  "PromptShield": {
    "Heuristics": {
      "Enabled": true,
      "DefinitiveThreatThreshold": 0.85,
      "DefinitiveSafeThreshold": 0.15
    }
  }
}
```

---

## ML Classification Options

### MLClassificationOptions

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `Enabled` | `bool` | `true` | Enable/disable ML classification layer |
| `ModelPath` | `string?` | `null` | Path to ONNX model file (null = embedded model) |
| `Threshold` | `double` | `0.8` | Confidence threshold for ML classification |
| `MaxSequenceLength` | `int` | `512` | Maximum token sequence length |
| `InferenceTimeoutMs` | `int` | `5` | Inference timeout in milliseconds |

### Usage

```csharp
options.ML.Enabled = true;
options.ML.Threshold = 0.8;
options.ML.MaxSequenceLength = 512;
options.ML.InferenceTimeoutMs = 5;

// Custom model path (optional)
options.ML.ModelPath = @"C:\models\promptshield.onnx";
```

### Custom Model

To use a custom-trained model:

```csharp
options.ML.Enabled = true;
options.ML.ModelPath = @"./models/custom-model.onnx";
```

**Model Requirements:**
- ONNX format
- Input: `input_ids` (int64), `attention_mask` (int64)
- Output: `logits` (float) with shape [batch, 2]

### JSON Configuration

```json
{
  "PromptShield": {
    "ML": {
      "Enabled": true,
      "ModelPath": null,
      "Threshold": 0.8,
      "MaxSequenceLength": 512,
      "InferenceTimeoutMs": 5
    }
  }
}
```

---

## Semantic Analysis Options

### SemanticAnalysisOptions

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `Enabled` | `bool` | `false` | Enable/disable semantic analysis layer |
| `Endpoint` | `string?` | `null` | LLM endpoint URL (Azure OpenAI) |
| `DeploymentName` | `string?` | `null` | Azure OpenAI deployment name |
| `ApiKey` | `string?` | `null` | API key for authentication |
| `TimeoutMs` | `int` | `50` | Analysis timeout in milliseconds |

### Usage

```csharp
// Semantic analysis is opt-in and requires LLM endpoint
options.SemanticAnalysis.Enabled = true;
options.SemanticAnalysis.Endpoint = "https://your-resource.openai.azure.com/";
options.SemanticAnalysis.DeploymentName = "gpt-4";
options.SemanticAnalysis.ApiKey = Environment.GetEnvironmentVariable("AZURE_OPENAI_KEY");
options.SemanticAnalysis.TimeoutMs = 50;
```

**Warning:** Semantic analysis adds latency and cost. Use only when required for deep content analysis.

### JSON Configuration

```json
{
  "PromptShield": {
    "SemanticAnalysis": {
      "Enabled": false,
      "Endpoint": null,
      "DeploymentName": null,
      "TimeoutMs": 50
    }
  }
}
```

**Note:** Store `ApiKey` in secure configuration (User Secrets, Azure Key Vault, etc.), not in `appsettings.json`.

---

## Telemetry Options

### TelemetryOptions

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `EnableMetrics` | `bool` | `true` | Enable OpenTelemetry metrics |
| `EnableTracing` | `bool` | `true` | Enable OpenTelemetry tracing |
| `EnableLogging` | `bool` | `true` | Enable structured logging |
| `LogPromptContent` | `bool` | `false` | Include prompt text in logs (privacy risk) |
| `LogLevel` | `LogLevel` | `Information` | Minimum log level |

### Usage

```csharp
options.Telemetry.EnableMetrics = true;
options.Telemetry.EnableTracing = true;
options.Telemetry.EnableLogging = true;
options.Telemetry.LogPromptContent = false; // Privacy protection
```

### LogPromptContent

**Security Warning:** Setting `LogPromptContent = true` will include full prompt text in logs. This may expose sensitive user data and should only be enabled in controlled environments.

```csharp
// Development only - never in production
if (builder.Environment.IsDevelopment())
{
    options.Telemetry.LogPromptContent = true;
}
```

### JSON Configuration

```json
{
  "PromptShield": {
    "Telemetry": {
      "EnableMetrics": true,
      "EnableTracing": true,
      "EnableLogging": true,
      "LogPromptContent": false,
      "LogLevel": "Information"
    }
  }
}
```

---

## Semantic Kernel Options

### SemanticKernelIntegrationOptions

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `OnAnalysisError` | `FailureBehavior` | `FailClosed` | Behavior on analysis error in SK filter |
| `ThrowOnThreat` | `bool` | `true` | Throw exception when threat detected |
| `AnalyzeSystemPrompt` | `bool` | `false` | Also analyze system prompts |
| `AnalyzeRenderedPrompt` | `bool` | `true` | Analyze final rendered prompt |

### Usage

```csharp
options.SemanticKernel.OnAnalysisError = FailureBehavior.FailClosed;
options.SemanticKernel.ThrowOnThreat = true;
options.SemanticKernel.AnalyzeRenderedPrompt = true;
```

### ThrowOnThreat

Controls exception behavior when a threat is detected:

```csharp
// Throw exception (default) - caller handles with try/catch
options.SemanticKernel.ThrowOnThreat = true;

// Silent blocking - returns null/empty, no exception
options.SemanticKernel.ThrowOnThreat = false;
```

### JSON Configuration

```json
{
  "PromptShield": {
    "SemanticKernel": {
      "OnAnalysisError": "FailClosed",
      "ThrowOnThreat": true,
      "AnalyzeSystemPrompt": false,
      "AnalyzeRenderedPrompt": true
    }
  }
}
```

---

## Complete Configuration Example

### appsettings.json

```json
{
  "PromptShield": {
    "ThreatThreshold": 0.75,
    "MaxPromptLength": 50000,
    "IncludeBreakdown": true,
    "OnAnalysisError": "FailClosed",
    
    "PatternMatching": {
      "Enabled": true,
      "TimeoutMs": 100,
      "EarlyExitThreshold": 0.9,
      "IncludeBuiltInPatterns": true,
      "MaxPatternsPerProvider": 1000
    },
    
    "Heuristics": {
      "Enabled": true,
      "DefinitiveThreatThreshold": 0.85,
      "DefinitiveSafeThreshold": 0.15
    },
    
    "ML": {
      "Enabled": true,
      "ModelPath": null,
      "Threshold": 0.8,
      "MaxSequenceLength": 512,
      "InferenceTimeoutMs": 5
    },
    
    "SemanticAnalysis": {
      "Enabled": false,
      "Endpoint": null,
      "DeploymentName": null,
      "TimeoutMs": 50
    },
    
    "SemanticKernel": {
      "OnAnalysisError": "FailClosed",
      "ThrowOnThreat": true,
      "AnalyzeSystemPrompt": false,
      "AnalyzeRenderedPrompt": true
    },
    
    "Telemetry": {
      "EnableMetrics": true,
      "EnableTracing": true,
      "EnableLogging": true,
      "LogPromptContent": false,
      "LogLevel": "Information"
    }
  }
}
```

### Program.cs

```csharp
var builder = WebApplication.CreateBuilder(args);

// Load configuration from appsettings.json with code overrides
builder.Services.AddPromptShield(options =>
{
    // Bind from configuration
    builder.Configuration.GetSection("PromptShield").Bind(options);
    
    // Environment-specific overrides
    if (builder.Environment.IsDevelopment())
    {
        options.ThreatThreshold = 0.5; // More sensitive in dev
        options.Telemetry.LogPromptContent = true;
    }
    
    if (builder.Environment.IsProduction())
    {
        options.ThreatThreshold = 0.8; // Less sensitive in prod
        options.Telemetry.LogPromptContent = false;
    }
});

var app = builder.Build();
```

---

## Environment-Specific Configuration

### Development

```json
// appsettings.Development.json
{
  "PromptShield": {
    "ThreatThreshold": 0.5,
    "IncludeBreakdown": true,
    "Telemetry": {
      "LogPromptContent": true,
      "LogLevel": "Debug"
    }
  }
}
```

### Production

```json
// appsettings.Production.json
{
  "PromptShield": {
    "ThreatThreshold": 0.8,
    "IncludeBreakdown": false,
    "Telemetry": {
      "LogPromptContent": false,
      "LogLevel": "Warning"
    }
  }
}
```

---

## Configuration Validation

PromptShield validates configuration at startup:

| Validation | Error Message |
|------------|---------------|
| `ThreatThreshold` < 0 or > 1 | "ThreatThreshold must be between 0.0 and 1.0" |
| `MaxPromptLength` < 1 | "MaxPromptLength must be positive" |
| `PatternMatching.TimeoutMs` < 1 | "Pattern matching timeout must be positive" |
| ML enabled without model | "ML enabled but no model path specified" |

```csharp
// Configuration validation happens during service registration
builder.Services.AddPromptShield(options =>
{
    options.ThreatThreshold = 1.5; // Throws ArgumentOutOfRangeException
});
```
