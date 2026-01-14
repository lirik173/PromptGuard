<p align="center">
  <img src="docs/assets/logo.svg" alt="PromptShield Logo" width="180"/>
</p>

<h1 align="center">PromptShield</h1>

<p align="center">
  <strong>Proof of Concept: Multi-Layer Prompt Injection Detection for .NET</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Status-POC-yellow?style=flat-square" alt="POC Status"/>
  <img src="https://img.shields.io/badge/.NET-8.0+-512BD4?style=flat-square&logo=dotnet" alt=".NET 8+"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="MIT License"/>
  <img src="https://img.shields.io/badge/OWASP-LLM%20Top%2010-orange?style=flat-square" alt="OWASP LLM Top 10"/>
</p>

---

> **⚠️ Disclaimer**: This is a **Proof of Concept (POC)** project demonstrating multi-layer prompt injection detection architecture for .NET applications. It is intended for **educational and research purposes** and is not production-ready.

---

## About

**PromptShield** demonstrates how to build a defense-in-depth prompt injection detection system for LLM-integrated .NET applications. This POC showcases:

- 🏗️ **Multi-layer detection architecture** — Pattern Matching → Heuristics → ML Classification → Semantic Analysis
- 🔌 **Semantic Kernel integration** — Seamless `IPromptRenderFilter` implementation
- 🌐 **ASP.NET Core middleware** — Request-level prompt protection
- 📊 **OpenTelemetry observability** — Metrics, traces, and structured logging
- 🧩 **Extensibility model** — Custom patterns, heuristics, and event handlers

All threat categories are aligned with [OWASP LLM Top 10 (2025)](https://owasp.org/www-project-top-10-for-large-language-model-applications/).

---

## Quick Example

```csharp
// Semantic Kernel integration — one line to enable protection
var kernel = Kernel.CreateBuilder()
    .AddAzureOpenAIChatCompletion("gpt-4", endpoint, apiKey)
    .AddPromptShield()
    .Build();

try
{
    var result = await kernel.InvokePromptAsync(userPrompt);
}
catch (PromptInjectionDetectedException ex)
{
    Console.WriteLine($"Blocked: {ex.Result.ThreatInfo?.ThreatType}");
}
```

---

## Project Structure

```
PromptShield/
├── src/
│   ├── PromptShield.Abstractions/    # Interfaces, models, contracts
│   ├── PromptShield.Core/            # Detection engine implementation
│   ├── PromptShield.SemanticKernel/  # Semantic Kernel integration
│   └── PromptShield.AspNetCore/      # ASP.NET Core middleware
├── tests/
│   ├── PromptShield.Core.Tests/
│   ├── PromptShield.SemanticKernel.Tests/
│   └── PromptShield.Benchmarks/
├── docs/                              # Documentation
└── specs/                             # Design specifications
```

---

## Detection Pipeline

The detection pipeline demonstrates a cascading architecture with early exit optimization:

| Layer | Description | Typical Latency |
|-------|-------------|-----------------|
| **Language Filter** | Gate: blocks unsupported languages | < 1ms |
| **Pattern Matching** | Regex-based known attack detection | < 0.5ms |
| **Heuristic Analysis** | Behavioral signals and anomalies | < 0.5ms |
| **ML Classification** | ONNX-based neural classifier | < 5ms |

```
Input → Language Filter → Pattern Layer → Heuristic Layer → [ML Layer] → Result
              │                 │               │
         Unsupported?      Early Exit      Early Exit
              │            (≥0.9 conf)    (≥0.85/≤0.15)
              ▼
           BLOCK
```

### Language Support

> ⚠️ **Important**: All detection layers require language-specific patterns and vocabulary. By default, only **English** is supported.

The Language Filter acts as a **gate**:
- **Supported language** → proceed to detection layers
- **Unsupported language** → block (configurable)

```csharp
services.AddPromptShield(options =>
{
    options.Language.Enabled = true;
    options.Language.SupportedLanguages = ["en"];  // Only English by default
    options.Language.OnUnsupportedLanguage = UnsupportedLanguageBehavior.Block;
});
```

**To add support for other languages:**
1. Add the language code to `SupportedLanguages`
2. Implement `IPatternProvider` with patterns for that language
3. Optionally implement `IHeuristicAnalyzer` for language-specific heuristics

```csharp
// Example: Adding Ukrainian support
options.Language.SupportedLanguages = ["en", "uk"];
services.AddPatternProvider<UkrainianPatternProvider>();
```

---

## Documentation

| Document | Description |
|----------|-------------|
| 📘 [Getting Started](docs/getting-started.md) | Setup guide and first steps |
| 🏗️ [Architecture](docs/architecture.md) | System design and layer details |
| ⚙️ [Configuration](docs/configuration.md) | All configuration options |
| 📚 [API Reference](docs/api-reference.md) | Full API documentation |

---

## Key Concepts Demonstrated

### 1. Multi-Layer Defense-in-Depth

Each detection layer has complementary strengths:

| Layer | Strength | Weakness |
|-------|----------|----------|
| Pattern Matching | Fast, precise, explainable | Easily bypassed with variations |
| Heuristics | Catches behavioral anomalies | May miss novel attacks |
| ML Classification | Generalizes to variations | Requires training data |
| Semantic Analysis | Deep understanding | Expensive, recursive risk |

### 2. Fail-Closed Security

```csharp
// Default: treat analysis failures as threats
options.OnAnalysisError = FailureBehavior.FailClosed;
```

### 3. Language Filter (Gate)

```csharp
services.AddPromptShield(options =>
{
    options.Language.Enabled = true;
    options.Language.SupportedLanguages = ["en"];  // Block non-English
    options.Language.OnUnsupportedLanguage = UnsupportedLanguageBehavior.Block;
});
```

### 4. False Positive Reduction

All layers support sensitivity tuning and allowlists:

```csharp
services.AddPromptShield(options =>
{
    // Global sensitivity: Low, Medium, High, Paranoid
    options.Heuristics.Sensitivity = SensitivityLevel.Medium;
    options.MLClassification.Sensitivity = SensitivityLevel.Low;
    options.PatternMatching.Sensitivity = SensitivityLevel.Medium;
    
    // Allowlist patterns (regex) - matched prompts bypass detection
    options.Heuristics.AllowedPatterns = new() { @"(?i)safe\s+context" };
    options.MLClassification.AllowedPatterns = new() { @"(?i)internal\s+test" };
    options.PatternMatching.AllowedPatterns = new() { @"(?i)demo\s+mode" };
    
    // Disable specific built-in patterns causing false positives
    options.PatternMatching.DisabledPatternIds = new()
    {
        BuiltInPatternIds.Base64EncodingDetection  // Example: disable base64 check
    };
    
    // Disable specific ML features
    options.MLClassification.DisabledFeatures = new() { "IgnorePattern" };
    
    // Custom feature weights for ML
    options.MLClassification.FeatureWeights = new()
    {
        ["InjectionKeywords"] = 0.6,  // Reduce weight
        ["PersonaSwitchPattern"] = 0.8
    };
});
```

### 5. Extensibility Points

```csharp
services.AddPromptShield()
    .AddPatternProvider<GermanPatternProvider>()      // Add patterns for German
    .AddHeuristicAnalyzer<GermanHeuristicAnalyzer>()  // Add German heuristics
    .AddLanguageDetector<AzureLanguageDetector>()     // Use Azure for detection
    .AddEventHandler<SecurityAuditHandler>();
```

### 6. Custom Semantic Analysis Prompts

```csharp
services.AddPromptShield(options =>
{
    options.SemanticAnalysis.Enabled = true;
    options.SemanticAnalysis.Endpoint = "https://your-openai.azure.com";
    
    // Custom system prompt for domain-specific detection
    options.SemanticAnalysis.CustomSystemPrompt = """
        You are a security analyst for a banking application...
        """;
    
    // Or just add context to the default prompt
    options.SemanticAnalysis.AdditionalContext = 
        "In this application, 'transfer funds' is a normal operation.";
});
```

### 7. Observable Architecture

```csharp
builder.Services.AddOpenTelemetry()
    .WithMetrics(m => m.AddMeter("PromptShield"))
    .WithTracing(t => t.AddSource("PromptShield"));
```

---

## Running the Project

### Prerequisites

- .NET 8.0 SDK or later
- (Optional) Azure OpenAI for semantic analysis layer

### Build

```powershell
dotnet restore
dotnet build
```

### Run Tests

```powershell
dotnet test
```

### Run Benchmarks

```powershell
cd tests/PromptShield.Benchmarks
dotnet run -c Release
```

---

## Limitations & Known Issues

As a POC, this project has the following limitations:

### Language Support

- ⚠️ **English-only rule-based detection** — Pattern matching, heuristics, and ML vocabulary are designed for English
- ✅ **Language Filter mitigation** — Non-English prompts can be routed to Semantic Analysis (LLM-based)
- 🔧 **Extensibility** — Implement `IPatternProvider` to add patterns for other languages

### Other Limitations

- ❌ **No pre-trained ML model** — ML layer requires external ONNX model
- ❌ **Limited pattern library** — Built-in patterns are illustrative only
- ❌ **No production hardening** — Error handling and edge cases are minimal
- ❌ **No real-time pattern updates** — Static pattern loading only
- ❌ **No caching layer** — Every prompt is analyzed from scratch

---

## Contributing

This is an educational POC project. Contributions, suggestions, and discussions are welcome!

1. Fork the repository
2. Create a feature branch
3. Submit a Pull Request

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

---

## Security

For security-related questions about this POC, see [SECURITY.md](SECURITY.md).

---

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

---

## References

- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/) — Threat categorization framework
- [Microsoft Semantic Kernel](https://github.com/microsoft/semantic-kernel) — AI orchestration framework
- [Azure AI Content Safety](https://learn.microsoft.com/azure/ai-services/content-safety/) — Production-grade content moderation

---

<p align="center">
  <sub>Built as a learning exercise for secure LLM integration patterns</sub>
</p>
