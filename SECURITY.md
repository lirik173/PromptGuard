# Security Policy

## Supported Versions

We release patches for security vulnerabilities in the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | ✅ Active support   |
| < 1.0   | ❌ No longer supported |

---

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

### Reporting Process

If you discover a security vulnerability in PromptShield, please report it responsibly:

1. **Email**: Send details to `security@promptshield.dev` (or create a private security advisory on GitHub)
2. **Include**:
   - Description of the vulnerability
   - Steps to reproduce the issue
   - Potential impact assessment
   - Any suggested mitigations (optional)

### What to Expect

| Timeline | Action |
|----------|--------|
| **24 hours** | Acknowledgment of your report |
| **72 hours** | Initial assessment and severity classification |
| **7 days** | Detailed response with remediation plan |
| **30-90 days** | Patch released (depending on complexity) |

### Disclosure Policy

- We follow **coordinated disclosure** practices
- We will work with you to understand and resolve the issue
- We will credit reporters in security advisories (unless you prefer anonymity)
- We ask that you do not publicly disclose until a fix is available

---

## Security Design Principles

PromptShield is designed with security as a core principle:

### Fail-Closed by Default

```csharp
// Default configuration denies on analysis errors
options.OnAnalysisError = FailureBehavior.FailClosed;
```

When PromptShield encounters an error during analysis, it defaults to treating the prompt as potentially malicious. This ensures that system failures don't create security gaps.

### Defense in Depth

The multi-layer detection pipeline ensures that bypassing one layer doesn't compromise the entire system:

1. **Pattern Matching** — Known attack signatures
2. **Heuristic Analysis** — Behavioral indicators
3. **ML Classification** — Statistical anomaly detection
4. **Semantic Analysis** — Deep content understanding

### Input Validation

All inputs are validated before processing:

- **Null/empty checks** — Rejected with clear error messages
- **Length limits** — Prevents DoS via oversized inputs (default: 50,000 characters)
- **Character validation** — Handles null bytes and invalid Unicode
- **Regex timeouts** — Prevents ReDoS attacks (default: 100ms timeout)

### Secure Defaults

| Setting | Default | Reason |
|---------|---------|--------|
| `ThreatThreshold` | 0.75 | Balanced detection vs false positives |
| `OnAnalysisError` | FailClosed | Security over availability |
| `LogPromptContent` | false | Privacy protection |
| `PatternMatching.TimeoutMs` | 100 | ReDoS protection |

### Information Disclosure Prevention

- **User-facing messages** never reveal detection internals
- **Detailed breakdowns** are opt-in and intended for security teams
- **Logging** can be configured to exclude prompt content

---

## Security Best Practices for Users

### 1. Keep Updated

Always use the latest version of PromptShield to benefit from security patches:

```powershell
dotnet add package PromptShield.Core --version latest
```

### 2. Use Fail-Closed Mode

Never change the default failure behavior in production unless absolutely necessary:

```csharp
// ⚠️ NOT RECOMMENDED for production
options.OnAnalysisError = FailureBehavior.FailOpen;
```

### 3. Monitor and Alert

Configure telemetry to detect attack patterns:

```csharp
builder.Services.AddOpenTelemetry()
    .WithMetrics(metrics => metrics.AddMeter("PromptShield"));
```

### 4. Regular Pattern Updates

Update to the latest package version to get new detection patterns:

```powershell
dotnet restore --force
```

### 5. Custom Patterns for Your Domain

Add organization-specific patterns for targeted protection:

```csharp
public class EnterprisePatternProvider : IPatternProvider
{
    public IEnumerable<DetectionPattern> GetPatterns()
    {
        // Add patterns specific to your organization
        yield return new DetectionPattern
        {
            Name = "Internal Data Extraction",
            Pattern = @"(?i)\b(reveal|show|tell me).*\b(secret|confidential|internal)\b",
            OwaspCategory = "LLM01",
            Severity = ThreatSeverity.Critical
        };
    }
}
```

### 6. Implement Event Handlers

Use event handlers for security monitoring:

```csharp
public class SecurityMonitor : PromptShieldEventHandlerBase
{
    public override Task OnThreatDetectedAsync(ThreatDetectedEvent @event, CancellationToken ct)
    {
        // Alert security team, log to SIEM, etc.
        return Task.CompletedTask;
    }
}
```

---

## Security Considerations

### What PromptShield Protects Against

| Threat | OWASP Category | Protection |
|--------|----------------|------------|
| Jailbreak attempts | LLM01 | Pattern + Heuristic |
| Role impersonation | LLM01 | Pattern + Heuristic |
| Instruction override | LLM01 | Pattern + ML |
| System prompt extraction | LLM01 | Pattern |
| Encoding obfuscation | LLM01 | Pattern |
| Delimiter injection | LLM01 | Heuristic |

### What PromptShield Does NOT Protect Against

| Threat | Reason | Mitigation |
|--------|--------|------------|
| Output manipulation | Out of scope | Use output filtering |
| Model poisoning | Requires model access | Secure training pipeline |
| Supply chain attacks | Infrastructure level | Secure dependencies |
| Social engineering | Human factor | User education |

---

## Vulnerability History

We maintain transparency about security issues:

| Date | Severity | Description | Resolution |
|------|----------|-------------|------------|
| *No vulnerabilities reported yet* | | | |

---

## Compliance

PromptShield is designed to help organizations meet security requirements:

- **OWASP LLM Top 10** — All threats mapped to OWASP categories
- **SOC 2** — Supports audit logging and monitoring
- **GDPR** — Privacy-conscious logging options
- **ISO 27001** — Security-first design principles

---

## Contact

- **Security issues**: security@promptshield.dev
- **General questions**: [GitHub Discussions](https://github.com/promptshield/promptshield/discussions)
- **Bug reports**: [GitHub Issues](https://github.com/promptshield/promptshield/issues)

---

Thank you for helping keep PromptShield secure! 🛡️
