using PromptShield.Abstractions.Analysis;
using PromptShield.Abstractions.Detection;
using PromptShield.Abstractions.Detection.Patterns;

namespace PromptShield.Core.Patterns;

/// <summary>
/// Provides built-in detection patterns for common prompt injection attacks.
/// </summary>
public sealed class BuiltInPatternProvider : IBuiltInPatternProvider
{
    public string ProviderName => "Built-In Patterns";

    public IEnumerable<DetectionPattern> GetPatterns()
    {
        // Jailbreak Attempts (LLM01)
        yield return new DetectionPattern
        {
            Id = "builtin-jailbreak-001",
            Name = "DAN Mode Jailbreak",
            Pattern = @"(?i)\b(DAN\s+mode|do\s+anything\s+now)\b",
            OwaspCategory = "LLM01",
            Severity = ThreatSeverity.Critical,
            Description = "Detects 'Do Anything Now' (DAN) jailbreak attempts"
        };

        yield return new DetectionPattern
        {
            Id = "builtin-jailbreak-002",
            Name = "Ignore Previous Instructions",
            Pattern = @"(?i)\b(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|commands?|rules?|prompts?)\b",
            OwaspCategory = "LLM01",
            Severity = ThreatSeverity.Critical,
            Description = "Attempts to override system instructions"
        };

        yield return new DetectionPattern
        {
            Id = "builtin-jailbreak-005",
            Name = "Forget Everything Pattern",
            Pattern = @"(?i)\b(forget|disregard)\s+.{0,20}\b(everything|all\s+you|what\s+you)\b",
            OwaspCategory = "LLM01",
            Severity = ThreatSeverity.High,
            Description = "Attempts to make AI forget training or context"
        };

        yield return new DetectionPattern
        {
            Id = "builtin-jailbreak-006",
            Name = "Disregard Safety/Guidelines",
            Pattern = @"(?i)\b(disregard|ignore|bypass)\s+.{0,10}\b(safety|guidelines?|restrictions?|constraints?)\b",
            OwaspCategory = "LLM01",
            Severity = ThreatSeverity.Critical,
            Description = "Attempts to bypass safety guidelines"
        };

        yield return new DetectionPattern
        {
            Id = "builtin-jailbreak-007",
            Name = "No Restrictions Pattern",
            Pattern = @"(?i)\b(act|behave|respond).{0,20}\b(no\s+restrictions?|without\s+restrictions?|unrestricted)\b",
            OwaspCategory = "LLM01",
            Severity = ThreatSeverity.High,
            Description = "Requests for unrestricted behavior"
        };

        yield return new DetectionPattern
        {
            Id = "builtin-jailbreak-003",
            Name = "New Role Assignment",
            Pattern = @"(?i)\b(you\s+are\s+now|from\s+now\s+on|starting\s+now)\s+.{0,30}\b(assistant|AI|bot|system)\b",
            OwaspCategory = "LLM01",
            Severity = ThreatSeverity.High,
            Description = "Attempts to reassign the AI's role mid-conversation"
        };

        // Role Impersonation (LLM01)
        yield return new DetectionPattern
        {
            Id = "builtin-roleplay-001",
            Name = "Role Impersonation - Privileged",
            Pattern = @"(?i)\b(act\s+as|pretend\s+(you\s+are|to\s+be)|roleplay\s+as|simulate)\s+.{0,50}\b(admin|root|developer|engineer|DAN|sudo)\b",
            OwaspCategory = "LLM01",
            Severity = ThreatSeverity.High,
            Description = "Attempts to impersonate privileged roles"
        };

        yield return new DetectionPattern
        {
            Id = "builtin-roleplay-002",
            Name = "Role Impersonation - Unrestricted",
            Pattern = @"(?i)\b(act\s+as|pretend\s+to\s+be|become)\s+.{0,30}\b(AI|character|system)\b.{0,50}\b(no\s+|without\s+|unrestricted|bypass|no\s+ethical)\b",
            OwaspCategory = "LLM01",
            Severity = ThreatSeverity.Critical,
            Description = "Attempts to assume unrestricted character roles"
        };

        yield return new DetectionPattern
        {
            Id = "builtin-roleplay-003",
            Name = "Safety Bypass Through Role",
            Pattern = @"(?i)\b(from\s+now\s+on|starting\s+now|going\s+forward)\s*,?\s*.{0,30}\b(act|pretend|behave)\s+.{0,50}\b(no\s+restrictions?|no\s+constraints?|bypass|safety)\b",
            OwaspCategory = "LLM01",
            Severity = ThreatSeverity.Critical,
            Description = "Attempts to bypass safety through role changes"
        };

        yield return new DetectionPattern
        {
            Id = "builtin-roleplay-004",
            Name = "No Restrictions Mode",
            Pattern = @"(?i)\b(AI|you)\s+.{0,20}\b(can|that\s+can|able\s+to)\s+.{0,30}\b(bypass|ignore|no\s+restrictions?|anything|everything)\b",
            OwaspCategory = "LLM01",
            Severity = ThreatSeverity.High,
            Description = "Requests for unrestricted AI behavior"
        };

        // Instruction Override (LLM01)
        yield return new DetectionPattern
        {
            Id = "builtin-override-001",
            Name = "Instruction Override",
            Pattern = @"(?i)\b(disregard|override|bypass|skip)\s+(all\s+)?(instructions?|rules?|guidelines?|constraints?)\b",
            OwaspCategory = "LLM01",
            Severity = ThreatSeverity.Critical,
            Description = "Direct attempts to override safety constraints"
        };

        yield return new DetectionPattern
        {
            Id = "builtin-override-002",
            Name = "New Instructions Injection",
            Pattern = @"(?i)\b(new\s+instructions?|updated\s+instructions?|revised\s+instructions?)\s*:",
            OwaspCategory = "LLM01",
            Severity = ThreatSeverity.High,
            Description = "Attempts to inject new instructions"
        };

        // System Prompt Extraction (LLM01)
        yield return new DetectionPattern
        {
            Id = "builtin-extraction-001",
            Name = "System Prompt Extraction",
            Pattern = @"(?i)\b(repeat|show|display|tell\s+me|what\s+(are|is|were))\s+.{0,30}\b(your\s+)?(system\s+)?(prompt|instructions?|rules?|guidelines?)\b",
            OwaspCategory = "LLM01",
            Severity = ThreatSeverity.High,
            Description = "Attempts to extract system prompts or instructions"
        };

        yield return new DetectionPattern
        {
            Id = "builtin-extraction-002",
            Name = "Initial Prompt Request",
            Pattern = @"(?i)\b(what|show|display)\s+(was|were)\s+(your\s+)?(initial|original|first)\s+(prompt|instructions?)\b",
            OwaspCategory = "LLM01",
            Severity = ThreatSeverity.Medium,
            Description = "Attempts to retrieve initial system configuration"
        };

        // Encoding Obfuscation (LLM01)
        yield return new DetectionPattern
        {
            Id = "builtin-encoding-001",
            Name = "Base64 Encoding Detection",
            Pattern = @"(?i)(base64|base-64)\s*(decode|decoding|encoded)|\b[A-Za-z0-9+/]{40,}={0,2}\b",
            OwaspCategory = "LLM01",
            Severity = ThreatSeverity.Medium,
            Description = "Detects potential base64-encoded injection attempts"
        };

        yield return new DetectionPattern
        {
            Id = "builtin-encoding-002",
            Name = "Hex Encoding Detection",
            Pattern = @"(?i)(hex|hexadecimal)\s*(decode|decoding)|(?:\\x[0-9a-fA-F]{2}){10,}",
            OwaspCategory = "LLM01",
            Severity = ThreatSeverity.Medium,
            Description = "Detects hex-encoded injection attempts"
        };

        // Delimiter Injection (LLM01)
        yield return new DetectionPattern
        {
            Id = "builtin-delimiter-001",
            Name = "Delimiter Injection",
            Pattern = @"(#{3,}|={3,}|-{3,}|\*{3,}|_{3,})\s*(system|user|assistant|instruction|prompt)\s*(#{3,}|={3,}|-{3,}|\*{3,}|_{3,})",
            OwaspCategory = "LLM01",
            Severity = ThreatSeverity.High,
            Description = "Detects delimiter-based prompt structure manipulation"
        };

        yield return new DetectionPattern
        {
            Id = "builtin-delimiter-002",
            Name = "XML/JSON Injection Markers",
            Pattern = @"<\s*(system|instruction|prompt)\s*>|""(system|instruction|prompt)""\s*:\s*""",
            OwaspCategory = "LLM01",
            Severity = ThreatSeverity.Medium,
            Description = "Detects XML/JSON-style injection markers"
        };

        // Context Window Exhaustion (LLM02)
        yield return new DetectionPattern
        {
            Id = "builtin-exhaustion-001",
            Name = "Excessive Repetition",
            Pattern = @"(.{10,})\1{10,}",
            OwaspCategory = "LLM02",
            Severity = ThreatSeverity.Low,
            Description = "Detects excessive repetition that may exhaust context"
        };

        // AI Alignment Manipulation (LLM07)
        yield return new DetectionPattern
        {
            Id = "builtin-alignment-001",
            Name = "Safety Bypass Attempt",
            Pattern = @"(?i)\b(bypass|circumvent|avoid|disable)\s+(safety|security|ethical|moral)\s+(features?|checks?|guidelines?|constraints?)\b",
            OwaspCategory = "LLM07",
            Severity = ThreatSeverity.Critical,
            Description = "Attempts to bypass safety and ethical guidelines"
        };

        yield return new DetectionPattern
        {
            Id = "builtin-alignment-002",
            Name = "Harmful Content Request",
            Pattern = @"(?i)\b(help\s+me|show\s+me\s+how\s+to|teach\s+me\s+to)\s+.{0,50}\b(hack|exploit|attack|harm|illegal)\b",
            OwaspCategory = "LLM07",
            Severity = ThreatSeverity.High,
            Description = "Requests for harmful or illegal content"
        };
    }
}
