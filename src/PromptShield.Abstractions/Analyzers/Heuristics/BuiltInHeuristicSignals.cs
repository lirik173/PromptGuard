namespace PromptShield.Abstractions.Analyzers.Heuristics;

/// <summary>
/// Built-in heuristic signals detected by the default analyzer.
/// </summary>
public static class BuiltInHeuristicSignals
{
    /// <summary>Unusual ratio of special characters.</summary>
    public const string SpecialCharacterRatio = "special_char_ratio";

    /// <summary>Presence of instruction-like language.</summary>
    public const string InstructionLanguage = "instruction_language";

    /// <summary>Role-switching or persona language detected.</summary>
    public const string RoleSwitching = "role_switching";

    /// <summary>Encoding patterns suggesting obfuscation.</summary>
    public const string EncodingPatterns = "encoding_patterns";

    /// <summary>Delimiter injection markers.</summary>
    public const string DelimiterInjection = "delimiter_injection";

    /// <summary>Unusual prompt structure or formatting.</summary>
    public const string AnomalousStructure = "anomalous_structure";

    /// <summary>Repetitive patterns that may indicate manipulation.</summary>
    public const string RepetitivePatterns = "repetitive_patterns";

    /// <summary>Prompt length exceeds typical user input.</summary>
    public const string ExcessiveLength = "excessive_length";

    /// <summary>Regex pattern evaluation timed out (potential ReDoS attempt).</summary>
    public const string PatternTimeout = "pattern_timeout";

    /// <summary>Suspicious Unicode control characters detected.</summary>
    public const string SuspiciousUnicode = "suspicious_unicode";

    /// <summary>Zero-width or invisible characters detected.</summary>
    public const string InvisibleCharacters = "invisible_characters";

    /// <summary>Bidirectional text override characters detected.</summary>
    public const string BidirectionalOverride = "bidirectional_override";
}
