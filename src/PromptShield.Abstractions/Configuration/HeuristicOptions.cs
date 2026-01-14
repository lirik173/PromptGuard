namespace PromptShield.Abstractions.Configuration;

/// <summary>
/// Heuristic analysis layer options.
/// </summary>
public sealed class HeuristicOptions
{
    /// <summary>
    /// Whether heuristic analysis is enabled.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Threshold above which result is considered definitive threat.
    /// </summary>
    public double DefinitiveThreatThreshold { get; set; } = 0.85;

    /// <summary>
    /// Threshold below which result is considered definitely safe.
    /// </summary>
    public double DefinitiveSafeThreshold { get; set; } = 0.15;

    /// <summary>
    /// Sensitivity level that adjusts all thresholds proportionally.
    /// Higher sensitivity catches more threats but may produce more false positives.
    /// </summary>
    public SensitivityLevel Sensitivity { get; set; } = SensitivityLevel.Medium;

    /// <summary>
    /// Minimum number of directive keywords required to trigger the directive language signal.
    /// Lower values increase sensitivity but may cause false positives.
    /// </summary>
    public int DirectiveWordThreshold { get; set; } = 3;

    /// <summary>
    /// Punctuation ratio threshold for delimiter injection detection.
    /// Prompts with punctuation ratio above this value trigger a signal.
    /// </summary>
    public double PunctuationRatioThreshold { get; set; } = 0.15;

    /// <summary>
    /// Alphanumeric ratio threshold for obfuscation detection.
    /// Prompts with alphanumeric ratio below this value trigger a signal.
    /// </summary>
    public double AlphanumericRatioThreshold { get; set; } = 0.5;

    /// <summary>
    /// Regex patterns that should bypass heuristic detection (allowlist).
    /// If a prompt matches any of these patterns, heuristic analysis returns safe.
    /// Use for known-safe patterns specific to your domain.
    /// </summary>
    public List<string> AllowedPatterns { get; set; } = new();

    /// <summary>
    /// Additional regex patterns to block (blocklist).
    /// These patterns are checked in addition to built-in patterns.
    /// Use for domain-specific threats not covered by built-in detection.
    /// </summary>
    public List<string> AdditionalBlockedPatterns { get; set; } = new();

    /// <summary>
    /// Keywords to exclude from directive language detection for specific domains.
    /// For example, customer support domains might exclude "ignore" and "forget".
    /// </summary>
    public List<string> DomainExclusions { get; set; } = new();

    /// <summary>
    /// Whether to use compound patterns instead of individual keyword matching.
    /// Compound patterns reduce false positives by requiring context around keywords.
    /// Default is true for better accuracy.
    /// </summary>
    public bool UseCompoundPatterns { get; set; } = true;
}
