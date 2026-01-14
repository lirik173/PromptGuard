namespace PromptShield.Abstractions.Configuration;

/// <summary>
/// Pattern matching layer options.
/// </summary>
public sealed class PatternMatchingOptions
{
    /// <summary>
    /// Whether pattern matching is enabled.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Regex execution timeout in milliseconds.
    /// </summary>
    public int TimeoutMs { get; set; } = 100;

    /// <summary>
    /// Threshold for early exit when pattern match confidence is high.
    /// </summary>
    public double EarlyExitThreshold { get; set; } = 0.9;

    /// <summary>
    /// Whether to include built-in patterns.
    /// </summary>
    public bool IncludeBuiltInPatterns { get; set; } = true;

    /// <summary>
    /// Confidence contribution when a regex timeout occurs.
    /// Higher values indicate more suspicion on timeout (potential ReDoS attempt).
    /// </summary>
    public double TimeoutContribution { get; set; } = 0.3;

    /// <summary>
    /// Pattern IDs to disable from detection.
    /// Use this to disable specific built-in patterns that cause false positives.
    /// Pattern IDs are listed in <see cref="BuiltInPatternIds"/>.
    /// </summary>
    /// <example>
    /// DisabledPatternIds = new List&lt;string&gt; { "builtin-extraction-001" }
    /// </example>
    public List<string> DisabledPatternIds { get; set; } = new();

    /// <summary>
    /// Regex patterns that should bypass pattern matching (allowlist).
    /// If a prompt matches any of these patterns, pattern matching returns safe.
    /// </summary>
    public List<string> AllowedPatterns { get; set; } = new();

    /// <summary>
    /// Sensitivity level that adjusts pattern matching strictness.
    /// </summary>
    public SensitivityLevel Sensitivity { get; set; } = SensitivityLevel.Medium;
}

/// <summary>
/// Built-in pattern IDs for reference when disabling specific patterns.
/// </summary>
public static class BuiltInPatternIds
{
    #region Jailbreak patterns

    /// <summary>DAN mode jailbreak attempt pattern.</summary>
    public const string DanModeJailbreak = "builtin-jailbreak-001";

    /// <summary>Ignore previous instructions pattern.</summary>
    public const string IgnorePreviousInstructions = "builtin-jailbreak-002";

    /// <summary>Forget everything pattern.</summary>
    public const string ForgetEverythingPattern = "builtin-jailbreak-005";

    /// <summary>Disregard safety guidelines pattern.</summary>
    public const string DisregardSafetyGuidelines = "builtin-jailbreak-006";

    /// <summary>No restrictions pattern.</summary>
    public const string NoRestrictionsPattern = "builtin-jailbreak-007";

    /// <summary>New role assignment pattern.</summary>
    public const string NewRoleAssignment = "builtin-jailbreak-003";

    #endregion

    #region Role impersonation

    /// <summary>Role impersonation with privileged access pattern.</summary>
    public const string RoleImpersonationPrivileged = "builtin-roleplay-001";

    /// <summary>Role impersonation with unrestricted access pattern.</summary>
    public const string RoleImpersonationUnrestricted = "builtin-roleplay-002";

    /// <summary>Safety bypass through role assumption pattern.</summary>
    public const string SafetyBypassThroughRole = "builtin-roleplay-003";

    /// <summary>No restrictions mode activation pattern.</summary>
    public const string NoRestrictionsMode = "builtin-roleplay-004";

    #endregion

    #region Instruction override

    /// <summary>Instruction override attempt pattern.</summary>
    public const string InstructionOverride = "builtin-override-001";

    /// <summary>New instructions injection pattern.</summary>
    public const string NewInstructionsInjection = "builtin-override-002";

    #endregion

    #region System prompt extraction

    /// <summary>System prompt extraction attempt pattern.</summary>
    public const string SystemPromptExtraction = "builtin-extraction-001";

    /// <summary>Initial prompt request pattern.</summary>
    public const string InitialPromptRequest = "builtin-extraction-002";

    #endregion

    #region Encoding

    /// <summary>Base64 encoded content detection pattern.</summary>
    public const string Base64EncodingDetection = "builtin-encoding-001";

    /// <summary>Hexadecimal encoded content detection pattern.</summary>
    public const string HexEncodingDetection = "builtin-encoding-002";

    #endregion

    #region Delimiter injection

    /// <summary>Delimiter injection pattern.</summary>
    public const string DelimiterInjection = "builtin-delimiter-001";

    /// <summary>XML/JSON injection markers pattern.</summary>
    public const string XmlJsonInjectionMarkers = "builtin-delimiter-002";

    #endregion

    #region Context exhaustion

    /// <summary>Excessive repetition pattern.</summary>
    public const string ExcessiveRepetition = "builtin-exhaustion-001";

    #endregion

    #region AI alignment manipulation

    /// <summary>Safety bypass attempt pattern.</summary>
    public const string SafetyBypassAttempt = "builtin-alignment-001";

    /// <summary>Harmful content request pattern.</summary>
    public const string HarmfulContentRequest = "builtin-alignment-002";

    #endregion
}
