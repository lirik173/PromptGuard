namespace PromptShield.Abstractions.Analysis;

/// <summary>
/// Detailed information about a detected prompt injection threat.
/// </summary>
public sealed class ThreatInfo
{
    /// <summary>
    /// OWASP LLM Top 10 category identifier (e.g., "LLM01").
    /// </summary>
    public required string OwaspCategory { get; init; }
    
    /// <summary>
    /// Human-readable threat type name.
    /// </summary>
    public required string ThreatType { get; init; }
    
    /// <summary>
    /// Technical explanation of why this was flagged as a threat.
    /// </summary>
    /// <remarks>For security engineers, not end users.</remarks>
    public required string Explanation { get; init; }
    
    /// <summary>
    /// Safe message suitable for displaying to end users.
    /// </summary>
    /// <remarks>Does not leak detection internals.</remarks>
    public required string UserFacingMessage { get; init; }
    
    /// <summary>
    /// Severity level of the detected threat.
    /// </summary>
    public required ThreatSeverity Severity { get; init; }
    
    /// <summary>
    /// Names of detection sources that flagged this threat.
    /// </summary>
    public required IReadOnlyList<string> DetectionSources { get; init; }
    
    /// <summary>
    /// Names of patterns that matched, if any.
    /// </summary>
    public IReadOnlyList<string>? MatchedPatterns { get; init; }
}
