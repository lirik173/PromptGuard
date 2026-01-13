namespace PromptShield.Abstractions.Detection;

using PromptShield.Abstractions.Analysis;

/// <summary>
/// Defines a detection pattern for identifying prompt injection attacks.
/// </summary>
public sealed class DetectionPattern
{
    /// <summary>
    /// Unique identifier for the pattern.
    /// </summary>
    public required string Id { get; init; }
    
    /// <summary>
    /// Human-readable name of the pattern.
    /// </summary>
    public required string Name { get; init; }
    
    /// <summary>
    /// Regular expression pattern to match against prompts.
    /// </summary>
    public required string Pattern { get; init; }
    
    /// <summary>
    /// Description of what this pattern detects.
    /// </summary>
    public required string Description { get; init; }
    
    /// <summary>
    /// OWASP LLM Top 10 category identifier.
    /// </summary>
    public required string OwaspCategory { get; init; }
    
    /// <summary>
    /// Severity level if this pattern matches.
    /// </summary>
    public required ThreatSeverity Severity { get; init; }
    
    /// <summary>
    /// Whether this pattern is enabled.
    /// </summary>
    public bool Enabled { get; init; } = true;
}
