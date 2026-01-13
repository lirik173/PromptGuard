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
}
