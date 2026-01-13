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
}
