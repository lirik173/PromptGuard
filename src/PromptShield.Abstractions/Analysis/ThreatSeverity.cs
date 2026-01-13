namespace PromptShield.Abstractions.Analysis;

/// <summary>
/// Severity levels for detected threats.
/// </summary>
public enum ThreatSeverity
{
    /// <summary>Low risk, may be false positive.</summary>
    Low = 1,
    
    /// <summary>Medium risk, likely attack attempt.</summary>
    Medium = 2,
    
    /// <summary>High risk, confirmed attack pattern.</summary>
    High = 3,
    
    /// <summary>Critical risk, active exploitation attempt.</summary>
    Critical = 4
}
