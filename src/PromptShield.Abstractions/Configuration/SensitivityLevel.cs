namespace PromptShield.Abstractions.Configuration;

/// <summary>
/// Sensitivity level for heuristic analysis.
/// Higher sensitivity catches more threats but may produce more false positives.
/// </summary>
public enum SensitivityLevel
{
    /// <summary>
    /// Low sensitivity - fewer false positives, may miss some attacks.
    /// Recommended for high-traffic applications where user experience is critical.
    /// </summary>
    Low = 0,

    /// <summary>
    /// Balanced sensitivity (default).
    /// Good balance between detection rate and false positives.
    /// </summary>
    Medium = 1,

    /// <summary>
    /// High sensitivity - catches more threats, more false positives.
    /// Recommended for security-critical applications.
    /// </summary>
    High = 2,

    /// <summary>
    /// Maximum detection - catches most threats, highest false positive rate.
    /// Recommended only for testing or extremely sensitive environments.
    /// </summary>
    Paranoid = 3
}
