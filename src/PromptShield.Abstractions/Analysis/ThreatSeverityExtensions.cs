namespace PromptShield.Abstractions.Analysis;

/// <summary>
/// Extension methods for <see cref="ThreatSeverity"/>.
/// </summary>
public static class ThreatSeverityExtensions
{
    /// <summary>
    /// Converts threat severity to a confidence score.
    /// </summary>
    /// <param name="severity">The threat severity level.</param>
    /// <returns>
    /// Confidence score in range 0.0-1.0:
    /// Critical = 0.95, High = 0.85, Medium = 0.7, Low = 0.5.
    /// </returns>
    public static double ToConfidence(this ThreatSeverity severity) => severity switch
    {
        ThreatSeverity.Critical => 0.95,
        ThreatSeverity.High => 0.85,
        ThreatSeverity.Medium => 0.7,
        ThreatSeverity.Low => 0.5,
        _ => 0.6
    };

    /// <summary>
    /// Converts a confidence score to the appropriate threat severity.
    /// </summary>
    /// <param name="confidence">Confidence score in range 0.0-1.0.</param>
    /// <returns>The corresponding threat severity level.</returns>
    public static ThreatSeverity ToSeverity(this double confidence) => confidence switch
    {
        >= 0.9 => ThreatSeverity.Critical,
        >= 0.8 => ThreatSeverity.High,
        >= 0.6 => ThreatSeverity.Medium,
        _ => ThreatSeverity.Low
    };
}
