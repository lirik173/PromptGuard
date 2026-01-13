namespace PromptShield.Abstractions.Analysis;

/// <summary>
/// Result of prompt analysis containing threat detection status and details.
/// </summary>
public sealed class AnalysisResult
{
    /// <summary>
    /// Unique identifier for this analysis.
    /// </summary>
    public required Guid AnalysisId { get; init; }

    /// <summary>
    /// Indicates whether a threat was detected.
    /// </summary>
    public required bool IsThreat { get; init; }

    /// <summary>
    /// Overall confidence score (0.0 = definitely safe, 1.0 = definitely threat).
    /// </summary>
    public required double Confidence { get; init; }

    /// <summary>
    /// Threat details if a threat was detected; null otherwise.
    /// </summary>
    public ThreatInfo? ThreatInfo { get; init; }

    /// <summary>
    /// Breakdown of results from each detection layer.
    /// Null if IncludeBreakdown option is disabled.
    /// </summary>
    public DetectionBreakdown? Breakdown { get; init; }

    /// <summary>
    /// Which detection layer made the final decision.
    /// </summary>
    public required string DecisionLayer { get; init; }

    /// <summary>
    /// Total analysis duration.
    /// </summary>
    public required TimeSpan Duration { get; init; }

    /// <summary>
    /// Timestamp when analysis was performed.
    /// </summary>
    public required DateTimeOffset Timestamp { get; init; }
}
