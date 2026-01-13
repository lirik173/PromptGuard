namespace PromptShield.Abstractions.Events;

using PromptShield.Abstractions.Analysis;

/// <summary>
/// Event raised when a threat is detected.
/// </summary>
public sealed class ThreatDetectedEvent
{
    /// <summary>
    /// Unique identifier for this analysis.
    /// </summary>
    public required Guid AnalysisId { get; init; }

    /// <summary>
    /// The original analysis request.
    /// </summary>
    public required AnalysisRequest Request { get; init; }

    /// <summary>
    /// Details about the detected threat.
    /// </summary>
    public required ThreatInfo ThreatInfo { get; init; }

    /// <summary>
    /// Which detection layer identified the threat.
    /// </summary>
    public required string DetectionLayer { get; init; }

    /// <summary>
    /// Timestamp when threat was detected.
    /// </summary>
    public required DateTimeOffset Timestamp { get; init; }
}
