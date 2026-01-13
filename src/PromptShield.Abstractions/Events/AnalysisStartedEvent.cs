namespace PromptShield.Abstractions.Events;

using PromptShield.Abstractions.Analysis;

/// <summary>
/// Event raised when analysis starts.
/// </summary>
public sealed class AnalysisStartedEvent
{
    /// <summary>
    /// Unique identifier for this analysis.
    /// </summary>
    public required Guid AnalysisId { get; init; }

    /// <summary>
    /// The analysis request being processed.
    /// </summary>
    public required AnalysisRequest Request { get; init; }

    /// <summary>
    /// Timestamp when analysis started.
    /// </summary>
    public required DateTimeOffset Timestamp { get; init; }
}
