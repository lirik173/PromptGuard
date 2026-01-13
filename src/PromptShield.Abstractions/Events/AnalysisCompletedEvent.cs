namespace PromptShield.Abstractions.Events;

using PromptShield.Abstractions.Analysis;

/// <summary>
/// Event raised when analysis completes.
/// </summary>
public sealed class AnalysisCompletedEvent
{
    /// <summary>
    /// The complete analysis result.
    /// </summary>
    public required AnalysisResult Result { get; init; }

    /// <summary>
    /// The original analysis request.
    /// </summary>
    public required AnalysisRequest Request { get; init; }

    /// <summary>
    /// Timestamp when analysis completed.
    /// </summary>
    public required DateTimeOffset Timestamp { get; init; }
}
