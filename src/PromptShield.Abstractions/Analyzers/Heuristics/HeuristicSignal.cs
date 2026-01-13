namespace PromptShield.Abstractions.Analyzers.Heuristics;

/// <summary>
/// A signal detected by heuristic analysis.
/// </summary>
public sealed class HeuristicSignal
{
    /// <summary>
    /// Name of the signal.
    /// </summary>
    public required string Name { get; init; }

    /// <summary>
    /// Contribution to the overall score.
    /// </summary>
    public required double Contribution { get; init; }

    /// <summary>
    /// Description of why this signal was triggered.
    /// </summary>
    public string? Description { get; init; }
}
