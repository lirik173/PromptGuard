namespace PromptShield.Abstractions.Analyzers.Heuristics;

/// <summary>
/// Result from a heuristic analyzer.
/// </summary>
public sealed class HeuristicResult
{
    /// <summary>
    /// Risk score from this analyzer (0.0 = safe, 1.0 = threat).
    /// </summary>
    public required double Score { get; init; }

    /// <summary>
    /// List of signals detected by this analyzer.
    /// </summary>
    public required IReadOnlyList<HeuristicSignal> Signals { get; init; }

    /// <summary>
    /// Optional explanation of the analysis.
    /// </summary>
    public string? Explanation { get; init; }
}
