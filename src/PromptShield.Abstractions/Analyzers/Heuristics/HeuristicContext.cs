namespace PromptShield.Abstractions.Analyzers.Heuristics;

using PromptShield.Abstractions.Analysis;
using PromptShield.Abstractions.Configuration;

/// <summary>
/// Context provided to heuristic analyzers.
/// </summary>
public sealed class HeuristicContext
{
    /// <summary>
    /// The prompt text being analyzed.
    /// </summary>
    public required string Prompt { get; init; }

    /// <summary>
    /// Optional system prompt for context.
    /// </summary>
    public string? SystemPrompt { get; init; }

    /// <summary>
    /// Results from pattern matching layer.
    /// </summary>
    public required LayerResult PatternMatchingResult { get; init; }

    /// <summary>
    /// Current configuration options.
    /// </summary>
    public required PromptShieldOptions Options { get; init; }
}
