namespace PromptShield.Abstractions.Analyzers.Heuristics;

using PromptShield.Abstractions.Analysis;
using PromptShield.Abstractions.Configuration;

/// <summary>
/// Interface for custom heuristic analyzers.
/// Implement this interface to add custom heuristic rules to the detection pipeline.
/// </summary>
/// <remarks>
/// Heuristic analyzers perform behavioral and structural analysis of prompts.
/// They run after pattern matching and before ML classification.
/// Multiple analyzers can be registered; their scores are aggregated.
/// </remarks>
public interface IHeuristicAnalyzer
{
    /// <summary>
    /// Analyzes a prompt using heuristic rules.
    /// </summary>
    /// <param name="context">Analysis context containing the prompt and accumulated results.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Heuristic analysis result with score and signals.</returns>
    Task<HeuristicResult> AnalyzeAsync(
        HeuristicContext context,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets the unique name of this heuristic analyzer.
    /// </summary>
    string AnalyzerName { get; }

    /// <summary>
    /// Gets the weight of this analyzer's score in the aggregate calculation.
    /// </summary>
    /// <remarks>Default weight is 1.0. Higher weights give more influence to this analyzer.</remarks>
    double Weight => 1.0;
}
