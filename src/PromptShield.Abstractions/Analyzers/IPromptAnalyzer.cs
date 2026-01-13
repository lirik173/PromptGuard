namespace PromptShield.Abstractions.Analyzers;

using PromptShield.Abstractions.Analysis;
using PromptShield.Abstractions.Exceptions;

/// <summary>
/// Core interface for analyzing prompts for injection attacks.
/// This is the primary entry point for prompt analysis.
/// </summary>
public interface IPromptAnalyzer
{
    /// <summary>
    /// Analyzes a prompt for potential injection attacks.
    /// </summary>
    /// <param name="request">The analysis request containing the prompt and optional context.</param>
    /// <param name="cancellationToken">Cancellation token for the operation.</param>
    /// <returns>Analysis result containing threat detection status and details.</returns>
    /// <exception cref="ArgumentNullException">Thrown when request is null.</exception>
    /// <exception cref="ValidationException">Thrown when request validation fails.</exception>
    /// <remarks>
    /// This method is thread-safe and can be called concurrently.
    /// The analysis pipeline executes layers in order: Pattern Matching → Heuristics → ML → Semantic.
    /// Early exit occurs when a definitive result is reached.
    /// </remarks>
    Task<AnalysisResult> AnalyzeAsync(
        AnalysisRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Analyzes a prompt string directly with default options.
    /// </summary>
    /// <param name="prompt">The prompt text to analyze.</param>
    /// <param name="cancellationToken">Cancellation token for the operation.</param>
    /// <returns>Analysis result containing threat detection status and details.</returns>
    /// <remarks>
    /// Convenience method that creates an AnalysisRequest internally.
    /// For more control, use <see cref="AnalyzeAsync(AnalysisRequest, CancellationToken)"/>.
    /// </remarks>
    Task<AnalysisResult> AnalyzeAsync(
        string prompt,
        CancellationToken cancellationToken = default);
}
