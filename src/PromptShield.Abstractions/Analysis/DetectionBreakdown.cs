namespace PromptShield.Abstractions.Analysis;

/// <summary>
/// Breakdown of detection results from each layer in the pipeline.
/// </summary>
public sealed class DetectionBreakdown
{
    /// <summary>
    /// Result from Language Filter layer (first layer, determines routing).
    /// </summary>
    /// <remarks>
    /// This layer detects input language and may route non-English prompts
    /// directly to Semantic Analysis, bypassing rule-based layers.
    /// </remarks>
    public LayerResult? LanguageFilter { get; init; }

    /// <summary>
    /// Result from Pattern Matching layer.
    /// </summary>
    /// <remarks>
    /// May be skipped for non-English input if Language Filter is enabled.
    /// </remarks>
    public required LayerResult PatternMatching { get; init; }

    /// <summary>
    /// Result from Heuristic Analysis layer.
    /// </summary>
    /// <remarks>
    /// May be skipped for non-English input if Language Filter is enabled.
    /// </remarks>
    public required LayerResult Heuristics { get; init; }

    /// <summary>
    /// Result from ML Classification layer (conditionally executed).
    /// </summary>
    public LayerResult? MLClassification { get; init; }

    /// <summary>
    /// Result from Semantic Analysis layer (conditionally executed, opt-in).
    /// </summary>
    /// <remarks>
    /// This is the only language-agnostic detection layer (LLM-based).
    /// Used as primary detection for non-English prompts.
    /// </remarks>
    public LayerResult? SemanticAnalysis { get; init; }

    /// <summary>
    /// List of layers that were executed, in order.
    /// </summary>
    public required IReadOnlyList<string> ExecutedLayers { get; init; }

    /// <summary>
    /// Detected language information, if available.
    /// </summary>
    public LanguageDetectionResult? DetectedLanguage =>
        LanguageFilter?.Data?.TryGetValue("language_code", out var code) == true
            ? new LanguageDetectionResult(
                code?.ToString() ?? "und",
                LanguageFilter.Data.TryGetValue("script_code", out var script) ? script?.ToString() ?? "Zzzz" : "Zzzz",
                LanguageFilter.Data.TryGetValue("detection_confidence", out var conf) && conf is double c ? c : 0.0,
                LanguageFilter.Data.TryGetValue("detection_reliable", out var rel) && rel is bool r && r)
            : null;
}
