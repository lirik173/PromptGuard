namespace PromptShield.Abstractions.Analysis;

/// <summary>
/// Breakdown of detection results from each layer in the pipeline.
/// </summary>
public sealed class DetectionBreakdown
{
    /// <summary>
    /// Result from Pattern Matching layer (always executed).
    /// </summary>
    public required LayerResult PatternMatching { get; init; }
    
    /// <summary>
    /// Result from Heuristic Analysis layer (always executed).
    /// </summary>
    public required LayerResult Heuristics { get; init; }
    
    /// <summary>
    /// Result from ML Classification layer (conditionally executed).
    /// </summary>
    public LayerResult? MLClassification { get; init; }
    
    /// <summary>
    /// Result from Semantic Analysis layer (conditionally executed, opt-in).
    /// </summary>
    public LayerResult? SemanticAnalysis { get; init; }
    
    /// <summary>
    /// List of layers that were executed, in order.
    /// </summary>
    public required IReadOnlyList<string> ExecutedLayers { get; init; }
}
