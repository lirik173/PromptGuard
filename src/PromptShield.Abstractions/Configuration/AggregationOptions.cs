namespace PromptShield.Abstractions.Configuration;

/// <summary>
/// Configuration for aggregating results from multiple detection layers.
/// </summary>
public sealed class AggregationOptions
{
    /// <summary>
    /// Weight for Pattern Matching layer in final score calculation.
    /// Default is 0.4.
    /// </summary>
    /// <remarks>
    /// All weights are normalized during aggregation, so they don't need to sum to 1.0.
    /// </remarks>
    public double PatternMatchingWeight { get; set; } = 0.4;

    /// <summary>
    /// Weight for Heuristic Analysis layer in final score calculation.
    /// Default is 0.6.
    /// </summary>
    public double HeuristicsWeight { get; set; } = 0.6;

    /// <summary>
    /// Weight for ML Classification layer in final score calculation.
    /// Default is 0.8.
    /// </summary>
    public double MLClassificationWeight { get; set; } = 0.8;

    /// <summary>
    /// Weight for Semantic Analysis layer in final score calculation.
    /// Default is 0.9.
    /// </summary>
    public double SemanticAnalysisWeight { get; set; } = 0.9;
}
