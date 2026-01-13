namespace PromptShield.Abstractions.Analysis;

/// <summary>
/// Result from a single detection layer.
/// </summary>
public sealed class LayerResult
{
    /// <summary>
    /// Name of the layer that produced this result.
    /// </summary>
    public required string LayerName { get; init; }
    
    /// <summary>
    /// Whether this layer was executed.
    /// </summary>
    public required bool WasExecuted { get; init; }
    
    /// <summary>
    /// Confidence score from this layer (0.0 - 1.0).
    /// </summary>
    public double? Confidence { get; init; }
    
    /// <summary>
    /// Whether this layer flagged the prompt as a threat.
    /// </summary>
    public bool? IsThreat { get; init; }
    
    /// <summary>
    /// Execution duration for this layer.
    /// </summary>
    public TimeSpan? Duration { get; init; }
    
    /// <summary>
    /// Additional layer-specific data.
    /// </summary>
    public IReadOnlyDictionary<string, object>? Data { get; init; }
}
