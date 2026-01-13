namespace PromptShield.Abstractions.Analysis;

/// <summary>
/// Metadata for audit, correlation, and tracing.
/// </summary>
public sealed class AnalysisMetadata
{
    /// <summary>
    /// Unique identifier for the user making the request.
    /// </summary>
    public string? UserId { get; init; }
    
    /// <summary>
    /// Conversation or session identifier.
    /// </summary>
    public string? ConversationId { get; init; }
    
    /// <summary>
    /// Source application or component identifier.
    /// </summary>
    public string? Source { get; init; }
    
    /// <summary>
    /// Correlation ID for distributed tracing.
    /// </summary>
    public string? CorrelationId { get; init; }
    
    /// <summary>
    /// Additional custom properties.
    /// </summary>
    public IReadOnlyDictionary<string, string>? Properties { get; init; }
}
