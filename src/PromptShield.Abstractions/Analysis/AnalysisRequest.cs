namespace PromptShield.Abstractions.Analysis;

/// <summary>
/// Request object for prompt analysis containing the text to analyze and optional context.
/// </summary>
public sealed class AnalysisRequest
{
    /// <summary>
    /// The user prompt text to analyze for injection attacks.
    /// </summary>
    /// <remarks>Required. Maximum length: 50,000 characters.</remarks>
    public required string Prompt { get; init; }
    
    /// <summary>
    /// Optional system prompt for context-aware analysis.
    /// </summary>
    public string? SystemPrompt { get; init; }
    
    /// <summary>
    /// Optional conversation history for multi-turn context.
    /// </summary>
    public IReadOnlyList<ConversationMessage>? ConversationHistory { get; init; }
    
    /// <summary>
    /// Optional metadata for audit and correlation.
    /// </summary>
    public AnalysisMetadata? Metadata { get; init; }
}
