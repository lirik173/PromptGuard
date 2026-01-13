namespace PromptShield.Abstractions.Analysis;

/// <summary>
/// A single message in conversation history.
/// </summary>
public sealed class ConversationMessage
{
    /// <summary>
    /// Role of the message author (user, assistant, system).
    /// </summary>
    public required string Role { get; init; }
    
    /// <summary>
    /// Content of the message.
    /// </summary>
    public required string Content { get; init; }
}
