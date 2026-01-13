namespace PromptShield.Abstractions.Configuration;

/// <summary>
/// Determines system behavior when analysis encounters an error.
/// </summary>
public enum FailureBehavior
{
    /// <summary>
    /// Block the prompt when analysis fails (secure default).
    /// Use this for security-critical applications.
    /// </summary>
    FailClosed = 0,

    /// <summary>
    /// Allow the prompt when analysis fails.
    /// Use with caution - only for non-critical scenarios where availability is paramount.
    /// </summary>
    FailOpen = 1
}
