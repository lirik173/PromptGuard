namespace PromptShield.SemanticKernel;

/// <summary>
/// Exception thrown when prompt analysis fails and fail-closed behavior is configured.
/// </summary>
/// <remarks>
/// This exception is thrown when the PromptShield analyzer encounters an unexpected error
/// and the system is configured to block prompts on failure (fail-closed).
/// This ensures security is maintained even when the analysis system has issues.
/// </remarks>
public sealed class PromptShieldAnalysisException : Exception
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PromptShieldAnalysisException"/> class.
    /// </summary>
    public PromptShieldAnalysisException()
        : base("Prompt analysis failed.")
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="PromptShieldAnalysisException"/> class
    /// with a specified error message.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    public PromptShieldAnalysisException(string message)
        : base(message)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="PromptShieldAnalysisException"/> class
    /// with a specified error message and inner exception.
    /// </summary>
    /// <param name="message">The message that describes the error.</param>
    /// <param name="innerException">The exception that caused this exception.</param>
    public PromptShieldAnalysisException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
