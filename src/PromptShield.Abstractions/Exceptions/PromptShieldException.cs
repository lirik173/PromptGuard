namespace PromptShield.Abstractions.Exceptions;

/// <summary>
/// Base exception for PromptShield errors.
/// </summary>
public class PromptShieldException : Exception
{
    /// <summary>
    /// Gets the timestamp when the exception occurred.
    /// </summary>
    public DateTimeOffset Timestamp { get; }

    /// <summary>
    /// Initializes a new instance of <see cref="PromptShieldException"/>.
    /// </summary>
    public PromptShieldException()
        : base("A PromptShield error occurred.")
    {
        Timestamp = DateTimeOffset.UtcNow;
    }

    /// <summary>
    /// Initializes a new instance of <see cref="PromptShieldException"/>.
    /// </summary>
    /// <param name="message">The error message.</param>
    public PromptShieldException(string message)
        : base(message)
    {
        Timestamp = DateTimeOffset.UtcNow;
    }

    /// <summary>
    /// Initializes a new instance of <see cref="PromptShieldException"/> with an inner exception.
    /// </summary>
    /// <param name="message">The error message.</param>
    /// <param name="innerException">The inner exception.</param>
    public PromptShieldException(string message, Exception innerException)
        : base(message, innerException)
    {
        Timestamp = DateTimeOffset.UtcNow;
    }
}
