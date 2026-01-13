namespace PromptShield.Abstractions.Exceptions;

/// <summary>
/// Exception thrown when input validation fails.
/// </summary>
public class ValidationException : PromptShieldException
{
    /// <summary>
    /// Gets the validation error code.
    /// </summary>
    public string ErrorCode { get; }

    /// <summary>
    /// Gets the validation errors that caused this exception.
    /// </summary>
    public IReadOnlyList<string> ValidationErrors { get; }

    /// <summary>
    /// Initializes a new instance of <see cref="ValidationException"/>.
    /// </summary>
    /// <param name="errorCode">The error code identifying the validation failure.</param>
    /// <param name="message">The error message.</param>
    public ValidationException(string errorCode, string message)
        : base(message)
    {
        ErrorCode = errorCode ?? throw new ArgumentNullException(nameof(errorCode));
        ValidationErrors = new[] { message };
    }

    /// <summary>
    /// Initializes a new instance of <see cref="ValidationException"/> with multiple errors.
    /// </summary>
    /// <param name="errorCode">The primary error code.</param>
    /// <param name="message">The error message.</param>
    /// <param name="validationErrors">The list of validation errors.</param>
    public ValidationException(string errorCode, string message, IReadOnlyList<string> validationErrors)
        : base(message)
    {
        ErrorCode = errorCode ?? throw new ArgumentNullException(nameof(errorCode));
        ValidationErrors = validationErrors ?? throw new ArgumentNullException(nameof(validationErrors));
    }

    /// <summary>
    /// Initializes a new instance of <see cref="ValidationException"/> with an inner exception.
    /// </summary>
    /// <param name="errorCode">The error code identifying the validation failure.</param>
    /// <param name="message">The error message.</param>
    /// <param name="innerException">The inner exception.</param>
    public ValidationException(string errorCode, string message, Exception innerException)
        : base(message, innerException)
    {
        ErrorCode = errorCode ?? throw new ArgumentNullException(nameof(errorCode));
        ValidationErrors = new[] { message };
    }
}
