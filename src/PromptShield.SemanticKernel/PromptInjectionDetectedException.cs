using PromptShield.Abstractions.Analysis;

namespace PromptShield.SemanticKernel;

/// <summary>
/// Exception thrown when a prompt injection threat is detected by PromptShield filter.
/// </summary>
public sealed class PromptInjectionDetectedException : Exception
{
    /// <summary>
    /// Gets the analysis result containing threat details.
    /// </summary>
    public AnalysisResult Result { get; }

    /// <summary>
    /// Gets the OWASP LLM category of the detected threat.
    /// </summary>
    public string? OwaspCategory => Result.ThreatInfo?.OwaspCategory;

    /// <summary>
    /// Gets the severity of the detected threat.
    /// </summary>
    public ThreatSeverity? Severity => Result.ThreatInfo?.Severity;

    /// <summary>
    /// Gets the confidence score of the detection.
    /// </summary>
    public double Confidence => Result.Confidence;

    /// <summary>
    /// Initializes a new instance of the <see cref="PromptInjectionDetectedException"/> class.
    /// </summary>
    /// <param name="result">The analysis result containing threat details.</param>
    public PromptInjectionDetectedException(AnalysisResult result)
        : base(GetMessage(result))
    {
        Result = result ?? throw new ArgumentNullException(nameof(result));
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="PromptInjectionDetectedException"/> class.
    /// </summary>
    /// <param name="result">The analysis result containing threat details.</param>
    /// <param name="message">Custom message.</param>
    public PromptInjectionDetectedException(AnalysisResult result, string message)
        : base(message)
    {
        Result = result ?? throw new ArgumentNullException(nameof(result));
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="PromptInjectionDetectedException"/> class.
    /// </summary>
    /// <param name="result">The analysis result containing threat details.</param>
    /// <param name="message">Custom message.</param>
    /// <param name="innerException">The inner exception.</param>
    public PromptInjectionDetectedException(AnalysisResult result, string message, Exception innerException)
        : base(message, innerException)
    {
        Result = result ?? throw new ArgumentNullException(nameof(result));
    }

    private static string GetMessage(AnalysisResult result)
    {
        ArgumentNullException.ThrowIfNull(result);

        if (result.ThreatInfo == null)
        {
            return $"Potential prompt injection detected (AnalysisId: {result.AnalysisId}, Confidence: {result.Confidence:P0})";
        }

        return $"Prompt injection detected: {result.ThreatInfo.ThreatType} " +
               $"(AnalysisId: {result.AnalysisId}, " +
               $"OWASP: {result.ThreatInfo.OwaspCategory}, " +
               $"Confidence: {result.Confidence:P0}, " +
               $"Severity: {result.ThreatInfo.Severity})";
    }

    /// <summary>
    /// Gets the user-facing message that is safe to display.
    /// </summary>
    public string GetUserFacingMessage()
    {
        return Result.ThreatInfo?.UserFacingMessage
            ?? "Your request could not be processed due to security concerns. Please rephrase your message and try again.";
    }
}
