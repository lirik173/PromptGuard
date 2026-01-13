namespace PromptShield.Abstractions.Configuration;

/// <summary>
/// Configuration options for Semantic Kernel integration.
/// </summary>
public sealed class SemanticKernelIntegrationOptions
{
    /// <summary>
    /// Determines behavior when prompt analysis encounters an error.
    /// Default is <see cref="FailureBehavior.FailClosed"/> for security.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="FailureBehavior.FailClosed"/>: Blocks the prompt if analysis fails.
    /// This is the secure default and recommended for production environments.
    /// </para>
    /// <para>
    /// <see cref="FailureBehavior.FailOpen"/>: Allows the prompt if analysis fails.
    /// Use only when availability is more critical than security, such as in
    /// development environments or non-sensitive applications.
    /// </para>
    /// </remarks>
    public FailureBehavior OnAnalysisError { get; set; } = FailureBehavior.FailClosed;

    /// <summary>
    /// Whether to skip analysis for empty or whitespace-only prompts.
    /// Default is true.
    /// </summary>
    public bool SkipEmptyPrompts { get; set; } = true;

    /// <summary>
    /// Whether to include function metadata in analysis request.
    /// Default is true.
    /// </summary>
    public bool IncludeFunctionMetadata { get; set; } = true;
}
