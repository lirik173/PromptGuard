namespace PromptShield.Abstractions.Configuration;

/// <summary>
/// Semantic analysis layer options.
/// </summary>
/// <remarks>
/// This layer uses an external LLM endpoint to perform deep semantic analysis
/// of prompts for potential injection attacks. Configure with either Azure OpenAI
/// or standard OpenAI API endpoints.
/// </remarks>
public sealed class SemanticAnalysisOptions
{
    /// <summary>
    /// Whether semantic analysis is enabled (requires LLM endpoint).
    /// </summary>
    public bool Enabled { get; set; } = false;

    /// <summary>
    /// Azure OpenAI or OpenAI endpoint URL.
    /// For Azure: https://{resource}.openai.azure.com
    /// For OpenAI: https://api.openai.com
    /// </summary>
    public string? Endpoint { get; set; }

    /// <summary>
    /// Model deployment name (for Azure OpenAI) or model name (for OpenAI).
    /// Examples: "gpt-4", "gpt-4-turbo", "gpt-3.5-turbo"
    /// </summary>
    public string? DeploymentName { get; set; }

    /// <summary>
    /// API key for authentication.
    /// For Azure OpenAI: Use the API key from Azure portal.
    /// For OpenAI: Use the API key from OpenAI dashboard.
    /// </summary>
    public string? ApiKey { get; set; }

    /// <summary>
    /// Azure OpenAI API version. Only used for Azure endpoints.
    /// </summary>
    public string? ApiVersion { get; set; } = "2024-08-01-preview";

    /// <summary>
    /// Confidence threshold for threat detection (0.0 to 1.0).
    /// Prompts with confidence above this threshold are flagged as threats.
    /// </summary>
    public double Threshold { get; set; } = 0.7;

    /// <summary>
    /// Maximum number of characters to send to the LLM for analysis.
    /// Longer prompts will be truncated.
    /// </summary>
    public int MaxInputLength { get; set; } = 8000;

    /// <summary>
    /// Request timeout in seconds.
    /// </summary>
    public int TimeoutSeconds { get; set; } = 30;

    /// <summary>
    /// Maximum number of retry attempts for transient failures.
    /// </summary>
    public int MaxRetries { get; set; } = 2;

    /// <summary>
    /// Base delay in milliseconds for retry backoff.
    /// Actual delay uses exponential backoff with jitter.
    /// </summary>
    public int RetryBaseDelayMs { get; set; } = 500;

    /// <summary>
    /// Maximum number of concurrent requests to the LLM endpoint.
    /// </summary>
    public int MaxConcurrentRequests { get; set; } = 5;

    /// <summary>
    /// Rate limiter token bucket capacity.
    /// </summary>
    public int RateLimitTokens { get; set; } = 10;

    /// <summary>
    /// Rate limiter replenishment period in seconds.
    /// </summary>
    public int RateLimitPeriodSeconds { get; set; } = 1;

    /// <summary>
    /// Maximum number of requests that can be queued when rate limited.
    /// </summary>
    public int MaxQueuedRequests { get; set; } = 5;
}
