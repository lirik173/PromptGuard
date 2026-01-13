using PromptShield.Abstractions.Configuration;

namespace PromptShield.AspNetCore;

/// <summary>
/// Configuration options for PromptShield ASP.NET Core middleware.
/// </summary>
public sealed class PromptShieldMiddlewareOptions
{
    /// <summary>
    /// Paths to protect with prompt analysis.
    /// If empty, all paths are protected.
    /// Supports glob patterns like "/api/chat/*".
    /// </summary>
    /// <example>
    /// <code>
    /// options.ProtectedPaths = new[] { "/api/chat", "/api/completion/*" };
    /// </code>
    /// </example>
    public IReadOnlyList<string> ProtectedPaths { get; set; } = Array.Empty<string>();

    /// <summary>
    /// Paths to exclude from prompt analysis.
    /// Takes precedence over <see cref="ProtectedPaths"/>.
    /// </summary>
    /// <example>
    /// <code>
    /// options.ExcludedPaths = new[] { "/health", "/metrics" };
    /// </code>
    /// </example>
    public IReadOnlyList<string> ExcludedPaths { get; set; } = new[] { "/health", "/healthz", "/ready", "/metrics" };

    /// <summary>
    /// JSON path to the prompt field in the request body.
    /// Default is "prompt".
    /// </summary>
    /// <example>
    /// For a request body like { "message": { "content": "hello" } },
    /// set to "message.content".
    /// </example>
    public string PromptJsonPath { get; set; } = "prompt";

    /// <summary>
    /// Alternative JSON paths to check if the primary path is not found.
    /// </summary>
    public IReadOnlyList<string> AlternativePromptPaths { get; set; } = new[]
    {
        "message",
        "content",
        "text",
        "input",
        "query",
        "messages[*].content"
    };

    /// <summary>
    /// HTTP methods to analyze. Default is POST and PUT.
    /// </summary>
    public IReadOnlyList<string> HttpMethods { get; set; } = new[] { "POST", "PUT", "PATCH" };

    /// <summary>
    /// Determines behavior when analysis fails due to errors.
    /// Default is <see cref="FailureBehavior.FailClosed"/> for security.
    /// </summary>
    public FailureBehavior OnAnalysisError { get; set; } = FailureBehavior.FailClosed;

    /// <summary>
    /// HTTP status code to return when a threat is detected.
    /// Default is 400 Bad Request.
    /// </summary>
    public int ThreatStatusCode { get; set; } = 400;

    /// <summary>
    /// Whether to include analysis details in the error response.
    /// Default is false for security (doesn't leak detection internals).
    /// </summary>
    public bool IncludeAnalysisDetailsInResponse { get; set; } = false;

    /// <summary>
    /// Maximum request body size to buffer for analysis.
    /// Default is 1MB.
    /// </summary>
    public int MaxRequestBodySize { get; set; } = 1024 * 1024;

    /// <summary>
    /// Content types to analyze. Others are skipped.
    /// </summary>
    public IReadOnlyList<string> ContentTypesToAnalyze { get; set; } = new[]
    {
        "application/json",
        "text/plain",
        "text/json"
    };

    /// <summary>
    /// Custom header name to look for the analysis ID in responses.
    /// </summary>
    public string AnalysisIdHeader { get; set; } = "X-PromptShield-AnalysisId";
}
