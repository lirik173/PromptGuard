namespace PromptShield.Abstractions.Configuration;

/// <summary>
/// Root configuration options for PromptShield.
/// </summary>
public sealed class PromptShieldOptions
{
    /// <summary>
    /// Configuration section name in appsettings.json.
    /// </summary>
    public const string SectionName = "PromptShield";

    /// <summary>
    /// Global confidence threshold for threat detection (0.0 - 1.0).
    /// </summary>
    public double ThreatThreshold { get; set; } = 0.75;

    /// <summary>
    /// Maximum allowed prompt length in characters.
    /// </summary>
    public int MaxPromptLength { get; set; } = 50_000;

    /// <summary>
    /// Whether to enable detailed breakdown in results.
    /// </summary>
    public bool IncludeBreakdown { get; set; } = true;

    /// <summary>
    /// Determines behavior when analysis encounters an unexpected error.
    /// Default is <see cref="FailureBehavior.FailClosed"/> for security.
    /// </summary>
    public FailureBehavior OnAnalysisError { get; set; } = FailureBehavior.FailClosed;

    /// <summary>
    /// Pattern matching layer configuration.
    /// </summary>
    public PatternMatchingOptions PatternMatching { get; set; } = new();

    /// <summary>
    /// Heuristic analysis layer configuration.
    /// </summary>
    public HeuristicOptions Heuristics { get; set; } = new();

    /// <summary>
    /// ML classification layer configuration.
    /// </summary>
    public MLClassificationOptions ML { get; set; } = new();

    /// <summary>
    /// Semantic analysis layer configuration.
    /// </summary>
    public SemanticAnalysisOptions SemanticAnalysis { get; set; } = new();

    /// <summary>
    /// Aggregation settings for combining layer results.
    /// </summary>
    public AggregationOptions Aggregation { get; set; } = new();

    /// <summary>
    /// Semantic Kernel integration specific options.
    /// </summary>
    public SemanticKernelIntegrationOptions SemanticKernel { get; set; } = new();

    /// <summary>
    /// Telemetry and observability configuration.
    /// </summary>
    public TelemetryOptions Telemetry { get; set; } = new();
}
