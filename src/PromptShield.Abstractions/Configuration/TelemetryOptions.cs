namespace PromptShield.Abstractions.Configuration;

/// <summary>
/// Telemetry configuration options.
/// </summary>
public sealed class TelemetryOptions
{
    /// <summary>
    /// Whether to emit OpenTelemetry metrics.
    /// </summary>
    public bool EnableMetrics { get; set; } = true;
    
    /// <summary>
    /// Whether to emit OpenTelemetry traces.
    /// </summary>
    public bool EnableTracing { get; set; } = true;
    
    /// <summary>
    /// Whether to emit structured logs.
    /// </summary>
    public bool EnableLogging { get; set; } = true;
    
    /// <summary>
    /// Whether to include prompt content in logs (security consideration).
    /// </summary>
    public bool LogPromptContent { get; set; } = false;
}
