using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace PromptShield.Core.Telemetry;

/// <summary>
/// Static telemetry instrumentation for PromptShield using OpenTelemetry.
/// </summary>
public static class PromptShieldTelemetry
{
    /// <summary>
    /// Meter name for PromptShield metrics.
    /// </summary>
    private const string MeterName = "PromptShield";

    /// <summary>
    /// Activity source name for PromptShield traces.
    /// </summary>
    private const string ActivitySourceName = "PromptShield";

    /// <summary>
    /// Meter for emitting metrics.
    /// </summary>
    public static readonly Meter Meter = new(MeterName, "1.0.0");

    /// <summary>
    /// Activity source for emitting traces.
    /// </summary>
    public static readonly ActivitySource ActivitySource = new(ActivitySourceName, "1.0.0");

    /// <summary>
    /// Counter for total analysis operations.
    /// </summary>
    public static readonly Counter<long> AnalysisTotal = Meter.CreateCounter<long>(
        "promptshield.analysis.total",
        "count",
        "Total number of prompt analyses performed");

    /// <summary>
    /// Counter for detected threats.
    /// </summary>
    public static readonly Counter<long> ThreatsDetected = Meter.CreateCounter<long>(
        "promptshield.threats.detected",
        "count",
        "Total number of threats detected");

    /// <summary>
    /// Histogram for analysis latency.
    /// </summary>
    public static readonly Histogram<double> AnalysisLatency = Meter.CreateHistogram<double>(
        "promptshield.analysis.latency",
        "ms",
        "Analysis latency in milliseconds");

    /// <summary>
    /// Histogram for prompt length.
    /// </summary>
    public static readonly Histogram<long> PromptLength = Meter.CreateHistogram<long>(
        "promptshield.prompt.length",
        "chars",
        "Length of analyzed prompts in characters");

    /// <summary>
    /// Counter for analysis errors.
    /// </summary>
    public static readonly Counter<long> AnalysisErrors = Meter.CreateCounter<long>(
        "promptshield.analysis.errors",
        "count",
        "Total number of analysis errors");
}
