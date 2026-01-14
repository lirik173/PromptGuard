using System.Diagnostics;
using PromptShield.Abstractions.Configuration;

namespace PromptShield.Core.Telemetry;

/// <summary>
/// Helper class for zero-overhead telemetry checks when no collector is configured.
/// </summary>
internal static class TelemetryHelper
{
    /// <summary>
    /// Checks if telemetry is enabled and collectors are available.
    /// </summary>
    /// <param name="options">Telemetry options.</param>
    /// <returns>True if telemetry should be emitted.</returns>
    public static bool ShouldEmitTelemetry(TelemetryOptions options)
    {
        if (!options.EnableMetrics && !options.EnableTracing && !options.EnableLogging)
        {
            return false;
        }

        // Note: ActivitySource.Listeners is not available in .NET 8
        // The HasListeners() method is used instead in StartActivity()

        return true;
    }

    /// <summary>
    /// Creates an activity for tracing if tracing is enabled.
    /// </summary>
    /// <param name="name">Activity name.</param>
    /// <param name="options">Telemetry options.</param>
    /// <returns>Activity if tracing is enabled, null otherwise.</returns>
    public static Activity? StartActivity(string name, TelemetryOptions options)
    {
        if (!options.EnableTracing || !PromptShieldTelemetry.ActivitySource.HasListeners())
        {
            return null;
        }

        return PromptShieldTelemetry.ActivitySource.StartActivity(name);
    }
}
