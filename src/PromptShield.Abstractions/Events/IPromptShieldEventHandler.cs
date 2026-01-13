namespace PromptShield.Abstractions.Events;

/// <summary>
/// Interface for handling PromptShield lifecycle events.
/// Implement this interface for custom actions on analysis events.
/// </summary>
/// <remarks>
/// Event handlers are invoked synchronously in the analysis pipeline.
/// Keep handlers lightweight to avoid impacting latency.
/// Multiple handlers can be registered; they are invoked in registration order.
/// </remarks>
public interface IPromptShieldEventHandler
{
    /// <summary>
    /// Called when analysis starts.
    /// </summary>
    /// <param name="event">Event containing analysis context.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task OnAnalysisStartedAsync(
        AnalysisStartedEvent @event,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Called when a threat is detected.
    /// </summary>
    /// <param name="event">Event containing threat details.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <remarks>
    /// This is called before OnAnalysisCompletedAsync.
    /// Use this for immediate threat response actions.
    /// </remarks>
    Task OnThreatDetectedAsync(
        ThreatDetectedEvent @event,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Called when analysis completes.
    /// </summary>
    /// <param name="event">Event containing the analysis result.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task OnAnalysisCompletedAsync(
        AnalysisCompletedEvent @event,
        CancellationToken cancellationToken = default);
}
