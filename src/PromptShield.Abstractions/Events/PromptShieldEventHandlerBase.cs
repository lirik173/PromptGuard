namespace PromptShield.Abstractions.Events;

/// <summary>
/// Base class for event handlers with no-op default implementations.
/// </summary>
/// <remarks>
/// Inherit from this class to only implement the events you need.
/// </remarks>
public abstract class PromptShieldEventHandlerBase : IPromptShieldEventHandler
{
    /// <inheritdoc />
    public virtual Task OnAnalysisStartedAsync(
        AnalysisStartedEvent @event,
        CancellationToken cancellationToken = default) => Task.CompletedTask;

    /// <inheritdoc />
    public virtual Task OnThreatDetectedAsync(
        ThreatDetectedEvent @event,
        CancellationToken cancellationToken = default) => Task.CompletedTask;

    /// <inheritdoc />
    public virtual Task OnAnalysisCompletedAsync(
        AnalysisCompletedEvent @event,
        CancellationToken cancellationToken = default) => Task.CompletedTask;
}
