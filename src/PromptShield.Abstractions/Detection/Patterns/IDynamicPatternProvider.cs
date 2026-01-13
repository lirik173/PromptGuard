namespace PromptShield.Abstractions.Detection.Patterns;

/// <summary>
/// Interface for pattern providers that support runtime updates.
/// </summary>
/// <remarks>
/// Use this interface for patterns that need to be updated without restart,
/// such as patterns loaded from a database or external configuration.
/// </remarks>
public interface IDynamicPatternProvider : IPatternProvider
{
    /// <summary>
    /// Event raised when patterns are updated.
    /// </summary>
    event EventHandler<PatternsUpdatedEventArgs>? PatternsUpdated;

    /// <summary>
    /// Forces a refresh of patterns from the underlying source.
    /// </summary>
    Task RefreshAsync(CancellationToken cancellationToken = default);
}
