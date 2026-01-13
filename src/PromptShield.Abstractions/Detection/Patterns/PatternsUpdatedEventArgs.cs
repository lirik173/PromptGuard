namespace PromptShield.Abstractions.Detection.Patterns;

/// <summary>
/// Event arguments for pattern update events.
/// </summary>
public sealed class PatternsUpdatedEventArgs : EventArgs
{
    /// <summary>
    /// Names of patterns that were added.
    /// </summary>
    public required IReadOnlyList<string> AddedPatterns { get; init; }

    /// <summary>
    /// Names of patterns that were removed.
    /// </summary>
    public required IReadOnlyList<string> RemovedPatterns { get; init; }

    /// <summary>
    /// Names of patterns that were modified.
    /// </summary>
    public required IReadOnlyList<string> ModifiedPatterns { get; init; }
}
