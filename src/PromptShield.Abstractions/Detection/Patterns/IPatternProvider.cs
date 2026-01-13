namespace PromptShield.Abstractions.Detection.Patterns;

using PromptShield.Abstractions.Detection;

/// <summary>
/// Interface for providing detection patterns to the Pattern Matching layer.
/// Implement this interface to add custom patterns without modifying the library.
/// </summary>
/// <remarks>
/// Multiple pattern providers can be registered. All patterns from all providers
/// are combined during analysis. Built-in patterns are provided by the default
/// <see cref="IBuiltInPatternProvider"/> implementation.
/// </remarks>
public interface IPatternProvider
{
    /// <summary>
    /// Gets all detection patterns from this provider.
    /// </summary>
    /// <returns>Collection of detection patterns.</returns>
    /// <remarks>
    /// This method is called once during initialization. Patterns are compiled
    /// and cached for performance. To update patterns, restart the application
    /// or use <see cref="IDynamicPatternProvider"/> for runtime updates.
    /// </remarks>
    IEnumerable<DetectionPattern> GetPatterns();

    /// <summary>
    /// Gets the unique name of this pattern provider.
    /// </summary>
    /// <remarks>Used for logging and diagnostics.</remarks>
    string ProviderName { get; }
}
