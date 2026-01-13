namespace PromptShield.Core.Patterns;

/// <summary>
/// Result of a pattern match attempt.
/// </summary>
internal readonly struct PatternMatchResult
{
    /// <summary>
    /// Whether the pattern matched the input.
    /// </summary>
    public bool IsMatch { get; }

    /// <summary>
    /// Whether a timeout occurred during pattern matching.
    /// </summary>
    public bool TimedOut { get; }

    /// <summary>
    /// Creates a successful match result.
    /// </summary>
    public static PatternMatchResult Match() => new(isMatch: true, timedOut: false);

    /// <summary>
    /// Creates a no-match result.
    /// </summary>
    public static PatternMatchResult NoMatch() => new(isMatch: false, timedOut: false);

    /// <summary>
    /// Creates a timeout result.
    /// </summary>
    public static PatternMatchResult Timeout() => new(isMatch: false, timedOut: true);

    private PatternMatchResult(bool isMatch, bool timedOut)
    {
        IsMatch = isMatch;
        TimedOut = timedOut;
    }
}
