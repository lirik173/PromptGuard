namespace PromptShield.Core.Patterns;

using System.Text.RegularExpressions;
using PromptShield.Abstractions.Detection;

/// <summary>
/// Represents a compiled regex pattern with timeout protection.
/// </summary>
internal sealed class CompiledPattern
{
    private readonly Regex _regex;
    private readonly TimeSpan _timeout;

    public DetectionPattern Pattern { get; }

    public CompiledPattern(DetectionPattern pattern, TimeSpan timeout)
    {
        Pattern = pattern ?? throw new ArgumentNullException(nameof(pattern));
        _timeout = timeout;

        _regex = new Regex(
            pattern.Pattern,
            RegexOptions.Compiled | RegexOptions.IgnoreCase,
            _timeout);
    }

    /// <summary>
    /// Tests if the pattern matches the input.
    /// </summary>
    /// <returns>Match result including timeout information.</returns>
    public PatternMatchResult TryMatch(string input)
    {
        ArgumentNullException.ThrowIfNull(input);

        try
        {
            return _regex.IsMatch(input)
                ? PatternMatchResult.Match()
                : PatternMatchResult.NoMatch();
        }
        catch (RegexMatchTimeoutException)
        {
            // Timeout is returned as a signal - the caller should treat this
            // as a suspicious indicator (potential ReDoS attempt)
            return PatternMatchResult.Timeout();
        }
    }

    /// <summary>
    /// Tests if the pattern matches the input (simple boolean version).
    /// </summary>
    /// <returns>True if match found, false otherwise (including timeout).</returns>
    /// <remarks>
    /// Use <see cref="TryMatch"/> if you need to distinguish between
    /// no-match and timeout scenarios.
    /// </remarks>
    public bool IsMatch(string input) => TryMatch(input).IsMatch;

    /// <summary>
    /// Finds all matches in the input.
    /// </summary>
    /// <param name="input">The input string to search.</param>
    /// <param name="timedOut">Set to true if the operation timed out.</param>
    /// <returns>Collection of matches, or empty if timeout occurred.</returns>
    public MatchCollection Matches(string input, out bool timedOut)
    {
        ArgumentNullException.ThrowIfNull(input);

        try
        {
            timedOut = false;
            return _regex.Matches(input);
        }
        catch (RegexMatchTimeoutException)
        {
            timedOut = true;
            return Regex.Matches(string.Empty, string.Empty);
        }
    }
}
