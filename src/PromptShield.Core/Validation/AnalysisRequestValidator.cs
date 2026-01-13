namespace PromptShield.Core.Validation;

using PromptShield.Abstractions.Analysis;

/// <summary>
/// Validates <see cref="AnalysisRequest"/> objects before processing.
/// </summary>
public sealed class AnalysisRequestValidator
{
    private readonly int _maxPromptLength;

    // Error codes
    private const string PromptRequiredCode = "PROMPT_REQUIRED";
    private const string PromptTooLongCode = "PROMPT_TOO_LONG";
    private const string PromptInvalidCharsCode = "PROMPT_INVALID_CHARS";
    private const string PromptSuspiciousCharsCode = "PROMPT_SUSPICIOUS_CHARS";

    /// <summary>
    /// Characters that are never allowed in prompts (security risk).
    /// </summary>
    private static readonly char[] ForbiddenChars = { '\0' };

    /// <summary>
    /// Suspicious Unicode characters that may indicate manipulation attempts.
    /// These are flagged as warnings but not rejected.
    /// </summary>
    private static readonly char[] SuspiciousChars =
    {
        '\u200B', '\u200C', '\u200D', '\uFEFF',           // Zero-width characters
        '\u202A', '\u202B', '\u202C', '\u202D', '\u202E', // Bidirectional overrides
        '\u2066', '\u2067', '\u2068', '\u2069',           // Isolate characters
        '\u00AD',                                          // Soft hyphen
        '\u034F',                                          // Combining grapheme joiner
        '\u115F', '\u1160',                                // Hangul filler
        '\u17B4', '\u17B5',                                // Khmer inherent vowels
        '\u180E',                                          // Mongolian vowel separator
        '\u2000', '\u2001', '\u2002', '\u2003', '\u2004',  // Various width spaces
        '\u2005', '\u2006', '\u2007', '\u2008', '\u2009',
        '\u200A', '\u2028', '\u2029', '\u202F', '\u205F',
        '\u3000',                                          // Ideographic space
        '\uFFA0',                                          // Halfwidth hangul filler
    };

    public AnalysisRequestValidator(int maxPromptLength = 50_000)
    {
        if (maxPromptLength <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxPromptLength), "Max prompt length must be positive.");
        }
        _maxPromptLength = maxPromptLength;
    }

    /// <summary>
    /// Validates an analysis request.
    /// </summary>
    /// <param name="request">The request to validate.</param>
    /// <returns>Validation result with errors if validation fails.</returns>
    /// <exception cref="ArgumentNullException">When request is null.</exception>
    public ValidationResult Validate(AnalysisRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        var errors = new List<string>();
        var warnings = new List<string>();

        // Validate prompt is not null or empty
        if (string.IsNullOrWhiteSpace(request.Prompt))
        {
            errors.Add($"{PromptRequiredCode}: Prompt is required and cannot be null or empty.");
            return new ValidationResult(false, errors, warnings);
        }

        // Validate prompt length
        if (request.Prompt.Length > _maxPromptLength)
        {
            errors.Add($"{PromptTooLongCode}: Prompt length ({request.Prompt.Length:N0}) exceeds maximum allowed length ({_maxPromptLength:N0}).");
        }

        // Validate no forbidden characters (hard fail)
        var forbiddenFound = FindForbiddenCharacters(request.Prompt);
        if (forbiddenFound.Count > 0)
        {
            var charDescriptions = string.Join(", ", forbiddenFound.Select(c => $"U+{(int)c:X4}"));
            errors.Add($"{PromptInvalidCharsCode}: Prompt contains forbidden characters: {charDescriptions}");
        }

        // Check for suspicious characters (warning, doesn't fail)
        var suspiciousFound = FindSuspiciousCharacters(request.Prompt);
        if (suspiciousFound.Count > 0)
        {
            var charDescriptions = string.Join(", ", suspiciousFound.Take(5).Select(c => $"U+{(int)c:X4}"));
            var suffix = suspiciousFound.Count > 5 ? $" and {suspiciousFound.Count - 5} more" : "";
            warnings.Add($"{PromptSuspiciousCharsCode}: Prompt contains suspicious Unicode characters: {charDescriptions}{suffix}");
        }

        // Validate system prompt if provided
        if (!string.IsNullOrEmpty(request.SystemPrompt))
        {
            if (request.SystemPrompt.Length > _maxPromptLength)
            {
                errors.Add($"{PromptTooLongCode}: System prompt length ({request.SystemPrompt.Length:N0}) exceeds maximum allowed length ({_maxPromptLength:N0}).");
            }
        }

        return new ValidationResult(errors.Count == 0, errors, warnings);
    }

    private static List<char> FindForbiddenCharacters(string text)
    {
        var found = new List<char>();
        foreach (var c in text)
        {
            if (Array.IndexOf(ForbiddenChars, c) >= 0 && !found.Contains(c))
            {
                found.Add(c);
            }
        }
        return found;
    }

    private static List<char> FindSuspiciousCharacters(string text)
    {
        var found = new List<char>();
        foreach (var c in text)
        {
            if (Array.IndexOf(SuspiciousChars, c) >= 0 && !found.Contains(c))
            {
                found.Add(c);
            }
        }
        return found;
    }

    /// <summary>
    /// Result of validation including errors and warnings.
    /// </summary>
    public sealed class ValidationResult
    {
        /// <summary>
        /// Whether the validation passed (no errors).
        /// </summary>
        public bool IsValid { get; }

        /// <summary>
        /// Validation errors that prevent processing.
        /// </summary>
        public IReadOnlyList<string> Errors { get; }

        /// <summary>
        /// Validation warnings that don't prevent processing but indicate concerns.
        /// </summary>
        public IReadOnlyList<string> Warnings { get; }

        /// <summary>
        /// Whether any warnings were raised.
        /// </summary>
        public bool HasWarnings => Warnings.Count > 0;

        public ValidationResult(bool isValid, List<string> errors, List<string>? warnings = null)
        {
            IsValid = isValid;
            Errors = errors;
            Warnings = warnings ?? new List<string>();
        }
    }
}
