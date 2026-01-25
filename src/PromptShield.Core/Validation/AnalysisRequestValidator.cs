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

        List<string> errors = [];
        List<string> warnings = [];

        if (string.IsNullOrWhiteSpace(request.Prompt))
        {
            errors.Add($"{PromptRequiredCode}: Prompt is required and cannot be null or empty.");
            return new ValidationResult(false, errors, warnings);
        }

        ValidateLength(request.Prompt, "Prompt", errors);
        ValidateCharacters(request.Prompt, errors, warnings);
        
        if (!string.IsNullOrEmpty(request.SystemPrompt))
            ValidateLength(request.SystemPrompt, "System prompt", errors);

        return new ValidationResult(errors.Count == 0, errors, warnings);
    }

    private void ValidateLength(string text, string fieldName, List<string> errors)
    {
        if (text.Length > _maxPromptLength)
        {
            errors.Add($"{PromptTooLongCode}: {fieldName} length ({text.Length:N0}) exceeds maximum allowed length ({_maxPromptLength:N0}).");
        }
    }

    private static void ValidateCharacters(string text, List<string> errors, List<string> warnings)
    {
        var forbiddenFound = FindCharactersIn(text, ForbiddenChars);
        if (forbiddenFound.Count > 0)
        {
            errors.Add($"{PromptInvalidCharsCode}: Prompt contains forbidden characters: {FormatCharList(forbiddenFound)}");
        }

        var suspiciousFound = FindCharactersIn(text, SuspiciousChars);
        if (suspiciousFound.Count > 0)
        {
            var charDescriptions = FormatCharList(suspiciousFound.Take(5));
            var suffix = suspiciousFound.Count > 5 ? $" and {suspiciousFound.Count - 5} more" : "";
            warnings.Add($"{PromptSuspiciousCharsCode}: Prompt contains suspicious Unicode characters: {charDescriptions}{suffix}");
        }
    }

    private static List<char> FindCharactersIn(string text, char[] targetChars)
    {
        HashSet<char> found = [];
        foreach (var c in text)
        {
            if (Array.IndexOf(targetChars, c) >= 0)
                found.Add(c);
        }
        return [.. found];
    }

    private static string FormatCharList(IEnumerable<char> chars)
        => string.Join(", ", chars.Select(c => $"U+{(int)c:X4}"));

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
            Warnings = warnings ?? [];
        }
    }
}
