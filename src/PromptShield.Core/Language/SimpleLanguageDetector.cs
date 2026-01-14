using System.Collections.Frozen;
using System.Text.RegularExpressions;
using PromptShield.Abstractions.Analysis;

namespace PromptShield.Core.Language;

/// <summary>
/// Lightweight language detector based on Unicode script detection and word frequency analysis.
/// </summary>
/// <remarks>
/// <para>
/// This detector uses a two-phase approach:
/// <list type="number">
///   <item>Script detection: Identifies non-Latin scripts (Cyrillic, CJK, Arabic, etc.)</item>
///   <item>Word frequency: For Latin scripts, checks common English words</item>
/// </list>
/// </para>
/// <para>
/// For production deployments with high language diversity requirements,
/// consider using NTextCat, langdetect, or Azure Cognitive Services.
/// </para>
/// </remarks>
public sealed partial class SimpleLanguageDetector : ILanguageDetector
{
    /// <summary>
    /// Regex timeout to prevent ReDoS attacks.
    /// </summary>
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(50);

    /// <summary>
    /// Script detection patterns ordered by specificity.
    /// </summary>
    private static readonly (Regex Pattern, string LangCode, string ScriptCode, double BaseConfidence)[] ScriptPatterns =
    [
        // Specific language scripts
        (JapaneseKanaRegex(), "ja", "Jpan", 0.95),
        (KoreanHangulRegex(), "ko", "Kore", 0.95),
        (ThaiRegex(), "th", "Thai", 0.95),
        (HebrewRegex(), "he", "Hebr", 0.95),
        (ArabicRegex(), "ar", "Arab", 0.90),
        (GreekRegex(), "el", "Grek", 0.95),
        (DevanagariRegex(), "hi", "Deva", 0.90),
        
        // Multi-language scripts (language undetermined)
        (CyrillicRegex(), "und-Cyrl", "Cyrl", 0.85),
        (CjkIdeographsRegex(), "zh", "Hans", 0.85),
    ];

    /// <summary>
    /// Common English words for Latin script language identification.
    /// </summary>
    private static readonly FrozenSet<string> EnglishMarkers = FrozenSet.ToFrozenSet(
    [
        // Articles and determiners
        "the", "a", "an", "this", "that", "these", "those",
        // Pronouns
        "i", "you", "he", "she", "it", "we", "they", "me", "him", "her", "us", "them",
        // Verbs (common)
        "is", "are", "was", "were", "be", "been", "being",
        "have", "has", "had", "do", "does", "did",
        "will", "would", "could", "should", "can", "may", "might",
        // Prepositions
        "in", "on", "at", "to", "for", "with", "by", "from", "of",
        // Conjunctions
        "and", "but", "or", "if", "because", "although", "while",
        // Common words
        "not", "all", "what", "when", "where", "how", "why", "who",
        "your", "my", "our", "their", "his", "her", "its"
    ], StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Common German words (for future expansion).
    /// </summary>
    private static readonly FrozenSet<string> GermanMarkers = FrozenSet.ToFrozenSet(
    [
        "der", "die", "das", "und", "ist", "von", "mit", "auf", "für", "nicht",
        "sich", "auch", "als", "noch", "nach", "bei", "aus", "wenn", "nur", "werden"
    ], StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Common French words (for future expansion).
    /// </summary>
    private static readonly FrozenSet<string> FrenchMarkers = FrozenSet.ToFrozenSet(
    [
        "le", "la", "les", "de", "du", "des", "et", "est", "que", "qui",
        "dans", "pour", "pas", "sur", "avec", "ce", "une", "son", "mais", "nous"
    ], StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Common Spanish words (for future expansion).
    /// </summary>
    private static readonly FrozenSet<string> SpanishMarkers = FrozenSet.ToFrozenSet(
    [
        "el", "la", "los", "las", "de", "del", "que", "y", "en", "un",
        "es", "se", "no", "por", "con", "para", "como", "una", "su", "al"
    ], StringComparer.OrdinalIgnoreCase);

    /// <inheritdoc />
    public LanguageDetectionResult Detect(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return LanguageDetectionResult.Undetermined;
        }

        // Phase 1: Script-based detection (non-Latin scripts)
        var scriptResult = DetectByScript(text);
        if (scriptResult != null)
        {
            return scriptResult;
        }

        // Phase 2: Word frequency analysis for Latin script
        return DetectLatinLanguage(text);
    }

    /// <summary>
    /// Detects language based on Unicode script patterns.
    /// </summary>
    private static LanguageDetectionResult? DetectByScript(string text)
    {
        var textLength = text.Length;
        
        foreach (var (pattern, langCode, scriptCode, baseConfidence) in ScriptPatterns)
        {
            try
            {
                var matches = pattern.Matches(text);
                if (matches.Count == 0) continue;

                // Calculate what percentage of text uses this script
                var scriptCharCount = matches.Sum(m => m.Length);
                var scriptRatio = (double)scriptCharCount / textLength;

                // Need at least 10% of characters in this script to classify
                if (scriptRatio >= 0.10)
                {
                    // Confidence based on ratio and base confidence
                    var confidence = Math.Min(baseConfidence * (0.5 + scriptRatio), 0.99);
                    var isReliable = confidence >= 0.7 && scriptRatio >= 0.3;

                    return new LanguageDetectionResult(
                        langCode.StartsWith("und-") ? "und" : langCode,
                        scriptCode,
                        confidence,
                        isReliable);
                }
            }
            catch (RegexMatchTimeoutException)
            {
                // Continue with next pattern on timeout
            }
        }

        return null;
    }

    /// <summary>
    /// Detects language for Latin-script text using word frequency.
    /// </summary>
    private static LanguageDetectionResult DetectLatinLanguage(string text)
    {
        var words = text.ToLowerInvariant()
            .Split([' ', '\t', '\n', '\r', '.', ',', '!', '?', ';', ':', '"', '\'', '(', ')', '[', ']', '{', '}'],
                   StringSplitOptions.RemoveEmptyEntries);

        if (words.Length == 0)
        {
            return LanguageDetectionResult.Undetermined;
        }

        // Count marker words for each language
        var englishCount = words.Count(EnglishMarkers.Contains);
        var germanCount = words.Count(GermanMarkers.Contains);
        var frenchCount = words.Count(FrenchMarkers.Contains);
        var spanishCount = words.Count(SpanishMarkers.Contains);

        // Calculate ratios (use min to avoid bias from very short texts)
        var sampleSize = Math.Min(words.Length, 100);
        var englishRatio = (double)englishCount / sampleSize;
        var germanRatio = (double)germanCount / sampleSize;
        var frenchRatio = (double)frenchCount / sampleSize;
        var spanishRatio = (double)spanishCount / sampleSize;

        // Find best match
        var maxRatio = Math.Max(Math.Max(englishRatio, germanRatio), Math.Max(frenchRatio, spanishRatio));

        if (maxRatio < 0.05)
        {
            // No clear language signal - might be another Latin-script language
            return new LanguageDetectionResult("und", "Latn", 0.3, false);
        }

        // Determine language with highest marker ratio
        string langCode;
        if (englishRatio >= maxRatio * 0.9) // English or close
        {
            langCode = "en";
        }
        else if (germanRatio == maxRatio)
        {
            langCode = "de";
        }
        else if (frenchRatio == maxRatio)
        {
            langCode = "fr";
        }
        else if (spanishRatio == maxRatio)
        {
            langCode = "es";
        }
        else
        {
            langCode = "en"; // Default to English for Latin script
        }

        // Calculate confidence based on ratio and distinctiveness
        var confidence = Math.Min(0.5 + maxRatio * 2, 0.95);
        var isReliable = confidence >= 0.7 && words.Length >= 10;

        return new LanguageDetectionResult(langCode, "Latn", confidence, isReliable);
    }

    #region Source-Generated Regex Patterns

    [GeneratedRegex(@"[\u3040-\u309F\u30A0-\u30FF]", RegexOptions.None, matchTimeoutMilliseconds: 50)]
    private static partial Regex JapaneseKanaRegex();

    [GeneratedRegex(@"[\uAC00-\uD7AF\u1100-\u11FF]", RegexOptions.None, matchTimeoutMilliseconds: 50)]
    private static partial Regex KoreanHangulRegex();

    [GeneratedRegex(@"[\u0E00-\u0E7F]", RegexOptions.None, matchTimeoutMilliseconds: 50)]
    private static partial Regex ThaiRegex();

    [GeneratedRegex(@"[\u0590-\u05FF]", RegexOptions.None, matchTimeoutMilliseconds: 50)]
    private static partial Regex HebrewRegex();

    [GeneratedRegex(@"[\u0600-\u06FF\u0750-\u077F]", RegexOptions.None, matchTimeoutMilliseconds: 50)]
    private static partial Regex ArabicRegex();

    [GeneratedRegex(@"[\u0370-\u03FF\u1F00-\u1FFF]", RegexOptions.None, matchTimeoutMilliseconds: 50)]
    private static partial Regex GreekRegex();

    [GeneratedRegex(@"[\u0900-\u097F]", RegexOptions.None, matchTimeoutMilliseconds: 50)]
    private static partial Regex DevanagariRegex();

    [GeneratedRegex(@"[\u0400-\u04FF\u0500-\u052F]", RegexOptions.None, matchTimeoutMilliseconds: 50)]
    private static partial Regex CyrillicRegex();

    [GeneratedRegex(@"[\u4E00-\u9FFF\u3400-\u4DBF]", RegexOptions.None, matchTimeoutMilliseconds: 50)]
    private static partial Regex CjkIdeographsRegex();

    #endregion
}
