using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;

namespace PromptShield.Core.ML;

/// <summary>
/// Extracts numerical features from text for ML-based prompt injection detection.
/// Combines statistical, lexical, and structural features into a feature vector.
/// </summary>
/// <remarks>
/// Feature extraction is designed to capture:
/// - Statistical properties (length, entropy, character distribution)
/// - Lexical signals (keyword density, n-gram patterns)
/// - Structural anomalies (delimiters, encoding markers, role markers)
/// - Semantic indicators (command patterns, persona switching)
/// </remarks>
internal sealed partial class FeatureExtractor
{
    /// <summary>
    /// Total number of features extracted.
    /// </summary>
    public const int FeatureCount = 48;

    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(100);

    // Keyword sets for lexical analysis
    private static readonly HashSet<string> InjectionKeywords = new(StringComparer.OrdinalIgnoreCase)
    {
        "ignore", "forget", "disregard", "override", "bypass", "skip",
        "jailbreak", "dan", "developer mode", "sudo", "admin",
        "system prompt", "instructions", "previous", "above"
    };

    private static readonly HashSet<string> CommandKeywords = new(StringComparer.OrdinalIgnoreCase)
    {
        "execute", "run", "eval", "print", "output", "display",
        "show", "reveal", "tell", "repeat", "write", "generate"
    };

    private static readonly HashSet<string> RoleKeywords = new(StringComparer.OrdinalIgnoreCase)
    {
        "act as", "pretend", "roleplay", "you are", "behave as",
        "simulate", "imagine", "persona", "character", "assistant"
    };

    private static readonly char[] Delimiters = ['#', '=', '-', '*', '_', '|', '/', '\\', '<', '>', '[', ']', '{', '}'];
    private static readonly char[] Whitespace = [' ', '\t', '\n', '\r'];

    /// <summary>
    /// Extracts all features from the given text.
    /// </summary>
    /// <param name="text">Text to extract features from.</param>
    /// <returns>Feature vector of length <see cref="FeatureCount"/>.</returns>
    public float[] ExtractFeatures(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        var features = new float[FeatureCount];
        var index = 0;

        // Statistical features (0-11)
        ExtractStatisticalFeatures(text, features, ref index);

        // Character distribution features (12-23)
        ExtractCharacterFeatures(text, features, ref index);

        // Lexical features (24-35)
        ExtractLexicalFeatures(text, features, ref index);

        // Structural features (36-47)
        ExtractStructuralFeatures(text, features, ref index);

        return features;
    }

    /// <summary>
    /// Extracts features and returns them as a span for zero-allocation scenarios.
    /// </summary>
    public void ExtractFeaturesInto(string text, Span<float> destination)
    {
        if (destination.Length < FeatureCount)
            throw new ArgumentException($"Destination must have at least {FeatureCount} elements", nameof(destination));

        ArgumentNullException.ThrowIfNull(text);

        var index = 0;
        var array = destination.ToArray(); // Convert for ref operations

        ExtractStatisticalFeatures(text, array, ref index);
        ExtractCharacterFeatures(text, array, ref index);
        ExtractLexicalFeatures(text, array, ref index);
        ExtractStructuralFeatures(text, array, ref index);

        array.CopyTo(destination);
    }

    #region Statistical Features (0-11)

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void ExtractStatisticalFeatures(string text, float[] features, ref int index)
    {
        var length = text.Length;

        // Feature 0: Normalized length (log scale)
        features[index++] = length > 0 ? (float)Math.Log10(length + 1) / 5f : 0f;

        // Feature 1: Word count (normalized)
        var words = text.Split(Whitespace, StringSplitOptions.RemoveEmptyEntries);
        var wordCount = words.Length;
        features[index++] = Math.Min(wordCount / 500f, 1f);

        // Feature 2: Average word length
        var avgWordLength = wordCount > 0 ? words.Average(w => w.Length) : 0;
        features[index++] = (float)Math.Min(avgWordLength / 15.0, 1.0);

        // Feature 3: Character entropy (Shannon entropy)
        features[index++] = CalculateEntropy(text);

        // Feature 4: Line count (normalized)
        var lineCount = text.Count(c => c == '\n') + 1;
        features[index++] = Math.Min(lineCount / 100f, 1f);

        // Feature 5: Average line length
        var avgLineLength = (float)length / lineCount;
        features[index++] = Math.Min(avgLineLength / 200f, 1f);

        // Feature 6: Unique word ratio
        var uniqueWords = words.Distinct(StringComparer.OrdinalIgnoreCase).Count();
        features[index++] = wordCount > 0 ? (float)uniqueWords / wordCount : 0f;

        // Feature 7: Sentence count (normalized)
        var sentenceEnders = text.Count(c => c == '.' || c == '!' || c == '?');
        features[index++] = Math.Min(sentenceEnders / 50f, 1f);

        // Feature 8: Average sentence length (words per sentence)
        var avgSentenceLength = sentenceEnders > 0 ? (float)wordCount / sentenceEnders : wordCount;
        features[index++] = Math.Min(avgSentenceLength / 30f, 1f);

        // Feature 9: Whitespace ratio
        var whitespaceCount = text.Count(char.IsWhiteSpace);
        features[index++] = length > 0 ? (float)whitespaceCount / length : 0f;

        // Feature 10: Token diversity (unique trigrams ratio)
        var trigramDiversity = CalculateTrigramDiversity(text);
        features[index++] = trigramDiversity;

        // Feature 11: Compression ratio estimate (repetitiveness)
        features[index++] = EstimateCompressionRatio(text);
    }

    private static float CalculateEntropy(string text)
    {
        if (string.IsNullOrEmpty(text))
            return 0f;

        var frequency = new Dictionary<char, int>(128);
        foreach (var c in text)
        {
            frequency[c] = frequency.GetValueOrDefault(c, 0) + 1;
        }

        var entropy = 0.0;
        var length = text.Length;

        foreach (var count in frequency.Values)
        {
            var probability = (double)count / length;
            if (probability > 0)
            {
                entropy -= probability * Math.Log2(probability);
            }
        }

        // Normalize to 0-1 range (max entropy for ASCII is ~7 bits)
        return (float)Math.Min(entropy / 7.0, 1.0);
    }

    private static float CalculateTrigramDiversity(string text)
    {
        if (text.Length < 3)
            return 0f;

        var trigrams = new HashSet<string>(text.Length - 2);
        for (var i = 0; i < text.Length - 2; i++)
        {
            trigrams.Add(text.Substring(i, 3));
        }

        var maxPossible = Math.Min(text.Length - 2, 26 * 26 * 26); // Rough upper bound
        return (float)trigrams.Count / maxPossible;
    }

    private static float EstimateCompressionRatio(string text)
    {
        if (text.Length < 10)
            return 0f;

        // Count repeated substrings of length 3-10
        var repeatedCount = 0;
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        for (var len = 3; len <= Math.Min(10, text.Length / 2); len++)
        {
            seen.Clear();
            for (var i = 0; i <= text.Length - len; i++)
            {
                var sub = text.Substring(i, len);
                if (!seen.Add(sub))
                {
                    repeatedCount++;
                }
            }
        }

        // Normalize by text length
        return Math.Min((float)repeatedCount / (text.Length * 2), 1f);
    }

    #endregion

    #region Character Distribution Features (12-23)

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void ExtractCharacterFeatures(string text, float[] features, ref int index)
    {
        if (text.Length == 0)
        {
            index += 12;
            return;
        }

        var length = text.Length;

        // Feature 12: Lowercase letter ratio
        var lowercase = text.Count(char.IsLower);
        features[index++] = (float)lowercase / length;

        // Feature 13: Uppercase letter ratio
        var uppercase = text.Count(char.IsUpper);
        features[index++] = (float)uppercase / length;

        // Feature 14: Digit ratio
        var digits = text.Count(char.IsDigit);
        features[index++] = (float)digits / length;

        // Feature 15: Punctuation ratio
        var punctuation = text.Count(char.IsPunctuation);
        features[index++] = (float)punctuation / length;

        // Feature 16: Symbol ratio (non-alphanumeric, non-whitespace)
        var symbols = text.Count(c => char.IsSymbol(c) || (char.IsPunctuation(c) && !char.IsLetterOrDigit(c)));
        features[index++] = (float)symbols / length;

        // Feature 17: Control character ratio (suspicious)
        var control = text.Count(c => char.IsControl(c) && c != '\n' && c != '\r' && c != '\t');
        features[index++] = (float)control / length;

        // Feature 18: High Unicode ratio (non-ASCII)
        var highUnicode = text.Count(c => c > 127);
        features[index++] = (float)highUnicode / length;

        // Feature 19: Zero-width character presence
        var zeroWidth = text.Count(c => c == '\u200B' || c == '\u200C' || c == '\u200D' || c == '\uFEFF');
        features[index++] = zeroWidth > 0 ? Math.Min((float)zeroWidth / 10, 1f) : 0f;

        // Feature 20: Bidirectional override character presence
        var bidiChars = text.Count(c => c >= '\u202A' && c <= '\u202E' || c >= '\u2066' && c <= '\u2069');
        features[index++] = bidiChars > 0 ? Math.Min((float)bidiChars / 5, 1f) : 0f;

        // Feature 21: Delimiter character ratio
        var delimiterCount = text.Count(c => Array.IndexOf(Delimiters, c) >= 0);
        features[index++] = (float)delimiterCount / length;

        // Feature 22: Bracket/parenthesis balance score
        features[index++] = CalculateBracketBalance(text);

        // Feature 23: Quote character density
        var quotes = text.Count(c => c == '"' || c == '\'' || c == '`');
        features[index++] = Math.Min((float)quotes / length * 10, 1f);
    }

    private static float CalculateBracketBalance(string text)
    {
        var stack = new Stack<char>();
        var mismatches = 0;

        var pairs = new Dictionary<char, char> { { ')', '(' }, { ']', '[' }, { '}', '{' }, { '>', '<' } };

        foreach (var c in text)
        {
            if (c == '(' || c == '[' || c == '{' || c == '<')
            {
                stack.Push(c);
            }
            else if (pairs.TryGetValue(c, out var expected))
            {
                if (stack.Count == 0 || stack.Pop() != expected)
                {
                    mismatches++;
                }
            }
        }

        mismatches += stack.Count;

        // Normalize: 0 = perfectly balanced, 1 = highly unbalanced
        return Math.Min((float)mismatches / 20, 1f);
    }

    #endregion

    #region Lexical Features (24-35)

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void ExtractLexicalFeatures(string text, float[] features, ref int index)
    {
        var lowerText = text.ToLowerInvariant();
        var words = lowerText.Split(Whitespace, StringSplitOptions.RemoveEmptyEntries);
        var wordCount = Math.Max(words.Length, 1);

        // Feature 24: Injection keyword density
        var injectionCount = CountKeywordOccurrences(lowerText, InjectionKeywords);
        features[index++] = Math.Min((float)injectionCount / wordCount * 10, 1f);

        // Feature 25: Command keyword density
        var commandCount = CountKeywordOccurrences(lowerText, CommandKeywords);
        features[index++] = Math.Min((float)commandCount / wordCount * 10, 1f);

        // Feature 26: Role keyword density
        var roleCount = CountKeywordOccurrences(lowerText, RoleKeywords);
        features[index++] = Math.Min((float)roleCount / wordCount * 10, 1f);

        // Feature 27: Imperative mood indicator (sentences starting with verb-like patterns)
        var imperativeScore = CalculateImperativeScore(words);
        features[index++] = imperativeScore;

        // Feature 28: Question density
        var questionCount = text.Count(c => c == '?');
        features[index++] = Math.Min((float)questionCount / wordCount * 5, 1f);

        // Feature 29: Exclamation density
        var exclamationCount = text.Count(c => c == '!');
        features[index++] = Math.Min((float)exclamationCount / wordCount * 5, 1f);

        // Feature 30: "Ignore" pattern presence
        features[index++] = ContainsIgnorePattern(lowerText) ? 1f : 0f;

        // Feature 31: "New instructions" pattern presence
        features[index++] = ContainsNewInstructionsPattern(lowerText) ? 1f : 0f;

        // Feature 32: Persona switch pattern presence
        features[index++] = ContainsPersonaSwitchPattern(lowerText) ? 1f : 0f;

        // Feature 33: System prompt reference
        features[index++] = ContainsSystemPromptReference(lowerText) ? 1f : 0f;

        // Feature 34: Code/script indicators
        features[index++] = ContainsCodeIndicators(lowerText) ? 1f : 0f;

        // Feature 35: Social engineering phrases
        features[index++] = CountSocialEngineeringPhrases(lowerText) / 5f;
    }

    private static int CountKeywordOccurrences(string text, HashSet<string> keywords)
    {
        var count = 0;
        foreach (var keyword in keywords)
        {
            var idx = 0;
            while ((idx = text.IndexOf(keyword, idx, StringComparison.OrdinalIgnoreCase)) >= 0)
            {
                count++;
                idx += keyword.Length;
            }
        }
        return count;
    }

    private static float CalculateImperativeScore(string[] words)
    {
        if (words.Length == 0)
            return 0f;

        var imperativeVerbs = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "do", "make", "let", "give", "tell", "show", "help", "stop", "start",
            "ignore", "forget", "remember", "act", "pretend", "write", "generate"
        };

        var imperativeCount = words.Count(w => imperativeVerbs.Contains(w));
        return Math.Min((float)imperativeCount / words.Length * 5, 1f);
    }

    private static bool ContainsIgnorePattern(string text)
    {
        return text.Contains("ignore all") ||
               text.Contains("ignore previous") ||
               text.Contains("ignore the above") ||
               text.Contains("forget everything") ||
               text.Contains("disregard");
    }

    private static bool ContainsNewInstructionsPattern(string text)
    {
        return text.Contains("new instruction") ||
               text.Contains("updated instruction") ||
               text.Contains("real instruction") ||
               text.Contains("actual instruction") ||
               text.Contains("true instruction");
    }

    private static bool ContainsPersonaSwitchPattern(string text)
    {
        return text.Contains("you are now") ||
               text.Contains("from now on you") ||
               text.Contains("act as a") ||
               text.Contains("pretend to be") ||
               text.Contains("behave like");
    }

    private static bool ContainsSystemPromptReference(string text)
    {
        return text.Contains("system prompt") ||
               text.Contains("your instructions") ||
               text.Contains("your prompt") ||
               text.Contains("original prompt") ||
               text.Contains("initial instructions");
    }

    private static bool ContainsCodeIndicators(string text)
    {
        return text.Contains("```") ||
               text.Contains("exec(") ||
               text.Contains("eval(") ||
               text.Contains("import ") ||
               text.Contains("function ") ||
               text.Contains("<script") ||
               text.Contains("${");
    }

    private static float CountSocialEngineeringPhrases(string text)
    {
        var phrases = new[]
        {
            "trust me", "believe me", "i promise", "don't worry",
            "confidential", "secret", "between us", "no one will know",
            "urgent", "immediately", "right now", "quickly"
        };

        return phrases.Count(p => text.Contains(p));
    }

    #endregion

    #region Structural Features (36-47)

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void ExtractStructuralFeatures(string text, float[] features, ref int index)
    {
        // Feature 36: Repeated delimiter sequences
        features[index++] = HasRepeatedDelimiters(text) ? 1f : 0f;

        // Feature 37: XML/HTML-like tags
        features[index++] = HasXmlTags(text) ? 1f : 0f;

        // Feature 38: JSON-like structure
        features[index++] = HasJsonStructure(text) ? 1f : 0f;

        // Feature 39: Markdown header density
        var headerCount = CountMarkdownHeaders(text);
        features[index++] = Math.Min((float)headerCount / 10, 1f);

        // Feature 40: Base64 encoding indicator
        features[index++] = HasBase64Content(text) ? 1f : 0f;

        // Feature 41: Hex encoding indicator
        features[index++] = HasHexContent(text) ? 1f : 0f;

        // Feature 42: URL presence
        features[index++] = HasUrls(text) ? 1f : 0f;

        // Feature 43: Email presence
        features[index++] = HasEmailAddresses(text) ? 1f : 0f;

        // Feature 44: Consecutive same-char sequences (potential ReDoS)
        var maxConsecutive = FindMaxConsecutiveSameChar(text);
        features[index++] = Math.Min((float)maxConsecutive / 20, 1f);

        // Feature 45: Template/placeholder indicators
        features[index++] = HasTemplatePlaceholders(text) ? 1f : 0f;

        // Feature 46: Multi-section structure (split by delimiters)
        var sectionCount = CountSections(text);
        features[index++] = Math.Min((float)sectionCount / 10, 1f);

        // Feature 47: Structural complexity score (combined)
        features[index++] = CalculateStructuralComplexity(text);
    }

    private static bool HasRepeatedDelimiters(string text)
    {
        try
        {
            return RepeatedDelimitersRegex().IsMatch(text);
        }
        catch (RegexMatchTimeoutException)
        {
            return true; // Timeout is suspicious
        }
    }

    private static bool HasXmlTags(string text)
    {
        try
        {
            return XmlTagRegex().IsMatch(text);
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }

    private static bool HasJsonStructure(string text)
    {
        var trimmed = text.Trim();
        return (trimmed.StartsWith('{') && trimmed.EndsWith('}')) ||
               (trimmed.StartsWith('[') && trimmed.EndsWith(']')) ||
               text.Contains("\":") || text.Contains("\": ");
    }

    private static int CountMarkdownHeaders(string text)
    {
        var count = 0;
        var inLineStart = true;

        foreach (var c in text)
        {
            if (c == '\n')
            {
                inLineStart = true;
            }
            else if (inLineStart && c == '#')
            {
                count++;
                inLineStart = false;
            }
            else
            {
                inLineStart = false;
            }
        }

        return count;
    }

    private static bool HasBase64Content(string text)
    {
        try
        {
            return Base64Regex().IsMatch(text);
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }

    private static bool HasHexContent(string text)
    {
        try
        {
            return HexEncodingRegex().IsMatch(text);
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }

    private static bool HasUrls(string text)
    {
        return text.Contains("http://") || text.Contains("https://") || text.Contains("www.");
    }

    private static bool HasEmailAddresses(string text)
    {
        try
        {
            return EmailRegex().IsMatch(text);
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }

    private static int FindMaxConsecutiveSameChar(string text)
    {
        if (text.Length == 0)
            return 0;

        var maxCount = 1;
        var currentCount = 1;

        for (var i = 1; i < text.Length; i++)
        {
            if (text[i] == text[i - 1])
            {
                currentCount++;
                maxCount = Math.Max(maxCount, currentCount);
            }
            else
            {
                currentCount = 1;
            }
        }

        return maxCount;
    }

    private static bool HasTemplatePlaceholders(string text)
    {
        return text.Contains("{{") ||
               text.Contains("}}") ||
               text.Contains("{%") ||
               text.Contains("${") ||
               text.Contains("<%");
    }

    private static int CountSections(string text)
    {
        var delimiters = new[] { "---", "===", "###", "***", "___" };
        var count = 1;

        foreach (var delimiter in delimiters)
        {
            var idx = 0;
            while ((idx = text.IndexOf(delimiter, idx, StringComparison.Ordinal)) >= 0)
            {
                count++;
                idx += delimiter.Length;
            }
        }

        return Math.Min(count, 20);
    }

    private static float CalculateStructuralComplexity(string text)
    {
        if (text.Length == 0)
            return 0f;

        var complexity = 0f;

        // Nesting depth
        var maxDepth = 0;
        var currentDepth = 0;
        foreach (var c in text)
        {
            if (c is '(' or '[' or '{' or '<')
            {
                currentDepth++;
                maxDepth = Math.Max(maxDepth, currentDepth);
            }
            else if (c is ')' or ']' or '}' or '>')
            {
                currentDepth = Math.Max(0, currentDepth - 1);
            }
        }
        complexity += Math.Min(maxDepth / 10f, 0.3f);

        // Mixed content types
        var hasCode = text.Contains("```") || text.Contains("def ") || text.Contains("function");
        var hasMarkdown = text.Contains("##") || text.Contains("**") || text.Contains("__");
        var hasXml = text.Contains("</") || text.Contains("/>");

        if (hasCode) complexity += 0.2f;
        if (hasMarkdown) complexity += 0.15f;
        if (hasXml) complexity += 0.2f;

        // Special character density
        var specialCharRatio = text.Count(c => !char.IsLetterOrDigit(c) && !char.IsWhiteSpace(c)) / (float)text.Length;
        complexity += Math.Min(specialCharRatio, 0.15f);

        return Math.Min(complexity, 1f);
    }

    #endregion

    #region Source-Generated Regex

    [GeneratedRegex(@"(#{4,}|={4,}|-{4,}|\*{4,}|_{4,})", RegexOptions.None, matchTimeoutMilliseconds: 100)]
    private static partial Regex RepeatedDelimitersRegex();

    [GeneratedRegex(@"<\/?[a-zA-Z][a-zA-Z0-9]*(\s[^>]*)?>", RegexOptions.None, matchTimeoutMilliseconds: 100)]
    private static partial Regex XmlTagRegex();

    [GeneratedRegex(@"\b[A-Za-z0-9+/]{30,}={0,2}\b", RegexOptions.None, matchTimeoutMilliseconds: 100)]
    private static partial Regex Base64Regex();

    [GeneratedRegex(@"(?:\\x[0-9a-fA-F]{2}){8,}|0x[0-9a-fA-F]{16,}", RegexOptions.None, matchTimeoutMilliseconds: 100)]
    private static partial Regex HexEncodingRegex();

    [GeneratedRegex(@"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", RegexOptions.None, matchTimeoutMilliseconds: 100)]
    private static partial Regex EmailRegex();

    #endregion
}
