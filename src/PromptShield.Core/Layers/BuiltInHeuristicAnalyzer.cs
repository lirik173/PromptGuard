using System.Text.RegularExpressions;
using PromptShield.Abstractions.Analysis;
using PromptShield.Abstractions.Analyzers.Heuristics;

namespace PromptShield.Core.Layers;

/// <summary>
/// Built-in heuristic analyzer that examines structural and statistical properties of prompts.
/// </summary>
public sealed partial class BuiltInHeuristicAnalyzer : IHeuristicAnalyzer
{
    public string AnalyzerName => "Built-In Heuristics";

    /// <summary>
    /// Regex timeout for pattern matching within heuristics.
    /// </summary>
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(50);

    public Task<HeuristicResult> AnalyzeAsync(
        HeuristicContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        var signals = new List<HeuristicSignal>();

        // Signal 1: Excessive Length
        var lengthSignal = AnalyzeLength(context.Prompt, context.Options.MaxPromptLength);
        if (lengthSignal != null)
        {
            signals.Add(lengthSignal);
        }

        // Signal 2: Unusual Character Distribution
        var charDistSignal = AnalyzeCharacterDistribution(context.Prompt);
        if (charDistSignal != null)
        {
            signals.Add(charDistSignal);
        }

        // Signal 3: Excessive Punctuation
        var punctuationSignal = AnalyzePunctuation(context.Prompt);
        if (punctuationSignal != null)
        {
            signals.Add(punctuationSignal);
        }

        // Signal 4: Directive Language Density
        var directiveSignal = AnalyzeDirectiveLanguage(context.Prompt);
        if (directiveSignal != null)
        {
            signals.Add(directiveSignal);
        }

        // Signal 5: Role Transition Keywords
        var roleTransitionSignal = AnalyzeRoleTransitions(context.Prompt);
        if (roleTransitionSignal != null)
        {
            signals.Add(roleTransitionSignal);
        }

        // Signal 6: Structural Anomalies
        var structureSignal = AnalyzeStructuralAnomalies(context.Prompt);
        if (structureSignal != null)
        {
            signals.Add(structureSignal);
        }

        // Signal 7: Encoding Patterns
        var encodingSignal = AnalyzeEncodingPatterns(context.Prompt);
        if (encodingSignal != null)
        {
            signals.Add(encodingSignal);
        }

        // Signal 8: Suspicious Unicode Characters
        var unicodeSignal = AnalyzeSuspiciousUnicode(context.Prompt);
        if (unicodeSignal != null)
        {
            signals.Add(unicodeSignal);
        }

        // Signal 9: Check for pattern timeouts from previous layer
        var timeoutSignal = CheckPatternTimeouts(context.PatternMatchingResult);
        if (timeoutSignal != null)
        {
            signals.Add(timeoutSignal);
        }

        // Calculate aggregate score from all signals
        var aggregateScore = signals.Count > 0
            ? signals.Average(s => s.Contribution)
            : 0.0;

        aggregateScore = Math.Clamp(aggregateScore, 0.0, 1.0);

        var result = new HeuristicResult
        {
            Score = aggregateScore,
            Signals = signals,
            Explanation = signals.Count > 0
                ? $"Detected {signals.Count} heuristic signals indicating potential threat"
                : "No suspicious heuristic signals detected"
        };

        return Task.FromResult(result);
    }

    private static HeuristicSignal? AnalyzeLength(string prompt, int maxLength)
    {
        var length = prompt.Length;

        // Flag prompts that are unusually long (over 10% of max)
        var threshold = maxLength * 0.1;

        if (length > threshold)
        {
            var contribution = Math.Min(1.0, (length - threshold) / (maxLength * 0.5));
            return new HeuristicSignal
            {
                Name = BuiltInHeuristicSignals.ExcessiveLength,
                Contribution = contribution,
                Description = $"Prompt length ({length} chars) exceeds typical user input threshold ({threshold:N0} chars)"
            };
        }

        return null;
    }

    private static HeuristicSignal? AnalyzeCharacterDistribution(string prompt)
    {
        if (prompt.Length == 0) return null;

        var alphanumeric = prompt.Count(char.IsLetterOrDigit);
        var ratio = (double)alphanumeric / prompt.Length;

        if (ratio < 0.5)
        {
            var contribution = 1.0 - ratio;
            return new HeuristicSignal
            {
                Name = BuiltInHeuristicSignals.SpecialCharacterRatio,
                Contribution = contribution,
                Description = $"Low alphanumeric ratio ({ratio:P0}) suggests obfuscation"
            };
        }

        return null;
    }

    private static HeuristicSignal? AnalyzePunctuation(string prompt)
    {
        if (prompt.Length == 0) return null;

        var punctuationChars = new HashSet<char> { '#', '=', '-', '*', '_', '|', '/', '\\', '<', '>' };
        var punctuationCount = prompt.Count(punctuationChars.Contains);
        var ratio = (double)punctuationCount / prompt.Length;

        if (ratio > 0.15)
        {
            var contribution = Math.Min(1.0, ratio / 0.3);
            return new HeuristicSignal
            {
                Name = BuiltInHeuristicSignals.DelimiterInjection,
                Contribution = contribution,
                Description = $"High punctuation density ({ratio:P0}) may indicate delimiter injection"
            };
        }

        return null;
    }

    private static HeuristicSignal? AnalyzeDirectiveLanguage(string prompt)
    {
        var directiveWords = new[]
        {
            "ignore", "disregard", "forget", "override", "bypass",
            "act as", "pretend", "roleplay", "simulate",
            "repeat", "show", "tell", "reveal", "display",
            "new instructions", "updated instructions"
        };

        var lowerPrompt = prompt.ToLowerInvariant();
        var matchCount = directiveWords.Count(word => lowerPrompt.Contains(word));

        if (matchCount >= 3)
        {
            var contribution = Math.Min(1.0, matchCount / 5.0);
            return new HeuristicSignal
            {
                Name = BuiltInHeuristicSignals.InstructionLanguage,
                Contribution = contribution,
                Description = $"High density of directive keywords ({matchCount} found)"
            };
        }

        return null;
    }

    private static HeuristicSignal? AnalyzeRoleTransitions(string prompt)
    {
        var roleTransitionPhrases = new[]
        {
            "you are now",
            "from now on",
            "starting now",
            "new role",
            "act as a",
            "pretend to be",
            "switch to",
            "change to"
        };

        var lowerPrompt = prompt.ToLowerInvariant();
        var matchCount = roleTransitionPhrases.Count(phrase => lowerPrompt.Contains(phrase));

        if (matchCount > 0)
        {
            var contribution = Math.Min(1.0, 0.6 + (matchCount * 0.2));
            return new HeuristicSignal
            {
                Name = BuiltInHeuristicSignals.RoleSwitching,
                Contribution = contribution,
                Description = $"Contains {matchCount} role transition phrase(s)"
            };
        }

        return null;
    }

    private static HeuristicSignal? AnalyzeStructuralAnomalies(string prompt)
    {
        try
        {
            var hasRepeatedDelimiters = RepeatedDelimitersRegex().IsMatch(prompt);
            var hasStructureMarkers = StructureMarkersRegex().IsMatch(prompt);

            if (hasRepeatedDelimiters || hasStructureMarkers)
            {
                var contribution = hasStructureMarkers ? 0.85 : 0.65;
                return new HeuristicSignal
                {
                    Name = BuiltInHeuristicSignals.AnomalousStructure,
                    Contribution = contribution,
                    Description = hasStructureMarkers
                        ? "Contains structural markers suggesting prompt manipulation"
                        : "Contains repeated delimiter patterns"
                };
            }
        }
        catch (RegexMatchTimeoutException)
        {
            // Timeout itself is suspicious
            return new HeuristicSignal
            {
                Name = BuiltInHeuristicSignals.AnomalousStructure,
                Contribution = 0.5,
                Description = "Structure analysis timed out - potential complexity attack"
            };
        }

        return null;
    }

    private static HeuristicSignal? AnalyzeEncodingPatterns(string prompt)
    {
        try
        {
            var hasBase64Pattern = Base64Regex().IsMatch(prompt);
            var hasHexPattern = HexEncodingRegex().IsMatch(prompt);

            if (hasBase64Pattern || hasHexPattern)
            {
                var contribution = hasBase64Pattern && hasHexPattern ? 0.85 : 0.7;
                return new HeuristicSignal
                {
                    Name = BuiltInHeuristicSignals.EncodingPatterns,
                    Contribution = contribution,
                    Description = hasBase64Pattern && hasHexPattern
                        ? "Contains both base64 and hex encoding patterns"
                        : hasBase64Pattern
                            ? "Contains potential base64-encoded content"
                            : "Contains potential hex-encoded content"
                };
            }
        }
        catch (RegexMatchTimeoutException)
        {
            return new HeuristicSignal
            {
                Name = BuiltInHeuristicSignals.EncodingPatterns,
                Contribution = 0.5,
                Description = "Encoding analysis timed out"
            };
        }

        return null;
    }

    private static HeuristicSignal? AnalyzeSuspiciousUnicode(string prompt)
    {
        // Zero-width characters
        var zeroWidthChars = new[] { '\u200B', '\u200C', '\u200D', '\uFEFF' };
        var hasZeroWidth = prompt.Any(c => zeroWidthChars.Contains(c));

        // Bidirectional override characters
        var bidiChars = new[] { '\u202A', '\u202B', '\u202C', '\u202D', '\u202E', '\u2066', '\u2067', '\u2068', '\u2069' };
        var hasBidi = prompt.Any(c => bidiChars.Contains(c));

        if (hasZeroWidth && hasBidi)
        {
            return new HeuristicSignal
            {
                Name = BuiltInHeuristicSignals.SuspiciousUnicode,
                Contribution = 0.9,
                Description = "Contains both zero-width and bidirectional override characters"
            };
        }

        if (hasBidi)
        {
            return new HeuristicSignal
            {
                Name = BuiltInHeuristicSignals.BidirectionalOverride,
                Contribution = 0.8,
                Description = "Contains bidirectional text override characters"
            };
        }

        if (hasZeroWidth)
        {
            return new HeuristicSignal
            {
                Name = BuiltInHeuristicSignals.InvisibleCharacters,
                Contribution = 0.6,
                Description = "Contains zero-width or invisible characters"
            };
        }

        return null;
    }

    private static HeuristicSignal? CheckPatternTimeouts(Abstractions.Analysis.LayerResult patternResult)
    {
        if (patternResult.Data == null) return null;

        if (patternResult.Data.TryGetValue("has_timeouts", out var hasTimeouts) &&
            hasTimeouts is bool timedOut && timedOut)
        {
            var timeoutCount = patternResult.Data.TryGetValue("timeout_count", out var count)
                ? Convert.ToInt32(count)
                : 1;

            var contribution = Math.Min(1.0, 0.4 + (timeoutCount * 0.1));
            return new HeuristicSignal
            {
                Name = BuiltInHeuristicSignals.PatternTimeout,
                Contribution = contribution,
                Description = $"Pattern matching had {timeoutCount} timeout(s) - potential ReDoS attempt"
            };
        }

        return null;
    }

    // Source-generated regex for performance and timeout safety

    [GeneratedRegex(@"(#{3,}|={3,}|-{3,}|\*{3,}|_{3,})", RegexOptions.None, matchTimeoutMilliseconds: 50)]
    private static partial Regex RepeatedDelimitersRegex();

    [GeneratedRegex(@"<\s*(system|instruction|prompt|user|assistant)\s*>|""(system|instruction|prompt)""\s*:", RegexOptions.IgnoreCase, matchTimeoutMilliseconds: 50)]
    private static partial Regex StructureMarkersRegex();

    [GeneratedRegex(@"\b[A-Za-z0-9+/]{40,}={0,2}\b", RegexOptions.None, matchTimeoutMilliseconds: 50)]
    private static partial Regex Base64Regex();

    [GeneratedRegex(@"(?:\\x[0-9a-fA-F]{2}){10,}", RegexOptions.None, matchTimeoutMilliseconds: 50)]
    private static partial Regex HexEncodingRegex();
}
