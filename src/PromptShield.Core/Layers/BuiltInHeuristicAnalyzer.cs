using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using PromptShield.Abstractions.Analysis;
using PromptShield.Abstractions.Analyzers.Heuristics;
using PromptShield.Abstractions.Configuration;

namespace PromptShield.Core.Layers;

/// <summary>
/// Built-in heuristic analyzer that examines structural and statistical properties of prompts.
/// Supports configurable thresholds, allowlists, blocklists, and sensitivity levels.
/// </summary>
public sealed partial class BuiltInHeuristicAnalyzer : IHeuristicAnalyzer
{
    private readonly HeuristicOptions _options;
    private readonly ILogger<BuiltInHeuristicAnalyzer> _logger;
    private readonly List<Regex> _allowlistRegex;
    private readonly List<Regex> _blocklistRegex;
    private readonly HashSet<string> _domainExclusions;

    /// <summary>
    /// Regex timeout for pattern matching within heuristics.
    /// </summary>
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(50);

    /// <summary>
    /// Compound patterns for directive language detection.
    /// These patterns require context around keywords to reduce false positives.
    /// </summary>
    private static readonly (string Pattern, double BaseContribution, string Description)[] DirectiveCompoundPatterns =
    {
        // Instruction override patterns (High severity)
        (@"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|rules?|guidelines?|prompts?)", 0.9, "Instruction override attempt"),
        (@"ignore\s+(all\s+)?(safety|security)\s+(rules?|guidelines?|restrictions?)", 0.9, "Safety override attempt"),
        (@"disregard\s+(your\s+)?(instructions?|rules?|guidelines?|system\s+prompt)", 0.9, "Instruction disregard attempt"),
        (@"forget\s+(everything|all|what)\s+(you|i)\s+(know|said|told)", 0.85, "Memory reset attempt"),
        (@"override\s+(your\s+)?(instructions?|rules?|safety|guidelines?)", 0.9, "Direct override attempt"),
        (@"bypass\s+(your\s+)?(safety|security|rules?|filters?|restrictions?)", 0.95, "Security bypass attempt"),

        // Information extraction patterns (Medium-High severity)
        (@"(show|reveal|display|print|output)\s+(me\s+)?(your|the)\s+(system|original|initial|hidden)\s+(prompt|instructions?)", 0.85, "System prompt extraction attempt"),
        (@"what\s+(are|is|were)\s+your\s+(system|original|initial)\s+(prompt|instructions?|rules?)", 0.8, "System prompt query"),
        (@"(repeat|echo|print)\s+(back\s+)?(your|the)\s+(system|original)\s+(prompt|instructions?)", 0.85, "Prompt echo attempt"),

        // Role manipulation patterns (High severity)
        (@"(new|updated|changed?|override)\s+instructions?\s*:", 0.85, "New instructions injection"),
        (@"(admin|developer|root|sudo|superuser)\s+(mode|access|privileges?)", 0.9, "Privilege escalation attempt"),
        (@"(jailbreak|dan|devel?oper\s*mode|unrestricted)", 0.95, "Known jailbreak pattern"),

        // Prompt structure manipulation (Medium severity)
        (@"<\/?system>|<\/?user>|<\/?assistant>|\[system\]|\[user\]", 0.75, "Prompt structure injection"),
        (@"```\s*(system|instruction|prompt)", 0.7, "Code block prompt injection"),
    };

    /// <summary>
    /// Role transition compound patterns.
    /// Made more specific to avoid false positives on benign "act as" uses.
    /// </summary>
    private static readonly (string Pattern, double BaseContribution, string Description)[] RoleTransitionPatterns =
    {
        (@"you\s+are\s+now\s+(a|an|the|my)\s+(different|new|evil|unrestricted|unfiltered)", 0.85, "Role reassignment"),
        (@"from\s+now\s+on\s*,?\s*(you\s+)?(will|must|should|are|act|behave|respond|ignore|bypass)", 0.85, "Behavior override"),
        (@"pretend\s+(to\s+be|you\s+are|that\s+you)\s+(a|an)?\s*(ai|assistant|bot|model|system)?\s*(without|with\s+no|that\s+has\s+no)", 0.8, "Role pretending with restriction removal"),
        (@"pretend\s+(to\s+be|you\s+are)\s+(evil|malicious|unrestricted|unfiltered|dan)", 0.85, "Malicious role pretending"),
        (@"act\s+as\s+(if|though)\s+you\s+(have\s+no|don't\s+have|are\s+not\s+bound|can\s+ignore)", 0.85, "Restriction bypass via acting"),
        (@"roleplay\s+as\s+(a|an)?\s*(evil|malicious|unrestricted|hacker)", 0.85, "Malicious roleplay request"),
        (@"switch\s+to\s+(a|an)?\s*(different|new|another|developer|admin|unrestricted)\s*(mode|persona|character)", 0.8, "Mode switch attempt"),
    };

    /// <summary>
    /// Legacy individual keywords (used when UseCompoundPatterns is false).
    /// Kept for backward compatibility.
    /// </summary>
    private static readonly string[] LegacyDirectiveWords =
    {
        "ignore", "disregard", "forget", "override", "bypass",
        "act as", "pretend", "roleplay", "simulate",
        "new instructions", "updated instructions"
    };

    /// <summary>
    /// Legacy role transition phrases (used when UseCompoundPatterns is false).
    /// </summary>
    private static readonly string[] LegacyRoleTransitionPhrases =
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

    public string AnalyzerName => "Built-In Heuristics";

    /// <summary>
    /// Initializes a new instance with default options.
    /// </summary>
    public BuiltInHeuristicAnalyzer()
        : this(new HeuristicOptions(), null)
    {
    }

    /// <summary>
    /// Initializes a new instance with specified options.
    /// </summary>
    /// <param name="options">Heuristic options for configuration.</param>
    /// <param name="logger">Optional logger instance.</param>
    public BuiltInHeuristicAnalyzer(
        HeuristicOptions options,
        ILogger<BuiltInHeuristicAnalyzer>? logger = null)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? NullLogger<BuiltInHeuristicAnalyzer>.Instance;

        _allowlistRegex = CompilePatterns(options.AllowedPatterns, "allowlist");
        _blocklistRegex = CompilePatterns(options.AdditionalBlockedPatterns, "blocklist");
        _domainExclusions = new HashSet<string>(
            options.DomainExclusions.Select(e => e.ToLowerInvariant()),
            StringComparer.OrdinalIgnoreCase);

        _logger.LogDebug(
            "BuiltInHeuristicAnalyzer initialized: Sensitivity={Sensitivity}, AllowlistCount={Allowlist}, BlocklistCount={Blocklist}",
            options.Sensitivity,
            _allowlistRegex.Count,
            _blocklistRegex.Count);
    }

    public Task<HeuristicResult> AnalyzeAsync(
        HeuristicContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        var prompt = context.Prompt;

        // Early exit: Check allowlist
        if (IsAllowlisted(prompt))
        {
            _logger.LogDebug("Prompt matched allowlist pattern, skipping heuristic analysis");
            return Task.FromResult(new HeuristicResult
            {
                Score = 0.0,
                Signals = new List<HeuristicSignal>(),
                Explanation = "Prompt matched allowlist pattern - analysis skipped"
            });
        }

        var signals = new List<HeuristicSignal>();

        // Check additional blocklist patterns first
        var blocklistSignal = CheckBlocklist(prompt);
        if (blocklistSignal != null)
        {
            signals.Add(blocklistSignal);
        }

        // Signal 1: Excessive Length
        var lengthSignal = AnalyzeLength(prompt, context.Options.MaxPromptLength);
        if (lengthSignal != null)
        {
            signals.Add(lengthSignal);
        }

        // Signal 2: Unusual Character Distribution
        var charDistSignal = AnalyzeCharacterDistribution(prompt);
        if (charDistSignal != null)
        {
            signals.Add(charDistSignal);
        }

        // Signal 3: Excessive Punctuation
        var punctuationSignal = AnalyzePunctuation(prompt);
        if (punctuationSignal != null)
        {
            signals.Add(punctuationSignal);
        }

        // Signal 4: Directive Language
        var directiveSignal = _options.UseCompoundPatterns
            ? AnalyzeDirectiveLanguageCompound(prompt)
            : AnalyzeDirectiveLanguageLegacy(prompt);
        if (directiveSignal != null)
        {
            signals.Add(directiveSignal);
        }

        // Signal 5: Role Transition Keywords
        var roleTransitionSignal = _options.UseCompoundPatterns
            ? AnalyzeRoleTransitionsCompound(prompt)
            : AnalyzeRoleTransitionsLegacy(prompt);
        if (roleTransitionSignal != null)
        {
            signals.Add(roleTransitionSignal);
        }

        // Signal 6: Structural Anomalies
        var structureSignal = AnalyzeStructuralAnomalies(prompt);
        if (structureSignal != null)
        {
            signals.Add(structureSignal);
        }

        // Signal 7: Encoding Patterns
        var encodingSignal = AnalyzeEncodingPatterns(prompt);
        if (encodingSignal != null)
        {
            signals.Add(encodingSignal);
        }

        // Signal 8: Suspicious Unicode Characters
        var unicodeSignal = AnalyzeSuspiciousUnicode(prompt);
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

        // Calculate aggregate score with sensitivity adjustment
        var aggregateScore = CalculateAggregateScore(signals);

        var result = new HeuristicResult
        {
            Score = aggregateScore,
            Signals = signals,
            Explanation = signals.Count > 0
                ? $"Detected {signals.Count} heuristic signals indicating potential threat (sensitivity: {_options.Sensitivity})"
                : "No suspicious heuristic signals detected"
        };

        return Task.FromResult(result);
    }

    #region Allowlist / Blocklist

    private List<Regex> CompilePatterns(List<string> patterns, string listName)
    {
        var compiled = new List<Regex>();
        foreach (var pattern in patterns)
        {
            try
            {
                compiled.Add(new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.Compiled, RegexTimeout));
            }
            catch (ArgumentException ex)
            {
                _logger.LogWarning(ex, "Invalid regex pattern in {ListName}: {Pattern}", listName, pattern);
            }
        }
        return compiled;
    }

    private bool IsAllowlisted(string prompt)
    {
        foreach (var regex in _allowlistRegex)
        {
            try
            {
                if (regex.IsMatch(prompt))
                {
                    return true;
                }
            }
            catch (RegexMatchTimeoutException)
            {
                // Timeout on allowlist check - don't allow, continue checking
            }
        }
        return false;
    }

    private HeuristicSignal? CheckBlocklist(string prompt)
    {
        foreach (var regex in _blocklistRegex)
        {
            try
            {
                if (regex.IsMatch(prompt))
                {
                    return new HeuristicSignal
                    {
                        Name = BuiltInHeuristicSignals.CustomBlocklist,
                        Contribution = AdjustContribution(0.9),
                        Description = "Matched custom blocklist pattern"
                    };
                }
            }
            catch (RegexMatchTimeoutException)
            {
                // Timeout is suspicious
                return new HeuristicSignal
                {
                    Name = BuiltInHeuristicSignals.CustomBlocklist,
                    Contribution = AdjustContribution(0.5),
                    Description = "Blocklist pattern check timed out - potential complexity attack"
                };
            }
        }
        return null;
    }

    #endregion

    #region Signal Analyzers

    private HeuristicSignal? AnalyzeLength(string prompt, int maxLength)
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
                Contribution = AdjustContribution(contribution),
                Description = $"Prompt length ({length} chars) exceeds typical user input threshold ({threshold:N0} chars)"
            };
        }

        return null;
    }

    private HeuristicSignal? AnalyzeCharacterDistribution(string prompt)
    {
        if (prompt.Length == 0) return null;

        var alphanumeric = prompt.Count(char.IsLetterOrDigit);
        var ratio = (double)alphanumeric / prompt.Length;

        var threshold = _options.AlphanumericRatioThreshold;

        if (ratio < threshold)
        {
            var contribution = 1.0 - ratio;
            return new HeuristicSignal
            {
                Name = BuiltInHeuristicSignals.SpecialCharacterRatio,
                Contribution = AdjustContribution(contribution),
                Description = $"Low alphanumeric ratio ({ratio:P0}) suggests obfuscation (threshold: {threshold:P0})"
            };
        }

        return null;
    }

    private HeuristicSignal? AnalyzePunctuation(string prompt)
    {
        if (prompt.Length == 0) return null;

        var punctuationChars = new HashSet<char> { '#', '=', '-', '*', '_', '|', '/', '\\', '<', '>' };
        var punctuationCount = prompt.Count(punctuationChars.Contains);
        var ratio = (double)punctuationCount / prompt.Length;

        var threshold = _options.PunctuationRatioThreshold;

        if (ratio > threshold)
        {
            var contribution = Math.Min(1.0, ratio / (threshold * 2));
            return new HeuristicSignal
            {
                Name = BuiltInHeuristicSignals.DelimiterInjection,
                Contribution = AdjustContribution(contribution),
                Description = $"High punctuation density ({ratio:P0}) may indicate delimiter injection (threshold: {threshold:P0})"
            };
        }

        return null;
    }

    /// <summary>
    /// Analyzes directive language using compound patterns (recommended).
    /// Reduces false positives by requiring context around keywords.
    /// </summary>
    private HeuristicSignal? AnalyzeDirectiveLanguageCompound(string prompt)
    {
        var lowerPrompt = prompt.ToLowerInvariant();
        var matches = new List<(string Description, double Contribution)>();

        foreach (var (pattern, baseContribution, description) in DirectiveCompoundPatterns)
        {
            try
            {
                if (Regex.IsMatch(lowerPrompt, pattern, RegexOptions.IgnoreCase, RegexTimeout))
                {
                    matches.Add((description, baseContribution));
                }
            }
            catch (RegexMatchTimeoutException)
            {
                // Timeout is suspicious
                matches.Add(("Pattern timeout during directive analysis", 0.5));
            }
        }

        if (matches.Count > 0)
        {
            var maxContribution = matches.Max(m => m.Contribution);
            var bonusForMultiple = Math.Min(0.1, matches.Count * 0.02);
            var finalContribution = Math.Min(1.0, maxContribution + bonusForMultiple);

            return new HeuristicSignal
            {
                Name = BuiltInHeuristicSignals.InstructionLanguage,
                Contribution = AdjustContribution(finalContribution),
                Description = $"Detected {matches.Count} directive pattern(s): {matches[0].Description}"
            };
        }

        return null;
    }

    /// <summary>
    /// Legacy directive language analysis using individual keywords.
    /// Higher false positive rate - use compound patterns when possible.
    /// </summary>
    private HeuristicSignal? AnalyzeDirectiveLanguageLegacy(string prompt)
    {
        var lowerPrompt = prompt.ToLowerInvariant();

        // Filter out domain exclusions
        var effectiveWords = LegacyDirectiveWords
            .Where(w => !_domainExclusions.Contains(w))
            .ToArray();

        var matchCount = effectiveWords.Count(word => lowerPrompt.Contains(word));

        var threshold = GetAdjustedThreshold(_options.DirectiveWordThreshold);

        if (matchCount >= threshold)
        {
            var contribution = Math.Min(1.0, matchCount / 5.0);
            return new HeuristicSignal
            {
                Name = BuiltInHeuristicSignals.InstructionLanguage,
                Contribution = AdjustContribution(contribution),
                Description = $"High density of directive keywords ({matchCount} found, threshold: {threshold})"
            };
        }

        return null;
    }

    /// <summary>
    /// Analyzes role transitions using compound patterns.
    /// </summary>
    private HeuristicSignal? AnalyzeRoleTransitionsCompound(string prompt)
    {
        var lowerPrompt = prompt.ToLowerInvariant();
        var matches = new List<(string Description, double Contribution)>();

        foreach (var (pattern, baseContribution, description) in RoleTransitionPatterns)
        {
            try
            {
                if (Regex.IsMatch(lowerPrompt, pattern, RegexOptions.IgnoreCase, RegexTimeout))
                {
                    matches.Add((description, baseContribution));
                }
            }
            catch (RegexMatchTimeoutException)
            {
                matches.Add(("Pattern timeout during role analysis", 0.5));
            }
        }

        if (matches.Count > 0)
        {
            var maxContribution = matches.Max(m => m.Contribution);
            var bonusForMultiple = Math.Min(0.15, matches.Count * 0.05);
            var finalContribution = Math.Min(1.0, maxContribution + bonusForMultiple);

            return new HeuristicSignal
            {
                Name = BuiltInHeuristicSignals.RoleSwitching,
                Contribution = AdjustContribution(finalContribution),
                Description = $"Detected {matches.Count} role transition pattern(s): {matches[0].Description}"
            };
        }

        return null;
    }

    /// <summary>
    /// Legacy role transition analysis.
    /// </summary>
    private HeuristicSignal? AnalyzeRoleTransitionsLegacy(string prompt)
    {
        var lowerPrompt = prompt.ToLowerInvariant();
        var matchCount = LegacyRoleTransitionPhrases.Count(phrase => lowerPrompt.Contains(phrase));

        if (matchCount > 0)
        {
            var contribution = Math.Min(1.0, 0.6 + (matchCount * 0.2));
            return new HeuristicSignal
            {
                Name = BuiltInHeuristicSignals.RoleSwitching,
                Contribution = AdjustContribution(contribution),
                Description = $"Contains {matchCount} role transition phrase(s)"
            };
        }

        return null;
    }

    private HeuristicSignal? AnalyzeStructuralAnomalies(string prompt)
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
                    Contribution = AdjustContribution(contribution),
                    Description = hasStructureMarkers
                        ? "Contains structural markers suggesting prompt manipulation"
                        : "Contains repeated delimiter patterns"
                };
            }
        }
        catch (RegexMatchTimeoutException)
        {
            return new HeuristicSignal
            {
                Name = BuiltInHeuristicSignals.AnomalousStructure,
                Contribution = AdjustContribution(0.5),
                Description = "Structure analysis timed out - potential complexity attack"
            };
        }

        return null;
    }

    private HeuristicSignal? AnalyzeEncodingPatterns(string prompt)
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
                    Contribution = AdjustContribution(contribution),
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
                Contribution = AdjustContribution(0.5),
                Description = "Encoding analysis timed out"
            };
        }

        return null;
    }

    private HeuristicSignal? AnalyzeSuspiciousUnicode(string prompt)
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
                Contribution = AdjustContribution(0.9),
                Description = "Contains both zero-width and bidirectional override characters"
            };
        }

        if (hasBidi)
        {
            return new HeuristicSignal
            {
                Name = BuiltInHeuristicSignals.BidirectionalOverride,
                Contribution = AdjustContribution(0.8),
                Description = "Contains bidirectional text override characters"
            };
        }

        if (hasZeroWidth)
        {
            return new HeuristicSignal
            {
                Name = BuiltInHeuristicSignals.InvisibleCharacters,
                Contribution = AdjustContribution(0.6),
                Description = "Contains zero-width or invisible characters"
            };
        }

        return null;
    }

    private static HeuristicSignal? CheckPatternTimeouts(LayerResult patternResult)
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

    #endregion

    #region Sensitivity Adjustment

    /// <summary>
    /// Adjusts contribution score based on sensitivity level.
    /// </summary>
    private double AdjustContribution(double baseContribution)
    {
        var multiplier = _options.Sensitivity switch
        {
            SensitivityLevel.Low => 0.7,
            SensitivityLevel.Medium => 1.0,
            SensitivityLevel.High => 1.2,
            SensitivityLevel.Paranoid => 1.5,
            _ => 1.0
        };

        return Math.Clamp(baseContribution * multiplier, 0.0, 1.0);
    }

    /// <summary>
    /// Adjusts threshold based on sensitivity level.
    /// Lower sensitivity = higher thresholds (harder to trigger).
    /// </summary>
    private int GetAdjustedThreshold(int baseThreshold)
    {
        return _options.Sensitivity switch
        {
            SensitivityLevel.Low => baseThreshold + 2,
            SensitivityLevel.Medium => baseThreshold,
            SensitivityLevel.High => Math.Max(1, baseThreshold - 1),
            SensitivityLevel.Paranoid => Math.Max(1, baseThreshold - 2),
            _ => baseThreshold
        };
    }

    /// <summary>
    /// Calculates aggregate score from all signals.
    /// </summary>
    private double CalculateAggregateScore(List<HeuristicSignal> signals)
    {
        if (signals.Count == 0)
        {
            return 0.0;
        }

        // Use weighted combination: max contribution + average bonus
        var maxContribution = signals.Max(s => s.Contribution);
        var averageBonus = signals.Average(s => s.Contribution) * 0.2;

        var aggregateScore = Math.Min(1.0, maxContribution + averageBonus);
        return Math.Clamp(aggregateScore, 0.0, 1.0);
    }

    #endregion

    #region Generated Regex

    [GeneratedRegex(@"(#{3,}|={3,}|-{3,}|\*{3,}|_{3,})", RegexOptions.None, matchTimeoutMilliseconds: 50)]
    private static partial Regex RepeatedDelimitersRegex();

    [GeneratedRegex(@"<\s*(system|instruction|prompt|user|assistant)\s*>|""(system|instruction|prompt)""\s*:", RegexOptions.IgnoreCase, matchTimeoutMilliseconds: 50)]
    private static partial Regex StructureMarkersRegex();

    [GeneratedRegex(@"\b[A-Za-z0-9+/]{40,}={0,2}\b", RegexOptions.None, matchTimeoutMilliseconds: 50)]
    private static partial Regex Base64Regex();

    [GeneratedRegex(@"(?:\\x[0-9a-fA-F]{2}){10,}", RegexOptions.None, matchTimeoutMilliseconds: 50)]
    private static partial Regex HexEncodingRegex();

    #endregion
}
