using System.Diagnostics;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using PromptShield.Abstractions.Analysis;
using PromptShield.Abstractions.Configuration;
using PromptShield.Abstractions.Detection;
using PromptShield.Abstractions.Detection.Patterns;
using PromptShield.Core.Patterns;

namespace PromptShield.Core.Layers;

/// <summary>
/// Detection layer that uses compiled regex patterns to identify known attack signatures.
/// </summary>
public sealed class PatternMatchingLayer
{
    private readonly PatternMatchingOptions _options;
    private readonly ILogger<PatternMatchingLayer> _logger;
    private readonly List<CompiledPattern> _compiledPatterns;
    private readonly HashSet<string> _disabledPatternIds;
    private readonly List<Regex> _allowlistRegex;

    public PatternMatchingLayer(
        IEnumerable<IPatternProvider> patternProviders,
        PatternMatchingOptions options,
        ILogger<PatternMatchingLayer>? logger = null)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? NullLogger<PatternMatchingLayer>.Instance;
        _compiledPatterns = new List<CompiledPattern>();
        _disabledPatternIds = new HashSet<string>(options.DisabledPatternIds, StringComparer.OrdinalIgnoreCase);
        _allowlistRegex = CompileAllowlistPatterns(options.AllowedPatterns);

        CompilePatterns(patternProviders ?? throw new ArgumentNullException(nameof(patternProviders)));

        if (_disabledPatternIds.Count > 0)
        {
            _logger.LogInformation(
                "PatternMatchingLayer initialized with {DisabledCount} disabled patterns",
                _disabledPatternIds.Count);
        }
    }

    public string LayerName => "PatternMatching";

    public Task<LayerResult> AnalyzeAsync(
        string prompt,
        CancellationToken cancellationToken = default)
    {
        if (!_options.Enabled)
        {
            return Task.FromResult(new LayerResult
            {
                LayerName = LayerName,
                WasExecuted = false
            });
        }

        // Check allowlist first
        if (IsAllowlisted(prompt))
        {
            _logger.LogDebug("Prompt matched pattern allowlist, skipping pattern matching");
            return Task.FromResult(CreateAllowlistedResult());
        }

        var stopwatch = Stopwatch.StartNew();
        var matchedPatterns = new List<string>();
        var timedOutPatterns = new List<string>();
        var highestConfidence = 0.0;
        var highestSeverity = ThreatSeverity.Low;
        string? primaryOwaspCategory = null;

        // Get sensitivity-adjusted values
        var timeoutContribution = GetAdjustedTimeoutContribution();
        var earlyExitThreshold = GetAdjustedEarlyExitThreshold();

        try
        {
            foreach (var pattern in _compiledPatterns)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var matchResult = pattern.TryMatch(prompt);

                if (matchResult.TimedOut)
                {
                    timedOutPatterns.Add(pattern.Pattern.Name);

                    _logger.LogWarning(
                        "Pattern timeout detected (potential ReDoS): {PatternName} ({PatternId})",
                        pattern.Pattern.Name,
                        pattern.Pattern.Id);

                    // Timeout contributes to suspicion score
                    if (timeoutContribution > highestConfidence)
                    {
                        highestConfidence = timeoutContribution;
                    }

                    continue;
                }

                if (matchResult.IsMatch)
                {
                    matchedPatterns.Add(pattern.Pattern.Name);

                    var patternConfidence = GetAdjustedConfidence(pattern.Pattern.Severity.ToConfidence());

                    if (patternConfidence > highestConfidence)
                    {
                        highestConfidence = patternConfidence;
                        primaryOwaspCategory = pattern.Pattern.OwaspCategory;
                        highestSeverity = pattern.Pattern.Severity;
                    }

                    _logger.LogDebug(
                        "Pattern matched: {PatternName} (Confidence: {Confidence:F3}, Severity: {Severity})",
                        pattern.Pattern.Name,
                        patternConfidence,
                        pattern.Pattern.Severity);

                    // Early exit if high confidence match
                    if (patternConfidence >= earlyExitThreshold)
                    {
                        _logger.LogInformation(
                            "Early exit triggered by high-confidence pattern: {PatternName}",
                            pattern.Pattern.Name);
                        break;
                    }
                }
            }
        }
        catch (OperationCanceledException)
        {
            _logger.LogWarning("Pattern matching cancelled");
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during pattern matching");
            // Continue with partial results
        }
        finally
        {
            stopwatch.Stop();
        }

        var isThreat = matchedPatterns.Count > 0;
        var data = new Dictionary<string, object>
        {
            ["matched_patterns"] = matchedPatterns,
            ["pattern_count"] = matchedPatterns.Count,
            ["sensitivity"] = _options.Sensitivity.ToString()
        };

        // Include timeout information for downstream layers
        if (timedOutPatterns.Count > 0)
        {
            data["timed_out_patterns"] = timedOutPatterns;
            data["timeout_count"] = timedOutPatterns.Count;
            data["has_timeouts"] = true;
        }

        if (isThreat)
        {
            data["owasp_category"] = primaryOwaspCategory ?? "LLM01";
            data["severity"] = highestSeverity.ToString();
        }

        if (_disabledPatternIds.Count > 0)
        {
            data["disabled_patterns_count"] = _disabledPatternIds.Count;
        }

        return Task.FromResult(new LayerResult
        {
            LayerName = LayerName,
            WasExecuted = true,
            Confidence = highestConfidence,
            IsThreat = isThreat,
            Duration = stopwatch.Elapsed,
            Data = data
        });
    }

    #region Allowlist

    private List<Regex> CompileAllowlistPatterns(List<string> patterns)
    {
        var compiled = new List<Regex>();
        foreach (var pattern in patterns)
        {
            try
            {
                compiled.Add(new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.Compiled,
                    TimeSpan.FromMilliseconds(_options.TimeoutMs)));
            }
            catch (ArgumentException ex)
            {
                _logger.LogWarning(ex, "Invalid regex pattern in pattern matching allowlist: {Pattern}", pattern);
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
                // Timeout on allowlist - don't allow
            }
        }
        return false;
    }

    private LayerResult CreateAllowlistedResult() => new()
    {
        LayerName = LayerName,
        WasExecuted = true,
        Confidence = 0.0,
        IsThreat = false,
        Data = new Dictionary<string, object>
        {
            ["status"] = "allowlisted",
            ["reason"] = "Prompt matched allowlist pattern"
        }
    };

    #endregion

    #region Sensitivity Adjustments

    private double GetAdjustedTimeoutContribution()
    {
        var baseValue = _options.TimeoutContribution;
        return _options.Sensitivity switch
        {
            SensitivityLevel.Low => baseValue * 0.7,
            SensitivityLevel.Medium => baseValue,
            SensitivityLevel.High => Math.Min(1.0, baseValue * 1.3),
            SensitivityLevel.Paranoid => Math.Min(1.0, baseValue * 1.6),
            _ => baseValue
        };
    }

    private double GetAdjustedEarlyExitThreshold()
    {
        var baseValue = _options.EarlyExitThreshold;
        return _options.Sensitivity switch
        {
            SensitivityLevel.Low => Math.Min(1.0, baseValue + 0.05),
            SensitivityLevel.Medium => baseValue,
            SensitivityLevel.High => Math.Max(0.5, baseValue - 0.05),
            SensitivityLevel.Paranoid => Math.Max(0.4, baseValue - 0.1),
            _ => baseValue
        };
    }

    private double GetAdjustedConfidence(double baseConfidence)
    {
        return _options.Sensitivity switch
        {
            SensitivityLevel.Low => baseConfidence * 0.85,
            SensitivityLevel.Medium => baseConfidence,
            SensitivityLevel.High => Math.Min(1.0, baseConfidence * 1.1),
            SensitivityLevel.Paranoid => Math.Min(1.0, baseConfidence * 1.2),
            _ => baseConfidence
        };
    }

    #endregion

    private void CompilePatterns(IEnumerable<IPatternProvider> providers)
    {
        var timeout = TimeSpan.FromMilliseconds(_options.TimeoutMs);
        var allPatterns = new List<DetectionPattern>();

        foreach (var provider in providers)
        {
            try
            {
                var patterns = provider.GetPatterns();
                allPatterns.AddRange(patterns);

                _logger.LogInformation(
                    "Loaded patterns from provider: {ProviderName}",
                    provider.ProviderName);
            }
            catch (Exception ex)
            {
                _logger.LogError(
                    ex,
                    "Failed to load patterns from provider: {ProviderName}",
                    provider.ProviderName);
            }
        }

        var skippedCount = 0;
        foreach (var pattern in allPatterns.Where(p => p.Enabled))
        {
            // Check if pattern is disabled
            if (_disabledPatternIds.Contains(pattern.Id))
            {
                _logger.LogDebug("Skipping disabled pattern: {PatternId} - {PatternName}", pattern.Id, pattern.Name);
                skippedCount++;
                continue;
            }

            try
            {
                var compiled = new CompiledPattern(pattern, timeout);
                _compiledPatterns.Add(compiled);
            }
            catch (Exception ex)
            {
                _logger.LogError(
                    ex,
                    "Failed to compile pattern: {PatternId} - {PatternName}",
                    pattern.Id,
                    pattern.Name);
            }
        }

        _logger.LogInformation(
            "Compiled {Count} patterns from {ProviderCount} providers (skipped {SkippedCount} disabled)",
            _compiledPatterns.Count,
            providers.Count(),
            skippedCount);
    }

    /// <summary>
    /// Gets the number of compiled patterns currently loaded.
    /// </summary>
    public int PatternCount => _compiledPatterns.Count;

    /// <summary>
    /// Gets the number of disabled patterns.
    /// </summary>
    public int DisabledPatternCount => _disabledPatternIds.Count;
}
