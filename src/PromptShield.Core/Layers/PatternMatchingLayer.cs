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

    /// <summary>
    /// Accumulates pattern analysis state during scanning.
    /// </summary>
    private sealed class PatternAnalysisContext
    {
        private readonly PatternMatchingOptions _options;

        public List<string> MatchedPatterns { get; } = [];
        public List<string> TimedOutPatterns { get; } = [];
        public double HighestConfidence { get; private set; }
        public ThreatSeverity HighestSeverity { get; private set; } = ThreatSeverity.Low;
        public string? PrimaryOwaspCategory { get; private set; }

        public PatternAnalysisContext(PatternMatchingOptions options)
        {
            _options = options;
        }

        public void RecordTimeout(string patternName, double timeoutContribution)
        {
            TimedOutPatterns.Add(patternName);
            if (timeoutContribution > HighestConfidence)
                HighestConfidence = timeoutContribution;
        }

        public void RecordMatch(CompiledPattern pattern, double adjustedConfidence)
        {
            MatchedPatterns.Add(pattern.Pattern.Name);

            if (adjustedConfidence > HighestConfidence)
            {
                HighestConfidence = adjustedConfidence;
                PrimaryOwaspCategory = pattern.Pattern.OwaspCategory;
                HighestSeverity = pattern.Pattern.Severity;
            }
        }

        public bool IsThreat => MatchedPatterns.Count > 0;

        public Dictionary<string, object> BuildResultData(int disabledPatternCount)
        {
            var data = new Dictionary<string, object>
            {
                ["matched_patterns"] = MatchedPatterns,
                ["pattern_count"] = MatchedPatterns.Count,
                ["sensitivity"] = _options.Sensitivity.ToString()
            };

            if (TimedOutPatterns.Count > 0)
            {
                data["timed_out_patterns"] = TimedOutPatterns;
                data["timeout_count"] = TimedOutPatterns.Count;
                data["has_timeouts"] = true;
            }

            if (IsThreat)
            {
                data["owasp_category"] = PrimaryOwaspCategory ?? "LLM01";
                data["severity"] = HighestSeverity.ToString();
            }

            if (disabledPatternCount > 0)
            {
                data["disabled_patterns_count"] = disabledPatternCount;
            }

            return data;
        }
    }

    public PatternMatchingLayer(
        IEnumerable<IPatternProvider> patternProviders,
        PatternMatchingOptions options,
        ILogger<PatternMatchingLayer>? logger = null)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? NullLogger<PatternMatchingLayer>.Instance;
        _compiledPatterns = [];
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
            return Task.FromResult(CreateDisabledResult());

        if (IsAllowlisted(prompt))
        {
            _logger.LogDebug("Prompt matched pattern allowlist, skipping pattern matching");
            return Task.FromResult(CreateAllowlistedResult());
        }

        var stopwatch = Stopwatch.StartNew();
        var ctx = new PatternAnalysisContext(_options);
        var earlyExitThreshold = GetAdjustedEarlyExitThreshold();
        var timeoutContribution = GetAdjustedTimeoutContribution();

        try
        {
            var shouldEarlyExit = ScanPatterns(prompt, ctx, earlyExitThreshold, timeoutContribution, cancellationToken);
        }
        catch (OperationCanceledException)
        {
            _logger.LogWarning("Pattern matching cancelled");
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during pattern matching");
        }
        finally
        {
            stopwatch.Stop();
        }

        return Task.FromResult(new LayerResult
        {
            LayerName = LayerName,
            WasExecuted = true,
            Confidence = ctx.HighestConfidence,
            IsThreat = ctx.IsThreat,
            Duration = stopwatch.Elapsed,
            Data = ctx.BuildResultData(_disabledPatternIds.Count)
        });
    }

    private bool ScanPatterns(
        string prompt,
        PatternAnalysisContext ctx,
        double earlyExitThreshold,
        double timeoutContribution,
        CancellationToken cancellationToken)
    {
        foreach (var pattern in _compiledPatterns)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var matchResult = pattern.TryMatch(prompt);

            if (matchResult.TimedOut)
            {
                HandlePatternTimeout(pattern, ctx, timeoutContribution);
                continue;
            }

            if (matchResult.IsMatch)
            {
                var shouldExit = HandlePatternMatch(pattern, ctx, earlyExitThreshold);
                if (shouldExit)
                    return true;
            }
        }

        return false;
    }

    private void HandlePatternTimeout(CompiledPattern pattern, PatternAnalysisContext ctx, double timeoutContribution)
    {
        _logger.LogWarning(
            "Pattern timeout detected (potential ReDoS): {PatternName} ({PatternId})",
            pattern.Pattern.Name,
            pattern.Pattern.Id);

        ctx.RecordTimeout(pattern.Pattern.Name, timeoutContribution);
    }

    private bool HandlePatternMatch(CompiledPattern pattern, PatternAnalysisContext ctx, double earlyExitThreshold)
    {
        var patternConfidence = GetAdjustedConfidence(pattern.Pattern.Severity.ToConfidence());
        ctx.RecordMatch(pattern, patternConfidence);

        _logger.LogDebug(
            "Pattern matched: {PatternName} (Confidence: {Confidence:F3}, Severity: {Severity})",
            pattern.Pattern.Name,
            patternConfidence,
            pattern.Pattern.Severity);

        if (patternConfidence >= earlyExitThreshold)
        {
            _logger.LogInformation(
                "Early exit triggered by high-confidence pattern: {PatternName}",
                pattern.Pattern.Name);
            return true;
        }

        return false;
    }

    private LayerResult CreateDisabledResult() => new()
    {
        LayerName = LayerName,
        WasExecuted = false
    };

    private List<Regex> CompileAllowlistPatterns(List<string> patterns)
    {
        List<Regex> compiled = [];
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

    private void CompilePatterns(IEnumerable<IPatternProvider> providers)
    {
        var timeout = TimeSpan.FromMilliseconds(_options.TimeoutMs);
        List<DetectionPattern> allPatterns = [];

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
