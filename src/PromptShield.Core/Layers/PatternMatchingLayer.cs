using System.Diagnostics;
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

    /// <summary>
    /// Contribution to confidence score when a regex timeout occurs.
    /// This signals potential ReDoS attempt.
    /// </summary>
    private const double TimeoutContribution = 0.3;

    public PatternMatchingLayer(
        IEnumerable<IPatternProvider> patternProviders,
        PatternMatchingOptions options,
        ILogger<PatternMatchingLayer>? logger = null)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? NullLogger<PatternMatchingLayer>.Instance;
        _compiledPatterns = new List<CompiledPattern>();

        CompilePatterns(patternProviders ?? throw new ArgumentNullException(nameof(patternProviders)));
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

        var stopwatch = Stopwatch.StartNew();
        var matchedPatterns = new List<string>();
        var timedOutPatterns = new List<string>();
        var highestConfidence = 0.0;
        var highestSeverity = ThreatSeverity.Low;
        string? primaryOwaspCategory = null;

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
                    if (TimeoutContribution > highestConfidence)
                    {
                        highestConfidence = TimeoutContribution;
                    }

                    continue;
                }

                if (matchResult.IsMatch)
                {
                    matchedPatterns.Add(pattern.Pattern.Name);

                    var patternConfidence = pattern.Pattern.Severity.ToConfidence();

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
                    if (patternConfidence >= _options.EarlyExitThreshold)
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
            ["pattern_count"] = matchedPatterns.Count
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

    private void CompilePatterns(IEnumerable<IPatternProvider> providers)
    {
        var timeout = TimeSpan.FromMilliseconds(_options.TimeoutMs);
        var allPatterns = new List<Abstractions.Detection.DetectionPattern>();

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

        foreach (var pattern in allPatterns.Where(p => p.Enabled))
        {
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
            "Compiled {Count} patterns from {ProviderCount} providers",
            _compiledPatterns.Count,
            providers.Count());
    }

    /// <summary>
    /// Gets the number of compiled patterns currently loaded.
    /// </summary>
    public int PatternCount => _compiledPatterns.Count;
}
