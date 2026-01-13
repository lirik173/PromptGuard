using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using PromptShield.Abstractions.Analysis;
using PromptShield.Abstractions.Analyzers.Heuristics;
using PromptShield.Abstractions.Configuration;

namespace PromptShield.Core.Layers;

/// <summary>
/// Detection layer that performs heuristic analysis of prompt structure and characteristics.
/// </summary>
public sealed class HeuristicLayer
{
    private readonly HeuristicOptions _heuristicOptions;
    private readonly PromptShieldOptions _globalOptions;
    private readonly ILogger<HeuristicLayer> _logger;
    private readonly IReadOnlyList<IHeuristicAnalyzer> _analyzers;

    public HeuristicLayer(
        IEnumerable<IHeuristicAnalyzer> analyzers,
        HeuristicOptions heuristicOptions,
        PromptShieldOptions globalOptions,
        ILogger<HeuristicLayer>? logger = null)
    {
        _heuristicOptions = heuristicOptions ?? throw new ArgumentNullException(nameof(heuristicOptions));
        _globalOptions = globalOptions ?? throw new ArgumentNullException(nameof(globalOptions));
        _logger = logger ?? NullLogger<HeuristicLayer>.Instance;
        _analyzers = (analyzers ?? throw new ArgumentNullException(nameof(analyzers))).ToList();

        if (_analyzers.Count == 0)
        {
            _logger.LogWarning("No heuristic analyzers registered");
        }
        else
        {
            _logger.LogInformation(
                "Initialized HeuristicLayer with {Count} analyzers",
                _analyzers.Count);
        }
    }

    public string LayerName => "Heuristics";

    public async Task<LayerResult> AnalyzeAsync(
        string prompt,
        LayerResult patternMatchingResult,
        CancellationToken cancellationToken = default)
    {
        if (!_heuristicOptions.Enabled)
        {
            return new LayerResult
            {
                LayerName = LayerName,
                WasExecuted = false
            };
        }

        var stopwatch = Stopwatch.StartNew();
        var allSignals = new List<HeuristicSignal>();
        var analyzerResults = new List<HeuristicResult>();

        try
        {
            var context = new HeuristicContext
            {
                Prompt = prompt,
                PatternMatchingResult = patternMatchingResult,
                Options = _globalOptions
            };

            foreach (var analyzer in _analyzers)
            {
                cancellationToken.ThrowIfCancellationRequested();

                try
                {
                    var analyzerStopwatch = Stopwatch.StartNew();
                    var result = await analyzer.AnalyzeAsync(context, cancellationToken);
                    analyzerStopwatch.Stop();

                    analyzerResults.Add(result);
                    allSignals.AddRange(result.Signals);

                    _logger.LogDebug(
                        "Heuristic analyzer {AnalyzerName} completed: Score={Score:F3}, Signals={SignalCount}, Duration={Duration}ms",
                        analyzer.AnalyzerName,
                        result.Score,
                        result.Signals.Count,
                        analyzerStopwatch.Elapsed.TotalMilliseconds);
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    _logger.LogError(
                        ex,
                        "Heuristic analyzer {AnalyzerName} failed",
                        analyzer.AnalyzerName);
                    // Continue with other analyzers
                }
            }
        }
        catch (OperationCanceledException)
        {
            _logger.LogWarning("Heuristic analysis cancelled");
            throw;
        }
        finally
        {
            stopwatch.Stop();
        }

        // Aggregate score from all analyzers using weighted average
        var aggregateScore = CalculateAggregateScore(analyzerResults);

        // Determine if result is definitive
        var isDefinitiveThreat = aggregateScore >= _heuristicOptions.DefinitiveThreatThreshold;
        var isDefinitiveSafe = aggregateScore <= _heuristicOptions.DefinitiveSafeThreshold;
        var isThreat = aggregateScore >= 0.5;

        var data = new Dictionary<string, object>
        {
            ["signal_count"] = allSignals.Count,
            ["analyzer_count"] = analyzerResults.Count,
            ["is_definitive"] = isDefinitiveThreat || isDefinitiveSafe
        };

        if (isDefinitiveThreat)
        {
            data["early_exit_reason"] = "definitive_threat";
        }
        else if (isDefinitiveSafe)
        {
            data["early_exit_reason"] = "definitive_safe";
        }

        // Include top signals in data
        var topSignals = allSignals
            .OrderByDescending(s => s.Contribution)
            .Take(5)
            .Select(s => new { s.Name, s.Contribution, s.Description })
            .ToList();

        if (topSignals.Count > 0)
        {
            data["top_signals"] = topSignals;
        }

        return new LayerResult
        {
            LayerName = LayerName,
            WasExecuted = true,
            Confidence = aggregateScore,
            IsThreat = isThreat,
            Duration = stopwatch.Elapsed,
            Data = data
        };
    }

    private static double CalculateAggregateScore(List<HeuristicResult> results)
    {
        if (results.Count == 0)
        {
            return 0.0;
        }

        // Use weighted average based on analyzer weights
        // For now, simple average (weights will be added when IHeuristicAnalyzer.Weight is used)
        var aggregateScore = results.Average(r => r.Score);
        return Math.Clamp(aggregateScore, 0.0, 1.0);
    }

    /// <summary>
    /// Checks if the result is definitive (should trigger early exit).
    /// </summary>
    public bool IsDefinitiveResult(LayerResult result)
    {
        if (result.Data == null)
            return false;

        return result.Data.TryGetValue("is_definitive", out var value) &&
               value is bool isDefinitive &&
               isDefinitive;
    }
}
