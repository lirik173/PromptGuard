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
            return CreateDisabledResult();

        var stopwatch = Stopwatch.StartNew();
        var context = new HeuristicContext
        {
            Prompt = prompt,
            PatternMatchingResult = patternMatchingResult,
            Options = _globalOptions
        };

        try
        {
            var (analyzerResults, allSignals) = await RunAnalyzersAsync(context, cancellationToken);
            stopwatch.Stop();
            return BuildResult(analyzerResults, allSignals, stopwatch.Elapsed);
        }
        catch (OperationCanceledException)
        {
            _logger.LogWarning("Heuristic analysis cancelled");
            throw;
        }
    }

    private async Task<(List<HeuristicResult> Results, List<HeuristicSignal> Signals)> RunAnalyzersAsync(
        HeuristicContext context,
        CancellationToken cancellationToken)
    {
        var results = new List<HeuristicResult>();
        var signals = new List<HeuristicSignal>();

        foreach (var analyzer in _analyzers)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var result = await RunAnalyzerSafelyAsync(analyzer, context, cancellationToken);
            if (result != null)
            {
                results.Add(result);
                signals.AddRange(result.Signals);
            }
        }

        return (results, signals);
    }

    private async Task<HeuristicResult?> RunAnalyzerSafelyAsync(
        IHeuristicAnalyzer analyzer,
        HeuristicContext context,
        CancellationToken cancellationToken)
    {
        try
        {
            var stopwatch = Stopwatch.StartNew();
            var result = await analyzer.AnalyzeAsync(context, cancellationToken);
            stopwatch.Stop();

            _logger.LogDebug(
                "Heuristic analyzer {AnalyzerName} completed: Score={Score:F3}, Signals={SignalCount}, Duration={Duration}ms",
                analyzer.AnalyzerName,
                result.Score,
                result.Signals.Count,
                stopwatch.Elapsed.TotalMilliseconds);

            return result;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Heuristic analyzer {AnalyzerName} failed", analyzer.AnalyzerName);
            return null;
        }
    }

    private LayerResult BuildResult(
        List<HeuristicResult> analyzerResults,
        List<HeuristicSignal> allSignals,
        TimeSpan duration)
    {
        var aggregateScore = CalculateAggregateScore(analyzerResults);
        var isDefinitiveThreat = aggregateScore >= _heuristicOptions.DefinitiveThreatThreshold;
        var isDefinitiveSafe = aggregateScore <= _heuristicOptions.DefinitiveSafeThreshold;

        var data = BuildResultData(analyzerResults, allSignals, isDefinitiveThreat, isDefinitiveSafe);

        return new LayerResult
        {
            LayerName = LayerName,
            WasExecuted = true,
            Confidence = aggregateScore,
            IsThreat = aggregateScore >= 0.5,
            Duration = duration,
            Data = data
        };
    }

    private static Dictionary<string, object> BuildResultData(
        List<HeuristicResult> analyzerResults,
        List<HeuristicSignal> allSignals,
        bool isDefinitiveThreat,
        bool isDefinitiveSafe)
    {
        var data = new Dictionary<string, object>
        {
            ["signal_count"] = allSignals.Count,
            ["analyzer_count"] = analyzerResults.Count,
            ["is_definitive"] = isDefinitiveThreat || isDefinitiveSafe
        };

        if (isDefinitiveThreat)
            data["early_exit_reason"] = "definitive_threat";
        else if (isDefinitiveSafe)
            data["early_exit_reason"] = "definitive_safe";

        var topSignals = allSignals
            .OrderByDescending(s => s.Contribution)
            .Take(5)
            .Select(s => new { s.Name, s.Contribution, s.Description })
            .ToList();

        if (topSignals.Count > 0)
            data["top_signals"] = topSignals;

        return data;
    }

    private LayerResult CreateDisabledResult() => new()
    {
        LayerName = LayerName,
        WasExecuted = false
    };

    private static double CalculateAggregateScore(List<HeuristicResult> results)
    {
        if (results.Count == 0)
        {
            return 0.0;
        }

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
