using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using PromptShield.Abstractions.Analysis;
using PromptShield.Abstractions.Configuration;
using PromptShield.Core.Analysis;
using PromptShield.Core.Layers;

namespace PromptShield.Core.Pipeline;

/// <summary>
/// Orchestrates the multi-layer detection pipeline with early exit optimization.
/// </summary>
/// <remarks>
/// <para>Pipeline execution flow:</para>
/// <list type="number">
///   <item><b>Language Filter</b>: Gate - blocks unsupported languages</item>
///   <item><b>Pattern Matching</b>: Fast regex-based detection</item>
///   <item><b>Heuristics</b>: Statistical and structural analysis</item>
///   <item><b>ML Classification</b>: Model-based prediction</item>
/// </list>
/// <para>
/// All detection layers require language-specific patterns/vocabulary.
/// By default, only English is supported. Add patterns for other languages
/// via <see cref="PromptShield.Abstractions.Detection.Patterns.IPatternProvider"/>.
/// </para>
/// </remarks>
public sealed class PipelineOrchestrator
{
    private readonly PromptShieldOptions _options;
    private readonly LanguageFilterLayer? _languageFilterLayer;
    private readonly PatternMatchingLayer _patternLayer;
    private readonly HeuristicLayer _heuristicLayer;
    private readonly MLClassificationLayer? _mlLayer;
    private readonly SemanticAnalysisLayer? _semanticLayer;
    private readonly ILogger<PipelineOrchestrator> _logger;

    /// <summary>
    /// Encapsulates pipeline execution state to reduce parameter passing.
    /// </summary>
    private sealed class PipelineContext
    {
        public required Guid AnalysisId { get; init; }
        public required DateTimeOffset Timestamp { get; init; }
        public required Stopwatch Stopwatch { get; init; }
        public List<string> ExecutedLayers { get; } = [];
        public LanguageFilterResult? LanguageFilterResult { get; set; }
        public LayerResult? PatternResult { get; set; }
        public LayerResult? HeuristicResult { get; set; }
        public LayerResult? MlResult { get; set; }
    }

    public PipelineOrchestrator(
        PatternMatchingLayer patternLayer,
        HeuristicLayer heuristicLayer,
        MLClassificationLayer? mlLayer,
        PromptShieldOptions options,
        ILogger<PipelineOrchestrator>? logger = null)
        : this(null, patternLayer, heuristicLayer, mlLayer, null, options, logger)
    {
    }

    public PipelineOrchestrator(
        LanguageFilterLayer? languageFilterLayer,
        PatternMatchingLayer patternLayer,
        HeuristicLayer heuristicLayer,
        MLClassificationLayer? mlLayer,
        SemanticAnalysisLayer? semanticLayer,
        PromptShieldOptions options,
        ILogger<PipelineOrchestrator>? logger = null)
    {
        _languageFilterLayer = languageFilterLayer;
        _patternLayer = patternLayer ?? throw new ArgumentNullException(nameof(patternLayer));
        _heuristicLayer = heuristicLayer ?? throw new ArgumentNullException(nameof(heuristicLayer));
        _mlLayer = mlLayer;
        _semanticLayer = semanticLayer;
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? NullLogger<PipelineOrchestrator>.Instance;
    }

    /// <summary>
    /// Executes the detection pipeline with early exit optimization.
    /// </summary>
    public async Task<AnalysisResult> ExecuteAsync(
        AnalysisRequest request,
        Guid analysisId,
        CancellationToken cancellationToken = default)
    {
        var ctx = new PipelineContext
        {
            AnalysisId = analysisId,
            Timestamp = DateTimeOffset.UtcNow,
            Stopwatch = Stopwatch.StartNew()
        };

        _logger.LogInformation(
            "Starting analysis pipeline for AnalysisId={AnalysisId}, PromptLength={Length}",
            analysisId,
            request.Prompt.Length);

        try
        {
            // Stage 1: Language Filter
            var languageBlockResult = await ExecuteLanguageFilterAsync(ctx, request.Prompt, cancellationToken);
            if (languageBlockResult != null)
                return languageBlockResult;

            // Stage 2: Pattern Matching
            var patternEarlyExit = await ExecutePatternMatchingAsync(ctx, request.Prompt, cancellationToken);
            if (patternEarlyExit != null)
                return patternEarlyExit;

            // Stage 3: Heuristics
            var heuristicEarlyExit = await ExecuteHeuristicLayerAsync(ctx, request.Prompt, cancellationToken);
            if (heuristicEarlyExit != null)
                return heuristicEarlyExit;

            // Stage 4: ML Classification (conditional)
            var mlEarlyExit = await ExecuteMLLayerAsync(ctx, request.Prompt, cancellationToken);
            if (mlEarlyExit != null)
                return mlEarlyExit;

            // Final aggregation
            return CreateFinalResult(ctx);
        }
        catch (OperationCanceledException)
        {
            _logger.LogWarning("Pipeline cancelled: AnalysisId={AnalysisId}", analysisId);
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Pipeline failed: AnalysisId={AnalysisId}", analysisId);
            throw;
        }
    }

    private async Task<AnalysisResult?> ExecuteLanguageFilterAsync(
        PipelineContext ctx,
        string prompt,
        CancellationToken cancellationToken)
    {
        if (_languageFilterLayer == null || !_options.Language.Enabled)
            return null;

        ctx.LanguageFilterResult = await _languageFilterLayer.AnalyzeAsync(prompt, cancellationToken);

        if (!ctx.LanguageFilterResult.WasExecuted)
            return null;

        ctx.ExecutedLayers.Add(_languageFilterLayer.LayerName);

        _logger.LogDebug(
            "Language filter: ShouldProceed={ShouldProceed}, Language={Language}",
            ctx.LanguageFilterResult.ShouldProceed,
            ctx.LanguageFilterResult.LanguageResult?.LanguageName ?? "unknown");

        if (ctx.LanguageFilterResult.ShouldProceed || !ctx.LanguageFilterResult.IsBlocked)
            return null;

        _logger.LogInformation(
            "Request blocked by language filter: {Message}",
            ctx.LanguageFilterResult.Message);

        return CreateLanguageBlockResult(ctx);
    }

    private async Task<AnalysisResult?> ExecutePatternMatchingAsync(
        PipelineContext ctx,
        string prompt,
        CancellationToken cancellationToken)
    {
        ctx.PatternResult = await ExecuteLayerSafelyAsync(
            () => _patternLayer.AnalyzeAsync(prompt, cancellationToken),
            _patternLayer.LayerName,
            ctx.ExecutedLayers);

        _logger.LogDebug(
            "Pattern matching: IsThreat={IsThreat}, Confidence={Confidence:P0}",
            ctx.PatternResult.IsThreat,
            ctx.PatternResult.Confidence);

        if (ctx.PatternResult.IsThreat != true ||
            ctx.PatternResult.Confidence < _options.PatternMatching.EarlyExitThreshold)
            return null;

        _logger.LogInformation(
            "Early exit: pattern matching (Confidence={Confidence:P0})",
            ctx.PatternResult.Confidence);

        return CreateEarlyExitResult(ctx, _patternLayer.LayerName);
    }

    private async Task<AnalysisResult?> ExecuteHeuristicLayerAsync(
        PipelineContext ctx,
        string prompt,
        CancellationToken cancellationToken)
    {
        ctx.HeuristicResult = await ExecuteLayerSafelyAsync(
            () => _heuristicLayer.AnalyzeAsync(prompt, ctx.PatternResult!, cancellationToken),
            _heuristicLayer.LayerName,
            ctx.ExecutedLayers);

        _logger.LogDebug(
            "Heuristics: IsThreat={IsThreat}, Confidence={Confidence:P0}",
            ctx.HeuristicResult.IsThreat,
            ctx.HeuristicResult.Confidence);

        if (!_heuristicLayer.IsDefinitiveResult(ctx.HeuristicResult))
            return null;

        var reason = ctx.HeuristicResult.IsThreat == true ? "threat" : "safe";
        _logger.LogInformation(
            "Early exit: heuristics definitive {Reason} (Confidence={Confidence:P0})",
            reason,
            ctx.HeuristicResult.Confidence);

        return CreateEarlyExitResult(ctx, _heuristicLayer.LayerName);
    }

    private async Task<AnalysisResult?> ExecuteMLLayerAsync(
        PipelineContext ctx,
        string prompt,
        CancellationToken cancellationToken)
    {
        if (_mlLayer == null || !_options.ML.Enabled)
            return null;

        var combinedConfidence = CalculateCombinedConfidence(ctx.PatternResult!, ctx.HeuristicResult!);
        if (combinedConfidence < _options.ML.Threshold * 0.5)
        {
            _logger.LogDebug("Skipping ML layer: low combined risk");
            return null;
        }

        ctx.MlResult = await ExecuteLayerSafelyAsync(
            () => _mlLayer.AnalyzeAsync(prompt, cancellationToken),
            _mlLayer.LayerName,
            ctx.ExecutedLayers);

        _logger.LogDebug(
            "ML classification: IsThreat={IsThreat}, Confidence={Confidence:P0}",
            ctx.MlResult.IsThreat,
            ctx.MlResult.Confidence);

        if (ctx.MlResult.IsThreat != true || ctx.MlResult.Confidence < _options.ML.Threshold)
            return null;

        _logger.LogInformation(
            "Early exit: ML classification (Confidence={Confidence:P0})",
            ctx.MlResult.Confidence);

        return CreateEarlyExitResult(ctx, _mlLayer.LayerName);
    }

    private async Task<LayerResult> ExecuteLayerSafelyAsync(
        Func<Task<LayerResult>> layerAction,
        string layerName,
        List<string> executedLayers)
    {
        try
        {
            var result = await layerAction();
            executedLayers.Add(layerName);
            return result;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "{LayerName} layer failed", layerName);
            return CreateFailedLayerResult(layerName);
        }
    }

    private AnalysisResult CreateEarlyExitResult(PipelineContext ctx, string decisionLayer)
    {
        ctx.Stopwatch.Stop();

        var (isThreat, confidence, threatInfo) = DetermineThreat(
            ctx.PatternResult!,
            ctx.HeuristicResult,
            ctx.MlResult,
            decisionLayer);

        return new AnalysisResult
        {
            AnalysisId = ctx.AnalysisId,
            IsThreat = isThreat,
            Confidence = confidence,
            ThreatInfo = threatInfo,
            Breakdown = CreateBreakdown(ctx),
            DecisionLayer = decisionLayer,
            Duration = ctx.Stopwatch.Elapsed,
            Timestamp = ctx.Timestamp
        };
    }

    private AnalysisResult CreateFinalResult(PipelineContext ctx)
    {
        ctx.Stopwatch.Stop();

        var result = CreateAggregatedResult(ctx);

        _logger.LogInformation(
            "Analysis completed: IsThreat={IsThreat}, Confidence={Confidence:P0}, Duration={Duration}ms",
            result.IsThreat,
            result.Confidence,
            result.Duration.TotalMilliseconds);

        return result;
    }

    private DetectionBreakdown CreateBreakdown(PipelineContext ctx) => new()
    {
        LanguageFilter = ctx.LanguageFilterResult?.ToLayerResult(),
        PatternMatching = ctx.PatternResult ?? CreateSkippedLayerResult("PatternMatching"),
        Heuristics = ctx.HeuristicResult ?? CreateSkippedLayerResult("Heuristics"),
        MLClassification = ctx.MlResult,
        SemanticAnalysis = null,
        ExecutedLayers = ctx.ExecutedLayers
    };

    private AnalysisResult CreateAggregatedResult(PipelineContext ctx)
    {
        var aggregateConfidence = CalculateAggregateConfidence(
            ctx.PatternResult!,
            ctx.HeuristicResult!,
            ctx.MlResult);

        var isThreat = aggregateConfidence >= _options.ThreatThreshold;

        var threatInfo = isThreat
            ? ThreatInfoBuilder.Build(ctx.PatternResult!, ctx.HeuristicResult!, ctx.MlResult, aggregateConfidence)
            : null;

        var breakdown = CreateBreakdown(ctx);

        return new AnalysisResult
        {
            AnalysisId = ctx.AnalysisId,
            IsThreat = isThreat,
            Confidence = aggregateConfidence,
            ThreatInfo = threatInfo,
            Breakdown = _options.IncludeBreakdown ? breakdown : CreateMinimalBreakdown(ctx.ExecutedLayers),
            DecisionLayer = "Aggregated",
            Duration = ctx.Stopwatch.Elapsed,
            Timestamp = ctx.Timestamp
        };
    }

    private double CalculateAggregateConfidence(
        LayerResult patternResult,
        LayerResult heuristicResult,
        LayerResult? mlResult)
    {
        var patternWeight = _options.Aggregation.PatternMatchingWeight;
        var heuristicWeight = _options.Aggregation.HeuristicsWeight;
        var mlWeight = _options.Aggregation.MLClassificationWeight;

        var totalWeight = patternWeight;
        if (heuristicResult.WasExecuted) totalWeight += heuristicWeight;
        if (mlResult is { WasExecuted: true }) totalWeight += mlWeight;

        var patternConfidence = (patternResult.Confidence ?? 0.0) * patternWeight / totalWeight;
        var heuristicConfidence = heuristicResult.WasExecuted
            ? (heuristicResult.Confidence ?? 0.0) * heuristicWeight / totalWeight
            : 0.0;
        var mlConfidence = mlResult is { WasExecuted: true }
            ? (mlResult.Confidence ?? 0.0) * mlWeight / totalWeight
            : 0.0;

        return Math.Clamp(patternConfidence + heuristicConfidence + mlConfidence, 0.0, 1.0);
    }

    private AnalysisResult CreateLanguageBlockResult(PipelineContext ctx)
    {
        ctx.Stopwatch.Stop();

        var languageResult = ctx.LanguageFilterResult!;
        var detectedLanguage = languageResult.LanguageResult?.LanguageName ?? "Unknown";
        var supportedLanguages = string.Join(", ", _options.Language.SupportedLanguages);

        var threatInfo = new ThreatInfo
        {
            OwaspCategory = "LLM01",
            ThreatType = "Unsupported Language",
            Explanation = $"Input language '{detectedLanguage}' is not supported. Supported languages: [{supportedLanguages}].",
            UserFacingMessage = $"Please submit your request in a supported language ({supportedLanguages}).",
            Severity = ThreatSeverity.Medium,
            DetectionSources = ["LanguageFilter"]
        };

        var breakdown = new DetectionBreakdown
        {
            LanguageFilter = languageResult.ToLayerResult(),
            PatternMatching = CreateSkippedLayerResult("PatternMatching"),
            Heuristics = CreateSkippedLayerResult("Heuristics"),
            MLClassification = null,
            SemanticAnalysis = null,
            ExecutedLayers = ctx.ExecutedLayers
        };

        return new AnalysisResult
        {
            AnalysisId = ctx.AnalysisId,
            IsThreat = true,
            Confidence = languageResult.BlockConfidence,
            ThreatInfo = threatInfo,
            Breakdown = _options.IncludeBreakdown ? breakdown : CreateMinimalBreakdown(ctx.ExecutedLayers),
            DecisionLayer = "LanguageFilter",
            Duration = ctx.Stopwatch.Elapsed,
            Timestamp = ctx.Timestamp
        };
    }

    private static double CalculateCombinedConfidence(LayerResult patternResult, LayerResult heuristicResult)
    {
        var patternConfidence = patternResult.Confidence ?? 0.0;
        var heuristicConfidence = heuristicResult.Confidence ?? 0.0;
        return (patternConfidence + heuristicConfidence) / 2.0;
    }

    private (bool isThreat, double confidence, ThreatInfo? threatInfo) DetermineThreat(
        LayerResult patternResult,
        LayerResult? heuristicResult,
        LayerResult? mlResult,
        string decisionLayer)
    {
        var decidingResult = decisionLayer switch
        {
            "PatternMatching" => patternResult,
            "Heuristics" => heuristicResult,
            "MLClassification" => mlResult,
            _ => patternResult
        };

        if (decidingResult == null) return (false, 0.0, null);

        var isThreat = decidingResult.IsThreat ?? false;
        var confidence = decidingResult.Confidence ?? 0.0;

        ThreatInfo? threatInfo = null;
        if (isThreat)
        {
            threatInfo = ThreatInfoBuilder.BuildFromSingleLayer(decidingResult, decisionLayer, confidence);
        }

        return (isThreat, confidence, threatInfo);
    }

    private static LayerResult CreateFailedLayerResult(string layerName) => new()
    {
        LayerName = layerName,
        WasExecuted = true,
        Confidence = 0.0,
        IsThreat = false,
        Duration = TimeSpan.Zero,
        Data = new Dictionary<string, object> { ["error"] = "Layer execution failed" }
    };

    private static LayerResult CreateSkippedLayerResult(string layerName) => new()
    {
        LayerName = layerName,
        WasExecuted = false
    };

    private static DetectionBreakdown CreateMinimalBreakdown(List<string> executedLayers) => new()
    {
        PatternMatching = CreateSkippedLayerResult("PatternMatching"),
        Heuristics = CreateSkippedLayerResult("Heuristics"),
        MLClassification = null,
        SemanticAnalysis = null,
        ExecutedLayers = executedLayers
    };
}
