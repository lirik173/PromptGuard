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
        var timestamp = DateTimeOffset.UtcNow;
        var overallStopwatch = Stopwatch.StartNew();
        var executedLayers = new List<string>();
        LanguageFilterResult? languageFilterResult = null;

        _logger.LogInformation(
            "Starting analysis pipeline for AnalysisId={AnalysisId}, PromptLength={Length}",
            analysisId,
            request.Prompt.Length);

        try
        {
            // Layer 0: Language Filter (gate)
            if (_languageFilterLayer != null && _options.Language.Enabled)
            {
                languageFilterResult = await _languageFilterLayer.AnalyzeAsync(
                    request.Prompt,
                    cancellationToken);

                if (languageFilterResult.WasExecuted)
                {
                    executedLayers.Add(_languageFilterLayer.LayerName);

                    _logger.LogDebug(
                        "Language filter: ShouldProceed={ShouldProceed}, Language={Language}",
                        languageFilterResult.ShouldProceed,
                        languageFilterResult.LanguageResult?.LanguageName ?? "unknown");

                    // Block if language not supported
                    if (!languageFilterResult.ShouldProceed && languageFilterResult.IsBlocked)
                    {
                        _logger.LogInformation(
                            "Request blocked by language filter: {Message}",
                            languageFilterResult.Message);

                        return CreateLanguageBlockResult(
                            analysisId,
                            timestamp,
                            overallStopwatch,
                            languageFilterResult,
                            executedLayers);
                    }
                }
            }

            // Layer 1: Pattern Matching
            LayerResult patternResult;
            try
            {
                patternResult = await _patternLayer.AnalyzeAsync(request.Prompt, cancellationToken);
                executedLayers.Add(_patternLayer.LayerName);

                _logger.LogDebug(
                    "Pattern matching: IsThreat={IsThreat}, Confidence={Confidence:P0}",
                    patternResult.IsThreat,
                    patternResult.Confidence);

                // Early exit on high-confidence pattern match
                if (patternResult.IsThreat == true &&
                    patternResult.Confidence >= _options.PatternMatching.EarlyExitThreshold)
                {
                    _logger.LogInformation(
                        "Early exit: pattern matching (Confidence={Confidence:P0})",
                        patternResult.Confidence);

                    return CreateResult(
                        analysisId,
                        timestamp,
                        overallStopwatch,
                        languageFilterResult,
                        patternResult,
                        heuristicResult: null,
                        mlResult: null,
                        executedLayers,
                        _patternLayer.LayerName);
                }
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Pattern matching layer failed");
                patternResult = CreateFailedLayerResult(_patternLayer.LayerName);
            }

            // Layer 2: Heuristic Analysis
            LayerResult heuristicResult;
            try
            {
                heuristicResult = await _heuristicLayer.AnalyzeAsync(
                    request.Prompt,
                    patternResult,
                    cancellationToken);
                executedLayers.Add(_heuristicLayer.LayerName);

                _logger.LogDebug(
                    "Heuristics: IsThreat={IsThreat}, Confidence={Confidence:P0}",
                    heuristicResult.IsThreat,
                    heuristicResult.Confidence);

                // Early exit on definitive heuristic result
                if (_heuristicLayer.IsDefinitiveResult(heuristicResult))
                {
                    var reason = heuristicResult.IsThreat == true ? "threat" : "safe";
                    _logger.LogInformation(
                        "Early exit: heuristics definitive {Reason} (Confidence={Confidence:P0})",
                        reason,
                        heuristicResult.Confidence);

                    return CreateResult(
                        analysisId,
                        timestamp,
                        overallStopwatch,
                        languageFilterResult,
                        patternResult,
                        heuristicResult,
                        mlResult: null,
                        executedLayers,
                        _heuristicLayer.LayerName);
                }
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Heuristic layer failed");
                heuristicResult = CreateFailedLayerResult(_heuristicLayer.LayerName);
            }

            // Layer 3: ML Classification (conditional)
            LayerResult? mlResult = null;
            if (_mlLayer != null && _options.ML.Enabled)
            {
                var combinedConfidence = CalculateCombinedConfidence(patternResult, heuristicResult);
                var shouldSkipML = combinedConfidence < _options.ML.Threshold * 0.5;

                if (!shouldSkipML)
                {
                    try
                    {
                        mlResult = await _mlLayer.AnalyzeAsync(request.Prompt, cancellationToken);
                        executedLayers.Add(_mlLayer.LayerName);

                        _logger.LogDebug(
                            "ML classification: IsThreat={IsThreat}, Confidence={Confidence:P0}",
                            mlResult.IsThreat,
                            mlResult.Confidence);

                        // Early exit on high-confidence ML detection
                        if (mlResult.IsThreat == true && mlResult.Confidence >= _options.ML.Threshold)
                        {
                            _logger.LogInformation(
                                "Early exit: ML classification (Confidence={Confidence:P0})",
                                mlResult.Confidence);

                            return CreateResult(
                                analysisId,
                                timestamp,
                                overallStopwatch,
                                languageFilterResult,
                                patternResult,
                                heuristicResult,
                                mlResult,
                                executedLayers,
                                _mlLayer.LayerName);
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        throw;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "ML classification layer failed");
                        mlResult = CreateFailedLayerResult(_mlLayer.LayerName);
                    }
                }
                else
                {
                    _logger.LogDebug("Skipping ML layer: low combined risk");
                }
            }

            // Final aggregated result
            overallStopwatch.Stop();

            var finalResult = CreateAggregatedResult(
                analysisId,
                timestamp,
                overallStopwatch,
                languageFilterResult,
                patternResult,
                heuristicResult,
                mlResult,
                executedLayers);

            _logger.LogInformation(
                "Analysis completed: IsThreat={IsThreat}, Confidence={Confidence:P0}, Duration={Duration}ms",
                finalResult.IsThreat,
                finalResult.Confidence,
                finalResult.Duration.TotalMilliseconds);

            return finalResult;
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

    private AnalysisResult CreateResult(
        Guid analysisId,
        DateTimeOffset timestamp,
        Stopwatch stopwatch,
        LanguageFilterResult? languageFilterResult,
        LayerResult patternResult,
        LayerResult? heuristicResult,
        LayerResult? mlResult,
        List<string> executedLayers,
        string decisionLayer)
    {
        stopwatch.Stop();

        var (isThreat, confidence, threatInfo) = DetermineThreat(
            patternResult,
            heuristicResult,
            mlResult,
            decisionLayer);

        var breakdown = new DetectionBreakdown
        {
            LanguageFilter = languageFilterResult?.ToLayerResult(),
            PatternMatching = patternResult,
            Heuristics = heuristicResult ?? CreateSkippedLayerResult("Heuristics"),
            MLClassification = mlResult,
            SemanticAnalysis = null,
            ExecutedLayers = executedLayers
        };

        return new AnalysisResult
        {
            AnalysisId = analysisId,
            IsThreat = isThreat,
            Confidence = confidence,
            ThreatInfo = threatInfo,
            Breakdown = _options.IncludeBreakdown ? breakdown : CreateMinimalBreakdown(executedLayers),
            DecisionLayer = decisionLayer,
            Duration = stopwatch.Elapsed,
            Timestamp = timestamp
        };
    }

    private AnalysisResult CreateAggregatedResult(
        Guid analysisId,
        DateTimeOffset timestamp,
        Stopwatch stopwatch,
        LanguageFilterResult? languageFilterResult,
        LayerResult patternResult,
        LayerResult heuristicResult,
        LayerResult? mlResult,
        List<string> executedLayers)
    {
        var patternWeight = _options.Aggregation.PatternMatchingWeight;
        var heuristicWeight = _options.Aggregation.HeuristicsWeight;
        var mlWeight = _options.Aggregation.MLClassificationWeight;

        var patternConfidence = patternResult.Confidence ?? 0.0;
        var heuristicConfidence = heuristicResult.Confidence ?? 0.0;
        var mlConfidence = mlResult?.Confidence ?? 0.0;

        var totalWeight = patternWeight;
        if (heuristicResult.WasExecuted) totalWeight += heuristicWeight;
        if (mlResult is { WasExecuted: true }) totalWeight += mlWeight;

        var normalizedPatternWeight = patternWeight / totalWeight;
        var normalizedHeuristicWeight = heuristicResult.WasExecuted ? heuristicWeight / totalWeight : 0.0;
        var normalizedMLWeight = mlResult is { WasExecuted: true } ? mlWeight / totalWeight : 0.0;

        var aggregateConfidence = (patternConfidence * normalizedPatternWeight) +
                                  (heuristicConfidence * normalizedHeuristicWeight) +
                                  (mlConfidence * normalizedMLWeight);
        aggregateConfidence = Math.Clamp(aggregateConfidence, 0.0, 1.0);

        var isThreat = aggregateConfidence >= _options.ThreatThreshold;

        ThreatInfo? threatInfo = null;
        if (isThreat)
        {
            threatInfo = ThreatInfoBuilder.Build(patternResult, heuristicResult, mlResult, aggregateConfidence);
        }

        var breakdown = new DetectionBreakdown
        {
            LanguageFilter = languageFilterResult?.ToLayerResult(),
            PatternMatching = patternResult,
            Heuristics = heuristicResult,
            MLClassification = mlResult,
            SemanticAnalysis = null,
            ExecutedLayers = executedLayers
        };

        return new AnalysisResult
        {
            AnalysisId = analysisId,
            IsThreat = isThreat,
            Confidence = aggregateConfidence,
            ThreatInfo = threatInfo,
            Breakdown = _options.IncludeBreakdown ? breakdown : CreateMinimalBreakdown(executedLayers),
            DecisionLayer = "Aggregated",
            Duration = stopwatch.Elapsed,
            Timestamp = timestamp
        };
    }

    private AnalysisResult CreateLanguageBlockResult(
        Guid analysisId,
        DateTimeOffset timestamp,
        Stopwatch stopwatch,
        LanguageFilterResult languageResult,
        List<string> executedLayers)
    {
        stopwatch.Stop();

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
            ExecutedLayers = executedLayers
        };

        return new AnalysisResult
        {
            AnalysisId = analysisId,
            IsThreat = true,
            Confidence = languageResult.BlockConfidence,
            ThreatInfo = threatInfo,
            Breakdown = _options.IncludeBreakdown ? breakdown : CreateMinimalBreakdown(executedLayers),
            DecisionLayer = "LanguageFilter",
            Duration = stopwatch.Elapsed,
            Timestamp = timestamp
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
