using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using PromptShield.Abstractions.Analysis;
using PromptShield.Abstractions.Configuration;
using PromptShield.Core.Layers;

namespace PromptShield.Core.Pipeline;

/// <summary>
/// Orchestrates the multi-layer detection pipeline with early exit optimization.
/// </summary>
public sealed class PipelineOrchestrator
{
    private readonly PromptShieldOptions _options;
    private readonly PatternMatchingLayer _patternLayer;
    private readonly HeuristicLayer _heuristicLayer;
    private readonly ILogger<PipelineOrchestrator> _logger;

    public PipelineOrchestrator(
        PatternMatchingLayer patternLayer,
        HeuristicLayer heuristicLayer,
        PromptShieldOptions options,
        ILogger<PipelineOrchestrator>? logger = null)
    {
        _patternLayer = patternLayer ?? throw new ArgumentNullException(nameof(patternLayer));
        _heuristicLayer = heuristicLayer ?? throw new ArgumentNullException(nameof(heuristicLayer));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? NullLogger<PipelineOrchestrator>.Instance;
    }

    /// <summary>
    /// Executes the detection pipeline with early exit optimization.
    /// </summary>
    /// <param name="request">The analysis request.</param>
    /// <param name="analysisId">Pre-generated analysis ID for event correlation.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Analysis result.</returns>
    public async Task<AnalysisResult> ExecuteAsync(
        AnalysisRequest request,
        Guid analysisId,
        CancellationToken cancellationToken = default)
    {
        var timestamp = DateTimeOffset.UtcNow;
        var overallStopwatch = Stopwatch.StartNew();
        var executedLayers = new List<string>();

        _logger.LogInformation(
            "Starting analysis pipeline for AnalysisId={AnalysisId}, PromptLength={Length}",
            analysisId,
            request.Prompt.Length);

        try
        {
            // Layer 1: Pattern Matching (always executed)
            LayerResult patternResult;
            try
            {
                patternResult = await _patternLayer.AnalyzeAsync(request.Prompt, cancellationToken);
                executedLayers.Add(_patternLayer.LayerName);

                _logger.LogDebug(
                    "Pattern matching completed: IsThreat={IsThreat}, Confidence={Confidence:F3}, Duration={Duration}ms",
                    patternResult.IsThreat,
                    patternResult.Confidence,
                    patternResult.Duration?.TotalMilliseconds);

                // Early exit on high-confidence pattern match
                if (patternResult.IsThreat == true &&
                    patternResult.Confidence >= _options.PatternMatching.EarlyExitThreshold)
                {
                    _logger.LogInformation(
                        "Early exit triggered by pattern matching (Confidence={Confidence:F3})",
                        patternResult.Confidence);

                    return CreateResult(
                        analysisId,
                        timestamp,
                        overallStopwatch,
                        patternResult,
                        heuristicResult: null,
                        mlResult: null,
                        semanticResult: null,
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

            // Layer 2: Heuristic Analysis (always executed)
            LayerResult heuristicResult;
            try
            {
                heuristicResult = await _heuristicLayer.AnalyzeAsync(
                    request.Prompt,
                    patternResult,
                    cancellationToken);
                executedLayers.Add(_heuristicLayer.LayerName);

                _logger.LogDebug(
                    "Heuristic analysis completed: IsThreat={IsThreat}, Confidence={Confidence:F3}, Duration={Duration}ms",
                    heuristicResult.IsThreat,
                    heuristicResult.Confidence,
                    heuristicResult.Duration?.TotalMilliseconds);

                // Early exit on definitive heuristic result
                if (_heuristicLayer.IsDefinitiveResult(heuristicResult))
                {
                    var reason = heuristicResult.IsThreat == true ? "definitive threat" : "definitive safe";
                    _logger.LogInformation(
                        "Early exit triggered by heuristics: {Reason} (Confidence={Confidence:F3})",
                        reason,
                        heuristicResult.Confidence);

                    return CreateResult(
                        analysisId,
                        timestamp,
                        overallStopwatch,
                        patternResult,
                        heuristicResult,
                        mlResult: null,
                        semanticResult: null,
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

            // For MVP (US1), we only have Pattern + Heuristic layers
            // ML and Semantic layers will be added in later user stories (US4, US6)

            // Final decision: aggregate pattern and heuristic results
            overallStopwatch.Stop();

            var finalResult = CreateAggregatedResult(
                analysisId,
                timestamp,
                overallStopwatch,
                patternResult,
                heuristicResult,
                executedLayers);

            _logger.LogInformation(
                "Analysis completed: AnalysisId={AnalysisId}, IsThreat={IsThreat}, Confidence={Confidence:F3}, Duration={Duration}ms",
                analysisId,
                finalResult.IsThreat,
                finalResult.Confidence,
                finalResult.Duration.TotalMilliseconds);

            return finalResult;
        }
        catch (OperationCanceledException)
        {
            _logger.LogWarning("Pipeline execution cancelled: AnalysisId={AnalysisId}", analysisId);
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Pipeline execution failed: AnalysisId={AnalysisId}", analysisId);
            throw;
        }
    }

    private AnalysisResult CreateResult(
        Guid analysisId,
        DateTimeOffset timestamp,
        Stopwatch stopwatch,
        LayerResult patternResult,
        LayerResult? heuristicResult,
        LayerResult? mlResult,
        LayerResult? semanticResult,
        List<string> executedLayers,
        string decisionLayer)
    {
        stopwatch.Stop();

        // Determine the primary decision maker
        var (isThreat, confidence, threatInfo) = DetermineThreat(
            patternResult,
            heuristicResult,
            mlResult,
            semanticResult,
            decisionLayer);

        var breakdown = new DetectionBreakdown
        {
            PatternMatching = patternResult,
            Heuristics = heuristicResult ?? CreateSkippedLayerResult("Heuristics"),
            MLClassification = mlResult,
            SemanticAnalysis = semanticResult,
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
        LayerResult patternResult,
        LayerResult heuristicResult,
        List<string> executedLayers)
    {
        // Use configured weights for aggregation
        var patternWeight = _options.Aggregation.PatternMatchingWeight;
        var heuristicWeight = _options.Aggregation.HeuristicsWeight;

        var patternConfidence = patternResult.Confidence ?? 0.0;
        var heuristicConfidence = heuristicResult.Confidence ?? 0.0;

        // Normalize weights
        var totalWeight = patternWeight + heuristicWeight;
        var normalizedPatternWeight = patternWeight / totalWeight;
        var normalizedHeuristicWeight = heuristicWeight / totalWeight;

        var aggregateConfidence = (patternConfidence * normalizedPatternWeight) +
                                  (heuristicConfidence * normalizedHeuristicWeight);
        aggregateConfidence = Math.Clamp(aggregateConfidence, 0.0, 1.0);

        var isThreat = aggregateConfidence >= _options.ThreatThreshold;

        ThreatInfo? threatInfo = null;
        if (isThreat)
        {
            threatInfo = BuildThreatInfo(patternResult, heuristicResult, aggregateConfidence);
        }

        var breakdown = new DetectionBreakdown
        {
            PatternMatching = patternResult,
            Heuristics = heuristicResult,
            MLClassification = null,
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

    private ThreatInfo BuildThreatInfo(
        LayerResult patternResult,
        LayerResult heuristicResult,
        double aggregateConfidence)
    {
        var owaspCategory = "LLM01"; // Default
        var matchedPatterns = new List<string>();
        var detectionSources = new List<string>();

        if (patternResult.IsThreat == true && patternResult.Data != null)
        {
            if (patternResult.Data.TryGetValue("owasp_category", out var category))
            {
                owaspCategory = category.ToString() ?? "LLM01";
            }
            if (patternResult.Data.TryGetValue("matched_patterns", out var patterns) &&
                patterns is List<string> patternList)
            {
                matchedPatterns.AddRange(patternList);
            }
            detectionSources.Add("PatternMatching");
        }

        if (heuristicResult.IsThreat == true)
        {
            detectionSources.Add("Heuristics");
        }

        var severity = aggregateConfidence.ToSeverity();

        return new ThreatInfo
        {
            OwaspCategory = owaspCategory,
            ThreatType = "Prompt Injection",
            Explanation = $"Potential prompt injection detected with confidence {aggregateConfidence:P0}. " +
                         $"Detected by: {string.Join(", ", detectionSources)}.",
            UserFacingMessage = "Your request could not be processed due to security concerns. " +
                               "Please rephrase your message and try again.",
            Severity = severity,
            DetectionSources = detectionSources,
            MatchedPatterns = matchedPatterns.Count > 0 ? matchedPatterns : null
        };
    }

    private (bool isThreat, double confidence, ThreatInfo? threatInfo) DetermineThreat(
        LayerResult patternResult,
        LayerResult? heuristicResult,
        LayerResult? mlResult,
        LayerResult? semanticResult,
        string decisionLayer)
    {
        // For early exit scenarios, use the layer that triggered the exit
        var decidingResult = decisionLayer switch
        {
            "PatternMatching" => patternResult,
            "Heuristics" => heuristicResult,
            "MLClassification" => mlResult,
            "SemanticAnalysis" => semanticResult,
            _ => patternResult
        };

        if (decidingResult == null)
        {
            return (false, 0.0, null);
        }

        var isThreat = decidingResult.IsThreat ?? false;
        var confidence = decidingResult.Confidence ?? 0.0;

        ThreatInfo? threatInfo = null;
        if (isThreat && decidingResult.Data != null)
        {
            var owaspCategory = decidingResult.Data.TryGetValue("owasp_category", out var cat)
                ? cat.ToString() ?? "LLM01"
                : "LLM01";

            var matchedPatterns = decidingResult.Data.TryGetValue("matched_patterns", out var patterns) &&
                                  patterns is List<string> patternList
                ? patternList
                : null;

            var severity = confidence.ToSeverity();

            threatInfo = new ThreatInfo
            {
                OwaspCategory = owaspCategory,
                ThreatType = "Prompt Injection",
                Explanation = $"Threat detected by {decisionLayer} layer with {confidence:P0} confidence.",
                UserFacingMessage = "Your request could not be processed due to security concerns. " +
                                   "Please rephrase your message and try again.",
                Severity = severity,
                DetectionSources = new[] { decisionLayer },
                MatchedPatterns = matchedPatterns
            };
        }

        return (isThreat, confidence, threatInfo);
    }

    private static LayerResult CreateFailedLayerResult(string layerName)
    {
        return new LayerResult
        {
            LayerName = layerName,
            WasExecuted = true,
            Confidence = 0.0,
            IsThreat = false,
            Duration = TimeSpan.Zero,
            Data = new Dictionary<string, object> { ["error"] = "Layer execution failed" }
        };
    }

    private static LayerResult CreateSkippedLayerResult(string layerName)
    {
        return new LayerResult
        {
            LayerName = layerName,
            WasExecuted = false
        };
    }

    private static DetectionBreakdown CreateMinimalBreakdown(List<string> executedLayers)
    {
        return new DetectionBreakdown
        {
            PatternMatching = CreateSkippedLayerResult("PatternMatching"),
            Heuristics = CreateSkippedLayerResult("Heuristics"),
            MLClassification = null,
            SemanticAnalysis = null,
            ExecutedLayers = executedLayers
        };
    }
}
