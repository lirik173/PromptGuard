using PromptShield.Abstractions.Analysis;

namespace PromptShield.Core.Analysis;

/// <summary>
/// Builder for assembling ThreatInfo from detection layer results.
/// </summary>
/// <remarks>
/// This class consolidates threat information from multiple detection layers
/// into a single ThreatInfo object for transparency and explainability (US2).
/// </remarks>
public static class ThreatInfoBuilder
{
    private const string DefaultOwaspCategory = "LLM01";
    private const string DefaultThreatType = "Prompt Injection";
    private const string DefaultUserMessage = "Your request could not be processed due to security concerns. " +
                                              "Please rephrase your message and try again.";

    /// <summary>
    /// Builds ThreatInfo from pattern matching and heuristic layer results.
    /// </summary>
    public static ThreatInfo? Build(
        LayerResult patternResult,
        LayerResult heuristicResult,
        double aggregateConfidence)
        => Build(patternResult, heuristicResult, mlResult: null, aggregateConfidence);

    /// <summary>
    /// Builds ThreatInfo from pattern matching, heuristic, and ML layer results.
    /// </summary>
    public static ThreatInfo? Build(
        LayerResult patternResult,
        LayerResult heuristicResult,
        LayerResult? mlResult,
        double aggregateConfidence)
    {
        var ctx = new ThreatContext();

        ctx.ProcessPatternResult(patternResult);
        ctx.ProcessLayerResult(heuristicResult, "Heuristics");
        ctx.ProcessLayerResult(mlResult, "MLClassification");

        if (ctx.DetectionSources.Count == 0)
            return null;

        return CreateThreatInfo(
            ctx,
            $"Potential prompt injection detected with confidence {aggregateConfidence:P0}. " +
            $"Detected by: {string.Join(", ", ctx.DetectionSources)}.",
            aggregateConfidence);
    }

    /// <summary>
    /// Builds ThreatInfo from a single layer result (for early exit scenarios).
    /// </summary>
    public static ThreatInfo? BuildFromSingleLayer(
        LayerResult layerResult,
        string decisionLayer,
        double confidence)
    {
        if (layerResult.IsThreat != true)
            return null;

        var ctx = new ThreatContext();
        ctx.ProcessPatternResult(layerResult);
        ctx.DetectionSources.Add(decisionLayer);

        return CreateThreatInfo(
            ctx,
            $"Threat detected by {decisionLayer} layer with {confidence:P0} confidence.",
            confidence);
    }

    private static ThreatInfo CreateThreatInfo(ThreatContext ctx, string explanation, double confidence) => new()
    {
        OwaspCategory = ctx.OwaspCategory,
        ThreatType = DefaultThreatType,
        Explanation = explanation,
        UserFacingMessage = DefaultUserMessage,
        Severity = confidence.ToSeverity(),
        DetectionSources = ctx.DetectionSources,
        MatchedPatterns = ctx.MatchedPatterns.Count > 0 ? ctx.MatchedPatterns : null
    };

    /// <summary>
    /// Accumulates threat detection context from multiple layers.
    /// </summary>
    private sealed class ThreatContext
    {
        public string OwaspCategory { get; private set; } = DefaultOwaspCategory;
        public List<string> MatchedPatterns { get; } = [];
        public List<string> DetectionSources { get; } = [];

        public void ProcessPatternResult(LayerResult? result)
        {
            if (result?.IsThreat != true || result.Data == null)
                return;

            if (result.Data.TryGetValue("owasp_category", out var category))
                OwaspCategory = category?.ToString() ?? DefaultOwaspCategory;

            if (result.Data.TryGetValue("matched_patterns", out var patterns) &&
                patterns is List<string> patternList)
            {
                MatchedPatterns.AddRange(patternList);
            }

            DetectionSources.Add("PatternMatching");
        }

        public void ProcessLayerResult(LayerResult? result, string layerName)
        {
            if (result?.IsThreat == true)
                DetectionSources.Add(layerName);
        }
    }
}
