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
    /// <summary>
    /// Builds ThreatInfo from pattern matching and heuristic layer results.
    /// </summary>
    /// <param name="patternResult">Result from pattern matching layer.</param>
    /// <param name="heuristicResult">Result from heuristic analysis layer.</param>
    /// <param name="aggregateConfidence">Aggregated confidence score.</param>
    /// <returns>ThreatInfo if threat detected, null otherwise.</returns>
    public static ThreatInfo? Build(
        LayerResult patternResult,
        LayerResult heuristicResult,
        double aggregateConfidence)
    {
        return Build(patternResult, heuristicResult, mlResult: null, aggregateConfidence);
    }

    /// <summary>
    /// Builds ThreatInfo from pattern matching, heuristic, and ML layer results.
    /// </summary>
    /// <param name="patternResult">Result from pattern matching layer.</param>
    /// <param name="heuristicResult">Result from heuristic analysis layer.</param>
    /// <param name="mlResult">Result from ML classification layer (optional).</param>
    /// <param name="aggregateConfidence">Aggregated confidence score.</param>
    /// <returns>ThreatInfo if threat detected, null otherwise.</returns>
    public static ThreatInfo? Build(
        LayerResult patternResult,
        LayerResult heuristicResult,
        LayerResult? mlResult,
        double aggregateConfidence)
    {
        var owaspCategory = "LLM01"; // Default
        var matchedPatterns = new List<string>();
        var detectionSources = new List<string>();

        // Extract information from pattern matching layer
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

        // Extract information from heuristic layer
        if (heuristicResult.IsThreat == true)
        {
            detectionSources.Add("Heuristics");
        }

        // Extract information from ML classification layer
        if (mlResult != null && mlResult.IsThreat == true)
        {
            detectionSources.Add("MLClassification");
        }

        // Only create ThreatInfo if at least one source detected a threat
        if (detectionSources.Count == 0)
        {
            return null;
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

    /// <summary>
    /// Builds ThreatInfo from a single layer result (for early exit scenarios).
    /// </summary>
    /// <param name="layerResult">Result from the deciding layer.</param>
    /// <param name="decisionLayer">Name of the layer that made the decision.</param>
    /// <param name="confidence">Confidence score from the layer.</param>
    /// <returns>ThreatInfo if threat detected, null otherwise.</returns>
    public static ThreatInfo? BuildFromSingleLayer(
        LayerResult layerResult,
        string decisionLayer,
        double confidence)
    {
        if (layerResult.IsThreat != true || layerResult.Data == null)
        {
            return null;
        }

        var owaspCategory = layerResult.Data.TryGetValue("owasp_category", out var cat)
            ? cat.ToString() ?? "LLM01"
            : "LLM01";

        var matchedPatterns = layerResult.Data.TryGetValue("matched_patterns", out var patterns) &&
                             patterns is List<string> patternList
            ? patternList
            : null;

        var severity = confidence.ToSeverity();

        return new ThreatInfo
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
}
