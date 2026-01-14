using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using PromptShield.Abstractions.Analysis;
using PromptShield.Abstractions.Configuration;

namespace PromptShield.Core.Layers;

/// <summary>
/// Gate layer that checks if input language is supported before proceeding to detection.
/// </summary>
/// <remarks>
/// <para>
/// This layer acts as a simple filter:
/// <list type="bullet">
///   <item>Supported language → proceed to detection layers</item>
///   <item>Unsupported language → block or allow based on configuration</item>
/// </list>
/// </para>
/// <para>
/// This prevents bypass attempts where attackers use non-supported languages
/// to evade language-specific detection patterns.
/// </para>
/// </remarks>
public sealed class LanguageFilterLayer
{
    private readonly LanguageOptions _options;
    private readonly ILanguageDetector _languageDetector;
    private readonly ILogger<LanguageFilterLayer> _logger;
    private readonly HashSet<string> _supportedLanguages;

    public LanguageFilterLayer(
        LanguageOptions options,
        ILanguageDetector languageDetector,
        ILogger<LanguageFilterLayer>? logger = null)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _languageDetector = languageDetector ?? throw new ArgumentNullException(nameof(languageDetector));
        _logger = logger ?? NullLogger<LanguageFilterLayer>.Instance;
        _supportedLanguages = new HashSet<string>(
            options.SupportedLanguages,
            StringComparer.OrdinalIgnoreCase);

        _logger.LogInformation(
            "LanguageFilterLayer initialized. Enabled={Enabled}, SupportedLanguages=[{Languages}]",
            options.Enabled,
            string.Join(", ", options.SupportedLanguages));
    }

    /// <summary>
    /// Gets the name of this layer.
    /// </summary>
    public string LayerName => "LanguageFilter";

    /// <summary>
    /// Checks if the prompt language is supported.
    /// </summary>
    /// <param name="prompt">Prompt text to analyze.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Result indicating whether to proceed or block.</returns>
    public Task<LanguageFilterResult> AnalyzeAsync(
        string prompt,
        CancellationToken cancellationToken = default)
    {
        if (!_options.Enabled)
        {
            return Task.FromResult(new LanguageFilterResult
            {
                WasExecuted = false,
                ShouldProceed = true,
                LanguageResult = null
            });
        }

        var stopwatch = Stopwatch.StartNew();

        try
        {
            // Check minimum length
            if (prompt.Length < _options.MinTextLengthForDetection)
            {
                _logger.LogDebug(
                    "Text too short for language detection ({Length} < {Min} chars)",
                    prompt.Length,
                    _options.MinTextLengthForDetection);

                return Task.FromResult(CreateResultForBehavior(
                    _options.OnShortText,
                    LanguageDetectionResult.Undetermined,
                    stopwatch.Elapsed,
                    "Text too short for reliable language detection"));
            }

            // Detect language
            var langResult = _languageDetector.Detect(prompt);

            _logger.LogDebug(
                "Language detected: {Language} ({Script}), Confidence={Confidence:P0}",
                langResult.LanguageName,
                langResult.ScriptName,
                langResult.Confidence);

            // Check confidence
            if (langResult.Confidence < _options.MinDetectionConfidence)
            {
                _logger.LogDebug(
                    "Detection confidence {Confidence:P0} below threshold {Threshold:P0}",
                    langResult.Confidence,
                    _options.MinDetectionConfidence);

                return Task.FromResult(CreateResultForBehavior(
                    _options.OnLowConfidenceDetection,
                    langResult,
                    stopwatch.Elapsed,
                    $"Language detection confidence ({langResult.Confidence:P0}) below threshold"));
            }

            // Check if language is supported
            if (_supportedLanguages.Contains(langResult.LanguageCode))
            {
                _logger.LogDebug("Language '{Language}' is supported, proceeding to detection", langResult.LanguageName);

                return Task.FromResult(new LanguageFilterResult
                {
                    WasExecuted = true,
                    ShouldProceed = true,
                    LanguageResult = langResult,
                    Duration = stopwatch.Elapsed,
                    Message = $"Language '{langResult.LanguageName}' is supported"
                });
            }

            // Unsupported language
            _logger.LogInformation(
                "Unsupported language: {Language}. Behavior: {Behavior}",
                langResult.LanguageName,
                _options.OnUnsupportedLanguage);

            return Task.FromResult(CreateResultForBehavior(
                _options.OnUnsupportedLanguage,
                langResult,
                stopwatch.Elapsed,
                $"Language '{langResult.LanguageName}' is not supported. Supported: [{string.Join(", ", _options.SupportedLanguages)}]"));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during language detection");

            // On error, allow with warning
            return Task.FromResult(new LanguageFilterResult
            {
                WasExecuted = true,
                ShouldProceed = true,
                LanguageResult = LanguageDetectionResult.Undetermined,
                Duration = stopwatch.Elapsed,
                Message = $"Language detection error: {ex.Message}",
                HasWarning = true
            });
        }
    }

    private static LanguageFilterResult CreateResultForBehavior(
        UnsupportedLanguageBehavior behavior,
        LanguageDetectionResult langResult,
        TimeSpan duration,
        string reason)
    {
        return behavior switch
        {
            UnsupportedLanguageBehavior.Block => new LanguageFilterResult
            {
                WasExecuted = true,
                ShouldProceed = false,
                IsBlocked = true,
                LanguageResult = langResult,
                Duration = duration,
                Message = reason,
                BlockConfidence = 0.9
            },

            UnsupportedLanguageBehavior.Allow => new LanguageFilterResult
            {
                WasExecuted = true,
                ShouldProceed = true,
                LanguageResult = langResult,
                Duration = duration,
                Message = reason
            },

            UnsupportedLanguageBehavior.AllowWithWarning => new LanguageFilterResult
            {
                WasExecuted = true,
                ShouldProceed = true,
                LanguageResult = langResult,
                Duration = duration,
                Message = $"{reason}. Detection may be less effective.",
                HasWarning = true
            },

            _ => new LanguageFilterResult
            {
                WasExecuted = true,
                ShouldProceed = false,
                IsBlocked = true,
                LanguageResult = langResult,
                Duration = duration,
                Message = reason,
                BlockConfidence = 0.9
            }
        };
    }
}

/// <summary>
/// Result of the language filter check.
/// </summary>
public sealed class LanguageFilterResult
{
    /// <summary>
    /// Whether the filter was executed.
    /// </summary>
    public bool WasExecuted { get; init; }

    /// <summary>
    /// Whether the prompt should proceed to detection layers.
    /// </summary>
    public bool ShouldProceed { get; init; }

    /// <summary>
    /// Whether the prompt was blocked due to unsupported language.
    /// </summary>
    public bool IsBlocked { get; init; }

    /// <summary>
    /// Language detection result.
    /// </summary>
    public LanguageDetectionResult? LanguageResult { get; init; }

    /// <summary>
    /// Processing duration.
    /// </summary>
    public TimeSpan Duration { get; init; }

    /// <summary>
    /// Human-readable message.
    /// </summary>
    public string? Message { get; init; }

    /// <summary>
    /// Whether a warning should be included in results.
    /// </summary>
    public bool HasWarning { get; init; }

    /// <summary>
    /// Confidence score when blocked (for threat reporting).
    /// </summary>
    public double BlockConfidence { get; init; }

    /// <summary>
    /// Converts to standard LayerResult.
    /// </summary>
    public LayerResult ToLayerResult()
    {
        var data = new Dictionary<string, object>();

        if (LanguageResult != null)
        {
            data["language_code"] = LanguageResult.LanguageCode;
            data["language_name"] = LanguageResult.LanguageName;
            data["script_code"] = LanguageResult.ScriptCode;
            data["detection_confidence"] = LanguageResult.Confidence;
        }

        data["should_proceed"] = ShouldProceed;
        if (Message != null) data["message"] = Message;
        if (HasWarning) data["warning"] = true;
        if (IsBlocked) data["blocked"] = true;

        return new LayerResult
        {
            LayerName = "LanguageFilter",
            WasExecuted = WasExecuted,
            IsThreat = IsBlocked,
            Confidence = IsBlocked ? BlockConfidence : 0.0,
            Duration = Duration,
            Data = data
        };
    }
}
