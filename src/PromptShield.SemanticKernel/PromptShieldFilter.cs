using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.SemanticKernel;
using PromptShield.Abstractions.Analyzers;
using PromptShield.Abstractions.Analysis;
using PromptShield.Abstractions.Configuration;

namespace PromptShield.SemanticKernel;

/// <summary>
/// Semantic Kernel filter that analyzes prompts for injection attacks before rendering.
/// </summary>
public sealed class PromptShieldFilter : IPromptRenderFilter
{
    private readonly IPromptAnalyzer _analyzer;
    private readonly SemanticKernelIntegrationOptions _options;
    private readonly ILogger<PromptShieldFilter> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="PromptShieldFilter"/> class.
    /// </summary>
    /// <param name="analyzer">The prompt analyzer instance.</param>
    /// <param name="options">Integration options. If null, uses secure defaults.</param>
    /// <param name="logger">Optional logger instance.</param>
    public PromptShieldFilter(
        IPromptAnalyzer analyzer,
        SemanticKernelIntegrationOptions? options = null,
        ILogger<PromptShieldFilter>? logger = null)
    {
        _analyzer = analyzer ?? throw new ArgumentNullException(nameof(analyzer));
        _options = options ?? new SemanticKernelIntegrationOptions();
        _logger = logger ?? NullLogger<PromptShieldFilter>.Instance;
    }

    /// <inheritdoc />
    public async Task OnPromptRenderAsync(PromptRenderContext context, Func<PromptRenderContext, Task> next)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(next);

        await next(context);
        var renderedPrompt = context.RenderedPrompt;

        if (_options.SkipEmptyPrompts && string.IsNullOrWhiteSpace(renderedPrompt))
        {
            _logger.LogDebug("Skipping analysis for empty prompt");
            return;
        }

        _logger.LogDebug(
            "Analyzing prompt for function: {FunctionName}, Length: {Length}",
            context.Function.Name,
            renderedPrompt?.Length ?? 0);

        try
        {
            var request = BuildAnalysisRequest(context, renderedPrompt!);
            var result = await _analyzer.AnalyzeAsync(request);

            if (result.IsThreat)
            {
                LogThreatDetected(context, result);
                throw new PromptInjectionDetectedException(result);
            }

            _logger.LogDebug(
                "Prompt analysis passed: AnalysisId={AnalysisId}, Confidence={Confidence:F3}",
                result.AnalysisId,
                result.Confidence);
        }
        catch (PromptInjectionDetectedException)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            _logger.LogDebug("Prompt analysis was cancelled");
            throw;
        }
        catch (Exception ex)
        {
            HandleAnalysisError(ex, context);
        }
    }

    private AnalysisRequest BuildAnalysisRequest(PromptRenderContext context, string renderedPrompt)
    {
        return new AnalysisRequest
        {
            Prompt = renderedPrompt,
            Metadata = _options.IncludeFunctionMetadata
                ? CreateMetadata(context)
                : null
        };
    }

    private static AnalysisMetadata CreateMetadata(PromptRenderContext context) => new()
    {
        Source = "SemanticKernel",
        Properties = new Dictionary<string, string>
        {
            ["FunctionName"] = context.Function.Name,
            ["PluginName"] = context.Function.PluginName ?? "Unknown"
        }
    };

    private void LogThreatDetected(PromptRenderContext context, AnalysisResult result)
    {
        _logger.LogWarning(
            "Prompt injection detected: AnalysisId={AnalysisId}, " +
            "Function={FunctionName}, " +
            "Confidence={Confidence:F3}, " +
            "OWASP={OwaspCategory}, " +
            "Severity={Severity}",
            result.AnalysisId,
            context.Function.Name,
            result.Confidence,
            result.ThreatInfo?.OwaspCategory,
            result.ThreatInfo?.Severity);
    }

    private void HandleAnalysisError(Exception ex, PromptRenderContext context)
    {
        _logger.LogError(ex, "Error during prompt analysis for function: {FunctionName}", context.Function.Name);

        if (_options.OnAnalysisError == FailureBehavior.FailOpen)
        {
            _logger.LogWarning(
                "Allowing prompt to proceed due to analysis error (fail-open behavior). Function: {FunctionName}",
                context.Function.Name);
            return;
        }

        var message = _options.OnAnalysisError == FailureBehavior.FailClosed
            ? "Prompt analysis failed. The prompt has been blocked for security. See inner exception for details."
            : "Prompt analysis failed with unknown failure behavior configured.";

        _logger.LogWarning(
            "Blocking prompt due to analysis error ({Behavior}). Function: {FunctionName}",
            _options.OnAnalysisError,
            context.Function.Name);

        throw new PromptShieldAnalysisException(message, ex);
    }
}
