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

        // Call next to render the prompt
        await next(context);

        // Get the rendered prompt
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
            // Re-throw prompt injection exceptions - these are intentional blocks
            throw;
        }
        catch (OperationCanceledException)
        {
            // Re-throw cancellation - let the caller handle it
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
        var request = new AnalysisRequest
        {
            Prompt = renderedPrompt
        };

        if (_options.IncludeFunctionMetadata)
        {
            request = new AnalysisRequest
            {
                Prompt = renderedPrompt,
                Metadata = new AnalysisMetadata
                {
                    Source = "SemanticKernel",
                    Properties = new Dictionary<string, string>
                    {
                        ["FunctionName"] = context.Function.Name,
                        ["PluginName"] = context.Function.PluginName ?? "Unknown"
                    }
                }
            };
        }

        return request;
    }

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
        _logger.LogError(
            ex,
            "Error during prompt analysis for function: {FunctionName}",
            context.Function.Name);

        switch (_options.OnAnalysisError)
        {
            case FailureBehavior.FailClosed:
                _logger.LogWarning(
                    "Blocking prompt due to analysis error (fail-closed behavior). " +
                    "Function: {FunctionName}",
                    context.Function.Name);

                throw new PromptShieldAnalysisException(
                    "Prompt analysis failed. The prompt has been blocked for security. " +
                    "See inner exception for details.",
                    ex);

            case FailureBehavior.FailOpen:
                _logger.LogWarning(
                    "Allowing prompt to proceed due to analysis error (fail-open behavior). " +
                    "Function: {FunctionName}. " +
                    "WARNING: This may allow malicious prompts through.",
                    context.Function.Name);
                break;

            default:
                // Unknown behavior - default to fail-closed for security
                _logger.LogWarning(
                    "Unknown failure behavior configured. Defaulting to fail-closed.");

                throw new PromptShieldAnalysisException(
                    "Prompt analysis failed with unknown failure behavior configured.",
                    ex);
        }
    }
}
