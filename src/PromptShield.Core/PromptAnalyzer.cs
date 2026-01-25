using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using PromptShield.Abstractions.Analyzers;
using PromptShield.Abstractions.Analysis;
using PromptShield.Abstractions.Configuration;
using PromptShield.Abstractions.Events;
using PromptShield.Abstractions.Exceptions;
using PromptShield.Core.Pipeline;
using PromptShield.Core.Telemetry;
using PromptShield.Core.Validation;

namespace PromptShield.Core;

/// <summary>
/// Main implementation of IPromptAnalyzer that orchestrates prompt injection detection.
/// </summary>
public sealed class PromptAnalyzer : IPromptAnalyzer
{
    private readonly PipelineOrchestrator _pipeline;
    private readonly AnalysisRequestValidator _validator;
    private readonly IEnumerable<IPromptShieldEventHandler> _eventHandlers;
    private readonly PromptShieldOptions _options;
    private readonly ILogger<PromptAnalyzer> _logger;

    public PromptAnalyzer(
        PipelineOrchestrator pipeline,
        AnalysisRequestValidator validator,
        PromptShieldOptions options,
        IEnumerable<IPromptShieldEventHandler> eventHandlers,
        ILogger<PromptAnalyzer>? logger = null)
    {
        _pipeline = pipeline ?? throw new ArgumentNullException(nameof(pipeline));
        _validator = validator ?? throw new ArgumentNullException(nameof(validator));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _eventHandlers = eventHandlers ?? [];
        _logger = logger ?? NullLogger<PromptAnalyzer>.Instance;
    }

    public async Task<AnalysisResult> AnalyzeAsync(
        string prompt,
        CancellationToken cancellationToken = default)
    {
        var request = new AnalysisRequest
        {
            Prompt = prompt
        };

        return await AnalyzeAsync(request, cancellationToken);
    }

    public async Task<AnalysisResult> AnalyzeAsync(
        AnalysisRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var validationResult = _validator.Validate(request);
        if (!validationResult.IsValid)
        {
            var errorMessage = string.Join("; ", validationResult.Errors);
            _logger.LogWarning("Analysis request validation failed: {Errors}", errorMessage);
            throw new ValidationException("VALIDATION_FAILED", errorMessage);
        }

        var analysisId = Guid.NewGuid();
        using var activity = TelemetryHelper.StartActivity("PromptShield.Analyze", _options.Telemetry);
        activity?.SetTag("analysis.id", analysisId.ToString());
        activity?.SetTag("prompt.length", request.Prompt.Length);
        if (request.Metadata?.UserId != null)
        {
            activity?.SetTag("user.id", request.Metadata.UserId);
        }

            _logger.LogInformation(
                "Starting prompt analysis: AnalysisId={AnalysisId}, PromptLength={Length}, UserId={UserId}, ConversationId={ConversationId}",
                analysisId,
                request.Prompt.Length,
                request.Metadata?.UserId,
                request.Metadata?.ConversationId);

        if (TelemetryHelper.ShouldEmitTelemetry(_options.Telemetry))
        {
            PromptShieldTelemetry.AnalysisTotal.Add(1);
            PromptShieldTelemetry.PromptLength.Record(request.Prompt.Length);
        }

        await RaiseAnalysisStartedAsync(analysisId, request, cancellationToken);

        AnalysisResult result;
        try
        {
            result = await _pipeline.ExecuteAsync(request, analysisId, cancellationToken);

            if (TelemetryHelper.ShouldEmitTelemetry(_options.Telemetry))
            {
                PromptShieldTelemetry.AnalysisLatency.Record(result.Duration.TotalMilliseconds);
                
                if (result.IsThreat)
                {
                    PromptShieldTelemetry.ThreatsDetected.Add(1);
                    activity?.SetTag("threat.detected", true);
                    activity?.SetTag("threat.confidence", result.Confidence);
                    activity?.SetTag("threat.owasp_category", result.ThreatInfo?.OwaspCategory ?? "unknown");
                }
                else
                {
                    activity?.SetTag("threat.detected", false);
                }
            }

            activity?.SetTag("analysis.confidence", result.Confidence);
            activity?.SetTag("analysis.decision_layer", result.DecisionLayer);

            _logger.LogInformation(
                "Analysis completed: AnalysisId={AnalysisId}, IsThreat={IsThreat}, Confidence={Confidence:F3}, Duration={Duration}ms",
                result.AnalysisId,
                result.IsThreat,
                result.Confidence,
                result.Duration.TotalMilliseconds);
        }
        catch (OperationCanceledException)
        {
            _logger.LogWarning("Analysis cancelled: AnalysisId={AnalysisId}", analysisId);
            activity?.SetStatus(ActivityStatusCode.Error, "Cancelled");
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Analysis failed: AnalysisId={AnalysisId}", analysisId);

            if (TelemetryHelper.ShouldEmitTelemetry(_options.Telemetry))
                PromptShieldTelemetry.AnalysisErrors.Add(1);

            activity?.SetStatus(ActivityStatusCode.Error, ex.Message);
            activity?.SetTag("exception.type", ex.GetType().FullName);
            activity?.SetTag("exception.message", ex.Message);

            if (_options.OnAnalysisError == FailureBehavior.FailClosed)
            {
                throw new PromptShieldException(
                    "Prompt analysis failed. The prompt has been blocked for security. See inner exception for details.",
                    ex);
            }

            _logger.LogWarning(
                "Returning safe result due to fail-open configuration. AnalysisId={AnalysisId}",
                analysisId);

            return CreateFailOpenResult(analysisId, request);
        }

        if (result.IsThreat && result.ThreatInfo != null)
            await RaiseThreatDetectedAsync(request, result, cancellationToken);

        await RaiseAnalysisCompletedAsync(request, result, cancellationToken);

        return result;
    }

    private AnalysisResult CreateFailOpenResult(Guid analysisId, AnalysisRequest request)
    {
        return new AnalysisResult
        {
            AnalysisId = analysisId,
            IsThreat = false,
            Confidence = 0.0,
            ThreatInfo = null,
            Breakdown = new DetectionBreakdown
            {
                PatternMatching = CreateErrorLayerResult("PatternMatching"),
                Heuristics = CreateErrorLayerResult("Heuristics"),
                MLClassification = null,
                SemanticAnalysis = null,
                ExecutedLayers = []
            },
            DecisionLayer = "FailOpen",
            Duration = TimeSpan.Zero,
            Timestamp = DateTimeOffset.UtcNow
        };
    }

    private static LayerResult CreateErrorLayerResult(string layerName)
    {
        return new LayerResult
        {
            LayerName = layerName,
            WasExecuted = false,
            Data = new Dictionary<string, object> { ["error"] = "Analysis failed - fail-open mode" }
        };
    }

    private Task RaiseAnalysisStartedAsync(
        Guid analysisId,
        AnalysisRequest request,
        CancellationToken cancellationToken)
    {
        var @event = new AnalysisStartedEvent
        {
            AnalysisId = analysisId,
            Request = request,
            Timestamp = DateTimeOffset.UtcNow
        };

        return RaiseEventAsync(
            @event,
            "AnalysisStarted",
            (h, e, ct) => h.OnAnalysisStartedAsync(e, ct),
            cancellationToken);
    }

    private Task RaiseThreatDetectedAsync(
        AnalysisRequest request,
        AnalysisResult result,
        CancellationToken cancellationToken)
    {
        var @event = new ThreatDetectedEvent
        {
            AnalysisId = result.AnalysisId,
            Request = request,
            ThreatInfo = result.ThreatInfo!,
            DetectionLayer = result.DecisionLayer,
            Timestamp = result.Timestamp
        };

        return RaiseEventAsync(
            @event,
            "ThreatDetected",
            (h, e, ct) => h.OnThreatDetectedAsync(e, ct),
            cancellationToken);
    }

    private Task RaiseAnalysisCompletedAsync(
        AnalysisRequest request,
        AnalysisResult result,
        CancellationToken cancellationToken)
    {
        var @event = new AnalysisCompletedEvent
        {
            Result = result,
            Request = request,
            Timestamp = result.Timestamp
        };

        return RaiseEventAsync(
            @event,
            "AnalysisCompleted",
            (h, e, ct) => h.OnAnalysisCompletedAsync(e, ct),
            cancellationToken);
    }

    private async Task RaiseEventAsync<TEvent>(
        TEvent @event,
        string eventName,
        Func<IPromptShieldEventHandler, TEvent, CancellationToken, Task> invoker,
        CancellationToken cancellationToken)
    {
        foreach (var handler in _eventHandlers)
        {
            try
            {
                await invoker(handler, @event, cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                _logger.LogDebug("Event handler cancelled during {EventName}", eventName);
                throw;
            }
            catch (Exception ex)
            {
                _logger.LogError(
                    ex,
                    "Event handler {HandlerType} failed on {EventName}",
                    handler.GetType().Name,
                    eventName);
            }
        }
    }
}
