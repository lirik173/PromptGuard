using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using PromptShield.Abstractions.Analyzers;
using PromptShield.Abstractions.Analysis;
using PromptShield.Abstractions.Configuration;

namespace PromptShield.AspNetCore;

/// <summary>
/// ASP.NET Core middleware for analyzing request prompts for injection attacks.
/// </summary>
public sealed class PromptShieldMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IPromptAnalyzer _analyzer;
    private readonly PromptShieldMiddlewareOptions _options;
    private readonly ILogger<PromptShieldMiddleware> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="PromptShieldMiddleware"/> class.
    /// </summary>
    /// <param name="next">The next middleware in the pipeline.</param>
    /// <param name="analyzer">The prompt analyzer instance.</param>
    /// <param name="options">Middleware configuration options.</param>
    /// <param name="logger">Optional logger instance.</param>
    public PromptShieldMiddleware(
        RequestDelegate next,
        IPromptAnalyzer analyzer,
        PromptShieldMiddlewareOptions options,
        ILogger<PromptShieldMiddleware>? logger = null)
    {
        _next = next ?? throw new ArgumentNullException(nameof(next));
        _analyzer = analyzer ?? throw new ArgumentNullException(nameof(analyzer));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _logger = logger ?? NullLogger<PromptShieldMiddleware>.Instance;
    }

    /// <summary>
    /// Invokes the middleware to analyze the request for prompt injection attacks.
    /// </summary>
    /// <param name="context">The HTTP context for the request.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    public async Task InvokeAsync(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (!ShouldAnalyze(context.Request))
        {
            await _next(context);
            return;
        }

        string? prompt;
        try
        {
            prompt = await ExtractPromptAsync(context.Request);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to extract prompt from request");
            await HandleExtractionError(context, ex);
            return;
        }

        if (string.IsNullOrWhiteSpace(prompt))
        {
            await _next(context);
            return;
        }

        AnalysisResult result;
        try
        {
            var request = new AnalysisRequest
            {
                Prompt = prompt,
                Metadata = new AnalysisMetadata
                {
                    Source = "AspNetCore",
                    CorrelationId = context.TraceIdentifier,
                    Properties = new Dictionary<string, string>
                    {
                        ["Path"] = context.Request.Path.Value ?? string.Empty,
                        ["Method"] = context.Request.Method,
                        ["RemoteIP"] = context.Connection.RemoteIpAddress?.ToString() ?? "unknown"
                    }
                }
            };

            result = await _analyzer.AnalyzeAsync(request, context.RequestAborted);
        }
        catch (OperationCanceledException)
        {
            _logger.LogDebug("Request cancelled during analysis");
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Prompt analysis failed for path: {Path}", context.Request.Path);
            await HandleAnalysisError(context, ex);
            return;
        }

        context.Response.Headers[_options.AnalysisIdHeader] = result.AnalysisId.ToString();

        if (result.IsThreat)
        {
            _logger.LogWarning(
                "Threat detected: AnalysisId={AnalysisId}, Path={Path}, Confidence={Confidence:F3}, OWASP={OwaspCategory}",
                result.AnalysisId,
                context.Request.Path,
                result.Confidence,
                result.ThreatInfo?.OwaspCategory);

            await WriteThreatResponse(context, result);
            return;
        }

        _logger.LogDebug(
            "Request passed analysis: AnalysisId={AnalysisId}, Path={Path}, Confidence={Confidence:F3}",
            result.AnalysisId,
            context.Request.Path,
            result.Confidence);

        await _next(context);
    }

    private bool ShouldAnalyze(HttpRequest request)
    {
        if (!IsMethodAllowed(request.Method))
            return false;

        if (!IsContentTypeAllowed(request.ContentType))
            return false;

        return IsPathAllowed(request.Path.Value ?? string.Empty);
    }

    private bool IsMethodAllowed(string method)
        => _options.HttpMethods.Contains(method, StringComparer.OrdinalIgnoreCase);

    private bool IsContentTypeAllowed(string? contentType)
    {
        var mimeType = contentType?.Split(';').FirstOrDefault()?.Trim();
        return !string.IsNullOrEmpty(mimeType) &&
               _options.ContentTypesToAnalyze.Contains(mimeType, StringComparer.OrdinalIgnoreCase);
    }

    private bool IsPathAllowed(string path)
    {
        if (_options.ExcludedPaths.Any(excluded => MatchPath(path, excluded)))
            return false;

        return _options.ProtectedPaths.Count == 0 ||
               _options.ProtectedPaths.Any(protectedPath => MatchPath(path, protectedPath));
    }

    private static bool MatchPath(string path, string pattern)
    {
        // Handle wildcard suffixes: "/api/*" or "/api*"
        if (pattern.EndsWith('*'))
        {
            var prefix = pattern.TrimEnd('*').TrimEnd('/');
            return path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
        }

        return path.Equals(pattern, StringComparison.OrdinalIgnoreCase);
    }

    private async Task<string?> ExtractPromptAsync(HttpRequest request)
    {
        request.EnableBuffering();

        if (request.ContentLength > _options.MaxRequestBodySize)
        {
            _logger.LogWarning(
                "Request body too large for analysis: {Size} > {MaxSize}",
                request.ContentLength,
                _options.MaxRequestBodySize);
            return null;
        }

        using var reader = new StreamReader(
            request.Body,
            Encoding.UTF8,
            detectEncodingFromByteOrderMarks: false,
            bufferSize: 4096,
            leaveOpen: true);

        var body = await reader.ReadToEndAsync();
        request.Body.Position = 0;

        if (string.IsNullOrWhiteSpace(body))
        {
            return null;
        }

        var contentType = request.ContentType?.Split(';').FirstOrDefault()?.Trim();
        if (contentType?.Equals("text/plain", StringComparison.OrdinalIgnoreCase) == true)
            return body;

        return ExtractPromptFromJson(body);
    }

    private string? ExtractPromptFromJson(string json)
    {
        try
        {
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;

            var prompt = GetJsonValue(root, _options.PromptJsonPath);
            if (!string.IsNullOrWhiteSpace(prompt))
                return prompt;

            foreach (var path in _options.AlternativePromptPaths)
            {
                prompt = GetJsonValue(root, path);
                if (!string.IsNullOrWhiteSpace(prompt))
                    return prompt;
            }

            return null;
        }
        catch (JsonException ex)
        {
            _logger.LogDebug(ex, "Failed to parse request body as JSON");
            return null;
        }
    }

    private static string? GetJsonValue(JsonElement element, string path)
    {
        if (path.Contains("[*]", StringComparison.Ordinal))
            return GetJsonArrayValue(element, path);

        var parts = path.Split('.');
        var current = element;

        foreach (var part in parts)
        {
            if (current.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            if (!current.TryGetProperty(part, out current))
            {
                return null;
            }
        }

        return current.ValueKind == JsonValueKind.String
            ? current.GetString()
            : current.ToString();
    }

    private static string? GetJsonArrayValue(JsonElement element, string path)
    {
        var arrayIndex = path.IndexOf("[*]", StringComparison.Ordinal);
        if (arrayIndex < 0) return null;

        var arrayPath = path[..arrayIndex];
        var propertyPath = path[(arrayIndex + 4)..]; // Skip "[*]."

        var arrayElement = element;
        if (!string.IsNullOrEmpty(arrayPath))
        {
            foreach (var part in arrayPath.Split('.'))
            {
                if (!arrayElement.TryGetProperty(part, out arrayElement))
                {
                    return null;
                }
            }
        }

        if (arrayElement.ValueKind != JsonValueKind.Array)
            return null;

        var values = new List<string>();
        foreach (var item in arrayElement.EnumerateArray())
        {
            var value = GetJsonValue(item, propertyPath);
            if (!string.IsNullOrWhiteSpace(value))
            {
                values.Add(value);
            }
        }

        return values.Count > 0 ? string.Join("\n", values) : null;
    }

    private Task HandleExtractionError(HttpContext context, Exception ex)
        => HandleErrorAsync(
            context,
            "extraction",
            "https://promptshield.dev/errors/extraction-failed",
            "Request Processing Failed",
            "Unable to process request for security analysis.");

    private Task HandleAnalysisError(HttpContext context, Exception ex)
        => HandleErrorAsync(
            context,
            "analysis",
            "https://promptshield.dev/errors/analysis-failed",
            "Security Analysis Failed",
            "Unable to complete security analysis. Request blocked for safety.");

    private async Task HandleErrorAsync(
        HttpContext context,
        string errorType,
        string problemType,
        string title,
        string detail)
    {
        if (_options.OnAnalysisError == FailureBehavior.FailOpen)
        {
            _logger.LogWarning("Allowing request due to {ErrorType} error (fail-open)", errorType);
            await _next(context);
            return;
        }

        context.Response.StatusCode = 500;
        context.Response.ContentType = "application/problem+json";

        await context.Response.WriteAsJsonAsync(new
        {
            type = problemType,
            title,
            status = 500,
            detail
        });
    }

    private async Task WriteThreatResponse(HttpContext context, AnalysisResult result)
    {
        context.Response.StatusCode = _options.ThreatStatusCode;
        context.Response.ContentType = "application/problem+json";

        var problem = BuildThreatProblem(result);
        await context.Response.WriteAsJsonAsync(problem);
    }

    private object BuildThreatProblem(AnalysisResult result)
    {
        var baseProblem = new Dictionary<string, object?>
        {
            ["type"] = "https://promptshield.dev/errors/threat-detected",
            ["title"] = "Request Blocked",
            ["status"] = _options.ThreatStatusCode,
            ["detail"] = result.ThreatInfo?.UserFacingMessage ?? "Your request was blocked due to security concerns.",
            ["analysisId"] = result.AnalysisId
        };

        if (_options.IncludeAnalysisDetailsInResponse)
        {
            baseProblem["owaspCategory"] = result.ThreatInfo?.OwaspCategory;
            baseProblem["confidence"] = result.Confidence;
        }

        return baseProblem;
    }
}
