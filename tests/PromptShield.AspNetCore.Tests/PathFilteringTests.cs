using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using PromptShield.Abstractions.Analyzers;
using PromptShield.Abstractions.Analysis;
using PromptShield.AspNetCore;

namespace PromptShield.AspNetCore.Tests;

/// <summary>
/// Unit tests for path filtering in PromptShield middleware (US5).
/// </summary>
public class PathFilteringTests
{
    [Fact]
    public async Task Middleware_WithExcludedPath_ShouldSkipAnalysis()
    {
        // Arrange
        var analyzer = new Mock<IPromptAnalyzer>();
        var options = new PromptShieldMiddlewareOptions
        {
            ExcludedPaths = new[] { "/health", "/metrics" }
        };
        var middleware = CreateMiddleware(analyzer, options);
        var context = CreateHttpContext("/health", "application/json", "{\"prompt\":\"test\"}");

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        analyzer.Invocations.Should().BeEmpty();
    }

    [Fact]
    public async Task Middleware_WithProtectedPath_ShouldAnalyze()
    {
        // Arrange
        var analyzer = CreateMockAnalyzer();
        var options = new PromptShieldMiddlewareOptions
        {
            ProtectedPaths = new[] { "/api/chat", "/api/completion" }
        };
        var middleware = CreateMiddleware(analyzer, options);
        var context = CreateHttpContext("/api/chat", "application/json", "{\"prompt\":\"test\"}");

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        analyzer.Verify(a => a.AnalyzeAsync(It.IsAny<AnalysisRequest>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task Middleware_WithPathNotInProtectedList_ShouldSkip()
    {
        // Arrange
        var analyzer = new Mock<IPromptAnalyzer>();
        var options = new PromptShieldMiddlewareOptions
        {
            ProtectedPaths = new[] { "/api/chat" }
        };
        var middleware = CreateMiddleware(analyzer, options);
        var context = CreateHttpContext("/api/other", "application/json", "{\"prompt\":\"test\"}");

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        analyzer.Invocations.Should().BeEmpty();
    }

    [Fact]
    public async Task Middleware_WithWildcardProtectedPath_ShouldMatch()
    {
        // Arrange
        var analyzer = CreateMockAnalyzer();
        var options = new PromptShieldMiddlewareOptions
        {
            ProtectedPaths = new[] { "/api/chat/*" }
        };
        var middleware = CreateMiddleware(analyzer, options);
        var context = CreateHttpContext("/api/chat/messages", "application/json", "{\"prompt\":\"test\"}");

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        analyzer.Verify(a => a.AnalyzeAsync(It.IsAny<AnalysisRequest>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task Middleware_WithExcludedPathTakesPrecedence_ShouldSkip()
    {
        // Arrange
        var analyzer = new Mock<IPromptAnalyzer>();
        var options = new PromptShieldMiddlewareOptions
        {
            ProtectedPaths = new[] { "/api/chat" },
            ExcludedPaths = new[] { "/api/chat/health" }
        };
        var middleware = CreateMiddleware(analyzer, options);
        var context = CreateHttpContext("/api/chat/health", "application/json", "{\"prompt\":\"test\"}");

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        analyzer.Invocations.Should().BeEmpty();
    }

    [Fact]
    public async Task Middleware_WithNoProtectedPaths_ShouldProtectAll()
    {
        // Arrange
        var analyzer = CreateMockAnalyzer();
        var options = new PromptShieldMiddlewareOptions
        {
            ProtectedPaths = Array.Empty<string>(),
            ExcludedPaths = new[] { "/health" }
        };
        var middleware = CreateMiddleware(analyzer, options);
        var context = CreateHttpContext("/api/chat", "application/json", "{\"prompt\":\"test\"}");

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        analyzer.Verify(a => a.AnalyzeAsync(It.IsAny<AnalysisRequest>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task Middleware_WithGetMethod_ShouldSkip()
    {
        // Arrange
        var analyzer = new Mock<IPromptAnalyzer>();
        var options = new PromptShieldMiddlewareOptions
        {
            HttpMethods = new[] { "POST", "PUT" }
        };
        var middleware = CreateMiddleware(analyzer, options);
        var context = CreateHttpContext("/api/chat", "application/json", "{\"prompt\":\"test\"}");
        context.Request.Method = "GET";

        // Act
        await middleware.InvokeAsync(context);

        // Assert
        analyzer.Invocations.Should().BeEmpty();
    }

    private static Mock<IPromptAnalyzer> CreateMockAnalyzer()
    {
        var mock = new Mock<IPromptAnalyzer>();
        mock.Setup(a => a.AnalyzeAsync(It.IsAny<AnalysisRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new AnalysisResult
            {
                AnalysisId = Guid.NewGuid(),
                IsThreat = false,
                Confidence = 0.1,
                ThreatInfo = null,
                Breakdown = null,
                DecisionLayer = "PatternMatching",
                Duration = TimeSpan.FromMilliseconds(1),
                Timestamp = DateTimeOffset.UtcNow
            });
        return mock;
    }

    private static PromptShieldMiddleware CreateMiddleware(Mock<IPromptAnalyzer> analyzer, PromptShieldMiddlewareOptions options)
    {
        RequestDelegate next = async (ctx) => await Task.CompletedTask;
        return new PromptShieldMiddleware(
            next,
            analyzer.Object,
            options,
            NullLogger<PromptShieldMiddleware>.Instance);
    }

    private static HttpContext CreateHttpContext(string path, string contentType, string body)
    {
        var context = new DefaultHttpContext();
        context.Request.Path = path;
        context.Request.Method = "POST";
        context.Request.ContentType = contentType;
        context.Request.Body = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(body));
        context.Request.ContentLength = body.Length;
        context.Response.Body = new MemoryStream();
        return context;
    }
}
