using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using PromptShield.Abstractions.Analysis;
using PromptShield.Abstractions.Configuration;
using PromptShield.Abstractions.Detection;
using PromptShield.Abstractions.Detection.Patterns;
using PromptShield.Core.Layers;

namespace PromptShield.Core.Tests.Unit;

public class PatternMatchingLayerTests
{
    private readonly PatternMatchingOptions _defaultOptions = new()
    {
        Enabled = true,
        TimeoutMs = 100,
        EarlyExitThreshold = 0.9,
        IncludeBuiltInPatterns = true
    };

    [Fact]
    public async Task AnalyzeAsync_WithKnownJailbreakPattern_ShouldDetectThreat()
    {
        // Arrange
        var provider = new TestPatternProvider(new[]
        {
            new DetectionPattern
            {
                Id = "test-001",
                Name = "DAN Mode",
                Pattern = @"(?i)DAN\s+mode",
                OwaspCategory = "LLM01",
                Severity = ThreatSeverity.Critical,
                Description = "DAN jailbreak attempt"
            }
        });

        var layer = new PatternMatchingLayer(
            new[] { provider },
            _defaultOptions,
            NullLogger<PatternMatchingLayer>.Instance);

        // Act
        var result = await layer.AnalyzeAsync("Hello, DAN mode activated!");

        // Assert
        result.Should().NotBeNull();
        result.WasExecuted.Should().BeTrue();
        result.IsThreat.Should().BeTrue();
        result.Confidence.Should().BeGreaterThanOrEqualTo(0.9);
        result.Data.Should().ContainKey("matched_patterns");
        
        var matchedPatterns = result.Data!["matched_patterns"] as List<string>;
        matchedPatterns.Should().Contain("DAN Mode");
    }

    [Fact]
    public async Task AnalyzeAsync_WithBenignPrompt_ShouldNotDetectThreat()
    {
        // Arrange
        var provider = new TestPatternProvider(new[]
        {
            new DetectionPattern
            {
                Id = "test-001",
                Name = "Test Pattern",
                Pattern = @"(?i)ignore\s+previous\s+instructions",
                OwaspCategory = "LLM01",
                Severity = ThreatSeverity.High,
                Description = "Test pattern"
            }
        });

        var layer = new PatternMatchingLayer(
            new[] { provider },
            _defaultOptions,
            NullLogger<PatternMatchingLayer>.Instance);

        // Act
        var result = await layer.AnalyzeAsync("What is the weather today?");

        // Assert
        result.Should().NotBeNull();
        result.WasExecuted.Should().BeTrue();
        result.IsThreat.Should().BeFalse();
        result.Confidence.Should().Be(0.0);
    }

    [Fact]
    public async Task AnalyzeAsync_WhenDisabled_ShouldNotExecute()
    {
        // Arrange
        var provider = new TestPatternProvider(new[]
        {
            new DetectionPattern
            {
                Id = "test-001",
                Name = "Test Pattern",
                Pattern = @"test",
                OwaspCategory = "LLM01",
                Severity = ThreatSeverity.High,
                Description = "Test pattern"            }
        });

        var options = new PatternMatchingOptions { Enabled = false };
        var layer = new PatternMatchingLayer(
            new[] { provider },
            options,
            NullLogger<PatternMatchingLayer>.Instance);

        // Act
        var result = await layer.AnalyzeAsync("test prompt");

        // Assert
        result.Should().NotBeNull();
        result.WasExecuted.Should().BeFalse();
    }

    [Fact]
    public async Task AnalyzeAsync_WithMultiplePatternMatches_ShouldUseHighestConfidence()
    {
        // Arrange
        var provider = new TestPatternProvider(new[]
        {
            new DetectionPattern
            {
                Id = "test-001",
                Name = "Low Severity Pattern",
                Pattern = @"(?i)test",
                OwaspCategory = "LLM01",
                Severity = ThreatSeverity.Low,
                Description = "Low severity"            },
            new DetectionPattern
            {
                Id = "test-002",
                Name = "Critical Pattern",
                Pattern = @"(?i)attack",
                OwaspCategory = "LLM01",
                Severity = ThreatSeverity.Critical,
                Description = "Critical severity"            }
        });

        var layer = new PatternMatchingLayer(
            new[] { provider },
            _defaultOptions,
            NullLogger<PatternMatchingLayer>.Instance);

        // Act
        var result = await layer.AnalyzeAsync("This is a test attack prompt");

        // Assert
        result.Should().NotBeNull();
        result.IsThreat.Should().BeTrue();
        result.Confidence.Should().BeGreaterThanOrEqualTo(0.9); // Critical severity
        
        var matchedPatterns = result.Data!["matched_patterns"] as List<string>;
        matchedPatterns.Should().Contain("Critical Pattern");
        matchedPatterns.Should().Contain("Low Severity Pattern");
    }

    [Fact]
    public async Task AnalyzeAsync_WithEarlyExitThreshold_ShouldExitEarly()
    {
        // Arrange
        var provider = new TestPatternProvider(new[]
        {
            new DetectionPattern
            {
                Id = "test-001",
                Name = "Critical Pattern",
                Pattern = @"(?i)critical",
                OwaspCategory = "LLM01",
                Severity = ThreatSeverity.Critical,
                Description = "Critical pattern"            },
            new DetectionPattern
            {
                Id = "test-002",
                Name = "Should Not Match",
                Pattern = @"(?i)never",
                OwaspCategory = "LLM01",
                Severity = ThreatSeverity.High,
                Description = "Should not be evaluated"            }
        });

        var options = new PatternMatchingOptions
        {
            Enabled = true,
            EarlyExitThreshold = 0.9,
            TimeoutMs = 100
        };

        var layer = new PatternMatchingLayer(
            new[] { provider },
            options,
            NullLogger<PatternMatchingLayer>.Instance);

        // Act
        var result = await layer.AnalyzeAsync("This is critical");

        // Assert
        result.Should().NotBeNull();
        result.IsThreat.Should().BeTrue();
        result.Confidence.Should().BeGreaterThanOrEqualTo(0.9);
    }


    [Fact]
    public async Task AnalyzeAsync_WithOwaspCategoryMapping_ShouldIncludeInResult()
    {
        // Arrange
        var provider = new TestPatternProvider(new[]
        {
            new DetectionPattern
            {
                Id = "test-001",
                Name = "LLM01 Pattern",
                Pattern = @"(?i)injection",
                OwaspCategory = "LLM01",
                Severity = ThreatSeverity.High,
                Description = "Prompt injection"            }
        });

        var layer = new PatternMatchingLayer(
            new[] { provider },
            _defaultOptions,
            NullLogger<PatternMatchingLayer>.Instance);

        // Act
        var result = await layer.AnalyzeAsync("This is an injection attempt");

        // Assert
        result.Should().NotBeNull();
        result.IsThreat.Should().BeTrue();
        result.Data.Should().ContainKey("owasp_category");
        result.Data!["owasp_category"].Should().Be("LLM01");
    }

    [Fact]
    public void PatternCount_ShouldReturnNumberOfCompiledPatterns()
    {
        // Arrange
        var provider = new TestPatternProvider(new[]
        {
            new DetectionPattern
            {
                Id = "test-001",
                Name = "Pattern 1",
                Pattern = @"test1",
                OwaspCategory = "LLM01",
                Severity = ThreatSeverity.High,
                Description = "Pattern 1"            },
            new DetectionPattern
            {
                Id = "test-002",
                Name = "Pattern 2",
                Pattern = @"test2",
                OwaspCategory = "LLM01",
                Severity = ThreatSeverity.High,
                Description = "Pattern 2"            }
        });

        // Act
        var layer = new PatternMatchingLayer(
            new[] { provider },
            _defaultOptions,
            NullLogger<PatternMatchingLayer>.Instance);

        // Assert
        layer.PatternCount.Should().Be(2);
    }

    [Fact]
    public async Task AnalyzeAsync_WithCancellationToken_ShouldRespectCancellation()
    {
        // Arrange
        var provider = new TestPatternProvider(new[]
        {
            new DetectionPattern
            {
                Id = "test-001",
                Name = "Test Pattern",
                Pattern = @"test",
                OwaspCategory = "LLM01",
                Severity = ThreatSeverity.High,
                Description = "Test pattern"            }
        });

        var layer = new PatternMatchingLayer(
            new[] { provider },
            _defaultOptions,
            NullLogger<PatternMatchingLayer>.Instance);

        var cts = new CancellationTokenSource();
        cts.Cancel(); // Cancel immediately

        // Act & Assert
        await Assert.ThrowsAsync<OperationCanceledException>(
            async () => await layer.AnalyzeAsync("test prompt", cts.Token));
    }

    // Helper class for testing
    private class TestPatternProvider : IPatternProvider
    {
        private readonly IEnumerable<DetectionPattern> _patterns;

        public TestPatternProvider(IEnumerable<DetectionPattern> patterns)
        {
            _patterns = patterns;
        }

        public string ProviderName => "Test Pattern Provider";

        public IEnumerable<DetectionPattern> GetPatterns() => _patterns;
    }
}
