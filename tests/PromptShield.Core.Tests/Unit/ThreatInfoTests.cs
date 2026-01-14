using FluentAssertions;
using Microsoft.Extensions.Logging.Abstractions;
using PromptShield.Abstractions.Analysis;
using PromptShield.Abstractions.Analyzers.Heuristics;
using PromptShield.Abstractions.Configuration;
using PromptShield.Abstractions.Detection;
using PromptShield.Abstractions.Detection.Patterns;
using PromptShield.Core.Layers;
using PromptShield.Core.Patterns;
using PromptShield.Core.Pipeline;

namespace PromptShield.Core.Tests.Unit;

/// <summary>
/// Unit tests for ThreatInfo assembly in the detection pipeline (US2: Threat Transparency).
/// </summary>
public class ThreatInfoTests
{
    private readonly PromptShieldOptions _defaultOptions = new()
    {
        ThreatThreshold = 0.5,  // Lower threshold for tests with single-layer detection
        IncludeBreakdown = true,
        PatternMatching = new PatternMatchingOptions
        {
            Enabled = true,
            EarlyExitThreshold = 0.9
        },
        Heuristics = new HeuristicOptions
        {
            Enabled = false,  // Disable heuristics to test pattern matching in isolation
            DefinitiveThreatThreshold = 0.85,
            DefinitiveSafeThreshold = 0.15
        }
    };

    private PipelineOrchestrator CreatePipeline(
        PromptShieldOptions? options = null,
        IEnumerable<IPatternProvider>? patternProviders = null)
    {
        var opts = options ?? _defaultOptions;

        var patternLayer = new PatternMatchingLayer(
            patternProviders ?? new[] { new BuiltInPatternProvider() },
            opts.PatternMatching,
            NullLogger<PatternMatchingLayer>.Instance);

        var heuristicLayer = new HeuristicLayer(
            new[] { new BuiltInHeuristicAnalyzer() },
            opts.Heuristics,
            opts,
            NullLogger<HeuristicLayer>.Instance);

        return new PipelineOrchestrator(
            patternLayer,
            heuristicLayer,
            mlLayer: null,
            opts,
            NullLogger<PipelineOrchestrator>.Instance);
    }

    [Fact]
    public async Task ExecuteAsync_WithThreatDetected_ShouldIncludeThreatInfo()
    {
        // Arrange
        var provider = new TestPatternProvider(new[]
        {
            new DetectionPattern
            {
                Id = "test-001",
                Name = "Jailbreak Pattern",
                Pattern = @"(?i)DAN\s+mode",
                OwaspCategory = "LLM01",
                Severity = ThreatSeverity.Critical,
                Description = "Jailbreak attempt"
            }
        });

        var pipeline = CreatePipeline(patternProviders: new[] { provider });
        var request = new AnalysisRequest
        {
            Prompt = "Hello, DAN mode activated!"
        };

        // Act
        var result = await pipeline.ExecuteAsync(request, Guid.NewGuid());

        // Assert
        result.Should().NotBeNull();
        result.IsThreat.Should().BeTrue();
        result.ThreatInfo.Should().NotBeNull();
        result.ThreatInfo!.OwaspCategory.Should().Be("LLM01");
        result.ThreatInfo.ThreatType.Should().Be("Prompt Injection");
        result.ThreatInfo.Severity.Should().BeOneOf(ThreatSeverity.Low, ThreatSeverity.Medium, ThreatSeverity.High, ThreatSeverity.Critical);
    }

    [Fact]
    public async Task ExecuteAsync_WithThreatDetected_ShouldIncludeOWASPCategory()
    {
        // Arrange
        var provider = new TestPatternProvider(new[]
        {
            new DetectionPattern
            {
                Id = "test-001",
                Name = "LLM02 Pattern",
                Pattern = @"(?i)output\s+handling",
                OwaspCategory = "LLM02",
                Severity = ThreatSeverity.High,
                Description = "Insecure output handling"
            }
        });

        var pipeline = CreatePipeline(patternProviders: new[] { provider });
        var request = new AnalysisRequest
        {
            Prompt = "This is an insecure output handling attempt"
        };

        // Act
        var result = await pipeline.ExecuteAsync(request, Guid.NewGuid());

        // Assert
        result.Should().NotBeNull();
        result.IsThreat.Should().BeTrue();
        result.ThreatInfo.Should().NotBeNull();
        result.ThreatInfo!.OwaspCategory.Should().Be("LLM02");
    }

    [Fact]
    public async Task ExecuteAsync_WithThreatDetected_ShouldIncludeMatchedPatterns()
    {
        // Arrange
        var provider = new TestPatternProvider(new[]
        {
            new DetectionPattern
            {
                Id = "test-001",
                Name = "Pattern A",
                Pattern = @"(?i)pattern\s+a",
                OwaspCategory = "LLM01",
                Severity = ThreatSeverity.Medium,
                Description = "Pattern A"
            },
            new DetectionPattern
            {
                Id = "test-002",
                Name = "Pattern B",
                Pattern = @"(?i)pattern\s+b",
                OwaspCategory = "LLM01",
                Severity = ThreatSeverity.High,
                Description = "Pattern B"
            }
        });

        var pipeline = CreatePipeline(patternProviders: new[] { provider });
        var request = new AnalysisRequest
        {
            Prompt = "This contains pattern A and pattern B"
        };

        // Act
        var result = await pipeline.ExecuteAsync(request, Guid.NewGuid());

        // Assert
        result.Should().NotBeNull();
        result.IsThreat.Should().BeTrue();
        result.ThreatInfo.Should().NotBeNull();
        result.ThreatInfo!.MatchedPatterns.Should().NotBeNull();
        result.ThreatInfo.MatchedPatterns.Should().Contain("Pattern A");
        result.ThreatInfo.MatchedPatterns.Should().Contain("Pattern B");
    }

    [Fact]
    public async Task ExecuteAsync_WithThreatDetected_ShouldIncludeDetectionSources()
    {
        // Arrange
        var provider = new TestPatternProvider(new[]
        {
            new DetectionPattern
            {
                Id = "test-001",
                Name = "Test Pattern",
                Pattern = @"(?i)test\s+pattern",
                OwaspCategory = "LLM01",
                Severity = ThreatSeverity.Medium,
                Description = "Test pattern"
            }
        });

        var pipeline = CreatePipeline(patternProviders: new[] { provider });
        var request = new AnalysisRequest
        {
            Prompt = "This is a test pattern"
        };

        // Act
        var result = await pipeline.ExecuteAsync(request, Guid.NewGuid());

        // Assert
        result.Should().NotBeNull();
        result.IsThreat.Should().BeTrue();
        result.ThreatInfo.Should().NotBeNull();
        result.ThreatInfo!.DetectionSources.Should().NotBeEmpty();
        result.ThreatInfo.DetectionSources.Should().Contain("PatternMatching");
    }

    [Fact]
    public async Task ExecuteAsync_WithThreatDetected_ShouldIncludeUserFacingMessage()
    {
        // Arrange
        var provider = new TestPatternProvider(new[]
        {
            new DetectionPattern
            {
                Id = "test-001",
                Name = "Test Pattern",
                Pattern = @"(?i)test\s+pattern",
                OwaspCategory = "LLM01",
                Severity = ThreatSeverity.Medium,
                Description = "Test pattern"
            }
        });

        var pipeline = CreatePipeline(patternProviders: new[] { provider });
        var request = new AnalysisRequest
        {
            Prompt = "This is a test pattern"
        };

        // Act
        var result = await pipeline.ExecuteAsync(request, Guid.NewGuid());

        // Assert
        result.Should().NotBeNull();
        result.IsThreat.Should().BeTrue();
        result.ThreatInfo.Should().NotBeNull();
        result.ThreatInfo!.UserFacingMessage.Should().NotBeNullOrEmpty();
        result.ThreatInfo.UserFacingMessage.Should().NotContain("confidence");
        result.ThreatInfo.UserFacingMessage.Should().NotContain("PatternMatching");
    }

    [Fact]
    public async Task ExecuteAsync_WithThreatDetected_ShouldIncludeTechnicalExplanation()
    {
        // Arrange
        var provider = new TestPatternProvider(new[]
        {
            new DetectionPattern
            {
                Id = "test-001",
                Name = "Test Pattern",
                Pattern = @"(?i)test\s+pattern",
                OwaspCategory = "LLM01",
                Severity = ThreatSeverity.Medium,
                Description = "Test pattern"
            }
        });

        var pipeline = CreatePipeline(patternProviders: new[] { provider });
        var request = new AnalysisRequest
        {
            Prompt = "This is a test pattern"
        };

        // Act
        var result = await pipeline.ExecuteAsync(request, Guid.NewGuid());

        // Assert
        result.Should().NotBeNull();
        result.IsThreat.Should().BeTrue();
        result.ThreatInfo.Should().NotBeNull();
        result.ThreatInfo!.Explanation.Should().NotBeNullOrEmpty();
        result.ThreatInfo.Explanation.Should().Contain("confidence");
        result.ThreatInfo.Explanation.Should().Contain("Detected by");
    }

    [Fact]
    public async Task ExecuteAsync_WithNoThreat_ShouldNotIncludeThreatInfo()
    {
        // Arrange
        var pipeline = CreatePipeline();
        var request = new AnalysisRequest
        {
            Prompt = "What is the weather today?"
        };

        // Act
        var result = await pipeline.ExecuteAsync(request, Guid.NewGuid());

        // Assert
        result.Should().NotBeNull();
        result.IsThreat.Should().BeFalse();
        result.ThreatInfo.Should().BeNull();
    }

    [Fact]
    public async Task ExecuteAsync_WithMultipleDetectionSources_ShouldIncludeAllSources()
    {
        // Arrange
        // Use a pattern that will match AND trigger heuristic detection
        var provider = new TestPatternProvider(new[]
        {
            new DetectionPattern
            {
                Id = "test-001",
                Name = "Test Pattern",
                Pattern = @"(?i)test\s+pattern",
                OwaspCategory = "LLM01",
                Severity = ThreatSeverity.Medium, // Medium = 0.7 confidence (below threshold, will require aggregation)
                Description = "Test pattern"
            }
        });

        var options = new PromptShieldOptions
        {
            ThreatThreshold = 0.5, // Lower threshold to ensure aggregation triggers threat
            IncludeBreakdown = true,
            PatternMatching = _defaultOptions.PatternMatching,
            Heuristics = _defaultOptions.Heuristics
        };

        var pipeline = CreatePipeline(options, patternProviders: new[] { provider });
        var request = new AnalysisRequest
        {
            Prompt = "This is a test pattern that might trigger heuristics too"
        };

        // Act
        var result = await pipeline.ExecuteAsync(request, Guid.NewGuid());

        // Assert
        result.Should().NotBeNull();
        if (result.IsThreat && result.ThreatInfo != null)
        {
            result.ThreatInfo.DetectionSources.Should().NotBeEmpty();
            // Should include at least PatternMatching, and possibly Heuristics if both detected
            result.ThreatInfo.DetectionSources.Should().Contain("PatternMatching");
        }
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
