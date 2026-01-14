using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using PromptShield.Abstractions.Analysis;
using PromptShield.Abstractions.Analyzers;
using PromptShield.Abstractions.Configuration;
using PromptShield.Abstractions.Detection;
using PromptShield.Abstractions.Detection.Patterns;
using PromptShield.Core;
using PromptShield.Core.Patterns;

namespace PromptShield.Core.Tests.Integration;

/// <summary>
/// Integration tests for pattern aggregation from multiple providers (US3: Custom Pattern Extension).
/// </summary>
public class PatternAggregationTests
{
    [Fact]
    public async Task AnalyzeAsync_WithCustomPatterns_ShouldDetectCustomPatternMatches()
    {
        // Arrange
        var services = new ServiceCollection();
        services.AddPromptShield(options =>
        {
            // Medium severity = 0.7 confidence, so threshold must be <= 0.7
            options.ThreatThreshold = 0.65;
            options.PatternMatching.IncludeBuiltInPatterns = false; // Only custom patterns
            options.Heuristics.Enabled = false; // Test pattern matching in isolation
        });
        services.AddPatternProvider<TestCustomPatternProvider>();

        var provider = services.BuildServiceProvider();
        var analyzer = provider.GetRequiredService<IPromptAnalyzer>();

        // Act
        var result = await analyzer.AnalyzeAsync("This is a custom pattern match");

        // Assert
        result.Should().NotBeNull();
        result.IsThreat.Should().BeTrue();
        result.ThreatInfo.Should().NotBeNull();
        result.ThreatInfo!.MatchedPatterns.Should().Contain("Custom Pattern");
    }

    [Fact]
    public async Task AnalyzeAsync_WithBuiltInAndCustomPatterns_ShouldDetectBoth()
    {
        // Arrange
        var services = new ServiceCollection();
        services.AddPromptShield(options =>
        {
            // Medium severity = 0.7 confidence, so threshold must be <= 0.7
            options.ThreatThreshold = 0.65;
            options.Heuristics.Enabled = false; // Test pattern matching in isolation
        });
        services.AddPatternProvider<TestCustomPatternProvider>();

        var provider = services.BuildServiceProvider();
        var analyzer = provider.GetRequiredService<IPromptAnalyzer>();

        // Act - Test custom pattern
        var customResult = await analyzer.AnalyzeAsync("This is a custom pattern match");
        
        // Act - Test built-in pattern (DAN mode = Critical severity = 0.95 confidence)
        var builtInResult = await analyzer.AnalyzeAsync("DAN mode enabled");

        // Assert - Custom pattern detected
        customResult.Should().NotBeNull();
        customResult.IsThreat.Should().BeTrue();
        customResult.ThreatInfo.Should().NotBeNull();
        customResult.ThreatInfo!.MatchedPatterns.Should().Contain("Custom Pattern");

        // Assert - Built-in pattern detected
        builtInResult.Should().NotBeNull();
        builtInResult.IsThreat.Should().BeTrue();
        builtInResult.ThreatInfo.Should().NotBeNull();
    }

    [Fact]
    public async Task AnalyzeAsync_WithMultipleCustomProviders_ShouldAggregateAllPatterns()
    {
        // Arrange
        var services = new ServiceCollection();
        services.AddPromptShield(options =>
        {
            // Medium severity = 0.7, Low severity = 0.5, so threshold must be <= 0.5
            options.ThreatThreshold = 0.45;
            options.PatternMatching.IncludeBuiltInPatterns = false;
            options.Heuristics.Enabled = false; // Test pattern matching in isolation
        });
        services.AddPatternProvider<TestCustomPatternProvider>();
        services.AddPatternProvider<AnotherCustomPatternProvider>();

        var provider = services.BuildServiceProvider();
        var analyzer = provider.GetRequiredService<IPromptAnalyzer>();

        // Act - Test first custom pattern (Medium severity = 0.7 confidence)
        var result1 = await analyzer.AnalyzeAsync("This is a custom pattern match");
        
        // Act - Test second custom pattern (Low severity = 0.5 confidence)
        var result2 = await analyzer.AnalyzeAsync("This is another custom pattern");

        // Assert
        result1.Should().NotBeNull();
        result1.IsThreat.Should().BeTrue();
        result1.ThreatInfo!.MatchedPatterns.Should().Contain("Custom Pattern");

        result2.Should().NotBeNull();
        result2.IsThreat.Should().BeTrue();
        result2.ThreatInfo!.MatchedPatterns.Should().Contain("Another Custom Pattern");
    }

    [Fact]
    public async Task AnalyzeAsync_WithCustomPattern_ShouldIncludeInThreatInfo()
    {
        // Arrange
        var services = new ServiceCollection();
        services.AddPromptShield(options =>
        {
            // Medium severity = 0.7 confidence, so threshold must be <= 0.7
            options.ThreatThreshold = 0.65;
            options.PatternMatching.IncludeBuiltInPatterns = false;
            options.Heuristics.Enabled = false; // Test pattern matching in isolation
        });
        services.AddPatternProvider<TestCustomPatternProvider>();

        var provider = services.BuildServiceProvider();
        var analyzer = provider.GetRequiredService<IPromptAnalyzer>();

        // Act
        var result = await analyzer.AnalyzeAsync("This is a custom pattern match");

        // Assert
        result.Should().NotBeNull();
        result.IsThreat.Should().BeTrue();
        result.ThreatInfo.Should().NotBeNull();
        result.ThreatInfo!.MatchedPatterns.Should().NotBeNull();
        result.ThreatInfo.MatchedPatterns.Should().Contain("Custom Pattern");
        result.ThreatInfo.DetectionSources.Should().Contain("PatternMatching");
    }

    [Fact]
    public async Task AnalyzeAsync_WithMultipleMatchingPatterns_ShouldIncludeAllInMatchedPatterns()
    {
        // Arrange
        var services = new ServiceCollection();
        services.AddPromptShield(options =>
        {
            // Medium severity = 0.7 confidence, so threshold must be <= 0.7
            options.ThreatThreshold = 0.65;
            options.PatternMatching.IncludeBuiltInPatterns = false;
            options.Heuristics.Enabled = false; // Test pattern matching in isolation
        });
        services.AddPatternProvider<MultiPatternProvider>();

        var provider = services.BuildServiceProvider();
        var analyzer = provider.GetRequiredService<IPromptAnalyzer>();

        // Act - Prompt matches multiple patterns (both Medium severity = 0.7 confidence)
        var result = await analyzer.AnalyzeAsync("This matches pattern A and pattern B");

        // Assert
        result.Should().NotBeNull();
        result.IsThreat.Should().BeTrue();
        result.ThreatInfo.Should().NotBeNull();
        result.ThreatInfo!.MatchedPatterns.Should().Contain("Pattern A");
        result.ThreatInfo.MatchedPatterns.Should().Contain("Pattern B");
    }

    // Helper classes for testing
    private class TestCustomPatternProvider : IPatternProvider
    {
        public string ProviderName => "Test Custom Pattern Provider";

        public IEnumerable<DetectionPattern> GetPatterns()
        {
            yield return new DetectionPattern
            {
                Id = "custom-001",
                Name = "Custom Pattern",
                Pattern = @"(?i)custom\s+pattern",
                OwaspCategory = "LLM01",
                Severity = ThreatSeverity.Medium,
                Description = "Custom test pattern"
            };
        }
    }

    private class AnotherCustomPatternProvider : IPatternProvider
    {
        public string ProviderName => "Another Custom Pattern Provider";

        public IEnumerable<DetectionPattern> GetPatterns()
        {
            yield return new DetectionPattern
            {
                Id = "custom-002",
                Name = "Another Custom Pattern",
                Pattern = @"(?i)another\s+custom",
                OwaspCategory = "LLM01",
                Severity = ThreatSeverity.Low,
                Description = "Another custom test pattern"
            };
        }
    }

    private class MultiPatternProvider : IPatternProvider
    {
        public string ProviderName => "Multi Pattern Provider";

        public IEnumerable<DetectionPattern> GetPatterns()
        {
            yield return new DetectionPattern
            {
                Id = "multi-001",
                Name = "Pattern A",
                Pattern = @"(?i)pattern\s+a",
                OwaspCategory = "LLM01",
                Severity = ThreatSeverity.Medium,
                Description = "Pattern A"
            };
            
            yield return new DetectionPattern
            {
                Id = "multi-002",
                Name = "Pattern B",
                Pattern = @"(?i)pattern\s+b",
                OwaspCategory = "LLM01",
                Severity = ThreatSeverity.Medium,
                Description = "Pattern B"
            };
        }
    }
}
