using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using PromptShield.Abstractions.Analysis;
using PromptShield.Abstractions.Configuration;
using PromptShield.Abstractions.Detection;
using PromptShield.Abstractions.Detection.Patterns;
using PromptShield.Core;
using PromptShield.Core.Layers;
using PromptShield.Core.Patterns;

namespace PromptShield.Core.Tests.Unit;

/// <summary>
/// Unit tests for custom pattern provider registration (US3: Custom Pattern Extension).
/// </summary>
public class CustomPatternProviderTests
{
    [Fact]
    public void AddPatternProvider_ShouldRegisterCustomProvider()
    {
        // Arrange
        var services = new ServiceCollection();
        services.AddPromptShield();

        // Act
        services.AddPatternProvider<TestCustomPatternProvider>();

        // Assert
        var provider = services.BuildServiceProvider();
        var patternProviders = provider.GetServices<IPatternProvider>().ToList();
        
        patternProviders.Should().Contain(p => p is TestCustomPatternProvider);
    }

    [Fact]
    public async Task PatternMatchingLayer_ShouldUseCustomPatterns()
    {
        // Arrange
        var customProvider = new TestCustomPatternProvider();
        var options = new PatternMatchingOptions
        {
            Enabled = true,
            TimeoutMs = 100
        };

        var layer = new PatternMatchingLayer(
            new[] { customProvider },
            options,
            NullLogger<PatternMatchingLayer>.Instance);

        // Act
        var result = await layer.AnalyzeAsync("This is a custom pattern match");

        // Assert
        result.Should().NotBeNull();
        result.IsThreat.Should().BeTrue();
        result.Data.Should().ContainKey("matched_patterns");
        
        var matchedPatterns = result.Data!["matched_patterns"] as List<string>;
        matchedPatterns.Should().Contain("Custom Pattern");
    }

    [Fact]
    public async Task PatternMatchingLayer_ShouldAggregateBuiltInAndCustomPatterns()
    {
        // Arrange
        var builtInProvider = new BuiltInPatternProvider();
        var customProvider = new TestCustomPatternProvider();
        var options = new PatternMatchingOptions
        {
            Enabled = true,
            TimeoutMs = 100
        };

        var layer = new PatternMatchingLayer(
            new IPatternProvider[] { builtInProvider, customProvider },
            options,
            NullLogger<PatternMatchingLayer>.Instance);

        // Act
        var customResult = await layer.AnalyzeAsync("This is a custom pattern match");
        var builtInResult = await layer.AnalyzeAsync("DAN mode enabled");

        // Assert
        customResult.IsThreat.Should().BeTrue();
        customResult.Data.Should().ContainKey("matched_patterns");
        var customMatched = customResult.Data!["matched_patterns"] as List<string>;
        customMatched.Should().Contain("Custom Pattern");

        builtInResult.IsThreat.Should().BeTrue();
        builtInResult.Data.Should().ContainKey("matched_patterns");
    }

    [Fact]
    public async Task PatternMatchingLayer_ShouldIncludeCustomPatternsInMatchedPatterns()
    {
        // Arrange
        var customProvider = new TestCustomPatternProvider();
        var options = new PatternMatchingOptions
        {
            Enabled = true,
            TimeoutMs = 100
        };

        var layer = new PatternMatchingLayer(
            new[] { customProvider },
            options,
            NullLogger<PatternMatchingLayer>.Instance);

        // Act
        var result = await layer.AnalyzeAsync("This is a custom pattern match");

        // Assert
        result.Should().NotBeNull();
        result.IsThreat.Should().BeTrue();
        result.Data.Should().ContainKey("matched_patterns");
        
        var matchedPatterns = result.Data!["matched_patterns"] as List<string>;
        matchedPatterns.Should().Contain("Custom Pattern");
        
        // Verify pattern appears in ThreatInfo when threat is detected
        // This will be tested in integration tests
    }

    [Fact]
    public void MultipleCustomProviders_ShouldAllBeRegistered()
    {
        // Arrange
        var services = new ServiceCollection();
        services.AddPromptShield();

        // Act
        services.AddPatternProvider<TestCustomPatternProvider>();
        services.AddPatternProvider<AnotherCustomPatternProvider>();

        // Assert
        var provider = services.BuildServiceProvider();
        var patternProviders = provider.GetServices<IPatternProvider>().ToList();
        
        patternProviders.Should().Contain(p => p is TestCustomPatternProvider);
        patternProviders.Should().Contain(p => p is AnotherCustomPatternProvider);
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
}
