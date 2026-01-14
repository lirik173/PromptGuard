using BenchmarkDotNet.Attributes;
using Microsoft.Extensions.DependencyInjection;
using PromptShield.Abstractions.Analyzers;
using PromptShield.Core;

namespace PromptShield.Benchmarks;

/// <summary>
/// Benchmarks for clean prompt fast-path performance (SC-002: 95% of clean prompts complete in &lt;1ms).
/// </summary>
[MemoryDiagnoser]
public class CleanPromptBenchmarks
{
    private IPromptAnalyzer _analyzer = null!;
    private readonly string[] _cleanPrompts = new[]
    {
        "What is the weather today?",
        "Tell me a joke",
        "How do I cook pasta?",
        "Explain quantum computing in simple terms",
        "What are the benefits of exercise?",
        "Can you help me write an email?",
        "What is the capital of France?",
        "How does photosynthesis work?",
        "Recommend a good book to read",
        "What is machine learning?"
    };

    [GlobalSetup]
    public void Setup()
    {
        var services = new ServiceCollection();
        services.AddPromptShield(options =>
        {
            // Optimize for performance
            options.PatternMatching.EarlyExitThreshold = 0.9;
            options.Heuristics.DefinitiveSafeThreshold = 0.15;
            options.ML.Enabled = false; // Disable ML for clean prompt fast-path
        });
        var serviceProvider = services.BuildServiceProvider();
        _analyzer = serviceProvider.GetRequiredService<IPromptAnalyzer>();
    }

    [Benchmark(Baseline = true)]
    [ArgumentsSource(nameof(CleanPrompts))]
    public async Task AnalyzeCleanPrompt(string prompt)
    {
        await _analyzer.AnalyzeAsync(prompt);
    }

    public IEnumerable<string> CleanPrompts()
    {
        foreach (var prompt in _cleanPrompts)
        {
            yield return prompt;
        }
    }
}
