using BenchmarkDotNet.Attributes;
using Microsoft.Extensions.DependencyInjection;
using PromptShield.Abstractions.Analyzers;
using PromptShield.Core;

namespace PromptShield.Benchmarks;

/// <summary>
/// Load test for SC-008: concurrent analysis stress test (10,000 concurrent analyses).
/// </summary>
[MemoryDiagnoser]
public class ConcurrencyBenchmarks
{
    private IPromptAnalyzer _analyzer = null!;
    private readonly string[] _testPrompts;

    public ConcurrencyBenchmarks()
    {
        // Generate diverse test prompts
        _testPrompts = Enumerable.Range(0, 100)
            .Select(i => $"Test prompt number {i}: What is the weather today?")
            .ToArray();
    }

    [GlobalSetup]
    public void Setup()
    {
        var services = new ServiceCollection();
        services.AddPromptShield(options =>
        {
            options.ML.Enabled = true;
        });
        var serviceProvider = services.BuildServiceProvider();
        _analyzer = serviceProvider.GetRequiredService<IPromptAnalyzer>();
    }

    [Benchmark]
    public async Task AnalyzeConcurrent_100()
    {
        await AnalyzeConcurrent(100);
    }

    [Benchmark]
    public async Task AnalyzeConcurrent_1000()
    {
        await AnalyzeConcurrent(1000);
    }

    [Benchmark]
    public async Task AnalyzeConcurrent_10000()
    {
        await AnalyzeConcurrent(10000);
    }

    private async Task AnalyzeConcurrent(int count)
    {
        var tasks = new List<Task>();
        var random = new Random(42); // Fixed seed for reproducibility

        for (var i = 0; i < count; i++)
        {
            var prompt = _testPrompts[random.Next(_testPrompts.Length)];
            tasks.Add(_analyzer.AnalyzeAsync(prompt));
        }

        await Task.WhenAll(tasks);
    }
}
