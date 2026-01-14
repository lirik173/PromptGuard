namespace PromptShield.Benchmarks;

using BenchmarkDotNet.Running;

internal class Program
{
    private static void Main(string[] args)
    {
        // Run all benchmarks
        BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args);
    }
}
