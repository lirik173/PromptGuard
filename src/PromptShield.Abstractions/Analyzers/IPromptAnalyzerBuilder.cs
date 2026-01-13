namespace PromptShield.Abstractions.Analyzers;

using PromptShield.Abstractions.Configuration;
using PromptShield.Abstractions.Detection.Patterns;
using PromptShield.Abstractions.Events;

/// <summary>
/// Builder interface for fluent configuration of the analyzer.
/// </summary>
public interface IPromptAnalyzerBuilder
{
    /// <summary>
    /// Configures the analyzer options.
    /// </summary>
    IPromptAnalyzerBuilder Configure(Action<PromptShieldOptions> configure);

    /// <summary>
    /// Adds a custom pattern provider.
    /// </summary>
    IPromptAnalyzerBuilder AddPatternProvider<TProvider>() where TProvider : class, IPatternProvider;

    /// <summary>
    /// Adds an event handler for analysis events.
    /// </summary>
    IPromptAnalyzerBuilder AddEventHandler<THandler>() where THandler : class, IPromptShieldEventHandler;

    /// <summary>
    /// Builds the analyzer with the configured options.
    /// </summary>
    IPromptAnalyzer Build();
}
