using Microsoft.Extensions.DependencyInjection;
using Microsoft.SemanticKernel;
using PromptShield.Abstractions.Analyzers;
using PromptShield.Abstractions.Configuration;
using PromptShield.Abstractions.Detection.Patterns;
using PromptShield.Abstractions.Events;
using PromptShield.Core;

namespace PromptShield.SemanticKernel;

/// <summary>
/// Extension methods for integrating PromptShield with Semantic Kernel.
/// </summary>
public static class KernelBuilderExtensions
{
    /// <summary>
    /// Adds PromptShield protection to the Semantic Kernel with default configuration.
    /// </summary>
    /// <param name="builder">The kernel builder.</param>
    /// <returns>The kernel builder for chaining.</returns>
    /// <remarks>
    /// Uses secure defaults:
    /// <list type="bullet">
    /// <item>Fail-closed behavior on analysis errors</item>
    /// <item>All detection layers enabled</item>
    /// <item>Default threat threshold of 0.75</item>
    /// </list>
    /// </remarks>
    public static IKernelBuilder AddPromptShield(this IKernelBuilder builder)
    {
        return builder.AddPromptShield(_ => { });
    }

    /// <summary>
    /// Adds PromptShield protection to the Semantic Kernel with custom configuration.
    /// </summary>
    /// <param name="builder">The kernel builder.</param>
    /// <param name="configure">Action to configure PromptShield options.</param>
    /// <returns>The kernel builder for chaining.</returns>
    /// <example>
    /// <code>
    /// var kernel = Kernel.CreateBuilder()
    ///     .AddPromptShield(options =>
    ///     {
    ///         options.ThreatThreshold = 0.8;
    ///         options.SemanticKernel.OnAnalysisError = FailureBehavior.FailOpen; // Not recommended
    ///     })
    ///     .Build();
    /// </code>
    /// </example>
    public static IKernelBuilder AddPromptShield(
        this IKernelBuilder builder,
        Action<PromptShieldOptions> configure)
    {
        return builder.AddPromptShield(configure, _ => { });
    }

    /// <summary>
    /// Adds PromptShield protection to the Semantic Kernel with custom configuration and builder.
    /// </summary>
    /// <param name="builder">The kernel builder.</param>
    /// <param name="configure">Action to configure PromptShield options.</param>
    /// <param name="builderAction">Action to configure the analyzer builder (e.g., add custom pattern providers).</param>
    /// <returns>The kernel builder for chaining.</returns>
    /// <example>
    /// <code>
    /// var kernel = Kernel.CreateBuilder()
    ///     .AddPromptShield(
    ///         options => { options.ThreatThreshold = 0.8; },
    ///         analyzerBuilder => analyzerBuilder.AddPatternProvider&lt;MyCustomPatternProvider&gt;())
    ///     .Build();
    /// </code>
    /// </example>
    public static IKernelBuilder AddPromptShield(
        this IKernelBuilder builder,
        Action<PromptShieldOptions> configure,
        Action<IPromptAnalyzerBuilder> builderAction)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);
        ArgumentNullException.ThrowIfNull(builderAction);

        // Build options to access them for filter registration
        var options = new PromptShieldOptions();
        configure(options);

        // Register PromptShield services
        builder.Services.AddPromptShield(configure);

        // Apply builder actions (e.g., custom pattern providers)
        // Create a temporary builder that uses the same service collection
        var analyzerBuilder = CreateBuilder(builder.Services, options);
        builderAction(analyzerBuilder);

        // Register PromptShield filter with proper options
        builder.Services.AddSingleton<IPromptRenderFilter>(sp =>
        {
            var analyzer = sp.GetRequiredService<IPromptAnalyzer>();
            var registeredOptions = sp.GetRequiredService<PromptShieldOptions>();
            var logger = sp.GetService<Microsoft.Extensions.Logging.ILogger<PromptShieldFilter>>();
            return new PromptShieldFilter(analyzer, registeredOptions.SemanticKernel, logger);
        });

        return builder;
    }

    private static IPromptAnalyzerBuilder CreateBuilder(IServiceCollection services, PromptShieldOptions options)
    {
        // Use reflection or create a wrapper since PromptAnalyzerBuilder constructor is internal
        // For now, we'll use the service collection extension methods directly
        // and create a simple builder wrapper
        return new KernelPromptAnalyzerBuilder(services, options);
    }

    private sealed class KernelPromptAnalyzerBuilder : IPromptAnalyzerBuilder
    {
        private readonly IServiceCollection _services;
        private readonly PromptShieldOptions _options;

        public KernelPromptAnalyzerBuilder(IServiceCollection services, PromptShieldOptions options)
        {
            _services = services;
            _options = options;
        }

        public IPromptAnalyzerBuilder Configure(Action<PromptShieldOptions> configure)
        {
            configure(_options);
            return this;
        }

        public IPromptAnalyzerBuilder AddPatternProvider<TProvider>() where TProvider : class, IPatternProvider
        {
            _services.AddPatternProvider<TProvider>();
            return this;
        }

        public IPromptAnalyzerBuilder AddEventHandler<THandler>() where THandler : class, IPromptShieldEventHandler
        {
            _services.AddEventHandler<THandler>();
            return this;
        }

        public IPromptAnalyzer Build()
        {
            // Services are already registered via AddPromptShield
            // The analyzer will be resolved from DI when the filter is created
            // This method is not typically called in Semantic Kernel scenario
            throw new InvalidOperationException(
                "Build() should not be called when using Semantic Kernel integration. " +
                "The analyzer is resolved from dependency injection.");
        }
    }
}
