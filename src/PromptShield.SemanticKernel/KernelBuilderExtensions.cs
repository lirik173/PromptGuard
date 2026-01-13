using Microsoft.Extensions.DependencyInjection;
using Microsoft.SemanticKernel;
using PromptShield.Abstractions.Analyzers;
using PromptShield.Abstractions.Configuration;
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
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configure);

        // Build options to access them for filter registration
        var options = new PromptShieldOptions();
        configure(options);

        // Register PromptShield services
        builder.Services.AddPromptShield(configure);

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
}
