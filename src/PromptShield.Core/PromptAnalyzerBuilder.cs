using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using PromptShield.Abstractions.Analyzers;
using PromptShield.Abstractions.Configuration;
using PromptShield.Abstractions.Detection.Patterns;
using PromptShield.Abstractions.Events;

namespace PromptShield.Core;

/// <summary>
/// Builder for fluent configuration of IPromptAnalyzer instances.
/// </summary>
/// <remarks>
/// This builder enables programmatic configuration of PromptShield analyzer
/// without requiring dependency injection (useful for Semantic Kernel integration).
/// </remarks>
public sealed class PromptAnalyzerBuilder : IPromptAnalyzerBuilder
{
    private readonly IServiceCollection _services;
    private readonly PromptShieldOptions _options;

    /// <summary>
    /// Initializes a new instance of the PromptAnalyzerBuilder.
    /// </summary>
    /// <param name="services">Service collection for registering dependencies.</param>
    /// <param name="options">PromptShield options.</param>
    internal PromptAnalyzerBuilder(IServiceCollection services, PromptShieldOptions options)
    {
        _services = services ?? throw new ArgumentNullException(nameof(services));
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    /// <inheritdoc/>
    public IPromptAnalyzerBuilder Configure(Action<PromptShieldOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        configure(_options);
        return this;
    }

    /// <inheritdoc/>
    public IPromptAnalyzerBuilder AddPatternProvider<TProvider>() where TProvider : class, IPatternProvider
    {
        _services.TryAddEnumerable(ServiceDescriptor.Singleton<IPatternProvider, TProvider>());
        return this;
    }

    /// <inheritdoc/>
    public IPromptAnalyzerBuilder AddEventHandler<THandler>() where THandler : class, IPromptShieldEventHandler
    {
        _services.TryAddEnumerable(ServiceDescriptor.Singleton<IPromptShieldEventHandler, THandler>());
        return this;
    }

    /// <inheritdoc/>
    public IPromptAnalyzer Build()
    {
        // Register core services if not already registered
        ServiceCollectionExtensions.RegisterCoreServices(_services, _options);

        // Build service provider and return analyzer
        // Note: This creates a new service provider. In DI scenarios, use the existing provider.
        var serviceProvider = _services.BuildServiceProvider();
        try
        {
            return serviceProvider.GetRequiredService<IPromptAnalyzer>();
        }
        finally
        {
            // Dispose the service provider if it implements IDisposable
            if (serviceProvider is IDisposable disposable)
            {
                disposable.Dispose();
            }
        }
    }
}
