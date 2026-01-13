using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using PromptShield.Abstractions.Analyzers;
using PromptShield.Abstractions.Analyzers.Heuristics;
using PromptShield.Abstractions.Configuration;
using PromptShield.Abstractions.Detection.Patterns;
using PromptShield.Abstractions.Events;
using PromptShield.Core.Layers;
using PromptShield.Core.Patterns;
using PromptShield.Core.Pipeline;
using PromptShield.Core.Validation;

namespace PromptShield.Core;

/// <summary>
/// Extension methods for registering PromptShield services with dependency injection.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds PromptShield services to the service collection with default configuration.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddPromptShield(this IServiceCollection services)
    {
        return services.AddPromptShield(_ => { });
    }

    /// <summary>
    /// Adds PromptShield services to the service collection with configuration action.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Action to configure PromptShield options.</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddPromptShield(
        this IServiceCollection services,
        Action<PromptShieldOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        // Configure options
        var options = new PromptShieldOptions();
        configure(options);
        services.AddSingleton(options);

        // Register core components
        RegisterCoreServices(services, options);

        return services;
    }

    /// <summary>
    /// Adds a custom pattern provider to the service collection.
    /// </summary>
    /// <typeparam name="TProvider">The pattern provider type.</typeparam>
    /// <param name="services">The service collection.</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddPatternProvider<TProvider>(this IServiceCollection services)
        where TProvider : class, IPatternProvider
    {
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IPatternProvider, TProvider>());
        return services;
    }

    /// <summary>
    /// Adds a custom heuristic analyzer to the service collection.
    /// </summary>
    /// <typeparam name="TAnalyzer">The heuristic analyzer type.</typeparam>
    /// <param name="services">The service collection.</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddHeuristicAnalyzer<TAnalyzer>(this IServiceCollection services)
        where TAnalyzer : class, IHeuristicAnalyzer
    {
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHeuristicAnalyzer, TAnalyzer>());
        return services;
    }

    /// <summary>
    /// Adds a custom event handler to the service collection.
    /// </summary>
    /// <typeparam name="THandler">The event handler type.</typeparam>
    /// <param name="services">The service collection.</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddEventHandler<THandler>(this IServiceCollection services)
        where THandler : class, IPromptShieldEventHandler
    {
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IPromptShieldEventHandler, THandler>());
        return services;
    }

    private static void RegisterCoreServices(IServiceCollection services, PromptShieldOptions options)
    {
        // Register built-in pattern provider
        if (options.PatternMatching.IncludeBuiltInPatterns)
        {
            services.TryAddEnumerable(
                ServiceDescriptor.Singleton<IPatternProvider, BuiltInPatternProvider>());
        }

        // Register built-in heuristic analyzer
        if (options.Heuristics.Enabled)
        {
            services.TryAddEnumerable(
                ServiceDescriptor.Singleton<IHeuristicAnalyzer, BuiltInHeuristicAnalyzer>());
        }

        // Register validator
        services.TryAddSingleton<AnalysisRequestValidator>(sp =>
            new AnalysisRequestValidator(options.MaxPromptLength));

        // Register Pattern Matching layer
        services.TryAddSingleton<PatternMatchingLayer>(sp =>
        {
            var patternProviders = sp.GetServices<IPatternProvider>();
            var logger = sp.GetService<ILogger<PatternMatchingLayer>>();
            return new PatternMatchingLayer(patternProviders, options.PatternMatching, logger);
        });

        // Register Heuristic layer
        services.TryAddSingleton<HeuristicLayer>(sp =>
        {
            var analyzers = sp.GetServices<IHeuristicAnalyzer>();
            var logger = sp.GetService<ILogger<HeuristicLayer>>();
            return new HeuristicLayer(analyzers, options.Heuristics, options, logger);
        });

        // Register pipeline orchestrator
        services.TryAddSingleton<PipelineOrchestrator>(sp =>
        {
            var patternLayer = sp.GetRequiredService<PatternMatchingLayer>();
            var heuristicLayer = sp.GetRequiredService<HeuristicLayer>();
            var logger = sp.GetService<ILogger<PipelineOrchestrator>>();
            return new PipelineOrchestrator(patternLayer, heuristicLayer, options, logger);
        });

        // Register main analyzer
        services.TryAddSingleton<IPromptAnalyzer>(sp =>
        {
            var pipeline = sp.GetRequiredService<PipelineOrchestrator>();
            var validator = sp.GetRequiredService<AnalysisRequestValidator>();
            var eventHandlers = sp.GetServices<IPromptShieldEventHandler>();
            var logger = sp.GetService<ILogger<PromptAnalyzer>>();
            return new PromptAnalyzer(pipeline, validator, options, eventHandlers, logger);
        });
    }
}
