using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using PromptShield.Abstractions.Analysis;
using PromptShield.Abstractions.Analyzers;
using PromptShield.Abstractions.Analyzers.Heuristics;
using PromptShield.Abstractions.Configuration;
using PromptShield.Abstractions.Detection.Patterns;
using PromptShield.Abstractions.Events;
using PromptShield.Core.Language;
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
    /// Adds PromptShield services to the service collection with IConfiguration binding.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configuration">Configuration instance to bind from.</param>
    /// <param name="configure">Optional action to further configure options after binding.</param>
    /// <returns>The service collection for chaining.</returns>
    /// <remarks>
    /// This method binds configuration from the "PromptShield" section in appsettings.json
    /// and allows additional programmatic configuration via the configure action.
    /// </remarks>
    public static IServiceCollection AddPromptShield(
        this IServiceCollection services,
        IConfiguration configuration,
        Action<PromptShieldOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        // Bind from configuration
        var options = new PromptShieldOptions();
        configuration.GetSection(PromptShieldOptions.SectionName).Bind(options);

        // Apply additional configuration if provided
        configure?.Invoke(options);

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

    /// <summary>
    /// Adds a custom language detector to the service collection.
    /// </summary>
    /// <typeparam name="TDetector">The language detector type.</typeparam>
    /// <param name="services">The service collection.</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddLanguageDetector<TDetector>(this IServiceCollection services)
        where TDetector : class, ILanguageDetector
    {
        services.AddSingleton<ILanguageDetector, TDetector>();
        return services;
    }

    internal static void RegisterCoreServices(IServiceCollection services, PromptShieldOptions options)
    {
        // Register Language Detector (default implementation)
        services.TryAddSingleton<ILanguageDetector, SimpleLanguageDetector>();

        // Register Language Filter layer (if enabled)
        if (options.Language.Enabled)
        {
            services.TryAddSingleton<LanguageFilterLayer>(sp =>
            {
                var languageDetector = sp.GetRequiredService<ILanguageDetector>();
                var logger = sp.GetService<ILogger<LanguageFilterLayer>>();
                return new LanguageFilterLayer(options.Language, languageDetector, logger);
            });
        }

        // Register built-in pattern provider
        if (options.PatternMatching.IncludeBuiltInPatterns)
        {
            services.TryAddEnumerable(
                ServiceDescriptor.Singleton<IPatternProvider, BuiltInPatternProvider>());
        }

        // Register heuristic options as singleton for DI
        services.TryAddSingleton(options.Heuristics);

        // Register built-in heuristic analyzer with options
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

        // Register ML Classification layer (if enabled)
        if (options.ML.Enabled)
        {
            services.TryAddSingleton<MLClassificationLayer>(sp =>
            {
                var logger = sp.GetService<ILogger<MLClassificationLayer>>();
                return new MLClassificationLayer(options.ML, options, logger);
            });
        }

        // Register Semantic Analysis layer (if enabled)
        if (options.SemanticAnalysis.Enabled)
        {
            services.TryAddSingleton<SemanticAnalysisLayer>(sp =>
            {
                var httpClientFactory = sp.GetService<IHttpClientFactory>();
                var logger = sp.GetService<ILogger<SemanticAnalysisLayer>>();
                return new SemanticAnalysisLayer(
                    options.SemanticAnalysis,
                    options,
                    httpClientFactory,
                    logger);
            });
        }

        // Register pipeline orchestrator
        services.TryAddSingleton<PipelineOrchestrator>(sp =>
        {
            var languageFilterLayer = sp.GetService<LanguageFilterLayer>();
            var patternLayer = sp.GetRequiredService<PatternMatchingLayer>();
            var heuristicLayer = sp.GetRequiredService<HeuristicLayer>();
            var mlLayer = sp.GetService<MLClassificationLayer>();
            var semanticLayer = sp.GetService<SemanticAnalysisLayer>();
            var logger = sp.GetService<ILogger<PipelineOrchestrator>>();

            return new PipelineOrchestrator(
                languageFilterLayer,
                patternLayer,
                heuristicLayer,
                mlLayer,
                semanticLayer,
                options,
                logger);
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
