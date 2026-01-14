using Microsoft.Extensions.DependencyInjection;
using PromptShield.Core;

namespace PromptShield.AspNetCore;

/// <summary>
/// Extension methods for registering PromptShield services with ASP.NET Core dependency injection.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds PromptShield services to the service collection for ASP.NET Core applications.
    /// This is a convenience method that delegates to PromptShield.Core.ServiceCollectionExtensions.AddPromptShield().
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddPromptShield(this IServiceCollection services)
    {
        return Core.ServiceCollectionExtensions.AddPromptShield(services);
    }

    /// <summary>
    /// Adds PromptShield services to the service collection with configuration action.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Action to configure PromptShield options.</param>
    /// <returns>The service collection for chaining.</returns>
    public static IServiceCollection AddPromptShield(
        this IServiceCollection services,
        Action<Abstractions.Configuration.PromptShieldOptions> configure)
    {
        return Core.ServiceCollectionExtensions.AddPromptShield(services, configure);
    }
}
