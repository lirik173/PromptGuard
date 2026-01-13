using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using PromptShield.Abstractions.Analyzers;

namespace PromptShield.AspNetCore;

/// <summary>
/// Extension methods for adding PromptShield middleware to the ASP.NET Core pipeline.
/// </summary>
public static class ApplicationBuilderExtensions
{
    /// <summary>
    /// Adds PromptShield middleware to the application pipeline with default options.
    /// </summary>
    /// <param name="app">The application builder.</param>
    /// <returns>The application builder for chaining.</returns>
    /// <remarks>
    /// Ensure PromptShield services are registered using <c>AddPromptShield()</c>
    /// before calling this method.
    /// </remarks>
    /// <example>
    /// <code>
    /// var app = builder.Build();
    /// app.UsePromptShield();
    /// app.MapControllers();
    /// </code>
    /// </example>
    public static IApplicationBuilder UsePromptShield(this IApplicationBuilder app)
    {
        return app.UsePromptShield(_ => { });
    }

    /// <summary>
    /// Adds PromptShield middleware to the application pipeline with custom options.
    /// </summary>
    /// <param name="app">The application builder.</param>
    /// <param name="configure">Action to configure middleware options.</param>
    /// <returns>The application builder for chaining.</returns>
    /// <example>
    /// <code>
    /// app.UsePromptShield(options =>
    /// {
    ///     options.ProtectedPaths = new[] { "/api/chat", "/api/completion" };
    ///     options.ExcludedPaths = new[] { "/health", "/metrics" };
    /// });
    /// </code>
    /// </example>
    public static IApplicationBuilder UsePromptShield(
        this IApplicationBuilder app,
        Action<PromptShieldMiddlewareOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(app);
        ArgumentNullException.ThrowIfNull(configure);

        var options = new PromptShieldMiddlewareOptions();
        configure(options);

        // Validate that PromptShield services are registered
        var analyzer = app.ApplicationServices.GetService<IPromptAnalyzer>();
        if (analyzer == null)
        {
            throw new InvalidOperationException(
                "PromptShield services are not registered. " +
                "Call services.AddPromptShield() in your service configuration before using UsePromptShield().");
        }

        var logger = app.ApplicationServices.GetService<ILogger<PromptShieldMiddleware>>();

        return app.UseMiddleware<PromptShieldMiddleware>(analyzer, options, logger);
    }
}
