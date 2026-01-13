namespace PromptShield.Abstractions.Configuration;

/// <summary>
/// Semantic analysis layer options.
/// </summary>
public sealed class SemanticAnalysisOptions
{
    /// <summary>
    /// Whether semantic analysis is enabled (requires LLM endpoint).
    /// </summary>
    public bool Enabled { get; set; } = false;
    
    /// <summary>
    /// Azure OpenAI or OpenAI endpoint URL.
    /// </summary>
    public string? Endpoint { get; set; }
    
    /// <summary>
    /// Model deployment name (for Azure OpenAI).
    /// </summary>
    public string? DeploymentName { get; set; }
    
    /// <summary>
    /// API key for authentication.
    /// </summary>
    public string? ApiKey { get; set; }
}
