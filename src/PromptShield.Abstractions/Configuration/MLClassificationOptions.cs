namespace PromptShield.Abstractions.Configuration;

/// <summary>
/// ML classification layer options.
/// </summary>
/// <remarks>
/// This layer uses a combination of:
/// - ONNX neural network model (if available) for deep pattern recognition
/// - Feature extraction with statistical analysis for robust fallback
/// - Ensemble scoring when both are available for improved accuracy
/// </remarks>
public sealed class MLClassificationOptions
{
    /// <summary>
    /// Whether ML classification is enabled.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Path to ONNX model file. If null, uses embedded model or feature-based scoring.
    /// Supported models: Binary classifiers with input shape [batch, sequence_length].
    /// </summary>
    public string? ModelPath { get; set; }

    /// <summary>
    /// Confidence threshold for ML decisions (0.0 to 1.0).
    /// Prompts with confidence above this threshold are flagged as threats.
    /// </summary>
    public double Threshold { get; set; } = 0.8;

    /// <summary>
    /// Maximum sequence length for tokenization.
    /// Longer prompts will be truncated. Should match the model's expected input size.
    /// </summary>
    public int MaxSequenceLength { get; set; } = 512;

    /// <summary>
    /// Maximum number of concurrent inference operations.
    /// Prevents resource exhaustion during high load.
    /// </summary>
    public int MaxConcurrentInferences { get; set; } = 4;

    /// <summary>
    /// Timeout in seconds for individual inference operations.
    /// </summary>
    public int InferenceTimeoutSeconds { get; set; } = 10;

    /// <summary>
    /// Whether to use ensemble scoring (combining model + feature-based scores).
    /// When true and model is available, both scores are combined for higher accuracy.
    /// </summary>
    public bool UseEnsemble { get; set; } = true;

    /// <summary>
    /// Weight of the neural network model in ensemble scoring (0.0 to 1.0).
    /// Higher values give more importance to model predictions.
    /// </summary>
    public double ModelWeight { get; set; } = 0.7;

    /// <summary>
    /// Whether to include feature importance in the analysis result.
    /// Useful for debugging and explainability but adds slight overhead.
    /// </summary>
    public bool IncludeFeatureImportance { get; set; } = true;

    /// <summary>
    /// Sensitivity level that adjusts feature scoring.
    /// Higher sensitivity catches more threats but may produce more false positives.
    /// </summary>
    public SensitivityLevel Sensitivity { get; set; } = SensitivityLevel.Medium;

    /// <summary>
    /// Custom feature weights for fine-tuning detection.
    /// Keys are feature names (e.g., "InjectionKeywords", "IgnorePattern").
    /// Values are weights (0.0 to 1.0). If null or empty, default weights are used.
    /// </summary>
    /// <remarks>
    /// Available feature names:
    /// - Statistical: Entropy, CompressionRatio
    /// - Character: ControlCharRatio, HighUnicodeRatio, ZeroWidthChars, BidiOverrides
    /// - Lexical: InjectionKeywords, CommandKeywords, RoleKeywords, IgnorePattern,
    ///   NewInstructionsPattern, PersonaSwitchPattern, SystemPromptRef, CodeIndicators
    /// - Structural: RepeatedDelimiters, XmlTags, Base64Content, TemplatePlaceholders, StructuralComplexity
    /// </remarks>
    public Dictionary<string, double>? FeatureWeights { get; set; }

    /// <summary>
    /// Regex patterns that should bypass ML classification (allowlist).
    /// If a prompt matches any of these patterns, ML analysis returns safe.
    /// Use for known-safe patterns specific to your domain.
    /// </summary>
    public List<string> AllowedPatterns { get; set; } = new();

    /// <summary>
    /// Feature names to exclude from scoring.
    /// Use to disable specific features that cause false positives in your domain.
    /// </summary>
    /// <example>
    /// To disable "IgnorePattern" feature which may cause false positives:
    /// DisabledFeatures = new List&lt;string&gt; { "IgnorePattern" }
    /// </example>
    public List<string> DisabledFeatures { get; set; } = new();

    /// <summary>
    /// Minimum feature contribution threshold.
    /// Features with values below this threshold are ignored in scoring.
    /// Higher values reduce noise but may miss subtle attacks.
    /// </summary>
    public double MinFeatureContribution { get; set; } = 0.1;
}
