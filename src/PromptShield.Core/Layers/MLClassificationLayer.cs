using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.OnnxRuntime.Tensors;
using PromptShield.Abstractions.Analysis;
using PromptShield.Abstractions.Configuration;
using PromptShield.Core.ML;

namespace PromptShield.Core.Layers;

/// <summary>
/// Detection layer that uses ONNX ML model for prompt injection classification.
/// Combines feature extraction, tokenization, and neural network inference.
/// </summary>
/// <remarks>
/// This layer supports two inference modes:
/// 1. Feature-based: Uses <see cref="FeatureExtractor"/> to generate statistical features
/// 2. Token-based: Uses <see cref="SimpleTokenizer"/> for sequence models (transformers, LSTMs)
/// 
/// When both are available, results are ensembled for higher accuracy.
/// </remarks>
public sealed class MLClassificationLayer : IDisposable
{
    private readonly MLClassificationOptions _options;
    private readonly PromptShieldOptions _globalOptions;
    private readonly ILogger<MLClassificationLayer> _logger;
    private readonly ModelLoader _modelLoader;
    private readonly SimpleTokenizer _tokenizer;
    private readonly FeatureExtractor _featureExtractor;
    private readonly SemaphoreSlim _inferenceSemaphore;
    private readonly List<Regex> _allowlistRegex;
    private readonly Dictionary<int, double> _featureWeightOverrides;
    private readonly HashSet<int> _disabledFeatureIndices;
    private bool _disposed;

    /// <summary>
    /// Default feature weights indexed by feature index.
    /// </summary>
    private static readonly Dictionary<int, (string Name, double Weight)> DefaultFeatureWeights = new()
    {
        // Statistical features (low weight - general indicators)
        [3] = ("Entropy", 0.05),
        [11] = ("CompressionRatio", 0.08),

        // Character distribution (medium weight)
        [17] = ("ControlCharRatio", 0.15),
        [18] = ("HighUnicodeRatio", 0.20),
        [19] = ("ZeroWidthChars", 0.25),
        [20] = ("BidiOverrides", 0.30),

        // Lexical features (high weight - direct indicators)
        [24] = ("InjectionKeywords", 0.40),
        [25] = ("CommandKeywords", 0.25),
        [26] = ("RoleKeywords", 0.35),
        [30] = ("IgnorePattern", 0.50),
        [31] = ("NewInstructionsPattern", 0.45),
        [32] = ("PersonaSwitchPattern", 0.55),
        [33] = ("SystemPromptRef", 0.40),
        [34] = ("CodeIndicators", 0.20),

        // Structural features (medium weight)
        [36] = ("RepeatedDelimiters", 0.15),
        [37] = ("XmlTags", 0.10),
        [40] = ("Base64Content", 0.15),
        [45] = ("TemplatePlaceholders", 0.20),
        [47] = ("StructuralComplexity", 0.10)
    };

    /// <summary>
    /// Mapping from feature name to index.
    /// </summary>
    private static readonly Dictionary<string, int> FeatureNameToIndex;

    static MLClassificationLayer()
    {
        FeatureNameToIndex = DefaultFeatureWeights.ToDictionary(
            kvp => kvp.Value.Name,
            kvp => kvp.Key,
            StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Classification result with additional metadata.
    /// </summary>
    private readonly struct ClassificationResult
    {
        public double ThreatProbability { get; init; }
        public double BenignProbability { get; init; }
        public string[] TopContributingFeatures { get; init; }
        public InferenceMode Mode { get; init; }
    }

    /// <summary>
    /// Inference mode used for classification.
    /// </summary>
    private enum InferenceMode
    {
        FeatureBased,
        TokenBased,
        Ensemble,
        Degraded
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="MLClassificationLayer"/>.
    /// </summary>
    /// <param name="options">ML classification configuration options.</param>
    /// <param name="globalOptions">Global PromptShield configuration.</param>
    /// <param name="logger">Optional logger instance.</param>
    public MLClassificationLayer(
        MLClassificationOptions options,
        PromptShieldOptions globalOptions,
        ILogger<MLClassificationLayer>? logger = null)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _globalOptions = globalOptions ?? throw new ArgumentNullException(nameof(globalOptions));
        _logger = logger ?? NullLogger<MLClassificationLayer>.Instance;

        // Initialize model loader
        _modelLoader = new ModelLoader(_options.ModelPath, logger: null);

        // Initialize tokenizer with subword strategy for better coverage
        _tokenizer = new SimpleTokenizer(
            _options.MaxSequenceLength,
            strategy: SimpleTokenizer.TokenizationStrategy.Subword,
            addSpecialTokens: true,
            lowercase: true);

        // Initialize feature extractor for statistical analysis
        _featureExtractor = new FeatureExtractor();

        // Limit concurrent inference to prevent resource exhaustion
        _inferenceSemaphore = new SemaphoreSlim(
            _options.MaxConcurrentInferences,
            _options.MaxConcurrentInferences);

        // Compile allowlist patterns
        _allowlistRegex = CompileAllowlistPatterns(options.AllowedPatterns);

        // Build feature weight overrides from configuration
        _featureWeightOverrides = BuildFeatureWeightOverrides(options.FeatureWeights);

        // Build disabled feature indices
        _disabledFeatureIndices = BuildDisabledFeatureIndices(options.DisabledFeatures);

        LogInitializationStatus();
    }

    /// <summary>
    /// Gets the name of this detection layer.
    /// </summary>
    public string LayerName => "MLClassification";

    /// <summary>
    /// Analyzes the prompt using ML classification.
    /// </summary>
    /// <param name="prompt">Prompt text to analyze.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Layer result with ML classification confidence.</returns>
    public async Task<LayerResult> AnalyzeAsync(
        string prompt,
        CancellationToken cancellationToken = default)
    {
        if (!_options.Enabled)
        {
            return CreateDisabledResult();
        }

        // Check allowlist first
        if (IsAllowlisted(prompt))
        {
            _logger.LogDebug("Prompt matched ML allowlist pattern, skipping classification");
            return CreateAllowlistedResult();
        }

        var stopwatch = Stopwatch.StartNew();

        try
        {
            // Acquire inference semaphore with timeout
            var acquired = await _inferenceSemaphore.WaitAsync(
                TimeSpan.FromSeconds(_options.InferenceTimeoutSeconds / 2),
                cancellationToken);

            if (!acquired)
            {
                _logger.LogWarning("ML inference concurrency limit reached");
                return CreateConcurrencyLimitResult(stopwatch.Elapsed);
            }

            try
            {
                cancellationToken.ThrowIfCancellationRequested();

                var result = await Task.Run(
                    () => PerformClassification(prompt, cancellationToken),
                    cancellationToken);

                stopwatch.Stop();

                return CreateSuccessResult(result, stopwatch.Elapsed);
            }
            finally
            {
                _inferenceSemaphore.Release();
            }
        }
        catch (OperationCanceledException)
        {
            _logger.LogDebug("ML classification was cancelled");
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "ML classification failed unexpectedly");
            stopwatch.Stop();
            return CreateErrorResult(ex.Message, stopwatch.Elapsed);
        }
    }

    #region Allowlist

    private List<Regex> CompileAllowlistPatterns(List<string> patterns)
    {
        var compiled = new List<Regex>();
        foreach (var pattern in patterns)
        {
            try
            {
                compiled.Add(new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.Compiled,
                    TimeSpan.FromMilliseconds(50)));
            }
            catch (ArgumentException ex)
            {
                _logger.LogWarning(ex, "Invalid regex pattern in ML allowlist: {Pattern}", pattern);
            }
        }
        return compiled;
    }

    private bool IsAllowlisted(string prompt)
    {
        foreach (var regex in _allowlistRegex)
        {
            try
            {
                if (regex.IsMatch(prompt))
                {
                    return true;
                }
            }
            catch (RegexMatchTimeoutException)
            {
                // Timeout on allowlist - don't allow
            }
        }
        return false;
    }

    #endregion

    #region Feature Weight Configuration

    private Dictionary<int, double> BuildFeatureWeightOverrides(Dictionary<string, double>? customWeights)
    {
        var overrides = new Dictionary<int, double>();

        if (customWeights == null || customWeights.Count == 0)
        {
            return overrides;
        }

        foreach (var (name, weight) in customWeights)
        {
            if (FeatureNameToIndex.TryGetValue(name, out var index))
            {
                overrides[index] = Math.Clamp(weight, 0.0, 1.0);
                _logger.LogDebug("Feature weight override: {Feature} = {Weight}", name, weight);
            }
            else
            {
                _logger.LogWarning("Unknown feature name in weight configuration: {Feature}", name);
            }
        }

        return overrides;
    }

    private HashSet<int> BuildDisabledFeatureIndices(List<string> disabledFeatures)
    {
        var indices = new HashSet<int>();

        foreach (var name in disabledFeatures)
        {
            if (FeatureNameToIndex.TryGetValue(name, out var index))
            {
                indices.Add(index);
                _logger.LogDebug("Feature disabled: {Feature}", name);
            }
            else
            {
                _logger.LogWarning("Unknown feature name in disabled list: {Feature}", name);
            }
        }

        return indices;
    }

    #endregion

    /// <summary>
    /// Performs the ML classification using available inference modes.
    /// </summary>
    private ClassificationResult PerformClassification(string prompt, CancellationToken cancellationToken)
    {
        // Extract features for statistical analysis
        var features = _featureExtractor.ExtractFeatures(prompt);
        var topFeatures = IdentifyTopContributingFeatures(features);

        // If ONNX model is available, use neural network inference
        if (_modelLoader.IsAvailable && _modelLoader.Session != null)
        {
            try
            {
                // Tokenize for sequence model
                var (tokenIds, attentionMask) = _tokenizer.TokenizeWithAttention(prompt);

                // Run model inference
                var modelPrediction = RunModelInference(tokenIds, attentionMask, _modelLoader.Session);

                // Combine with feature-based heuristic for ensemble
                var featureScore = CalculateFeatureScore(features);
                var ensembleScore = CombineScores(modelPrediction, featureScore);

                _logger.LogDebug(
                    "Ensemble classification: Model={Model:F3}, Features={Features:F3}, Combined={Combined:F3}",
                    modelPrediction,
                    featureScore,
                    ensembleScore);

                return new ClassificationResult
                {
                    ThreatProbability = ensembleScore,
                    BenignProbability = 1.0 - ensembleScore,
                    TopContributingFeatures = topFeatures,
                    Mode = InferenceMode.Ensemble
                };
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Model inference failed, falling back to feature-based classification");
            }
        }

        // Fallback: Use feature-based scoring only
        var score = CalculateFeatureScore(features);

        return new ClassificationResult
        {
            ThreatProbability = score,
            BenignProbability = 1.0 - score,
            TopContributingFeatures = topFeatures,
            Mode = _modelLoader.IsAvailable ? InferenceMode.Degraded : InferenceMode.FeatureBased
        };
    }

    /// <summary>
    /// Runs inference on the ONNX model.
    /// </summary>
    private double RunModelInference(int[] tokenIds, int[] attentionMask, InferenceSession session)
    {
        // Determine input requirements from model metadata
        var inputNames = session.InputMetadata.Keys.ToList();
        var inputs = new List<NamedOnnxValue>();

        // Prepare token IDs tensor (using int64 for compatibility with most models)
        var tokenShape = new[] { 1, tokenIds.Length };
        var longTokenIds = Array.ConvertAll(tokenIds, x => (long)x);
        var tokenTensor = new DenseTensor<long>(longTokenIds, tokenShape);

        inputs.Add(NamedOnnxValue.CreateFromTensor(
            inputNames.FirstOrDefault(n => n.Contains("input", StringComparison.OrdinalIgnoreCase)) ?? "input_ids",
            tokenTensor));

        // Add attention mask if model expects it
        if (inputNames.Any(n => n.Contains("attention", StringComparison.OrdinalIgnoreCase) ||
                                n.Contains("mask", StringComparison.OrdinalIgnoreCase)))
        {
            var attentionShape = new[] { 1, attentionMask.Length };
            var longAttentionMask = Array.ConvertAll(attentionMask, x => (long)x);
            var attentionTensor = new DenseTensor<long>(longAttentionMask, attentionShape);

            inputs.Add(NamedOnnxValue.CreateFromTensor(
                inputNames.First(n => n.Contains("attention", StringComparison.OrdinalIgnoreCase) ||
                                      n.Contains("mask", StringComparison.OrdinalIgnoreCase)),
                attentionTensor));
        }

        // Add token type IDs if model expects them (for BERT-style models)
        if (inputNames.Any(n => n.Contains("token_type", StringComparison.OrdinalIgnoreCase) ||
                                n.Contains("segment", StringComparison.OrdinalIgnoreCase)))
        {
            var typeIdsShape = new[] { 1, tokenIds.Length };
            var typeIdsTensor = new DenseTensor<long>(new long[tokenIds.Length], typeIdsShape);

            inputs.Add(NamedOnnxValue.CreateFromTensor(
                inputNames.First(n => n.Contains("token_type", StringComparison.OrdinalIgnoreCase) ||
                                      n.Contains("segment", StringComparison.OrdinalIgnoreCase)),
                typeIdsTensor));
        }

        // Run inference
        using var results = session.Run(inputs);

        var output = results.FirstOrDefault()
            ?? throw new InvalidOperationException("Model produced no output");

        return ExtractProbabilityFromOutput(output);
    }

    /// <summary>
    /// Extracts threat probability from model output tensor.
    /// </summary>
    private static double ExtractProbabilityFromOutput(DisposableNamedOnnxValue output)
    {
        var tensor = output.AsTensor<float>();
        var values = tensor.ToArray();

        if (values.Length >= 2)
        {
            // Binary classification: apply softmax and return threat probability
            var probabilities = Softmax(values);
            return probabilities[1]; // Index 1 = threat class
        }
        else if (values.Length == 1)
        {
            // Single output: sigmoid activation assumed
            return Sigmoid(values[0]);
        }

        throw new InvalidOperationException($"Unexpected output shape: {values.Length} elements");
    }

    /// <summary>
    /// Calculates a threat score from extracted features using configurable weighted heuristics.
    /// </summary>
    private double CalculateFeatureScore(float[] features)
    {
        var score = 0.0;
        var minContribution = _options.MinFeatureContribution;
        var sensitivityMultiplier = GetSensitivityMultiplier();

        foreach (var (index, (name, defaultWeight)) in DefaultFeatureWeights)
        {
            // Skip disabled features
            if (_disabledFeatureIndices.Contains(index))
            {
                continue;
            }

            // Get feature value
            if (index >= features.Length)
            {
                continue;
            }

            var featureValue = features[index];

            // Skip features below minimum contribution threshold
            if (featureValue < minContribution)
            {
                continue;
            }

            // Get weight (override or default)
            var weight = _featureWeightOverrides.TryGetValue(index, out var overrideWeight)
                ? overrideWeight
                : defaultWeight;

            // Apply sensitivity adjustment
            var adjustedWeight = weight * sensitivityMultiplier;

            score += featureValue * adjustedWeight;
        }

        // Normalize to 0-1 range using sigmoid
        return Sigmoid(score * 2 - 2);
    }

    /// <summary>
    /// Gets the sensitivity multiplier based on configured sensitivity level.
    /// </summary>
    private double GetSensitivityMultiplier()
    {
        return _options.Sensitivity switch
        {
            SensitivityLevel.Low => 0.7,
            SensitivityLevel.Medium => 1.0,
            SensitivityLevel.High => 1.3,
            SensitivityLevel.Paranoid => 1.6,
            _ => 1.0
        };
    }

    /// <summary>
    /// Combines model prediction with feature-based score using weighted ensemble.
    /// </summary>
    private double CombineScores(double modelScore, double featureScore)
    {
        // Use configured model weight
        var baseModelWeight = _options.ModelWeight;

        // Adjust based on model confidence (more weight when confident)
        var modelConfidence = Math.Abs(modelScore - 0.5) * 2; // 0 at 0.5, 1 at extremes
        var modelWeight = baseModelWeight + (modelConfidence * (1.0 - baseModelWeight) * 0.3);
        var featureWeight = 1.0 - modelWeight;

        var combined = (modelScore * modelWeight) + (featureScore * featureWeight);
        return Math.Clamp(combined, 0.0, 1.0);
    }

    /// <summary>
    /// Identifies top contributing features for explainability.
    /// </summary>
    private string[] IdentifyTopContributingFeatures(float[] features)
    {
        var featureNames = new[]
        {
            "Length", "WordCount", "AvgWordLength", "Entropy", "LineCount",
            "AvgLineLength", "UniqueWordRatio", "SentenceCount", "AvgSentenceLength",
            "WhitespaceRatio", "TrigramDiversity", "CompressionRatio",
            "LowercaseRatio", "UppercaseRatio", "DigitRatio", "PunctuationRatio",
            "SymbolRatio", "ControlCharRatio", "HighUnicodeRatio", "ZeroWidthChars",
            "BidiOverrides", "DelimiterRatio", "BracketBalance", "QuoteDensity",
            "InjectionKeywords", "CommandKeywords", "RoleKeywords", "ImperativeMood",
            "QuestionDensity", "ExclamationDensity", "IgnorePattern", "NewInstructionsPattern",
            "PersonaSwitchPattern", "SystemPromptRef", "CodeIndicators", "SocialEngineering",
            "RepeatedDelimiters", "XmlTags", "JsonStructure", "MarkdownHeaders",
            "Base64Content", "HexContent", "UrlPresence", "EmailPresence",
            "ConsecutiveSameChar", "TemplatePlaceholders", "SectionCount", "StructuralComplexity"
        };

        return features
            .Select((value, index) => (Name: index < featureNames.Length ? featureNames[index] : $"Feature{index}", Value: value, Index: index))
            .Where(f => f.Value > 0.3 && !_disabledFeatureIndices.Contains(f.Index))
            .OrderByDescending(f => f.Value)
            .Take(5)
            .Select(f => $"{f.Name}:{f.Value:F2}")
            .ToArray();
    }

    #region Mathematical Functions

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static double[] Softmax(float[] logits)
    {
        var maxLogit = logits.Max();
        var expValues = logits.Select(x => Math.Exp(x - maxLogit)).ToArray();
        var sum = expValues.Sum();
        return expValues.Select(exp => exp / sum).ToArray();
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static double Sigmoid(double x)
    {
        return 1.0 / (1.0 + Math.Exp(-x));
    }

    #endregion

    #region Result Factory Methods

    private LayerResult CreateDisabledResult() => new()
    {
        LayerName = LayerName,
        WasExecuted = false
    };

    private LayerResult CreateAllowlistedResult() => new()
    {
        LayerName = LayerName,
        WasExecuted = true,
        Confidence = 0.0,
        IsThreat = false,
        Data = new Dictionary<string, object>
        {
            ["status"] = "allowlisted",
            ["reason"] = "Prompt matched allowlist pattern"
        }
    };

    private LayerResult CreateConcurrencyLimitResult(TimeSpan duration) => new()
    {
        LayerName = LayerName,
        WasExecuted = false,
        Confidence = 0.0,
        IsThreat = false,
        Duration = duration,
        Data = new Dictionary<string, object>
        {
            ["status"] = "concurrency_limited",
            ["degraded"] = true
        }
    };

    private LayerResult CreateErrorResult(string error, TimeSpan duration) => new()
    {
        LayerName = LayerName,
        WasExecuted = true,
        Confidence = 0.0,
        IsThreat = false,
        Duration = duration,
        Data = new Dictionary<string, object>
        {
            ["status"] = "error",
            ["error"] = error,
            ["degraded"] = true
        }
    };

    private LayerResult CreateSuccessResult(ClassificationResult result, TimeSpan duration)
    {
        var isThreat = result.ThreatProbability >= _options.Threshold;

        _logger.LogDebug(
            "ML classification completed: IsThreat={IsThreat}, Confidence={Confidence:F3}, Mode={Mode}, Sensitivity={Sensitivity}, Duration={Duration}ms",
            isThreat,
            result.ThreatProbability,
            result.Mode,
            _options.Sensitivity,
            duration.TotalMilliseconds);

        var data = new Dictionary<string, object>
        {
            ["status"] = "success",
            ["threshold"] = _options.Threshold,
            ["mode"] = result.Mode.ToString(),
            ["sensitivity"] = _options.Sensitivity.ToString(),
            ["threat_probability"] = result.ThreatProbability,
            ["benign_probability"] = result.BenignProbability,
            ["model_available"] = _modelLoader.IsAvailable
        };

        if (result.TopContributingFeatures.Length > 0)
        {
            data["top_features"] = result.TopContributingFeatures;
        }

        if (_disabledFeatureIndices.Count > 0)
        {
            data["disabled_features_count"] = _disabledFeatureIndices.Count;
        }

        return new LayerResult
        {
            LayerName = LayerName,
            WasExecuted = true,
            Confidence = result.ThreatProbability,
            IsThreat = isThreat,
            Duration = duration,
            Data = data
        };
    }

    #endregion

    private void LogInitializationStatus()
    {
        if (!_modelLoader.IsAvailable)
        {
            _logger.LogWarning(
                "ML model not available. Layer will use feature-based scoring only. " +
                "For improved accuracy, provide an ONNX model via ModelPath configuration.");
        }
        else
        {
            _logger.LogInformation(
                "MLClassificationLayer initialized. ModelAvailable={ModelAvailable}, " +
                "MaxSequenceLength={MaxSequenceLength}, Threshold={Threshold}, Sensitivity={Sensitivity}, " +
                "FeatureCount={FeatureCount}, DisabledFeatures={DisabledCount}, AllowlistPatterns={AllowlistCount}",
                _modelLoader.IsAvailable,
                _options.MaxSequenceLength,
                _options.Threshold,
                _options.Sensitivity,
                FeatureExtractor.FeatureCount,
                _disabledFeatureIndices.Count,
                _allowlistRegex.Count);
        }
    }

    public void Dispose()
    {
        if (_disposed)
            return;

        _modelLoader.Dispose();
        _inferenceSemaphore.Dispose();
        _disposed = true;
    }
}
