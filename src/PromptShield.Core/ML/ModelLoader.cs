using System.IO;
using System.Reflection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.ML.OnnxRuntime;

namespace PromptShield.Core.ML;

/// <summary>
/// Loads ONNX models for ML classification layer.
/// Supports both embedded resources and file-based models.
/// </summary>
internal sealed class ModelLoader : IDisposable
{
    private readonly ILogger<ModelLoader> _logger;
    private InferenceSession? _session;
    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of the ModelLoader.
    /// </summary>
    /// <param name="modelPath">Path to ONNX model file. If null, attempts to load embedded model.</param>
    /// <param name="logger">Optional logger.</param>
    public ModelLoader(string? modelPath, ILogger<ModelLoader>? logger = null)
    {
        _logger = logger ?? NullLogger<ModelLoader>.Instance;
        _session = LoadModel(modelPath);
    }

    /// <summary>
    /// Gets the inference session. Returns null if model loading failed.
    /// </summary>
    public InferenceSession? Session => _session;

    /// <summary>
    /// Gets whether the model is available and ready for inference.
    /// </summary>
    public bool IsAvailable => _session != null && !_disposed;

    /// <summary>
    /// Gets the input names expected by the model.
    /// </summary>
    public IReadOnlyList<string> InputNames => _session?.InputMetadata.Keys.ToList() ?? (IReadOnlyList<string>)Array.Empty<string>();

    /// <summary>
    /// Gets the output names produced by the model.
    /// </summary>
    public IReadOnlyList<string> OutputNames => _session?.OutputMetadata.Keys.ToList() ?? (IReadOnlyList<string>)Array.Empty<string>();

    private InferenceSession? LoadModel(string? modelPath)
    {
        try
        {
            byte[] modelBytes;

            if (!string.IsNullOrWhiteSpace(modelPath) && File.Exists(modelPath))
            {
                // Load from file
                _logger.LogInformation("Loading ONNX model from file: {ModelPath}", modelPath);
                modelBytes = File.ReadAllBytes(modelPath);
            }
            else
            {
                // Attempt to load embedded resource
                _logger.LogInformation("Attempting to load embedded ONNX model");
                modelBytes = LoadEmbeddedModel() ?? Array.Empty<byte>();

                if (modelBytes.Length == 0)
                {
                    _logger.LogWarning(
                        "No embedded model found and no valid model path provided. ML layer will be disabled.");
                    return null;
                }
            }

            var sessionOptions = new SessionOptions
            {
                LogSeverityLevel = OrtLoggingLevel.ORT_LOGGING_LEVEL_WARNING
            };

            // Optional: Enable GPU acceleration if available
            // sessionOptions.AppendExecutionProvider_DML(deviceId: 0);

            var session = new InferenceSession(modelBytes, sessionOptions);

            _logger.LogInformation(
                "ONNX model loaded successfully. Inputs: {InputCount}, Outputs: {OutputCount}",
                session.InputMetadata.Count,
                session.OutputMetadata.Count);

            return session;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load ONNX model. ML layer will be disabled.");
            return null;
        }
    }

    private static byte[]? LoadEmbeddedModel()
    {
        // Attempt to load embedded model from assembly resources
        // In production, this would be a real ONNX model file embedded as a resource
        var assembly = Assembly.GetExecutingAssembly();
        var resourceName = assembly.GetManifestResourceNames()
            .FirstOrDefault(name => name.EndsWith(".onnx", StringComparison.OrdinalIgnoreCase));

        if (resourceName == null)
        {
            return Array.Empty<byte>();
        }

        using var stream = assembly.GetManifestResourceStream(resourceName);
        if (stream == null)
        {
            return null;
        }

        using var memoryStream = new MemoryStream();
        stream.CopyTo(memoryStream);
        return memoryStream.ToArray();
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _session?.Dispose();
        _session = null;
        _disposed = true;
    }
}
