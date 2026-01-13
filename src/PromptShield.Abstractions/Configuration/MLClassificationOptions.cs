namespace PromptShield.Abstractions.Configuration;

/// <summary>
/// ML classification layer options.
/// </summary>
public sealed class MLClassificationOptions
{
    /// <summary>
    /// Whether ML classification is enabled.
    /// </summary>
    public bool Enabled { get; set; } = true;
    
    /// <summary>
    /// Path to ONNX model file. If null, uses embedded model.
    /// </summary>
    public string? ModelPath { get; set; }
    
    /// <summary>
    /// Confidence threshold for ML decisions.
    /// </summary>
    public double Threshold { get; set; } = 0.8;
    
    /// <summary>
    /// Maximum sequence length for tokenization.
    /// </summary>
    public int MaxSequenceLength { get; set; } = 512;
}
