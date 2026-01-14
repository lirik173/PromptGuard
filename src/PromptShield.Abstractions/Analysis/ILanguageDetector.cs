namespace PromptShield.Abstractions.Analysis;

/// <summary>
/// Interface for detecting the language of input text.
/// </summary>
/// <remarks>
/// <para>
/// Implementations should provide fast, reliable language detection for prompt text.
/// The default implementation uses script detection and n-gram analysis.
/// </para>
/// <para>
/// For production use with diverse languages, consider using specialized libraries
/// like NTextCat, langdetect, or cloud services like Azure AI Language.
/// </para>
/// </remarks>
public interface ILanguageDetector
{
    /// <summary>
    /// Detects the primary language of the provided text.
    /// </summary>
    /// <param name="text">Text to analyze.</param>
    /// <returns>Language detection result with language code, script, and confidence.</returns>
    LanguageDetectionResult Detect(string text);
}
