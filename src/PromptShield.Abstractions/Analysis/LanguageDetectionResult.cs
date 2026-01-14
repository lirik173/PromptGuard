namespace PromptShield.Abstractions.Analysis;

/// <summary>
/// Result of language detection analysis.
/// </summary>
/// <param name="LanguageCode">ISO 639-1 language code (e.g., "en", "de", "zh"). "und" for undetermined.</param>
/// <param name="ScriptCode">ISO 15924 script code (e.g., "Latn", "Cyrl", "Hans"). "Zzzz" for unknown.</param>
/// <param name="Confidence">Detection confidence from 0.0 to 1.0.</param>
/// <param name="IsReliable">Whether the detection is considered reliable based on text length and confidence.</param>
public sealed record LanguageDetectionResult(
    string LanguageCode,
    string ScriptCode,
    double Confidence,
    bool IsReliable)
{
    /// <summary>
    /// Creates an undetermined/unknown language result.
    /// </summary>
    public static LanguageDetectionResult Undetermined { get; } = 
        new("und", "Zzzz", 0.0, false);

    /// <summary>
    /// Creates a result for English language.
    /// </summary>
    public static LanguageDetectionResult English(double confidence) =>
        new("en", "Latn", confidence, confidence >= 0.7);

    /// <summary>
    /// Gets human-readable language name.
    /// </summary>
    public string LanguageName => LanguageCode switch
    {
        "en" => "English",
        "de" => "German",
        "fr" => "French",
        "es" => "Spanish",
        "it" => "Italian",
        "pt" => "Portuguese",
        "nl" => "Dutch",
        "pl" => "Polish",
        "uk" => "Ukrainian",
        "ru" => "Russian",
        "zh" => "Chinese",
        "ja" => "Japanese",
        "ko" => "Korean",
        "ar" => "Arabic",
        "he" => "Hebrew",
        "hi" => "Hindi",
        "th" => "Thai",
        "vi" => "Vietnamese",
        "tr" => "Turkish",
        "el" => "Greek",
        "und" => "Undetermined",
        _ => $"Unknown ({LanguageCode})"
    };

    /// <summary>
    /// Gets human-readable script name.
    /// </summary>
    public string ScriptName => ScriptCode switch
    {
        "Latn" => "Latin",
        "Cyrl" => "Cyrillic",
        "Hans" => "Simplified Chinese",
        "Hant" => "Traditional Chinese",
        "Jpan" => "Japanese",
        "Kore" => "Korean",
        "Arab" => "Arabic",
        "Hebr" => "Hebrew",
        "Deva" => "Devanagari",
        "Thai" => "Thai",
        "Grek" => "Greek",
        "Zzzz" => "Unknown",
        _ => ScriptCode
    };

    /// <summary>
    /// Indicates whether the detected script is Latin-based.
    /// </summary>
    public bool IsLatinScript => ScriptCode == "Latn";

    /// <summary>
    /// Indicates whether the detected language is English.
    /// </summary>
    public bool IsEnglish => LanguageCode == "en";
}
