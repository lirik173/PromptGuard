namespace PromptShield.Abstractions.Configuration;

/// <summary>
/// Language detection and filtering configuration.
/// </summary>
/// <remarks>
/// <para>
/// PromptShield's detection layers (Pattern Matching, Heuristics, ML) require
/// language-specific patterns and vocabulary. By default, only <b>English</b> is supported.
/// </para>
/// <para>
/// The Language Filter acts as a gate: prompts in unsupported languages are blocked
/// before reaching detection layers. This prevents bypass attempts via non-supported languages.
/// </para>
/// <para>
/// To add support for additional languages:
/// <list type="number">
///   <item>Add the language code to <see cref="SupportedLanguages"/></item>
///   <item>Implement <see cref="Detection.Patterns.IPatternProvider"/> with patterns for that language</item>
///   <item>Optionally implement <see cref="Analyzers.Heuristics.IHeuristicAnalyzer"/> for language-specific heuristics</item>
/// </list>
/// </para>
/// </remarks>
public sealed class LanguageOptions
{
    /// <summary>
    /// Whether language filtering is enabled.
    /// </summary>
    /// <remarks>
    /// When enabled, prompts in unsupported languages are blocked before detection.
    /// <b>Disabling this creates a security risk</b> - attackers can bypass English-only
    /// detection rules by using other languages.
    /// </remarks>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// ISO 639-1 language codes that have detection support.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Only languages listed here will pass through to detection layers.
    /// By default, only English ("en") has built-in patterns and vocabulary.
    /// </para>
    /// <para>
    /// Add language codes here only after implementing corresponding detection rules.
    /// Examples: "en" (English), "de" (German), "uk" (Ukrainian), "fr" (French)
    /// </para>
    /// </remarks>
    public string[] SupportedLanguages { get; set; } = ["en"];

    /// <summary>
    /// Behavior when a prompt is in an unsupported language.
    /// </summary>
    public UnsupportedLanguageBehavior OnUnsupportedLanguage { get; set; } =
        UnsupportedLanguageBehavior.Block;

    /// <summary>
    /// Minimum confidence threshold for language detection (0.0 - 1.0).
    /// </summary>
    /// <remarks>
    /// If detection confidence is below this threshold, the behavior is determined
    /// by <see cref="OnLowConfidenceDetection"/>.
    /// </remarks>
    public double MinDetectionConfidence { get; set; } = 0.7;

    /// <summary>
    /// Minimum text length in characters for reliable language detection.
    /// </summary>
    /// <remarks>
    /// Very short texts cannot be reliably classified.
    /// Texts shorter than this use <see cref="OnShortText"/> behavior.
    /// </remarks>
    public int MinTextLengthForDetection { get; set; } = 20;

    /// <summary>
    /// Behavior when text is too short for reliable language detection.
    /// </summary>
    public UnsupportedLanguageBehavior OnShortText { get; set; } =
        UnsupportedLanguageBehavior.Allow;

    /// <summary>
    /// Behavior when language detection confidence is below threshold.
    /// </summary>
    public UnsupportedLanguageBehavior OnLowConfidenceDetection { get; set; } =
        UnsupportedLanguageBehavior.Block;

    /// <summary>
    /// Whether to include detected language info in analysis results.
    /// </summary>
    public bool IncludeLanguageInResults { get; set; } = true;
}

/// <summary>
/// Behavior when input language is not supported or cannot be determined.
/// </summary>
public enum UnsupportedLanguageBehavior
{
    /// <summary>
    /// Block the request. Analysis result will indicate language policy violation.
    /// This is the recommended default for security.
    /// </summary>
    Block = 0,

    /// <summary>
    /// Allow through detection layers. Use only when you have detection rules
    /// for the expected languages or for testing purposes.
    /// </summary>
    Allow = 1,

    /// <summary>
    /// Allow but include a warning in the analysis result indicating
    /// that detection may be less effective for the detected language.
    /// </summary>
    AllowWithWarning = 2
}
