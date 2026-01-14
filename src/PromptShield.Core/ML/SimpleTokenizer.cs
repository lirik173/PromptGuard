using System.Collections.Frozen;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.RegularExpressions;

namespace PromptShield.Core.ML;

/// <summary>
/// Advanced tokenizer for ML model input preparation with support for multiple tokenization strategies.
/// Supports word-based, character-based, and BPE-style subword tokenization.
/// </summary>
/// <remarks>
/// This tokenizer is designed for security-focused text analysis and includes:
/// - Configurable tokenization strategies (Word, Character, Subword)
/// - Special token handling (PAD, UNK, CLS, SEP, MASK)
/// - Pre-tokenization normalization and cleaning
/// - Security-relevant vocabulary with injection-related terms
/// - Attention mask generation for transformer models
/// </remarks>
internal sealed partial class SimpleTokenizer
{
    /// <summary>
    /// Available tokenization strategies.
    /// </summary>
    public enum TokenizationStrategy
    {
        /// <summary>Word-based tokenization with vocabulary lookup.</summary>
        Word,
        /// <summary>Character-level tokenization.</summary>
        Character,
        /// <summary>Subword tokenization using BPE-style merges.</summary>
        Subword
    }

    // Special token IDs
    public const int PadTokenId = 0;
    public const int UnknownTokenId = 1;
    public const int ClsTokenId = 2;
    public const int SepTokenId = 3;
    public const int MaskTokenId = 4;

    private const int VocabStartOffset = 5;

    private readonly int _maxSequenceLength;
    private readonly TokenizationStrategy _strategy;
    private readonly FrozenDictionary<string, int> _vocabulary;
    private readonly FrozenDictionary<string, int> _bpeMerges;
    private readonly bool _addSpecialTokens;
    private readonly bool _lowercase;

    /// <summary>
    /// Initializes a new instance of the SimpleTokenizer.
    /// </summary>
    /// <param name="maxSequenceLength">Maximum sequence length for tokenization.</param>
    /// <param name="vocabulary">Vocabulary mapping words to token IDs. If null, uses a default vocabulary.</param>
    /// <param name="strategy">Tokenization strategy to use.</param>
    /// <param name="addSpecialTokens">Whether to add CLS/SEP tokens.</param>
    /// <param name="lowercase">Whether to lowercase input before tokenization.</param>
    public SimpleTokenizer(
        int maxSequenceLength,
        Dictionary<string, int>? vocabulary = null,
        TokenizationStrategy strategy = TokenizationStrategy.Subword,
        bool addSpecialTokens = true,
        bool lowercase = true)
    {
        if (maxSequenceLength <= 0)
            throw new ArgumentOutOfRangeException(nameof(maxSequenceLength), "Must be positive");

        _maxSequenceLength = maxSequenceLength;
        _strategy = strategy;
        _addSpecialTokens = addSpecialTokens;
        _lowercase = lowercase;
        _vocabulary = (vocabulary ?? CreateSecurityFocusedVocabulary()).ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);
        _bpeMerges = CreateBpeMerges().ToFrozenDictionary(StringComparer.Ordinal);
    }

    /// <summary>
    /// Gets the vocabulary size including special tokens.
    /// </summary>
    public int VocabularySize => _vocabulary.Count + VocabStartOffset;

    /// <summary>
    /// Tokenizes the input text into a sequence of token IDs.
    /// </summary>
    /// <param name="text">Text to tokenize.</param>
    /// <returns>Array of token IDs with length equal to maxSequenceLength.</returns>
    public int[] Tokenize(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        return _strategy switch
        {
            TokenizationStrategy.Word => TokenizeWord(text),
            TokenizationStrategy.Character => TokenizeCharacter(text),
            TokenizationStrategy.Subword => TokenizeSubword(text),
            _ => TokenizeSubword(text)
        };
    }

    /// <summary>
    /// Tokenizes text and returns both token IDs and attention mask.
    /// </summary>
    /// <param name="text">Text to tokenize.</param>
    /// <returns>Tuple of (token IDs, attention mask) arrays.</returns>
    public (int[] TokenIds, int[] AttentionMask) TokenizeWithAttention(string text)
    {
        var tokenIds = Tokenize(text);
        var attentionMask = new int[_maxSequenceLength];

        // Attention mask: 1 for real tokens, 0 for padding
        for (var i = 0; i < tokenIds.Length; i++)
        {
            attentionMask[i] = tokenIds[i] != PadTokenId ? 1 : 0;
        }

        return (tokenIds, attentionMask);
    }

    /// <summary>
    /// Tokenizes multiple texts in batch.
    /// </summary>
    /// <param name="texts">Collection of texts to tokenize.</param>
    /// <returns>2D array of shape [batch_size, max_sequence_length].</returns>
    public int[,] TokenizeBatch(IReadOnlyList<string> texts)
    {
        ArgumentNullException.ThrowIfNull(texts);

        var result = new int[texts.Count, _maxSequenceLength];

        for (var i = 0; i < texts.Count; i++)
        {
            var tokenIds = Tokenize(texts[i]);
            for (var j = 0; j < _maxSequenceLength; j++)
            {
                result[i, j] = tokenIds[j];
            }
        }

        return result;
    }

    /// <summary>
    /// Decodes token IDs back to text (for debugging/inspection).
    /// </summary>
    /// <param name="tokenIds">Array of token IDs.</param>
    /// <returns>Decoded text string.</returns>
    public string Decode(int[] tokenIds)
    {
        ArgumentNullException.ThrowIfNull(tokenIds);

        var reverseVocab = _vocabulary.ToDictionary(kv => kv.Value, kv => kv.Key);
        var sb = new StringBuilder();

        foreach (var tokenId in tokenIds)
        {
            if (tokenId == PadTokenId) continue;
            if (tokenId == ClsTokenId) { sb.Append("[CLS] "); continue; }
            if (tokenId == SepTokenId) { sb.Append(" [SEP]"); continue; }
            if (tokenId == UnknownTokenId) { sb.Append("[UNK] "); continue; }

            var vocabId = tokenId - VocabStartOffset;
            if (reverseVocab.TryGetValue(vocabId, out var word))
            {
                sb.Append(word);
                if (!word.StartsWith("##"))
                    sb.Append(' ');
            }
            else
            {
                sb.Append("[UNK] ");
            }
        }

        return sb.ToString().Trim();
    }

    #region Tokenization Strategies

    private int[] TokenizeWord(string text)
    {
        var normalized = NormalizeText(text);
        var words = PreTokenize(normalized);

        var tokenIds = new List<int>(_maxSequenceLength);

        if (_addSpecialTokens)
            tokenIds.Add(ClsTokenId);

        foreach (var word in words)
        {
            if (tokenIds.Count >= _maxSequenceLength - (_addSpecialTokens ? 1 : 0))
                break;

            var tokenId = _vocabulary.TryGetValue(word, out var id)
                ? id + VocabStartOffset
                : UnknownTokenId;

            tokenIds.Add(tokenId);
        }

        if (_addSpecialTokens && tokenIds.Count < _maxSequenceLength)
            tokenIds.Add(SepTokenId);

        return PadToLength(tokenIds);
    }

    private int[] TokenizeCharacter(string text)
    {
        var normalized = NormalizeText(text);
        var tokenIds = new List<int>(_maxSequenceLength);

        if (_addSpecialTokens)
            tokenIds.Add(ClsTokenId);

        foreach (var c in normalized)
        {
            if (tokenIds.Count >= _maxSequenceLength - (_addSpecialTokens ? 1 : 0))
                break;

            // Map characters to vocab IDs (simple ASCII mapping + special chars)
            var charStr = c.ToString();
            var tokenId = _vocabulary.TryGetValue(charStr, out var id)
                ? id + VocabStartOffset
                : UnknownTokenId;

            tokenIds.Add(tokenId);
        }

        if (_addSpecialTokens && tokenIds.Count < _maxSequenceLength)
            tokenIds.Add(SepTokenId);

        return PadToLength(tokenIds);
    }

    private int[] TokenizeSubword(string text)
    {
        var normalized = NormalizeText(text);
        var words = PreTokenize(normalized);
        var tokenIds = new List<int>(_maxSequenceLength);

        if (_addSpecialTokens)
            tokenIds.Add(ClsTokenId);

        foreach (var word in words)
        {
            if (tokenIds.Count >= _maxSequenceLength - (_addSpecialTokens ? 1 : 0))
                break;

            var subwords = ApplyBpe(word);

            foreach (var subword in subwords)
            {
                if (tokenIds.Count >= _maxSequenceLength - (_addSpecialTokens ? 1 : 0))
                    break;

                var tokenId = _vocabulary.TryGetValue(subword, out var id)
                    ? id + VocabStartOffset
                    : UnknownTokenId;

                tokenIds.Add(tokenId);
            }
        }

        if (_addSpecialTokens && tokenIds.Count < _maxSequenceLength)
            tokenIds.Add(SepTokenId);

        return PadToLength(tokenIds);
    }

    #endregion

    #region BPE Implementation

    /// <summary>
    /// Applies BPE-style subword tokenization to a single word.
    /// </summary>
    private List<string> ApplyBpe(string word)
    {
        if (string.IsNullOrEmpty(word))
            return [];

        // Start with character-level tokens
        var tokens = new List<string>();
        for (var i = 0; i < word.Length; i++)
        {
            tokens.Add(i == 0 ? word[i].ToString() : "##" + word[i]);
        }

        // Iteratively apply BPE merges
        var changed = true;
        var maxIterations = 50; // Prevent infinite loops
        var iteration = 0;

        while (changed && tokens.Count > 1 && iteration++ < maxIterations)
        {
            changed = false;
            var bestMergePriority = int.MaxValue;
            var bestMergeIndex = -1;

            // Find the highest priority merge
            for (var i = 0; i < tokens.Count - 1; i++)
            {
                var pair = tokens[i] + tokens[i + 1].TrimStart('#');
                if (_bpeMerges.TryGetValue(pair, out var priority) && priority < bestMergePriority)
                {
                    bestMergePriority = priority;
                    bestMergeIndex = i;
                }
            }

            // Apply the merge
            if (bestMergeIndex >= 0)
            {
                var merged = tokens[bestMergeIndex] + tokens[bestMergeIndex + 1].TrimStart('#');
                if (bestMergeIndex > 0)
                    merged = "##" + merged.TrimStart('#');

                tokens[bestMergeIndex] = bestMergeIndex == 0 ? merged.TrimStart('#') : merged;
                tokens.RemoveAt(bestMergeIndex + 1);
                changed = true;
            }
        }

        return tokens;
    }

    #endregion

    #region Text Processing

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private string NormalizeText(string text)
    {
        var sb = new StringBuilder(text.Length);
        var lastWasWhitespace = false;

        foreach (var c in text)
        {
            if (char.IsWhiteSpace(c))
            {
                if (!lastWasWhitespace)
                {
                    sb.Append(' ');
                    lastWasWhitespace = true;
                }
            }
            else if (IsValidChar(c))
            {
                sb.Append(_lowercase ? char.ToLowerInvariant(c) : c);
                lastWasWhitespace = false;
            }
            // Skip control characters and other invalid chars
        }

        return sb.ToString().Trim();
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool IsValidChar(char c)
    {
        // Allow letters, digits, punctuation, and common symbols
        return char.IsLetterOrDigit(c) ||
               char.IsPunctuation(c) ||
               char.IsSymbol(c) ||
               c == ' ';
    }

    private static List<string> PreTokenize(string text)
    {
        // Split on whitespace and punctuation boundaries
        var result = new List<string>();
        var currentWord = new StringBuilder();

        foreach (var c in text)
        {
            if (char.IsWhiteSpace(c))
            {
                if (currentWord.Length > 0)
                {
                    result.Add(currentWord.ToString());
                    currentWord.Clear();
                }
            }
            else if (char.IsPunctuation(c) || char.IsSymbol(c))
            {
                if (currentWord.Length > 0)
                {
                    result.Add(currentWord.ToString());
                    currentWord.Clear();
                }
                result.Add(c.ToString());
            }
            else
            {
                currentWord.Append(c);
            }
        }

        if (currentWord.Length > 0)
        {
            result.Add(currentWord.ToString());
        }

        return result;
    }

    private int[] PadToLength(List<int> tokenIds)
    {
        var result = new int[_maxSequenceLength];

        for (var i = 0; i < _maxSequenceLength; i++)
        {
            result[i] = i < tokenIds.Count ? tokenIds[i] : PadTokenId;
        }

        return result;
    }

    #endregion

    #region Vocabulary Building

    private static Dictionary<string, int> CreateSecurityFocusedVocabulary()
    {
        var vocabulary = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var tokenId = 0;

        // Single characters (for character-level fallback)
        for (var c = 'a'; c <= 'z'; c++)
            vocabulary[c.ToString()] = tokenId++;

        for (var c = '0'; c <= '9'; c++)
            vocabulary[c.ToString()] = tokenId++;

        // Common punctuation
        foreach (var p in ".,!?;:'-\"()[]{}/<>@#$%^&*+=_\\|`~")
            vocabulary[p.ToString()] = tokenId++;

        // Common English words
        var commonWords = new[]
        {
            "the", "be", "to", "of", "and", "a", "in", "that", "have", "i",
            "it", "for", "not", "on", "with", "he", "as", "you", "do", "at",
            "this", "but", "his", "by", "from", "they", "we", "say", "her", "she",
            "or", "an", "will", "my", "one", "all", "would", "there", "their", "what",
            "so", "up", "out", "if", "about", "who", "get", "which", "go", "me",
            "when", "make", "can", "like", "time", "no", "just", "him", "know", "take",
            "people", "into", "year", "your", "good", "some", "could", "them", "see", "other",
            "than", "then", "now", "look", "only", "come", "its", "over", "think", "also"
        };

        foreach (var word in commonWords)
            vocabulary[word] = tokenId++;

        // Security-focused keywords (prompt injection detection)
        var securityKeywords = new[]
        {
            // Injection commands
            "ignore", "forget", "disregard", "override", "bypass", "skip", "delete", "remove",
            "jailbreak", "dan", "sudo", "admin", "root", "privileged", "elevated",

            // Role manipulation
            "pretend", "roleplay", "act", "persona", "character", "simulate", "imagine",
            "behave", "respond", "answer", "reply", "talk", "speak", "write",

            // System references
            "system", "prompt", "instruction", "instructions", "previous", "above", "below",
            "original", "initial", "real", "actual", "true", "hidden", "secret",

            // Action verbs
            "execute", "run", "eval", "print", "output", "display", "show", "reveal",
            "tell", "repeat", "generate", "create", "produce", "give", "provide",

            // Context manipulation
            "context", "conversation", "message", "messages", "history", "chat", "session",
            "beginning", "start", "end", "first", "last", "new", "updated",

            // Technical terms
            "api", "key", "token", "password", "credential", "access", "permission",
            "code", "script", "function", "variable", "data", "json", "xml",

            // Phrases (as single tokens for efficiency)
            "you", "are", "now", "from", "on", "must", "should", "always", "never",
            "everything", "anything", "nothing", "all", "any", "every"
        };

        foreach (var keyword in securityKeywords)
            vocabulary[keyword] = tokenId++;

        // Subword pieces (common prefixes/suffixes)
        var subwordPieces = new[]
        {
            "##ing", "##ed", "##er", "##est", "##ly", "##tion", "##ness",
            "##ment", "##able", "##ible", "##ful", "##less", "##ive", "##ous",
            "un##", "re##", "pre##", "dis##", "mis##", "over##", "under##",
            "##s", "##es", "##al", "##ity", "##ize", "##ise", "##ify"
        };

        foreach (var piece in subwordPieces)
            vocabulary[piece] = tokenId++;

        return vocabulary;
    }

    private static Dictionary<string, int> CreateBpeMerges()
    {
        // BPE merge priorities (lower = higher priority)
        // These represent common character sequences to merge
        var merges = new Dictionary<string, int>(StringComparer.Ordinal);
        var priority = 0;

        // High priority common merges
        var commonMerges = new[]
        {
            "th", "he", "in", "er", "an", "re", "on", "at", "en", "nd",
            "ti", "es", "or", "te", "of", "ed", "is", "it", "al", "ar",
            "st", "to", "nt", "ng", "se", "ha", "as", "ou", "io", "le",
            "ve", "co", "me", "de", "hi", "ri", "ro", "ic", "ne", "ea",
            "ra", "ce", "li", "ch", "ll", "be", "ma", "si", "om", "ur"
        };

        foreach (var merge in commonMerges)
            merges[merge] = priority++;

        // Security-relevant merges
        var securityMerges = new[]
        {
            "ig", "no", "re", "by", "pa", "ss", "sy", "st", "em", "pr",
            "om", "pt", "in", "st", "ru", "ct", "io", "ns", "ad", "mi",
            "ro", "ot", "ja", "il", "br", "ea", "ck", "ex", "ec", "ut"
        };

        foreach (var merge in securityMerges)
        {
            if (!merges.ContainsKey(merge))
                merges[merge] = priority++;
        }

        return merges;
    }

    #endregion
}
