using System.Security.Cryptography;
using System.Text;

namespace NetchX.Utils;

public static class StringExtension
{
    public static bool IsNullOrEmpty(this string? value)
    {
        return string.IsNullOrEmpty(value);
    }

    public static bool IsNullOrWhiteSpace(this string? value)
    {
        return string.IsNullOrWhiteSpace(value);
    }

    public static bool BeginWithAny(this string s, IEnumerable<char> chars)
    {
        if (s.IsNullOrEmpty())
            return false;

        return chars.Contains(s[0]);
    }

    public static bool IsWhiteSpace(this string value)
    {
        return value.All(char.IsWhiteSpace);
    }

    public static IEnumerable<string> NonWhiteSpaceLines(this TextReader reader)
    {
        string? line;
        while ((line = reader.ReadLine()) != null)
        {
            if (line.IsWhiteSpace())
                continue;

            yield return line;
        }
    }

    public static string ToRegexString(this string value)
    {
        var sb = new StringBuilder();
        foreach (var t in value)
        {
            var escapeCharacters = new[] { '\\', '*', '+', '?', '|', '{', '}', '[', ']', '(', ')', '^', '$', '.' };
            if (escapeCharacters.Any(s => s == t))
                sb.Append('\\');

            sb.Append(t);
        }

        return sb.ToString();
    }

    public static string[] SplitRemoveEmptyEntriesAndTrimEntries(this string value, params char[] separator)
    {
        return value.Split(separator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    public static string[] SplitTrimEntries(this string value, params char[] separator)
    {
        return value.Split(separator, StringSplitOptions.TrimEntries);
    }

    public static string[] SplitRemoveEmptyEntries(this string value, params char[] separator)
    {
        return value.Split(separator, StringSplitOptions.RemoveEmptyEntries);
    }

    public static string? ValueOrDefault(this string? value, string? defaultValue = default)
    {
        return string.IsNullOrWhiteSpace(value) ? defaultValue : value;
    }

    public static string[]? SplitOrDefault(this string? value)
    {
        return !string.IsNullOrWhiteSpace(value) ? value.Split(',') : default;
    }

    public static string GenerateUUIDv5(this string str)
    {
        // https://github.com/XTLS/Xray-core/discussions/715
        // https://xray-uuid.ducksoft.site/

        // example string: "example"
        var byteSource = new byte[16 + Encoding.UTF8.GetByteCount(str)];
        Encoding.UTF8.GetBytes(str, byteSource.AsSpan(16));

        var sha1Bytes = SHA1.HashData(byteSource)[..16];

        //UUIDv5: [254 181 68 49 48 27 82 187 166 221 225 233 62 129 187 158]

        sha1Bytes[6] = (byte)((sha1Bytes[6] & 0x0f) | (5 << 4));
        sha1Bytes[8] = (byte)(sha1Bytes[8] & (0xff >> 2) | (0x02 << 6));

        return Convert.ToHexString(sha1Bytes)
            .Insert(8, "-").Insert(13, "-").Insert(18, "-").Insert(23, "-")
            .ToLowerInvariant();
        //UUIDv5: feb54431-301b-52bb-a6dd-e1e93e81bb9e
    }
}