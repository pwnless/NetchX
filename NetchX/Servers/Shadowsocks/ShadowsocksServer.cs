using NetchX.Models;

namespace NetchX.Servers;

public class ShadowsocksServer : Server
{
    public override string Type { get; } = "SS";
    public override string MaskedData()
    {
        return $"{EncryptMethod} + {Plugin}";
    }

    /// <summary>
    ///     Encryption method.
    /// </summary>
    public string EncryptMethod { get; set; } = SSGlobal.EncryptMethods[4];

    /// <summary>
    ///     Password.
    /// </summary>
    public string Password { get; set; } = string.Empty;

    /// <summary>
    ///     Plugin.
    /// </summary>
    public string? Plugin { get; set; }

    /// <summary>
    ///     Plugin arguments.
    /// </summary>
    public string? PluginOption { get; set; }

    public bool HasPlugin()
    {
        return !string.IsNullOrWhiteSpace(Plugin) && !string.IsNullOrWhiteSpace(PluginOption);
    }
}

public static class SSGlobal
{
    /// <summary>
    ///     Supported Shadowsocks encryption methods.
    /// </summary>
    public static readonly List<string> EncryptMethods = new()
    {
        "none",

        // 2022 edition cipher
        "2022-blake3-aes-128-gcm",
        "2022-blake3-aes-256-gcm",
        "2022-blake3-chacha20-poly1305",

        // AEAD cipher
        "aes-128-gcm",
        "aes-192-gcm",
        "aes-256-gcm",
        "chacha20-ietf-poly1305",
        "xchacha20-ietf-poly1305",

        // stream cipher
        "rc4",
        "rc4-md5",
        "aes-128-ctr",
        "aes-192-ctr",
        "aes-256-ctr",
        "aes-128-cfb",
        "aes-192-cfb",
        "aes-256-cfb",
        "aes-128-cfb8",
        "aes-192-cfb8",
        "aes-256-cfb8",
        "aes-128-ofb",
        "aes-192-ofb",
        "aes-256-ofb",
        "bf-cfb",
        "cast5-cfb",
        "des-cfb",
        "idea-cfb",
        "rc2-cfb",
        "seed-cfb",
        "camellia-128-cfb",
        "camellia-192-cfb",
        "camellia-256-cfb",
        "camellia-128-cfb8",
        "camellia-192-cfb8",
        "camellia-256-cfb8",
        "salsa20",
        "chacha20",
        "chacha20-ietf",
        "xchacha20"
    };
}
