using NetchX.Models;

namespace NetchX.Servers;

public class ShadowsocksRServer : Server
{
    public override string Type { get; } = "SSR";
    public override string MaskedData()
    {
        return $"{EncryptMethod} + {Protocol} + {OBFS}";
    }

    /// <summary>
    ///     Password.
    /// </summary>
    public string Password { get; set; } = string.Empty;

    /// <summary>
    ///     Encryption method.
    /// </summary>
    public string EncryptMethod { get; set; } = SSRGlobal.EncryptMethods[4];

    /// <summary>
    ///     Protocol.
    /// </summary>
    public string Protocol { get; set; } = SSRGlobal.Protocols[0];

    /// <summary>
    ///     Protocol arguments.
    /// </summary>
    public string? ProtocolParam { get; set; }

    /// <summary>
    ///     Obfuscation method.
    /// </summary>
    public string OBFS { get; set; } = SSRGlobal.OBFSs[0];

    /// <summary>
    ///     Obfuscation arguments.
    /// </summary>
    public string? OBFSParam { get; set; }
}

public class SSRGlobal
{
    /// <summary>
    ///     Supported ShadowsocksR protocols.
    /// </summary>
    public static readonly List<string> Protocols = new()
    {
        "origin",
        "auth_sha1_v4",
        "auth_aes128_md5",
        "auth_aes128_sha1",
        "auth_chain_a",
        "auth_chain_b"
    };

    /// <summary>
    ///     Supported ShadowsocksR obfuscation methods.
    /// </summary>
    public static readonly List<string> OBFSs = new()
    {
        "plain",
        "http_simple",
        "http_post",
        "tls_simple",
        "tls1.2_ticket_auth",
        "tls1.2_ticket_fastauth",
        "random_head"
    };

    /// <summary>
    ///     Supported Shadowsocks and ShadowsocksR encryption methods.
    /// </summary>
    public static readonly List<string> EncryptMethods = SSGlobal.EncryptMethods;
}
