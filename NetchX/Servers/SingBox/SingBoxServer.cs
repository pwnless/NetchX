using System.Text.Json.Serialization;
using NetchX.Models;

namespace NetchX.Servers;

/// <summary>
///     Shared TLS controls for sing-box client outbounds.
/// </summary>
public abstract class SingBoxTlsServer : Server
{
    /// <summary>
    ///     TLS SNI. Falls back to <see cref="Server.Hostname"/> when empty.
    /// </summary>
    public string? ServerName { get; set; }

    /// <summary>
    ///     Skip certificate validation. Intended only for explicitly trusted deployments.
    /// </summary>
    public bool AllowInsecure { get; set; }

    /// <summary>
    ///     Comma-separated ALPN values.
    /// </summary>
    public string? ALPN { get; set; }

    /// <summary>
    ///     Optional sing-box uTLS fingerprint.
    /// </summary>
    public string? UTLSFingerprint { get; set; } = "chrome";

    /// <summary>
    ///     Optional PEM certificate used to verify servers that do not chain to a system trust root.
    /// </summary>
    public string? Certificate { get; set; }

    /// <summary>
    ///     Optional ECH configuration value.
    /// </summary>
    public string? ECH { get; set; }

    protected string TlsMaskedData() => $"TLS: {(AllowInsecure ? "insecure" : "verify")}";
}

public sealed class AnyTlsServer : SingBoxTlsServer
{
    public override string Type { get; } = "AnyTLS";

    public string Password { get; set; } = string.Empty;

    public string? IdleSessionCheckInterval { get; set; }

    public string? IdleSessionTimeout { get; set; }

    public int? MinIdleSession { get; set; }

    public string? ClientMetadata { get; set; }

    public override string MaskedData() => TlsMaskedData();
}

public sealed class HysteriaServer : SingBoxTlsServer
{
    public override string Type { get; } = "Hysteria";

    public int UpMbps { get; set; } = 100;

    public int DownMbps { get; set; } = 100;

    public string? Obfs { get; set; }

    public string? Auth { get; set; }

    /// <summary>
    ///     Optional comma-separated server port ranges for port hopping.
    /// </summary>
    public string? ServerPorts { get; set; }

    public string? HopInterval { get; set; }

    /// <summary>
    ///     Enabled proxy networks: tcp, udp, or tcp,udp.
    /// </summary>
    public string Network { get; set; } = "tcp,udp";

    [JsonIgnore]
    public override ServerNetworkCapability NetworkCapabilities => SingBoxServerNetworks.Parse(Network);

    public override string MaskedData() => TlsMaskedData();
}

public sealed class Hysteria2Server : SingBoxTlsServer
{
    public override string Type { get; } = "Hysteria2";

    public string Password { get; set; } = string.Empty;

    public int? UpMbps { get; set; }

    public int? DownMbps { get; set; }

    public string ObfsType { get; set; } = "none";

    public string? ObfsPassword { get; set; }

    public string? ServerPorts { get; set; }

    public string? HopInterval { get; set; }

    public string? HopIntervalMax { get; set; }

    public string BbrProfile { get; set; } = "standard";

    public bool DisableChromeParrot { get; set; }

    public string Network { get; set; } = "tcp,udp";

    [JsonIgnore]
    public override ServerNetworkCapability NetworkCapabilities => SingBoxServerNetworks.Parse(Network);

    public override string MaskedData() => TlsMaskedData();
}

public sealed class TuicServer : SingBoxTlsServer
{
    public override string Type { get; } = "TUIC";

    public string UserID { get; set; } = string.Empty;

    public string? Password { get; set; }

    public string CongestionControl { get; set; } = "cubic";

    public string UdpRelayMode { get; set; } = "native";

    public bool UdpOverStream { get; set; }

    public bool ZeroRttHandshake { get; set; }

    public string? Heartbeat { get; set; }

    public string Network { get; set; } = "tcp,udp";

    [JsonIgnore]
    public override ServerNetworkCapability NetworkCapabilities => SingBoxServerNetworks.Parse(Network);

    public override string MaskedData() => TlsMaskedData();
}

public sealed class NaiveServer : SingBoxTlsServer
{
    public override string Type { get; } = "Naive";

    public string? Username { get; set; }

    public string? Password { get; set; }

    public int? InsecureConcurrency { get; set; }

    /// <summary>
    ///     JSON object with additional HTTP request headers.
    /// </summary>
    public string? ExtraHeaders { get; set; }

    public bool UdpOverTcp { get; set; }

    public bool Quic { get; set; }

    public string? QuicCongestionControl { get; set; }

    public string? StreamReceiveWindow { get; set; }

    public string? QuicSessionReceiveWindow { get; set; }

    [JsonIgnore]
    public override ServerNetworkCapability NetworkCapabilities => UdpOverTcp
        ? ServerNetworkCapability.Tcp | ServerNetworkCapability.Udp
        : ServerNetworkCapability.Tcp;

    public override string MaskedData() => TlsMaskedData();
}

public sealed class ShadowTlsServer : SingBoxTlsServer
{
    public override string Type { get; } = "ShadowTLS";

    public int Version { get; set; } = 3;

    /// <summary>
    ///     ShadowTLS v2/v3 password.
    /// </summary>
    public string? Password { get; set; }

    /// <summary>
    ///     Shadowsocks method carried inside the ShadowTLS transport.
    /// </summary>
    public string EncryptMethod { get; set; } = SingBoxGlobal.ShadowsocksMethods[4];

    /// <summary>
    ///     Shadowsocks password carried inside the ShadowTLS transport.
    /// </summary>
    public string ShadowsocksPassword { get; set; } = string.Empty;

    [JsonIgnore]
    public override ServerNetworkCapability NetworkCapabilities => ServerNetworkCapability.Tcp;

    public override string MaskedData() => $"v{Version} + {EncryptMethod} + {TlsMaskedData()}";
}

public sealed class HttpProxyServer : SingBoxTlsServer
{
    public override string Type { get; } = "HTTP";

    public bool UseTls { get; set; }

    public string? Username { get; set; }

    public string? Password { get; set; }

    public string? Path { get; set; }

    /// <summary>
    ///     JSON object with additional CONNECT request headers.
    /// </summary>
    public string? Headers { get; set; }

    [JsonIgnore]
    public override ServerNetworkCapability NetworkCapabilities => ServerNetworkCapability.Tcp;

    public override string MaskedData() => UseTls ? TlsMaskedData() : "HTTP";
}

internal static class SingBoxServerNetworks
{
    public static ServerNetworkCapability Parse(string? network)
    {
        var result = 0;
        foreach (var item in (network ?? string.Empty).Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (item.Equals("tcp", StringComparison.OrdinalIgnoreCase))
                result |= (int)ServerNetworkCapability.Tcp;
            else if (item.Equals("udp", StringComparison.OrdinalIgnoreCase))
                result |= (int)ServerNetworkCapability.Udp;
        }

        return result == 0 ? ServerNetworkCapability.Tcp | ServerNetworkCapability.Udp : (ServerNetworkCapability)result;
    }
}


internal static class SingBoxGlobal
{
    public static readonly List<string> ShadowsocksMethods = new()
    {
        "none",
        "2022-blake3-aes-128-gcm",
        "2022-blake3-aes-256-gcm",
        "2022-blake3-chacha20-poly1305",
        "aes-128-gcm",
        "aes-192-gcm",
        "aes-256-gcm",
        "chacha20-ietf-poly1305",
        "xchacha20-ietf-poly1305",
        "aes-128-ctr",
        "aes-192-ctr",
        "aes-256-ctr",
        "aes-128-cfb",
        "aes-192-cfb",
        "aes-256-cfb",
        "rc4-md5",
        "chacha20-ietf",
        "xchacha20"
    };
}
