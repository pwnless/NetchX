using Netch.Models;

namespace Netch.Servers;

public class VMessServer : Server
{
    private string _tlsSecureType = VMessGlobal.TLSSecure[0];

    public override string Type { get; } = "VMess";

    public override string MaskedData()
    {
        var maskedData = $"{EncryptMethod} + {TransferProtocol} + {PacketEncoding} + {FakeType}";
        switch (TransferProtocol)
        {
            case "tcp":
            case "ws":
                maskedData += $" + {TLSSecureType}";
                break;
            case "quic":
                maskedData += $" + {QUICSecure}";
                break;
            case "grpc":
                break;
            case "kcp":
                break;
        }

        return maskedData;
    }

    /// <summary>
    ///     User ID
    /// </summary>
    public string UserID { get; set; } = string.Empty;

    /// <summary>
    ///     Alter ID
    /// </summary>
    public int AlterID { get; set; }

    /// <summary>
    ///     Encryption method
    /// </summary>
    public virtual string EncryptMethod { get; set; } = VMessGlobal.EncryptMethods[0];

    /// <summary>
    ///     Transport protocol
    /// </summary>
    public virtual string TransferProtocol { get; set; } = VMessGlobal.TransferProtocols[0];

    /// <summary>
    ///     Packet encoding
    /// </summary>
    public virtual string PacketEncoding { get; set; } = VMessGlobal.PacketEncodings[2];

    /// <summary>
    ///     Camouflage type
    /// </summary>
    public virtual string FakeType { get; set; } = VMessGlobal.FakeTypes[0];

    /// <summary>
    ///     Camouflage host
    /// </summary>
    public string? Host { get; set; }

    /// <summary>
    ///     Transport path
    /// </summary>
    public string? Path { get; set; }

    /// <summary>
    ///     QUIC encryption method
    /// </summary>
    public string? QUICSecure { get; set; } = VMessGlobal.QUIC[0];

    /// <summary>
    ///     QUIC encryption key
    /// </summary>
    public string? QUICSecret { get; set; } = string.Empty;

    /// <summary>
    ///     TLS transport security
    /// </summary>
    public string TLSSecureType
    {
        get => _tlsSecureType;
        set
        {
            if (value == "")
                value = "none";

            _tlsSecureType = value;
        }
    }

    /// <summary>
    ///     Mux multiplexing
    /// </summary>
    public bool? UseMux { get; set; }

    public string? ServerName { get; set; } = string.Empty;
}

public class VMessGlobal
{
    public static readonly List<string> EncryptMethods = new()
    {
        "auto",
        "none",
        "aes-128-gcm",
        "chacha20-poly1305",
        "zero"
    };

    public static readonly List<string> QUIC = new()
    {
        "none",
        "aes-128-gcm",
        "chacha20-poly1305"
    };

    public static readonly List<string> PacketEncodings = new()
    {
        "none",
        "packet", // requires v2fly/v2ray-core v5.0.2+ or SagerNet/v2ray-core
        "xudp" // requires XTLS/Xray-core or SagerNet/v2ray-core
    };

    /// <summary>
    ///     V2Ray transport protocols
    /// </summary>
    public static readonly List<string> TransferProtocols = new()
    {
        "tcp",
        "kcp",
        "ws",
        "h2",
        "quic",
        "grpc"
    };

    /// <summary>
    ///     V2Ray camouflage types
    /// </summary>
    public static readonly List<string> FakeTypes = new()
    {
        "none",
        "http",
        "srtp",
        "utp",
        "wechat-video",
        "dtls",
        "wireguard",
        "gun",
        "multi"
    };

    /// <summary>
    ///     TLS security types
    /// </summary>
    public static readonly List<string> TLSSecure = new()
    {
        "none",
        "tls"
    };
}
