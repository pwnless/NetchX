using Netch.Models;

namespace Netch.Servers;

public class VMessServer : Server
{
    private string _tlsSecureType = VMessGlobal.TLSSecure[0];

    public override string Type { get; } = "VMess";

    public override string MaskedData()
    {
        var maskedData = $"{EncryptMethod} + {TransferProtocol} + {PacketEncoding} + {FakeType}";
        maskedData += $" + {TLSSecureType}";

        if (TLSSecureType == "reality")
            maskedData += $" + {RealityFingerprint}";

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

    /// <summary>
    ///     TLS or REALITY client fingerprint.
    /// </summary>
    public string RealityFingerprint { get; set; } = "chrome";

    /// <summary>
    ///     REALITY server public key (called <c>password</c> by current Xray configuration).
    /// </summary>
    public string RealityPublicKey { get; set; } = string.Empty;

    /// <summary>
    ///     REALITY short ID.
    /// </summary>
    public string RealityShortId { get; set; } = string.Empty;

    /// <summary>
    ///     REALITY crawler path and query.
    /// </summary>
    public string RealitySpiderX { get; set; } = string.Empty;

    /// <summary>
    ///     Optional ML-DSA-65 public verification key for REALITY.
    /// </summary>
    public string RealityMldsa65Verify { get; set; } = string.Empty;

    /// <summary>
    ///     XHTTP request mode.
    /// </summary>
    public string XHttpMode { get; set; } = "auto";

    /// <summary>
    ///     Hysteria 2 authentication value when used as an Xray transport.
    /// </summary>
    public string HysteriaAuth { get; set; } = string.Empty;
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
        "packet",
        "xudp"
    };

    /// <summary>
    ///     Xray transport methods. The legacy aliases remain so saved profiles
    ///     can be opened and migrated by the config generator.
    /// </summary>
    public static readonly List<string> TransferProtocols = new()
    {
        "raw",
        "xhttp",
        "mkcp",
        "grpc",
        "websocket",
        "httpupgrade",
        "hysteria",

        // Persisted legacy aliases are accepted by the generator where Xray
        // provides an equivalent, but are intentionally not offered for new
        // profiles.
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
        "tls",
        "reality"
    };
}
