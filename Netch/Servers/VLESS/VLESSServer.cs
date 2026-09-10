namespace Netch.Servers;

public class VLESSServer : VMessServer
{
    public override string Type { get; } = "VLESS";

    /// <summary>
    ///     Encryption method.
    /// </summary>
    public override string EncryptMethod { get; set; } = "none";

    /// <summary>
    ///     XTLS flow control. Vision requires TLS or REALITY security.
    /// </summary>
    public string Flow { get; set; } = string.Empty;

    /// <summary>
    ///     Transport protocol.
    /// </summary>
    public override string TransferProtocol { get; set; } = VLESSGlobal.TransferProtocols[0];

    /// <summary>
    ///     Camouflage type.
    /// </summary>
    public override string FakeType { get; set; } = VLESSGlobal.FakeTypes[0];
}

public class VLESSGlobal
{
    public static readonly List<string> TLSSecure = new()
    {
        "none",
        "tls",
        "reality"
    };

    public static readonly List<string> Flows = new()
    {
        "",
        "xtls-rprx-vision",
        "xtls-rprx-vision-udp443"
    };

    public static List<string> FakeTypes => VMessGlobal.FakeTypes;

    public static List<string> TransferProtocols => VMessGlobal.TransferProtocols;

    public static List<string> QUIC => VMessGlobal.QUIC;
}
