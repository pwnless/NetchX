using Netch.Forms;

namespace Netch.Servers;

[Fody.ConfigureAwait(true)]
internal class VLESSForm : ServerForm
{
    public VLESSForm(VLESSServer? server = default)
    {
        server ??= new VLESSServer();
        Server = server;
        CreateTextBox("Sni", "ServerName(Sni)", s => true, s => server.ServerName = s, server.ServerName);
        CreateTextBox("UUID", "UUID", s => true, s => server.UserID = s, server.UserID);
        CreateTextBox("EncryptMethod",
            "Encrypt Method",
            s => true,
            s => server.EncryptMethod = !string.IsNullOrWhiteSpace(s) ? s : "none",
            server.EncryptMethod);

        CreateComboBox("TransferProtocol",
            "Xray Transport",
            VLESSGlobal.TransferProtocols,
            s => server.TransferProtocol = s,
            server.TransferProtocol);
        CreateComboBox("PacketEncoding",
            "Packet Encoding",
            VMessGlobal.PacketEncodings,
            s => server.PacketEncoding = s,
            server.PacketEncoding);

        CreateComboBox("Flow", "XTLS Flow", VLESSGlobal.Flows, s => server.Flow = s, server.Flow);

        CreateComboBox("FakeType", "Fake Type", VLESSGlobal.FakeTypes, s => server.FakeType = s, server.FakeType);
        CreateTextBox("Host", "Host", s => true, s => server.Host = s, server.Host);
        CreateTextBox("Path", "Path", s => true, s => server.Path = s, server.Path);
        CreateComboBox("XHttpMode",
            "XHTTP Mode",
            new List<string> { "auto", "packet-up", "stream-up", "stream-one" },
            s => server.XHttpMode = s,
            server.XHttpMode);
        CreateComboBox("UseMux",
            "Use Mux",
            new List<string> { "", "true", "false" },
            s => server.UseMux = s switch { "" => null, "true" => true, "false" => false, _ => null },
            server.UseMux?.ToString().ToLower() ?? "");

        CreateComboBox("TLSSecure", "TLS Secure", VLESSGlobal.TLSSecure, s => server.TLSSecureType = s, server.TLSSecureType);
        CreateTextBox("RealityPublicKey", "Reality Public Key", s => true, s => server.RealityPublicKey = s, server.RealityPublicKey);
        CreateTextBox("RealityShortId", "Reality Short ID", s => true, s => server.RealityShortId = s, server.RealityShortId);
        CreateComboBox("RealityFingerprint",
            "TLS/REALITY Fingerprint",
            new List<string> { "chrome", "firefox", "safari", "edge", "android", "ios", "360", "qq", "random", "randomized" },
            s => server.RealityFingerprint = s,
            server.RealityFingerprint);
        CreateTextBox("RealitySpiderX", "Reality SpiderX", s => true, s => server.RealitySpiderX = s, server.RealitySpiderX);
        CreateTextBox("RealityMldsa65Verify", "ML-DSA-65 Verify Key", s => true, s => server.RealityMldsa65Verify = s, server.RealityMldsa65Verify);
        CreateTextBox("HysteriaAuth", "Hysteria 2 Auth", s => true, s => server.HysteriaAuth = s, server.HysteriaAuth);
    }

    protected override string TypeName { get; } = "VLESS";
}
