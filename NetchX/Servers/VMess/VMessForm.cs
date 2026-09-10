using NetchX.Forms;

namespace NetchX.Servers;

[Fody.ConfigureAwait(true)]
public class VMessForm : ServerForm
{
    public VMessForm(VMessServer? server = default)
    {
        server ??= new VMessServer();
        Server = server;
        CreateTextBox("Sni", "ServerName(Sni)", s => true, s => server.ServerName = s, server.ServerName);
        CreateTextBox("UserId", "User ID", s => true, s => server.UserID = s, server.UserID);
        CreateTextBox("AlterId", "Alter ID", s => int.TryParse(s, out _), s => server.AlterID = int.Parse(s), server.AlterID.ToString(), 76);
        CreateComboBox("EncryptMethod", "Encrypt Method", VMessGlobal.EncryptMethods, s => server.EncryptMethod = s, server.EncryptMethod);
        CreateComboBox("TransferProtocol",
            "Xray Transport",
            VMessGlobal.TransferProtocols,
            s => server.TransferProtocol = s,
            server.TransferProtocol);
        CreateComboBox("PacketEncoding",
            "Packet Encoding",
            VMessGlobal.PacketEncodings,
            s => server.PacketEncoding = s,
            server.PacketEncoding);

        CreateComboBox("FakeType", "Fake Type", VMessGlobal.FakeTypes, s => server.FakeType = s, server.FakeType);
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

        CreateComboBox("TLSSecure", "TLS Secure", VMessGlobal.TLSSecure, s => server.TLSSecureType = s, server.TLSSecureType);
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

    protected override string TypeName { get; } = "VMess";
}
