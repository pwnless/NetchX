using NetchX.Forms;
using NetchX.Models;

namespace NetchX.Servers;

[Fody.ConfigureAwait(true)]
internal sealed class SingBoxServerForm : ServerForm
{
    private readonly Server _server;

    public SingBoxServerForm(Server server)
    {
        _server = server;
        Server = server;

        switch (server)
        {
            case AnyTlsServer anyTls:
                CreateTextBox("Password", "Password", _ => true, value => anyTls.Password = value, anyTls.Password);
                CreateTextBox("IdleSessionCheckInterval", "Idle Check Interval", _ => true, value => anyTls.IdleSessionCheckInterval = value, anyTls.IdleSessionCheckInterval ?? string.Empty);
                CreateTextBox("IdleSessionTimeout", "Idle Session Timeout", _ => true, value => anyTls.IdleSessionTimeout = value, anyTls.IdleSessionTimeout ?? string.Empty);
                CreateTextBox("MinIdleSession", "Min Idle Sessions", value => string.IsNullOrWhiteSpace(value) || int.TryParse(value, out _), value => anyTls.MinIdleSession = string.IsNullOrWhiteSpace(value) ? null : int.Parse(value), anyTls.MinIdleSession?.ToString() ?? string.Empty);
                CreateTextBox("ClientMetadata", "Client Metadata", _ => true, value => anyTls.ClientMetadata = value, anyTls.ClientMetadata ?? string.Empty);
                AddTls(anyTls, supportsInsecure: true, supportsUtls: true, supportsEch: true);
                break;
            case HysteriaServer hysteria:
                CreateTextBox("UpMbps", "Up Mbps", value => int.TryParse(value, out var number) && number > 0, value => hysteria.UpMbps = int.Parse(value), hysteria.UpMbps.ToString());
                CreateTextBox("DownMbps", "Down Mbps", value => int.TryParse(value, out var number) && number > 0, value => hysteria.DownMbps = int.Parse(value), hysteria.DownMbps.ToString());
                CreateTextBox("Auth", "Authentication", _ => true, value => hysteria.Auth = value, hysteria.Auth ?? string.Empty);
                CreateTextBox("Obfs", "Obfuscation", _ => true, value => hysteria.Obfs = value, hysteria.Obfs ?? string.Empty);
                CreateTextBox("ServerPorts", "Server Port Range", _ => true, value => hysteria.ServerPorts = value, hysteria.ServerPorts ?? string.Empty);
                CreateTextBox("HopInterval", "Hop Interval", _ => true, value => hysteria.HopInterval = value, hysteria.HopInterval ?? string.Empty);
                CreateComboBox("Network", "Network", new List<string> { "tcp,udp", "tcp", "udp" }, value => hysteria.Network = value, hysteria.Network);
                AddTls(hysteria, supportsInsecure: true, supportsUtls: false, supportsEch: false);
                break;
            case Hysteria2Server hysteria2:
                CreateTextBox("Password", "Password", _ => true, value => hysteria2.Password = value, hysteria2.Password);
                CreateTextBox("UpMbps", "Up Mbps", value => string.IsNullOrWhiteSpace(value) || int.TryParse(value, out _), value => hysteria2.UpMbps = string.IsNullOrWhiteSpace(value) ? null : int.Parse(value), hysteria2.UpMbps?.ToString() ?? string.Empty);
                CreateTextBox("DownMbps", "Down Mbps", value => string.IsNullOrWhiteSpace(value) || int.TryParse(value, out _), value => hysteria2.DownMbps = string.IsNullOrWhiteSpace(value) ? null : int.Parse(value), hysteria2.DownMbps?.ToString() ?? string.Empty);
                CreateComboBox("ObfsType", "Obfuscation", new List<string> { "none", "salamander", "gecko" }, value => hysteria2.ObfsType = value, hysteria2.ObfsType);
                CreateTextBox("ObfsPassword", "Obfuscation Password", _ => true, value => hysteria2.ObfsPassword = value, hysteria2.ObfsPassword ?? string.Empty);
                CreateTextBox("ServerPorts", "Server Port Range", _ => true, value => hysteria2.ServerPorts = value, hysteria2.ServerPorts ?? string.Empty);
                CreateTextBox("HopInterval", "Hop Interval", _ => true, value => hysteria2.HopInterval = value, hysteria2.HopInterval ?? string.Empty);
                CreateTextBox("HopIntervalMax", "Max Hop Interval", _ => true, value => hysteria2.HopIntervalMax = value, hysteria2.HopIntervalMax ?? string.Empty);
                CreateComboBox("BbrProfile", "BBR Profile", new List<string> { "standard", "conservative", "aggressive" }, value => hysteria2.BbrProfile = value, hysteria2.BbrProfile);
                CreateCheckBox("DisableChromeParrot", "Disable Chrome Parrot", value => hysteria2.DisableChromeParrot = value, hysteria2.DisableChromeParrot);
                CreateComboBox("Network", "Network", new List<string> { "tcp,udp", "tcp", "udp" }, value => hysteria2.Network = value, hysteria2.Network);
                AddTls(hysteria2, supportsInsecure: true, supportsUtls: false, supportsEch: false);
                break;
            case TuicServer tuic:
                CreateTextBox("UserID", "UUID", value => Guid.TryParse(value, out _), value => tuic.UserID = value, tuic.UserID);
                CreateTextBox("Password", "Password", _ => true, value => tuic.Password = value, tuic.Password ?? string.Empty);
                CreateComboBox("CongestionControl", "Congestion Control", new List<string> { "cubic", "new_reno", "bbr" }, value => tuic.CongestionControl = value, tuic.CongestionControl);
                CreateComboBox("UdpRelayMode", "UDP Relay Mode", new List<string> { "native", "quic" }, value => tuic.UdpRelayMode = value, tuic.UdpRelayMode);
                CreateCheckBox("UdpOverStream", "UDP Over Stream", value => tuic.UdpOverStream = value, tuic.UdpOverStream);
                CreateCheckBox("ZeroRttHandshake", "Zero RTT Handshake", value => tuic.ZeroRttHandshake = value, tuic.ZeroRttHandshake);
                CreateTextBox("Heartbeat", "Heartbeat", _ => true, value => tuic.Heartbeat = value, tuic.Heartbeat ?? string.Empty);
                CreateComboBox("Network", "Network", new List<string> { "tcp,udp", "tcp", "udp" }, value => tuic.Network = value, tuic.Network);
                AddTls(tuic, supportsInsecure: true, supportsUtls: false, supportsEch: false);
                break;
            case NaiveServer naive:
                CreateTextBox("Username", "User", _ => true, value => naive.Username = value, naive.Username ?? string.Empty);
                CreateTextBox("Password", "Password", _ => true, value => naive.Password = value, naive.Password ?? string.Empty);
                CreateTextBox("InsecureConcurrency", "Insecure Concurrency", value => string.IsNullOrWhiteSpace(value) || int.TryParse(value, out _), value => naive.InsecureConcurrency = string.IsNullOrWhiteSpace(value) ? null : int.Parse(value), naive.InsecureConcurrency?.ToString() ?? string.Empty);
                CreateTextBox("ExtraHeaders", "Extra Headers JSON", _ => true, value => naive.ExtraHeaders = value, naive.ExtraHeaders ?? string.Empty);
                CreateCheckBox("UdpOverTcp", "UDP Over TCP", value => naive.UdpOverTcp = value, naive.UdpOverTcp);
                CreateCheckBox("Quic", "Use QUIC", value => naive.Quic = value, naive.Quic);
                CreateComboBox("QuicCongestionControl", "QUIC Congestion", new List<string> { "", "cubic", "bbr", "bbr2", "reno" }, value => naive.QuicCongestionControl = value, naive.QuicCongestionControl ?? string.Empty);
                CreateTextBox("StreamReceiveWindow", "Stream Receive Window", _ => true, value => naive.StreamReceiveWindow = value, naive.StreamReceiveWindow ?? string.Empty);
                CreateTextBox("QuicSessionReceiveWindow", "QUIC Session Window", _ => true, value => naive.QuicSessionReceiveWindow = value, naive.QuicSessionReceiveWindow ?? string.Empty);
                AddTls(naive, supportsInsecure: false, supportsUtls: false, supportsEch: true);
                break;
            case ShadowTlsServer shadowTls:
                CreateComboBox("Version", "Version", new List<string> { "1", "2", "3" }, value => shadowTls.Version = int.Parse(value), shadowTls.Version.ToString());
                CreateTextBox("Password", "ShadowTLS Password", _ => true, value => shadowTls.Password = value, shadowTls.Password ?? string.Empty);
                CreateComboBox("EncryptMethod", "Inner SS Method", SingBoxGlobal.ShadowsocksMethods, value => shadowTls.EncryptMethod = value, shadowTls.EncryptMethod);
                CreateTextBox("ShadowsocksPassword", "Inner SS Password", _ => true, value => shadowTls.ShadowsocksPassword = value, shadowTls.ShadowsocksPassword);
                AddTls(shadowTls, supportsInsecure: true, supportsUtls: true, supportsEch: true);
                break;
            case HttpProxyServer http:
                CreateCheckBox("UseTls", "Use HTTPS", value => http.UseTls = value, http.UseTls);
                CreateTextBox("Username", "User", _ => true, value => http.Username = value, http.Username ?? string.Empty);
                CreateTextBox("Password", "Password", _ => true, value => http.Password = value, http.Password ?? string.Empty);
                CreateTextBox("Path", "CONNECT Path", _ => true, value => http.Path = value, http.Path ?? string.Empty);
                CreateTextBox("Headers", "Headers JSON", _ => true, value => http.Headers = value, http.Headers ?? string.Empty);
                AddTls(http, supportsInsecure: false, supportsUtls: true, supportsEch: false, supportsCertificate: false, supportsAlpn: false);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(server));
        }
    }

    protected override string TypeName => _server.Type;

    private void AddTls(SingBoxTlsServer server, bool supportsInsecure, bool supportsUtls, bool supportsEch, bool supportsCertificate = true, bool supportsAlpn = true)
    {
        CreateTextBox("ServerName", "TLS Server Name", _ => true, value => server.ServerName = value, server.ServerName ?? string.Empty);
        if (supportsInsecure)
            CreateCheckBox("AllowInsecure", "Allow Insecure TLS", value => server.AllowInsecure = value, server.AllowInsecure);
        if (supportsCertificate)
            CreateTextBox("Certificate", "TLS Certificate PEM", _ => true, value => server.Certificate = value, server.Certificate ?? string.Empty);
        if (supportsAlpn && server is not NaiveServer)
            CreateTextBox("ALPN", "TLS ALPN", _ => true, value => server.ALPN = value, server.ALPN ?? string.Empty);
        if (supportsUtls)
            CreateComboBox("UTLSFingerprint", "uTLS Fingerprint", new List<string> { "", "chrome", "chrome_psk", "chrome_psk_shuffle", "chrome_padding_psk_shuffle", "chrome_pq", "chrome_pq_psk", "firefox", "edge", "safari", "360", "qq", "ios", "android", "random", "randomized" }, value => server.UTLSFingerprint = value, server.UTLSFingerprint ?? string.Empty);
        if (supportsEch)
            CreateTextBox("ECH", "ECH Config", _ => true, value => server.ECH = value, server.ECH ?? string.Empty);
    }
}
