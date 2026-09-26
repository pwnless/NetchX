using System.Collections.Specialized;
using System.Web;
using NetchX.Models;

namespace NetchX.Servers;

internal static class SingBoxUri
{
    public static string GetShareLink(Server server)
    {
        return server switch
        {
            AnyTlsServer anyTls => Build("anytls", anyTls, anyTls.Password, BuildTlsQuery(anyTls)),
            HysteriaServer hysteria => Build("hysteria", hysteria, hysteria.Auth, Merge(BuildTlsQuery(hysteria),
                ("upmbps", hysteria.UpMbps.ToString()), ("downmbps", hysteria.DownMbps.ToString()), ("obfs", hysteria.Obfs), ("server_ports", hysteria.ServerPorts), ("hop_interval", hysteria.HopInterval), ("network", hysteria.Network))),
            Hysteria2Server hysteria2 => Build("hysteria2", hysteria2, hysteria2.Password, Merge(BuildTlsQuery(hysteria2),
                ("upmbps", hysteria2.UpMbps?.ToString()), ("downmbps", hysteria2.DownMbps?.ToString()), ("obfs", hysteria2.ObfsType == "none" ? null : hysteria2.ObfsType), ("obfs-password", hysteria2.ObfsPassword), ("network", hysteria2.Network))),
            TuicServer tuic => Build("tuic", tuic, tuic.UserID + ":" + (tuic.Password ?? string.Empty), Merge(BuildTlsQuery(tuic),
                ("congestion_control", tuic.CongestionControl), ("udp_relay_mode", tuic.UdpRelayMode), ("udp_over_stream", tuic.UdpOverStream ? "1" : null), ("zero_rtt", tuic.ZeroRttHandshake ? "1" : null), ("heartbeat", tuic.Heartbeat), ("network", tuic.Network))),
            NaiveServer naive => Build(naive.Quic ? "naive+quic" : "naive+https", naive, (naive.Username ?? string.Empty) + ":" + (naive.Password ?? string.Empty), Merge(BuildTlsQuery(naive),
                ("uot", naive.UdpOverTcp ? "1" : null), ("insecure_concurrency", naive.InsecureConcurrency?.ToString()))),
            ShadowTlsServer => Utils.ShareLink.GetNetchXLink(server),
            HttpProxyServer http => Build(http.UseTls ? "https" : "http", http, string.IsNullOrEmpty(http.Username) ? null : http.Username + ":" + (http.Password ?? string.Empty), Merge(BuildTlsQuery(http), ("path", http.Path), ("headers", http.Headers))),
            SSHServer ssh when string.IsNullOrWhiteSpace(ssh.PrivateKey) && string.IsNullOrWhiteSpace(ssh.PublicKey) && string.IsNullOrWhiteSpace(ssh.PrivateKeyPassphrase) && string.IsNullOrWhiteSpace(ssh.HostKeyAlgorithms) && string.IsNullOrWhiteSpace(ssh.ClientVersion) && string.IsNullOrWhiteSpace(ssh.Cipher) && string.IsNullOrWhiteSpace(ssh.Mac) && string.IsNullOrWhiteSpace(ssh.KexAlgorithms)
                => Build("ssh", ssh, ssh.User + (string.IsNullOrWhiteSpace(ssh.Password) ? string.Empty : ":" + ssh.Password), Array.Empty<(string, string?)>()),
            _ => Utils.ShareLink.GetNetchXLink(server)
        };
    }

    public static T Parse<T>(string text, params string[] acceptedSchemes) where T : Server, new()
    {
        var uri = new Uri(text, UriKind.Absolute);
        if (!acceptedSchemes.Contains(uri.Scheme, StringComparer.OrdinalIgnoreCase))
            throw new FormatException();

        var server = new T
        {
            Hostname = uri.Host,
            Port = checked((ushort)uri.Port),
            Remark = Uri.UnescapeDataString(uri.Fragment.TrimStart('#'))
        };
        return server;
    }

    public static (string? User, string? Password) GetUserInfo(Uri uri)
    {
        var userInfo = Uri.UnescapeDataString(uri.UserInfo);
        var separator = userInfo.IndexOf(':');
        return separator < 0
            ? (string.IsNullOrEmpty(userInfo) ? null : userInfo, null)
            : (userInfo[..separator], userInfo[(separator + 1)..]);
    }

    public static NameValueCollection GetQuery(Uri uri) => HttpUtility.ParseQueryString(uri.Query);

    public static void ApplyTls(SingBoxTlsServer server, NameValueCollection query)
    {
        server.ServerName = query["sni"];
        server.AllowInsecure = query["insecure"] is "1" or "true";
        server.ALPN = query["alpn"];
        server.UTLSFingerprint = query["fp"] ?? server.UTLSFingerprint;
        server.ECH = query["ech"];
    }

    private static string Build(string scheme, Server server, string? userInfo, IEnumerable<(string Key, string? Value)> query)
    {
        var authority = server.Hostname.Contains(':') && !server.Hostname.StartsWith('[')
            ? $"[{server.Hostname}]"
            : server.Hostname;
        var credentials = string.IsNullOrEmpty(userInfo) ? string.Empty : Uri.EscapeDataString(userInfo).Replace("%3A", ":") + "@";
        var queryText = string.Join("&", query.Where(item => !string.IsNullOrWhiteSpace(item.Value)).Select(item => $"{Uri.EscapeDataString(item.Key)}={Uri.EscapeDataString(item.Value!)}"));
        return $"{scheme}://{credentials}{authority}:{server.Port}{(queryText.Length == 0 ? string.Empty : "?" + queryText)}#{Uri.EscapeDataString(server.Remark)}";
    }

    private static IEnumerable<(string Key, string? Value)> BuildTlsQuery(SingBoxTlsServer server)
    {
        return new[]
        {
            ("sni", server.ServerName),
            ("insecure", server.AllowInsecure ? "1" : null),
            ("alpn", server.ALPN),
            ("fp", server.UTLSFingerprint),
            ("certificate", server.Certificate),
            ("ech", server.ECH)
        };
    }

    private static IEnumerable<(string Key, string? Value)> Merge(IEnumerable<(string Key, string? Value)> first, params (string Key, string? Value)[] second)
    {
        return first.Concat(second);
    }
}
