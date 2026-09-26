using System.Text.Json;
using System.Text.Json.Nodes;
using NetchX.Models;
using NetchX.Utils;

namespace NetchX.Servers;

/// <summary>
///     Builds the small sing-box client configuration NetchX needs: a local
///     SOCKS5 listener and one explicitly selected outbound.
/// </summary>
public static class SingBoxConfigUtils
{
    public const string LocalInboundTag = "netchx-socks";
    public const string ProxyOutboundTag = "netchx-proxy";

    public static async Task<object> GenerateClientConfigAsync(Server server, string localAddress, ushort localPort)
    {
        ValidateServer(server);
        var serverAddress = await server.AutoResolveHostnameAsync();
        var outbound = BuildOutbound(server, serverAddress);
        var outbounds = new List<Dictionary<string, object?>> { outbound };
        if (outbound.Remove("_additional_outbound", out var additional) && additional is Dictionary<string, object?> additionalOutbound)
            outbounds.Add(additionalOutbound);

        return new Dictionary<string, object?>
        {
            ["log"] = new Dictionary<string, object?>
            {
                ["level"] = "info",
                ["timestamp"] = true
            },
            ["inbounds"] = new object[]
            {
                new Dictionary<string, object?>
                {
                    ["type"] = "socks",
                    ["tag"] = LocalInboundTag,
                    ["listen"] = localAddress,
                    ["listen_port"] = localPort
                }
            },
            ["outbounds"] = outbounds,
            ["route"] = new Dictionary<string, object?>
            {
                ["final"] = ProxyOutboundTag
            }
        };
    }

    public static void ValidateServer(Server server)
    {
        switch (server)
        {
            case SSHServer ssh when string.IsNullOrWhiteSpace(ssh.User):
                throw new MessageException("SSH requires a user name.");
            case SSHServer ssh when string.IsNullOrWhiteSpace(ssh.Password) && string.IsNullOrWhiteSpace(ssh.PrivateKey):
                throw new MessageException("SSH requires a password or private key.");
            case AnyTlsServer anyTls when string.IsNullOrWhiteSpace(anyTls.Password):
                throw new MessageException("AnyTLS requires a password.");
            case HysteriaServer hysteria when hysteria.UpMbps <= 0 || hysteria.DownMbps <= 0:
                throw new MessageException("Hysteria requires positive upload and download bandwidth.");
            case Hysteria2Server hysteria2 when string.IsNullOrWhiteSpace(hysteria2.Password):
                throw new MessageException("Hysteria2 requires a password.");
            case Hysteria2Server hysteria2 when hysteria2.ObfsType is not ("none" or "salamander" or "gecko"):
                throw new MessageException("Hysteria2 obfuscation must be none, salamander, or gecko.");
            case Hysteria2Server hysteria2 when hysteria2.ObfsType != "none" && string.IsNullOrWhiteSpace(hysteria2.ObfsPassword):
                throw new MessageException("Hysteria2 obfuscation requires a password.");
            case TuicServer tuic when !Guid.TryParse(tuic.UserID, out _):
                throw new MessageException("TUIC requires a valid UUID.");
            case ShadowTlsServer shadowTls when shadowTls.Version is < 1 or > 3:
                throw new MessageException("ShadowTLS version must be 1, 2, or 3.");
            case ShadowTlsServer shadowTls when shadowTls.Version > 1 && string.IsNullOrWhiteSpace(shadowTls.Password):
                throw new MessageException("ShadowTLS v2 and v3 require a password.");
            case ShadowTlsServer shadowTls when string.IsNullOrWhiteSpace(shadowTls.ShadowsocksPassword) || !SingBoxGlobal.ShadowsocksMethods.Contains(shadowTls.EncryptMethod):
                throw new MessageException("ShadowTLS requires a supported Shadowsocks method and password for its inner proxy.");
            case NaiveServer naive when string.IsNullOrWhiteSpace(naive.Username) || string.IsNullOrWhiteSpace(naive.Password):
                throw new MessageException("Naive requires a user name and password.");
            case NaiveServer naive when naive.AllowInsecure:
                throw new MessageException("Naive does not support insecure TLS. Supply the server certificate instead.");
        }

        if (string.IsNullOrWhiteSpace(server.Hostname) || server.Port == 0)
            throw new MessageException("Server address and port are required.");
    }

    private static Dictionary<string, object?> BuildOutbound(Server server, string serverAddress)
    {
        return server switch
        {
            SSHServer ssh => BuildSsh(ssh, serverAddress),
            AnyTlsServer anyTls => BuildAnyTls(anyTls, serverAddress),
            HysteriaServer hysteria => BuildHysteria(hysteria, serverAddress),
            Hysteria2Server hysteria2 => BuildHysteria2(hysteria2, serverAddress),
            TuicServer tuic => BuildTuic(tuic, serverAddress),
            NaiveServer naive => BuildNaive(naive, serverAddress),
            ShadowTlsServer shadowTls => BuildShadowTls(shadowTls, serverAddress),
            _ => throw new MessageException($"{server.Type} is not supported by the bundled sing-box runtime.")
        };
    }

    private static Dictionary<string, object?> BuildSsh(SSHServer server, string address)
    {
        var outbound = BaseOutbound("ssh", server, address);
        Add(outbound, "user", server.User);
        Add(outbound, "password", server.Password);
        Add(outbound, "private_key", server.PrivateKey);
        Add(outbound, "private_key_passphrase", server.PrivateKeyPassphrase);
        Add(outbound, "host_key", server.PublicKey);
        var hostKeyAlgorithms = server.HostKeyAlgorithms;
        if (string.IsNullOrWhiteSpace(hostKeyAlgorithms) && !string.IsNullOrWhiteSpace(server.PublicKey))
            hostKeyAlgorithms = server.PublicKey.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).FirstOrDefault();
        AddStringList(outbound, "host_key_algorithms", hostKeyAlgorithms);
        Add(outbound, "client_version", server.ClientVersion);
        AddStringList(outbound, "cipher", server.Cipher);
        AddStringList(outbound, "mac", server.Mac);
        AddStringList(outbound, "kex_algorithm", server.KexAlgorithms);
        return outbound;
    }

    private static Dictionary<string, object?> BuildAnyTls(AnyTlsServer server, string address)
    {
        var outbound = BaseOutbound("anytls", server, address);
        Add(outbound, "password", server.Password);
        Add(outbound, "idle_session_check_interval", server.IdleSessionCheckInterval);
        Add(outbound, "idle_session_timeout", server.IdleSessionTimeout);
        if (server.MinIdleSession is not null)
            outbound["min_idle_session"] = server.MinIdleSession;
        Add(outbound, "client_metadata", server.ClientMetadata);
        outbound["tls"] = BuildTls(server);
        return outbound;
    }

    private static Dictionary<string, object?> BuildHysteria(HysteriaServer server, string address)
    {
        var outbound = BaseOutbound("hysteria", server, address);
        outbound["up_mbps"] = server.UpMbps;
        outbound["down_mbps"] = server.DownMbps;
        Add(outbound, "obfs", server.Obfs);
        Add(outbound, "auth_str", server.Auth);
        var ports = Split(server.ServerPorts);
        if (ports.Length > 0)
        {
            outbound.Remove("server_port");
            outbound["server_ports"] = ports;
        }
        Add(outbound, "hop_interval", server.HopInterval);
        outbound["network"] = ParseNetwork(server.Network);
        outbound["tls"] = BuildTls(server, supportsUtls: false, supportsEch: false);
        return outbound;
    }

    private static Dictionary<string, object?> BuildHysteria2(Hysteria2Server server, string address)
    {
        var outbound = BaseOutbound("hysteria2", server, address);
        Add(outbound, "password", server.Password);
        if (server.UpMbps is > 0)
            outbound["up_mbps"] = server.UpMbps;
        if (server.DownMbps is > 0)
            outbound["down_mbps"] = server.DownMbps;
        var ports = Split(server.ServerPorts);
        if (ports.Length > 0)
        {
            outbound.Remove("server_port");
            outbound["server_ports"] = ports;
        }
        Add(outbound, "hop_interval", server.HopInterval);
        Add(outbound, "hop_interval_max", server.HopIntervalMax);
        if (server.ObfsType != "none")
        {
            outbound["obfs"] = new Dictionary<string, object?>
            {
                ["type"] = server.ObfsType,
                ["password"] = server.ObfsPassword
            };
        }
        if (!string.IsNullOrWhiteSpace(server.BbrProfile))
            outbound["bbr_profile"] = server.BbrProfile;
        if (server.DisableChromeParrot)
            outbound["disable_chrome_parrot"] = true;
        outbound["network"] = ParseNetwork(server.Network);
        outbound["tls"] = BuildTls(server, supportsUtls: false, supportsEch: false);
        return outbound;
    }

    private static Dictionary<string, object?> BuildTuic(TuicServer server, string address)
    {
        var outbound = BaseOutbound("tuic", server, address);
        outbound["uuid"] = server.UserID;
        Add(outbound, "password", server.Password);
        Add(outbound, "congestion_control", server.CongestionControl);
        if (server.UdpOverStream)
            outbound["udp_over_stream"] = true;
        else
            Add(outbound, "udp_relay_mode", server.UdpRelayMode);
        if (server.ZeroRttHandshake)
            outbound["zero_rtt_handshake"] = true;
        Add(outbound, "heartbeat", server.Heartbeat);
        outbound["network"] = ParseNetwork(server.Network);
        outbound["tls"] = BuildTls(server, supportsUtls: false, supportsEch: false);
        return outbound;
    }

    private static Dictionary<string, object?> BuildNaive(NaiveServer server, string address)
    {
        var outbound = BaseOutbound("naive", server, address);
        Add(outbound, "username", server.Username);
        Add(outbound, "password", server.Password);
        if (server.InsecureConcurrency is > 0)
            outbound["insecure_concurrency"] = server.InsecureConcurrency;
        if (server.UdpOverTcp)
            outbound["udp_over_tcp"] = true;
        if (server.Quic)
            outbound["quic"] = true;
        Add(outbound, "quic_congestion_control", server.QuicCongestionControl);
        Add(outbound, "stream_receive_window", server.StreamReceiveWindow);
        Add(outbound, "quic_session_receive_window", server.QuicSessionReceiveWindow);
        if (!string.IsNullOrWhiteSpace(server.ExtraHeaders))
            outbound["extra_headers"] = ParseJsonObject(server.ExtraHeaders, "Naive extra headers");
        outbound["tls"] = BuildTls(server, supportsInsecure: false, supportsUtls: false, supportsEch: true, naiveOnly: true);
        return outbound;
    }

    private static Dictionary<string, object?> BuildShadowTls(ShadowTlsServer server, string address)
    {
        var shadowsocks = new Dictionary<string, object?>
        {
            ["type"] = "shadowsocks",
            ["tag"] = ProxyOutboundTag,
            ["method"] = server.EncryptMethod,
            ["password"] = server.ShadowsocksPassword,
            ["detour"] = "netchx-shadowtls"
        };
        var shadowTls = BaseOutbound("shadowtls", server, address);
        shadowTls["tag"] = "netchx-shadowtls";
        shadowTls["version"] = server.Version;
        if (server.Version > 1)
            Add(shadowTls, "password", server.Password);
        shadowTls["tls"] = BuildTls(server);

        // A ShadowTLS connection is only a camouflage transport. It carries a
        // Shadowsocks stream which supplies the destination framing.
        shadowsocks["_additional_outbound"] = shadowTls;
        return shadowsocks;
    }

    private static Dictionary<string, object?> BaseOutbound(string type, Server server, string address)
    {
        return new Dictionary<string, object?>
        {
            ["type"] = type,
            ["tag"] = ProxyOutboundTag,
            ["server"] = address,
            ["server_port"] = server.Port
        };
    }

    internal static Dictionary<string, object?> BuildTls(SingBoxTlsServer server, bool supportsInsecure = true, bool supportsUtls = true, bool supportsEch = true, bool naiveOnly = false)
    {
        var tls = new Dictionary<string, object?>
        {
            ["enabled"] = true,
            ["server_name"] = string.IsNullOrWhiteSpace(server.ServerName) ? server.Hostname : server.ServerName
        };
        if (supportsInsecure)
            tls["insecure"] = server.AllowInsecure;
        if (!string.IsNullOrWhiteSpace(server.Certificate))
            tls["certificate"] = server.Certificate;

        var alpn = Split(server.ALPN);
        if (alpn.Length > 0 && !naiveOnly)
            tls["alpn"] = alpn;
        if (supportsUtls && !naiveOnly && !string.IsNullOrWhiteSpace(server.UTLSFingerprint))
        {
            tls["utls"] = new Dictionary<string, object?>
            {
                ["enabled"] = true,
                ["fingerprint"] = server.UTLSFingerprint
            };
        }
        if (supportsEch && !string.IsNullOrWhiteSpace(server.ECH))
        {
            tls["ech"] = new Dictionary<string, object?>
            {
                ["enabled"] = true,
                ["config"] = server.ECH
            };
        }

        return tls;
    }

    internal static string[] ParseNetwork(string value)
    {
        var network = Split(value).Where(item => item is "tcp" or "udp").Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        return network.Length == 0 ? new[] { "tcp", "udp" } : network;
    }

    internal static string[] Split(string? value)
    {
        return (value ?? string.Empty).Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    private static Dictionary<string, string> ParseJsonObject(string json, string field)
    {
        try
        {
            var node = JsonNode.Parse(json) as JsonObject;
            if (node is null)
                throw new JsonException();

            var result = new Dictionary<string, string>();
            foreach (var property in node)
            {
                if (property.Value is null)
                    continue;
                result[property.Key] = property.Value.GetValue<string>();
            }
            return result;
        }
        catch (Exception e) when (e is JsonException or InvalidOperationException)
        {
            throw new MessageException($"{field} must be a JSON object containing string values.");
        }
    }

    private static void Add(Dictionary<string, object?> target, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
            target[key] = value;
    }

    private static void AddStringList(Dictionary<string, object?> target, string key, string? value)
    {
        var list = Split(value);
        if (list.Length > 0)
            target[key] = list;
    }
}
