using Netch.Models;

#pragma warning disable VSTHRD200

namespace Netch.Servers;

/// <summary>
///     Configuration generator for the bundled SagerNet compatibility runtime.
///     Keep this limited to outbounds that current Xray-core deliberately no
///     longer provides; modern transports and features belong in
///     <see cref="V2rayConfigUtils"/> and run on Xray.
/// </summary>
public static class LegacyV2rayConfigUtils
{
    public static async Task<V2rayConfig> GenerateClientConfigAsync(Server server)
    {
        var config = new V2rayConfig
        {
            inbounds = new object[]
            {
                new
                {
                    port = Global.Settings.Socks5LocalPort,
                    protocol = "socks",
                    listen = Global.Settings.LocalAddress,
                    settings = new
                    {
                        auth = "noauth",
                        udp = true
                    }
                }
            }
        };

        config.outbounds = new[] { await CreateLegacyOutboundAsync(server) };
        return config;
    }

    private static async Task<Outbound> CreateLegacyOutboundAsync(Server server)
    {
        var outbound = new Outbound
        {
            settings = new OutboundConfiguration(),
            mux = new Mux()
        };

        switch (server)
        {
            case ShadowsocksRServer ssr:
                outbound.protocol = "shadowsocks";
                outbound.settings.servers = new[]
                {
                    new ShadowsocksServerItem
                    {
                        address = await server.AutoResolveHostnameAsync(),
                        port = server.Port,
                        method = ssr.EncryptMethod,
                        password = ssr.Password
                    }
                };
                outbound.settings.plugin = "shadowsocksr";
                outbound.settings.pluginArgs = new[]
                {
                    $"--obfs={ssr.OBFS}",
                    $"--obfs-param={ssr.OBFSParam ?? string.Empty}",
                    $"--protocol={ssr.Protocol}",
                    $"--protocol-param={ssr.ProtocolParam ?? string.Empty}"
                };
                break;

            case SSHServer ssh:
                outbound.protocol = "ssh";
                outbound.settings.address = await server.AutoResolveHostnameAsync();
                outbound.settings.port = server.Port;
                outbound.settings.user = ssh.User;
                outbound.settings.password = ssh.Password;
                outbound.settings.privateKey = ssh.PrivateKey;
                outbound.settings.publicKey = ssh.PublicKey;
                break;

            default:
                throw new MessageException("The legacy SagerNet fallback supports only ShadowsocksR and SSH profiles.");
        }

        if (Global.Settings.V2RayConfig.TCPFastOpen)
        {
            outbound.streamSettings = new StreamSettings
            {
                sockopt = new Sockopt
                {
                    tcpFastOpen = true
                }
            };
        }

        return outbound;
    }
}
