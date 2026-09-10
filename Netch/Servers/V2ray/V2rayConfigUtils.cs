using Netch.Models;
using Netch.Utils;

#pragma warning disable VSTHRD200

namespace Netch.Servers;

public static class V2rayConfigUtils
{
    public static async Task<V2rayConfig> GenerateClientConfigAsync(Server server)
    {
        var v2rayConfig = new V2rayConfig
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

        v2rayConfig.outbounds = new[] { await outbound(server) };

        return v2rayConfig;
    }

    private static async Task<Outbound> outbound(Server server)
    {
        var outbound = new Outbound
        {
            settings = new OutboundConfiguration(),
            mux = new Mux()
        };

        switch (server)
        {
            case Socks5Server socks:
            {
                outbound.protocol = "socks";
                outbound.settings.servers = new object[]
                {
                    new
                    {
                        address = await server.AutoResolveHostnameAsync(),
                        port = server.Port,
                        users = socks.Auth()
                            ? new[]
                            {
                                new
                                {
                                    user = socks.Username,
                                    pass = socks.Password,
                                    level = 1
                                }
                            }
                            : null
                    }
                };
                outbound.settings.version = socks.Version;

                outbound.mux.enabled = false;
                outbound.mux.concurrency = -1;
                break;
            }
            case VLESSServer vless:
            {
                var flow = GetVlessFlow(vless);
                outbound.protocol = "vless";
                outbound.settings.vnext = new[]
                {
                    new VnextItem
                    {
                        address = await server.AutoResolveHostnameAsync(),
                        port = server.Port,
                        users = new[]
                        {
                            new User
                            {
                                id = getUUID(vless.UserID),
                                flow = flow,
                                encryption = vless.EncryptMethod
                            }
                        }
                    }
                };

                outbound.settings.packetEncoding = Global.Settings.V2RayConfig.XrayCone ? vless.PacketEncoding : "none";
                outbound.mux.packetEncoding = Global.Settings.V2RayConfig.XrayCone ? vless.PacketEncoding : "none";

                outbound.streamSettings = boundStreamSettings(vless);

                if (!string.IsNullOrEmpty(flow))
                {
                    // Vision controls the underlying TCP flow itself. Keeping
                    // mux.cool off is the compatible and least surprising
                    // default for both TLS and REALITY deployments.
                    outbound.mux.enabled = false;
                    outbound.mux.concurrency = -1;
                }
                else
                {
                    outbound.mux.enabled = vless.UseMux ?? Global.Settings.V2RayConfig.UseMux;
                    outbound.mux.concurrency = vless.UseMux ?? Global.Settings.V2RayConfig.UseMux ? 8 : -1;
                }

                break;
            }
            case VMessServer vmess:
            {
                outbound.protocol = "vmess";
                if (vmess.EncryptMethod == "auto" && vmess.TLSSecureType != "none" && !Global.Settings.V2RayConfig.AllowInsecure)
                {
                    vmess.EncryptMethod = "zero";
                }
                outbound.settings.vnext = new[]
                {
                    new VnextItem
                    {
                        address = await server.AutoResolveHostnameAsync(),
                        port = server.Port,
                        users = new[]
                        {
                            new User
                            {
                                id = getUUID(vmess.UserID),
                                alterId = vmess.AlterID,
                                security = vmess.EncryptMethod
                            }
                        }
                    }
                };

                outbound.settings.packetEncoding = Global.Settings.V2RayConfig.XrayCone ? vmess.PacketEncoding : "none";
                outbound.mux.packetEncoding = Global.Settings.V2RayConfig.XrayCone ? vmess.PacketEncoding : "none";

                outbound.streamSettings = boundStreamSettings(vmess);

                outbound.mux.enabled = vmess.UseMux ?? Global.Settings.V2RayConfig.UseMux;
                outbound.mux.concurrency = vmess.UseMux ?? Global.Settings.V2RayConfig.UseMux ? 8 : -1;
                break;
            }
            case ShadowsocksServer ss:
                outbound.protocol = "shadowsocks";
                outbound.settings.servers = new[]
                {
                    new ShadowsocksServerItem
                    {
                        address = await server.AutoResolveHostnameAsync(),
                        port = server.Port,
                        method = ss.EncryptMethod,
                        password = ss.Password
                    }
                };
                outbound.settings.plugin = ss.Plugin ?? "";
                outbound.settings.pluginOpts = ss.PluginOption ?? "";
                
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
                break;
            case ShadowsocksRServer:
                throw new MessageException("ShadowsocksR is not supported by the bundled Xray-core runtime. Use a standard Shadowsocks profile or install a dedicated SSR controller.");
             case TrojanServer trojan:
                outbound.protocol = "trojan";
                outbound.settings.servers = new[]
                {
                    new ShadowsocksServerItem // I'm not serious
                    {
                        address = await server.AutoResolveHostnameAsync(),
                        port = server.Port,
                        method = "",
                        password = trojan.Password
                    }
                };

                outbound.streamSettings = new StreamSettings
                {
                    method = "raw",
                    security = NormalizeSecurity(trojan.TLSSecureType, false)
                };
                if (outbound.streamSettings.security == "tls")
                    outbound.streamSettings.tlsSettings = BuildTlsSettings(trojan.Host);

                if (Global.Settings.V2RayConfig.TCPFastOpen)
                {
                    outbound.streamSettings.sockopt = new Sockopt
                    {
                        tcpFastOpen = true
                    };
                }
                break;
            case WireGuardServer wg:
                outbound.protocol = "wireguard";
                outbound.settings.address = await server.AutoResolveHostnameAsync();
                outbound.settings.port = server.Port;
                outbound.settings.localAddresses = wg.LocalAddresses.SplitOrDefault();
                outbound.settings.peerPublicKey = wg.PeerPublicKey;
                outbound.settings.privateKey = wg.PrivateKey;
                outbound.settings.preSharedKey = wg.PreSharedKey;
                outbound.settings.mtu = wg.MTU;

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
                break;

            case SSHServer:
                throw new MessageException("SSH is not supported by the bundled Xray-core runtime. Use a dedicated SSH controller for this profile.");
        }

        return outbound;
    }

    private static StreamSettings boundStreamSettings(VMessServer server)
    {
        var method = NormalizeTransport(server.TransferProtocol);
        var isVless = server is VLESSServer;
        var security = NormalizeSecurity(server.TLSSecureType, isVless);

        if (server is VLESSServer vless && !string.IsNullOrEmpty(GetVlessFlow(vless)))
        {
            if (method != "raw" || security is not ("tls" or "reality"))
                throw new MessageException("XTLS Vision requires VLESS over raw transport with TLS or REALITY security in Xray-core.");
        }

        var streamSettings = new StreamSettings
        {
            method = method,
            security = security
        };

        if (security == "tls")
        {
            streamSettings.tlsSettings = BuildTlsSettings(
                server.ServerName.ValueOrDefault() ?? server.Host.SplitOrDefault()?[0],
                server.RealityFingerprint);
        }
        else if (security == "reality")
        {
            if (method is not ("raw" or "xhttp" or "grpc"))
                throw new MessageException("REALITY only supports raw, xhttp, or grpc transport in Xray-core.");

            if (string.IsNullOrWhiteSpace(server.RealityPublicKey))
                throw new MessageException("REALITY requires the server public key.");

            streamSettings.realitySettings = new RealitySettings
            {
                serverName = server.ServerName.ValueOrDefault() ?? server.Host.SplitOrDefault()?[0] ?? string.Empty,
                fingerprint = string.IsNullOrWhiteSpace(server.RealityFingerprint) ? "chrome" : server.RealityFingerprint,
                password = server.RealityPublicKey,
                shortId = server.RealityShortId,
                mldsa65Verify = server.RealityMldsa65Verify,
                spiderX = server.RealitySpiderX
            };
        }

        switch (method)
        {
            case "raw":
                streamSettings.rawSettings = new TcpSettings
                {
                    header = new
                    {
                        type = server.FakeType is "none" or "http" ? server.FakeType : "none",
                        request = server.FakeType switch
                        {
                            "none" => null,
                            "http" => new
                            {
                                path = server.Path.SplitOrDefault(),
                                headers = new
                                {
                                    Host = server.Host.SplitOrDefault()
                                }
                            },
                            _ => throw new MessageException($"Invalid tcp type {server.FakeType}")
                        }
                    }
                };

                break;
            case "websocket":

                streamSettings.wsSettings = new WsSettings
                {
                    path = server.Path.ValueOrDefault(),
                    headers = new
                    {
                        Host = server.Host.ValueOrDefault()
                    }
                };

                break;
            case "mkcp":

                streamSettings.kcpSettings = new KcpSettings
                {
                    mtu = Global.Settings.V2RayConfig.KcpConfig.mtu,
                    tti = Global.Settings.V2RayConfig.KcpConfig.tti,
                    uplinkCapacity = Global.Settings.V2RayConfig.KcpConfig.uplinkCapacity,
                    downlinkCapacity = Global.Settings.V2RayConfig.KcpConfig.downlinkCapacity,
                    congestion = Global.Settings.V2RayConfig.KcpConfig.congestion,
                    readBufferSize = Global.Settings.V2RayConfig.KcpConfig.readBufferSize,
                    writeBufferSize = Global.Settings.V2RayConfig.KcpConfig.writeBufferSize,
                    header = new
                    {
                        type = server.FakeType
                    },
                    seed = server.Path.ValueOrDefault()
                };

                break;
            case "xhttp":
                streamSettings.xhttpSettings = new XHttpSettings
                {
                    host = server.Host.ValueOrDefault() ?? string.Empty,
                    path = server.Path.ValueOrDefault() ?? "/",
                    mode = string.IsNullOrWhiteSpace(server.XHttpMode) ? "auto" : server.XHttpMode
                };

                break;
            case "httpupgrade":
                streamSettings.httpupgradeSettings = new HttpUpgradeSettings
                {
                    host = server.Host.ValueOrDefault() ?? string.Empty,
                    path = server.Path.ValueOrDefault() ?? "/"
                };

                break;
            case "grpc":

                streamSettings.grpcSettings = new GrpcSettings
                {
                    authority = server.Host.ValueOrDefault() ?? string.Empty,
                    serviceName = server.Path,
                    multiMode = server.FakeType == "multi"
                };

                break;
            case "hysteria":
                if (security != "tls")
                    throw new MessageException("Hysteria transport requires TLS security in Xray-core.");

                streamSettings.hysteriaSettings = new HysteriaSettings
                {
                    auth = server.HysteriaAuth
                };
                break;
        }

        if (Global.Settings.V2RayConfig.TCPFastOpen)
        {
            streamSettings.sockopt = new Sockopt
            {
                tcpFastOpen = true
            };
        }

        return streamSettings;
    }

    private static TlsSettings BuildTlsSettings(string? serverName, string? fingerprint = null)
    {
        return new TlsSettings
        {
            allowInsecure = Global.Settings.V2RayConfig.AllowInsecure,
            serverName = serverName ?? string.Empty,
            fingerprint = string.IsNullOrWhiteSpace(fingerprint) ? "chrome" : fingerprint
        };
    }

    private static string GetVlessFlow(VLESSServer server)
    {
        var flow = !string.IsNullOrEmpty(server.Flow)
            ? server.Flow
            // Xray 26 removed the standalone XTLS security layer. This
            // preserves the intent of a persisted legacy Netch profile using
            // Vision.
            : server.TLSSecureType == "xtls" ? "xtls-rprx-vision" : string.Empty;

        if (!VLESSGlobal.Flows.Contains(flow))
            throw new MessageException($"Unsupported Xray-core VLESS flow \"{flow}\".");

        return flow;
    }

    private static string NormalizeSecurity(string security, bool supportsVision)
    {
        return security switch
        {
            "" or "none" => "none",
            "tls" => "tls",
            "reality" => "reality",
            "xtls" when supportsVision => "tls",
            "xtls" => throw new MessageException("Xray-core removed legacy XTLS. Use TLS or REALITY, and XTLS Vision for VLESS."),
            _ => throw new MessageException($"Unsupported Xray-core transport security \"{security}\".")
        };
    }

    private static string NormalizeTransport(string transport)
    {
        return transport switch
        {
            "raw" or "tcp" => "raw",
            "xhttp" or "splithttp" => "xhttp",
            "mkcp" or "kcp" => "mkcp",
            "websocket" or "ws" => "websocket",
            "grpc" => "grpc",
            "httpupgrade" => "httpupgrade",
            "hysteria" => "hysteria",
            "h2" or "h3" or "http" => throw new MessageException("Xray-core removed HTTP/2 transport. Change this profile to XHTTP."),
            "quic" => throw new MessageException("Xray-core removed the legacy QUIC transport. Change this profile to XHTTP stream-one or Hysteria."),
            _ => throw new MessageException($"Unsupported Xray-core transport method \"{transport}\".")
        };
    }

    public static string getUUID(string uuid)
    {
        if (uuid.Length == 36 || uuid.Length == 32)
        {
            return uuid;
        }
        return uuid.GenerateUUIDv5();
    }
}
