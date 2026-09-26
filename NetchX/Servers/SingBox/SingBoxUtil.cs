using NetchX.Controllers;
using NetchX.Interfaces;
using NetchX.Models;

namespace NetchX.Servers;

public abstract class SingBoxServerUtil<TServer> : IServerUtil where TServer : Server, new()
{
    public abstract ushort Priority { get; }

    public abstract string TypeName { get; }

    public abstract string FullName { get; }

    public abstract string ShortName { get; }

    public abstract string[] UriScheme { get; }

    public Type ServerType => typeof(TServer);

    public void Edit(Server server) => new SingBoxServerForm((TServer)server).ShowDialog();

    public void Create() => new SingBoxServerForm(new TServer()).ShowDialog();

    public string GetShareLink(Server server) => SingBoxUri.GetShareLink(server);

    public abstract IEnumerable<Server> ParseUri(string text);

    public virtual IServerController GetController() => new SingBoxController();

    public virtual bool CheckServer(Server server)
    {
        try
        {
            SingBoxConfigUtils.ValidateServer(server);
            return true;
        }
        catch (MessageException e)
        {
            Log.Error(e, "Invalid {Type} server", server.Type);
            return false;
        }
    }
}

public sealed class AnyTlsUtil : SingBoxServerUtil<AnyTlsServer>
{
    public override ushort Priority => 3;
    public override string TypeName => "AnyTLS";
    public override string FullName => "AnyTLS";
    public override string ShortName => "AT";
    public override string[] UriScheme => new[] { "anytls" };

    public override IEnumerable<Server> ParseUri(string text)
    {
        var server = SingBoxUri.Parse<AnyTlsServer>(text, UriScheme);
        var uri = new Uri(text);
        var (password, _) = SingBoxUri.GetUserInfo(uri);
        server.Password = password ?? string.Empty;
        var query = SingBoxUri.GetQuery(uri);
        SingBoxUri.ApplyTls(server, query);
        server.IdleSessionCheckInterval = query["idle_session_check_interval"];
        server.IdleSessionTimeout = query["idle_session_timeout"];
        server.ClientMetadata = query["client_metadata"];
        if (int.TryParse(query["min_idle_session"], out var minIdle))
            server.MinIdleSession = minIdle;
        return new[] { server };
    }
}

public sealed class HysteriaUtil : SingBoxServerUtil<HysteriaServer>
{
    public override ushort Priority => 3;
    public override string TypeName => "Hysteria";
    public override string FullName => "Hysteria";
    public override string ShortName => "HY";
    public override string[] UriScheme => new[] { "hysteria", "hy" };

    public override IEnumerable<Server> ParseUri(string text)
    {
        var server = SingBoxUri.Parse<HysteriaServer>(text, UriScheme);
        var uri = new Uri(text);
        var (auth, _) = SingBoxUri.GetUserInfo(uri);
        var query = SingBoxUri.GetQuery(uri);
        server.Auth = auth ?? query["auth"];
        server.Obfs = query["obfs"];
        server.ServerPorts = query["server_ports"];
        server.HopInterval = query["hop_interval"];
        server.Network = query["network"] ?? server.Network;
        if (int.TryParse(query["upmbps"] ?? query["up_mbps"], out var up))
            server.UpMbps = up;
        if (int.TryParse(query["downmbps"] ?? query["down_mbps"], out var down))
            server.DownMbps = down;
        SingBoxUri.ApplyTls(server, query);
        return new[] { server };
    }
}

public sealed class Hysteria2Util : SingBoxServerUtil<Hysteria2Server>
{
    public override ushort Priority => 3;
    public override string TypeName => "Hysteria2";
    public override string FullName => "Hysteria2";
    public override string ShortName => "HY2";
    public override string[] UriScheme => new[] { "hysteria2", "hy2" };

    public override IEnumerable<Server> ParseUri(string text)
    {
        var server = SingBoxUri.Parse<Hysteria2Server>(text, UriScheme);
        var uri = new Uri(text);
        var (password, _) = SingBoxUri.GetUserInfo(uri);
        var query = SingBoxUri.GetQuery(uri);
        server.Password = password ?? query["password"] ?? string.Empty;
        server.ObfsType = query["obfs"] ?? server.ObfsType;
        server.ObfsPassword = query["obfs-password"] ?? query["obfs_password"];
        server.ServerPorts = query["server_ports"];
        server.HopInterval = query["hop_interval"];
        server.HopIntervalMax = query["hop_interval_max"];
        server.BbrProfile = query["bbr_profile"] ?? server.BbrProfile;
        server.DisableChromeParrot = query["disable_chrome_parrot"] is "1" or "true";
        server.Network = query["network"] ?? server.Network;
        if (int.TryParse(query["upmbps"] ?? query["up_mbps"], out var up))
            server.UpMbps = up;
        if (int.TryParse(query["downmbps"] ?? query["down_mbps"], out var down))
            server.DownMbps = down;
        SingBoxUri.ApplyTls(server, query);
        return new[] { server };
    }
}

public sealed class TuicUtil : SingBoxServerUtil<TuicServer>
{
    public override ushort Priority => 3;
    public override string TypeName => "TUIC";
    public override string FullName => "TUIC";
    public override string ShortName => "TUIC";
    public override string[] UriScheme => new[] { "tuic" };

    public override IEnumerable<Server> ParseUri(string text)
    {
        var server = SingBoxUri.Parse<TuicServer>(text, UriScheme);
        var uri = new Uri(text);
        var (userInfo, password) = SingBoxUri.GetUserInfo(uri);
        var query = SingBoxUri.GetQuery(uri);
        server.UserID = userInfo ?? query["uuid"] ?? string.Empty;
        server.Password = password ?? query["password"];
        server.CongestionControl = query["congestion_control"] ?? server.CongestionControl;
        server.UdpRelayMode = query["udp_relay_mode"] ?? server.UdpRelayMode;
        server.UdpOverStream = query["udp_over_stream"] is "1" or "true";
        server.ZeroRttHandshake = query["zero_rtt"] is "1" or "true";
        server.Heartbeat = query["heartbeat"];
        server.Network = query["network"] ?? server.Network;
        SingBoxUri.ApplyTls(server, query);
        return new[] { server };
    }
}

public sealed class NaiveUtil : SingBoxServerUtil<NaiveServer>
{
    public override ushort Priority => 3;
    public override string TypeName => "Naive";
    public override string FullName => "NaiveProxy";
    public override string ShortName => "NV";
    public override string[] UriScheme => new[] { "naive+https", "naive+quic" };

    public override IEnumerable<Server> ParseUri(string text)
    {
        var server = SingBoxUri.Parse<NaiveServer>(text, UriScheme);
        var uri = new Uri(text);
        var (username, password) = SingBoxUri.GetUserInfo(uri);
        var query = SingBoxUri.GetQuery(uri);
        server.Username = username;
        server.Password = password;
        server.Quic = uri.Scheme.Equals("naive+quic", StringComparison.OrdinalIgnoreCase);
        server.UdpOverTcp = query["uot"] is "1" or "true";
        if (int.TryParse(query["insecure_concurrency"], out var concurrency))
            server.InsecureConcurrency = concurrency;
        SingBoxUri.ApplyTls(server, query);
        return new[] { server };
    }
}

public sealed class ShadowTlsUtil : SingBoxServerUtil<ShadowTlsServer>
{
    public override ushort Priority => 3;
    public override string TypeName => "ShadowTLS";
    public override string FullName => "ShadowTLS";
    public override string ShortName => "ST";
    public override string[] UriScheme => new[] { "shadowtls" };

    public override IEnumerable<Server> ParseUri(string text)
    {
        var server = SingBoxUri.Parse<ShadowTlsServer>(text, UriScheme);
        var uri = new Uri(text);
        var (password, _) = SingBoxUri.GetUserInfo(uri);
        var query = SingBoxUri.GetQuery(uri);
        server.Password = password;
        if (int.TryParse(query["version"], out var version))
            server.Version = version;
        SingBoxUri.ApplyTls(server, query);
        return new[] { server };
    }
}

public sealed class HttpProxyUtil : SingBoxServerUtil<HttpProxyServer>
{
    public override ushort Priority => 3;
    public override string TypeName => "HTTP";
    public override string FullName => "HTTP / HTTPS Proxy";
    public override string ShortName => "HTTP";
    public override string[] UriScheme => new[] { "http", "https" };

    public override IServerController GetController() => new XrayController();

    public override bool CheckServer(Server server)
    {
        var http = (HttpProxyServer)server;
        if (http.UseTls && http.AllowInsecure)
        {
            Log.Error("Current Xray-core no longer supports insecure TLS verification for HTTP CONNECT outbounds.");
            return false;
        }
        if (!string.IsNullOrWhiteSpace(http.Headers))
        {
            try
            {
                using var document = System.Text.Json.JsonDocument.Parse(http.Headers);
                if (document.RootElement.ValueKind != System.Text.Json.JsonValueKind.Object)
                    return false;
            }
            catch (System.Text.Json.JsonException)
            {
                return false;
            }
        }
        return true;
    }

    public override IEnumerable<Server> ParseUri(string text)
    {
        var server = SingBoxUri.Parse<HttpProxyServer>(text, UriScheme);
        var uri = new Uri(text);
        var (username, password) = SingBoxUri.GetUserInfo(uri);
        var query = SingBoxUri.GetQuery(uri);
        server.UseTls = uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase);
        server.Username = username;
        server.Password = password;
        server.Path = query["path"];
        server.Headers = query["headers"];
        SingBoxUri.ApplyTls(server, query);
        return new[] { server };
    }
}
