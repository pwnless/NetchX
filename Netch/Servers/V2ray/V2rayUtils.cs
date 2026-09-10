using System.Text.RegularExpressions;
using System.Web;
using Netch.Models;
using Netch.Utils;

namespace Netch.Servers;

public static class V2rayUtils
{
    public static IEnumerable<Server> ParseVUri(string text)
    {
        var scheme = ShareLink.GetUriScheme(text).ToLower();
        var server = scheme switch { "vmess" => new VMessServer(), "vless" => new VLESSServer(), _ => throw new ArgumentOutOfRangeException() };
        if (text.Contains("#"))
        {
            server.Remark = Uri.UnescapeDataString(text.Split('#')[1]);
            text = text.Split('#')[0];
        }

        if (text.Contains("?"))
        {
            var parameter = HttpUtility.ParseQueryString(text.Split('?')[1]);
            text = text.Substring(0, text.IndexOf("?", StringComparison.Ordinal));
            server.TransferProtocol = parameter.Get("type") ?? "tcp";
            server.PacketEncoding = parameter.Get("packetEncoding") ?? "xudp";
            server.EncryptMethod = parameter.Get("encryption") ?? scheme switch { "vless" => "none", _ => "auto" };
            switch (server.TransferProtocol)
            {
                case "raw":
                case "tcp":
                    break;
                case "xhttp":
                case "splithttp":
                    server.Path = Uri.UnescapeDataString(parameter.Get("path") ?? "/");
                    server.Host = Uri.UnescapeDataString(parameter.Get("host") ?? "");
                    server.XHttpMode = parameter.Get("mode") ?? "auto";
                    break;
                case "kcp":
                case "mkcp":
                    server.FakeType = parameter.Get("headerType") ?? "none";
                    server.Path = Uri.UnescapeDataString(parameter.Get("seed") ?? "");
                    break;
                case "ws":
                case "websocket":
                    server.Path = Uri.UnescapeDataString(parameter.Get("path") ?? "/");
                    server.Host = Uri.UnescapeDataString(parameter.Get("host") ?? "");
                    break;
                case "h2":
                    server.Path = Uri.UnescapeDataString(parameter.Get("path") ?? "/");
                    server.Host = Uri.UnescapeDataString(parameter.Get("host") ?? "");
                    break;
                case "quic":
                    server.QUICSecure = parameter.Get("quicSecurity") ?? "none";
                    server.QUICSecret = parameter.Get("key") ?? "";
                    server.FakeType = parameter.Get("headerType") ?? "none";
                    break;
                case "grpc":
                    server.FakeType = parameter.Get("mode") ?? "gun";
                    server.Path = parameter.Get("serviceName") ?? "";
                    server.Host = parameter.Get("authority") ?? "";
                    break;
                case "httpupgrade":
                    server.Path = Uri.UnescapeDataString(parameter.Get("path") ?? "/");
                    server.Host = Uri.UnescapeDataString(parameter.Get("host") ?? "");
                    break;
                case "hysteria":
                    server.HysteriaAuth = parameter.Get("auth") ?? "";
                    break;
            }

            server.TLSSecureType = parameter.Get("security") ?? "none";
            server.ServerName = parameter.Get("sni") ?? "";
            server.RealityFingerprint = parameter.Get("fp") ?? "chrome";
            server.RealityPublicKey = parameter.Get("pbk") ?? parameter.Get("password") ?? "";
            server.RealityShortId = parameter.Get("sid") ?? "";
            server.RealitySpiderX = parameter.Get("spx") ?? "";
            server.RealityMldsa65Verify = parameter.Get("mldsa65Verify") ?? "";

            if (server is VLESSServer vless)
            {
                vless.Flow = parameter.Get("flow") ?? string.Empty;
            }
        }

        var finder = new Regex(@$"^{scheme}://(?<guid>.+?)@(?<server>.+):(?<port>\d+)");
        var match = finder.Match(text.Split('?')[0]);
        if (!match.Success)
            throw new FormatException();

        server.UserID = match.Groups["guid"].Value;
        server.Hostname = match.Groups["server"].Value;
        server.Port = ushort.Parse(match.Groups["port"].Value);

        return new[] { server };
    }

    public static string GetVShareLink(Server s, string scheme = "vmess")
    {
        // https://github.com/XTLS/Xray-core/issues/91
        var server = (VMessServer)s;
        var parameter = new Dictionary<string, string>();
        // protocol-specific fields
        parameter.Add("type", server.TransferProtocol);
        parameter.Add("encryption", server.EncryptMethod);
        parameter.Add("packetEncoding", server.PacketEncoding);

        // transport-specific fields
        switch (server.TransferProtocol)
        {
            case "raw":
            case "tcp":
                break;
            case "xhttp":
            case "splithttp":
                parameter.Add("path", Uri.EscapeDataString(server.Path.ValueOrDefault() ?? "/"));
                if (!server.Host.IsNullOrWhiteSpace())
                    parameter.Add("host", Uri.EscapeDataString(server.Host!));

                if (!string.IsNullOrWhiteSpace(server.XHttpMode) && server.XHttpMode != "auto")
                    parameter.Add("mode", server.XHttpMode);

                break;
            case "kcp":
            case "mkcp":
                if (server.FakeType != "none")
                    parameter.Add("headerType", server.FakeType);

                if (!server.Path.IsNullOrWhiteSpace())
                    parameter.Add("seed", Uri.EscapeDataString(server.Path!));

                break;
            case "ws":
            case "websocket":
                parameter.Add("path", Uri.EscapeDataString(server.Path.ValueOrDefault() ?? "/"));
                if (!server.Host.IsNullOrWhiteSpace())
                    parameter.Add("host", Uri.EscapeDataString(server.Host!));

                break;
            case "h2":
                parameter.Add("path", Uri.EscapeDataString(server.Path.ValueOrDefault() ?? "/"));
                if (!server.Host.IsNullOrWhiteSpace())
                    parameter.Add("host", Uri.EscapeDataString(server.Host!));

                break;
            case "quic":
                if (server.QUICSecure is not (null or "none"))
                {
                    parameter.Add("quicSecurity", server.QUICSecure);
                    parameter.Add("key", server.QUICSecret!);
                }

                if (server.FakeType != "none")
                    parameter.Add("headerType", server.FakeType);

                break;
            case "grpc":
                if (!string.IsNullOrEmpty(server.Path))
                    parameter.Add("serviceName", server.Path);

                if (!server.Host.IsNullOrWhiteSpace())
                    parameter.Add("authority", Uri.EscapeDataString(server.Host!));

                if (server.FakeType is "gun" or "multi")
                    parameter.Add("mode", server.FakeType);

                break;
            case "httpupgrade":
                parameter.Add("path", Uri.EscapeDataString(server.Path.ValueOrDefault() ?? "/"));
                if (!server.Host.IsNullOrWhiteSpace())
                    parameter.Add("host", Uri.EscapeDataString(server.Host!));

                break;
            case "hysteria":
                if (!string.IsNullOrWhiteSpace(server.HysteriaAuth))
                    parameter.Add("auth", Uri.EscapeDataString(server.HysteriaAuth));

                break;
        }

        if (server.TLSSecureType != "none")
        {
            parameter.Add("security", server.TLSSecureType == "xtls" ? "tls" : server.TLSSecureType);

            if (!server.ServerName.IsNullOrWhiteSpace())
                parameter.Add("sni", Uri.EscapeDataString(server.ServerName!));

            if (!string.IsNullOrWhiteSpace(server.RealityFingerprint))
                parameter.Add("fp", server.RealityFingerprint);

            if (server.TLSSecureType == "reality")
            {
                parameter.Add("pbk", Uri.EscapeDataString(server.RealityPublicKey));
                if (!string.IsNullOrWhiteSpace(server.RealityShortId))
                    parameter.Add("sid", Uri.EscapeDataString(server.RealityShortId));

                if (!string.IsNullOrWhiteSpace(server.RealitySpiderX))
                    parameter.Add("spx", Uri.EscapeDataString(server.RealitySpiderX));

                if (!string.IsNullOrWhiteSpace(server.RealityMldsa65Verify))
                    parameter.Add("mldsa65Verify", Uri.EscapeDataString(server.RealityMldsa65Verify));
            }
        }

        if (server is VLESSServer vless)
        {
            var flow = string.IsNullOrWhiteSpace(vless.Flow) && vless.TLSSecureType == "xtls"
                ? "xtls-rprx-vision"
                : vless.Flow;
            if (!string.IsNullOrWhiteSpace(flow))
                parameter.Add("flow", flow);
        }

        return
            $"{scheme}://{server.UserID}@{server.Hostname}:{server.Port}?{string.Join("&", parameter.Select(p => $"{p.Key}={p.Value}"))}{(!server.Remark.IsNullOrWhiteSpace() ? $"#{Uri.EscapeDataString(server.Remark)}" : "")}";
    }
}
