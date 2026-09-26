using System.Text;
using System.Text.Json;
using NetchX.JsonConverter;
using NetchX.Models;
using NetchX.Servers;

namespace NetchX.Utils;

public static class ShareLink
{
    private const string NetchXScheme = "NetchX://";
    private const string LegacyNetchScheme = "Netch://";

    public static string GetShareLink(Server server)
    {
        return ServerHelper.GetUtilByTypeName(server.Type).GetShareLink(server);
    }

    public static List<Server> ParseText(string text)
    {
        try
        {
            text = URLSafeBase64Decode(text);
        }
        catch
        {
            // ignored
        }

        var list = new List<Server>();

        try
        {
            list.AddRange(JsonSerializer.Deserialize<List<ShadowsocksConfig>>(text)!.Select(server => new ShadowsocksServer
            {
                Hostname = server.server,
                Port = server.server_port,
                EncryptMethod = server.method,
                Password = server.password,
                Remark = server.remarks,
                Plugin = server.plugin,
                PluginOption = server.plugin_opts
            }));
        }
        catch (JsonException)
        {
            foreach (var line in text.GetLines())
            {
                try
                {
                    list.AddRange(ParseUri(line));
                }
                catch (Exception e)
                {
                    Log.Error(e, "Parse servers from share link error");
                }
            }
        }
        catch (Exception e)
        {
            Log.Error(e, "Parse servers from share link error");
        }

        return list;
    }

    private static IEnumerable<Server> ParseUri(in string text)
    {
        var list = new List<Server>();

        if (text.StartsWith("tg://socks?") || text.StartsWith("https://t.me/socks?"))
        {
            list.AddRange(ServerHelper.GetUtilByTypeName("Socks5").ParseUri(text));
        }
        else if (text.StartsWith(NetchXScheme, StringComparison.OrdinalIgnoreCase) ||
                 text.StartsWith(LegacyNetchScheme, StringComparison.OrdinalIgnoreCase))
        {
            list.Add(ParseNetchXUri(text));
        }
        else if (text.StartsWith("ssr://", StringComparison.OrdinalIgnoreCase))
        {
            list.Add(ParseLegacySsrUri(text));
        }
        else
        {
            var scheme = GetUriScheme(text);
            var util = ServerHelper.GetUtilByUriScheme(scheme);
            if (util != null)
                list.AddRange(util.ParseUri(text));
            else
                Log.Warning("\"{Scheme}\" scheme share link not supported", scheme);
        }

        foreach (var node in list.Where(node => !node.Remark.IsNullOrWhiteSpace()))
            node.Remark = RemoveEmoji(node.Remark);

        return list;
    }


    public static Server ParseLegacySsrUri(string text)
    {
        var encoded = text["ssr://".Length..];
        var value = URLSafeBase64Decode(encoded);
        var parameterIndex = value.IndexOf('?', StringComparison.Ordinal);
        var endpoint = parameterIndex >= 0 ? value[..parameterIndex] : value;
        var parameters = parameterIndex >= 0 ? ParseLegacySsrParameters(value[(parameterIndex + 1)..]) : new Dictionary<string, string>();
        var fields = endpoint.Split(':');
        if (fields.Length < 6 || !ushort.TryParse(fields[1], out var port))
            throw new FormatException();

        var protocol = fields[2].Replace("_compatible", string.Empty, StringComparison.OrdinalIgnoreCase);
        var method = fields[3];
        var obfs = fields[4].Replace("_compatible", string.Empty, StringComparison.OrdinalIgnoreCase);
        if (!protocol.Equals("origin", StringComparison.OrdinalIgnoreCase) || !obfs.Equals("plain", StringComparison.OrdinalIgnoreCase))
            throw new NotSupportedException("ShadowsocksR is no longer supported. Only SSR links that represent plain standard Shadowsocks can be imported.");
        if (!SSGlobal.EncryptMethods.Contains(method))
            throw new FormatException();

        var password = URLSafeBase64Decode(fields[5].Split('/')[0]);
        var server = new ShadowsocksServer
        {
            Hostname = fields[0],
            Port = port,
            EncryptMethod = method,
            Password = password
        };
        if (parameters.TryGetValue("remarks", out var remark))
            server.Remark = URLSafeBase64Decode(remark);
        if (parameters.TryGetValue("group", out var group))
            server.Group = URLSafeBase64Decode(group);
        return server;
    }

    private static Dictionary<string, string> ParseLegacySsrParameters(string value)
    {
        return value.Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(item => item.Split('=', 2))
            .Where(item => item.Length == 2)
            .ToDictionary(item => item[0], item => item[1], StringComparer.OrdinalIgnoreCase);
    }

    public static string GetUriScheme(string text)
    {
        var endIndex = text.IndexOf("://", StringComparison.Ordinal);
        if (endIndex == -1)
            throw new UriFormatException("Text is not a URI");

        return text.Substring(0, endIndex);
    }

    private static Server ParseNetchXUri(string text)
    {
        text = URLSafeBase64Decode(text[(text.IndexOf("://", StringComparison.Ordinal) + 3)..]);

        var NetchXLink = JsonSerializer.Deserialize<JsonElement>(text);

        if (string.IsNullOrEmpty(NetchXLink.GetProperty("Hostname").GetString()))
            throw new FormatException();

        var port = NetchXLink.GetProperty("Port");
        if (!(port.ValueKind == JsonValueKind.Number && port.TryGetUInt16(out _)) &&
            !(port.ValueKind == JsonValueKind.String && ushort.TryParse(port.GetString(), out _)))
            throw new FormatException();

        var server = JsonSerializer.Deserialize<Server>(text,
            new JsonSerializerOptions
            {
                Converters = { new ServerConverterWithTypeDiscriminator() }
            })!;
        if (server is RemovedShadowsocksRServer)
            throw new NotSupportedException("ShadowsocksR profiles are no longer supported. Migrate this server to standard Shadowsocks or a current protocol.");
        return server;
    }

    public static string GetNetchXLink(Server s)
    {
        var jsonSerializerOptions = Global.NewCustomJsonSerializerOptions();
        jsonSerializerOptions.WriteIndented = false;
        jsonSerializerOptions.Converters.Add(new ServerConverterWithTypeDiscriminator());
        return NetchXScheme + URLSafeBase64Encode(JsonSerializer.Serialize<Server>(s, jsonSerializerOptions));
    }

    #region Utils

    /// <summary>
    ///     Decodes URL-safe Base64 text.
    /// </summary>
    /// <param name="text">Text to decode.</param>
    /// <returns>The decoded text.</returns>
    public static string URLSafeBase64Decode(string text)
    {
        return Encoding.UTF8.GetString(
            Convert.FromBase64String(text.Replace("-", "+").Replace("_", "/").PadRight(text.Length + (4 - text.Length % 4) % 4, '=')));
    }

    /// <summary>
    ///     Encodes text as URL-safe Base64.
    /// </summary>
    /// <param name="text">Text to encode.</param>
    /// <returns>The encoded text.</returns>
    public static string URLSafeBase64Encode(string text)
    {
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(text)).Replace("+", "-").Replace("/", "_").Replace("=", "");
    }

    private static string RemoveEmoji(string text)
    {
        byte[] emojiBytes = { 240, 159 };
        var remark = Encoding.UTF8.GetBytes(text);
        var startIndex = 0;
        while (remark.Length > startIndex + 1 && remark[startIndex] == emojiBytes[0] && remark[startIndex + 1] == emojiBytes[1])
            startIndex += 4;

        return Encoding.UTF8.GetString(remark.Skip(startIndex).ToArray()).Trim();
    }

    public static string UnBase64String(string value)
    {
        if (string.IsNullOrEmpty(value))
            return "";

        var bytes = Convert.FromBase64String(value);
        return Encoding.UTF8.GetString(bytes);
    }

    public static string ToBase64String(string value)
    {
        if (string.IsNullOrEmpty(value))
            return "";

        var bytes = Encoding.UTF8.GetBytes(value);
        return Convert.ToBase64String(bytes);
    }

    public static Dictionary<string, string> ParseParam(string paramStr)
    {
        var paramsDict = new Dictionary<string, string>();
        var obfsParams = paramStr.Split('&');
        foreach (var p in obfsParams)
            if (p.IndexOf('=') > 0)
            {
                var index = p.IndexOf('=');
                var key = p.Substring(0, index);
                var val = p.Substring(index + 1);
                paramsDict[key] = val;
            }

        return paramsDict;
    }

    public static IEnumerable<string> GetLines(this string str, bool removeEmptyLines = true)
    {
        using var sr = new StringReader(str);
        string? line;
        while ((line = sr.ReadLine()) != null)
        {
            if (removeEmptyLines && string.IsNullOrWhiteSpace(line))
                continue;

            yield return line;
        }
    }

    #endregion
}
