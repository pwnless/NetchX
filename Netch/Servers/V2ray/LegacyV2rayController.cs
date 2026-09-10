using System.Net;
using System.Text.Json;
using Netch.Controllers;
using Netch.Interfaces;
using Netch.Models;

namespace Netch.Servers;

/// <summary>
///     Compatibility-only SagerNet runtime for SSH and ShadowsocksR. Do not
///     add current Xray transports or protocols here.
/// </summary>
public class LegacyV2rayController : Guard, IServerController
{
    public LegacyV2rayController() : base("v2ray-sn.exe")
    {
    }

    protected override IEnumerable<string> StartedKeywords => new[] { "started" };

    protected override IEnumerable<string> FailedKeywords => new[] { "config file not readable", "failed to", "Failed to" };

    public override string Name => "V2Ray (SagerNet, legacy fallback)";

    public ushort? Socks5LocalPort { get; set; }

    public string? LocalAddress { get; set; }

    public async Task<Socks5Server> StartAsync(Server server)
    {
        await using (var fileStream = new FileStream(Constants.TempConfig, FileMode.Create, FileAccess.Write, FileShare.Read))
        {
            await JsonSerializer.SerializeAsync(fileStream, await LegacyV2rayConfigUtils.GenerateClientConfigAsync(server), Global.NewCustomJsonSerializerOptions());
        }

        await StartGuardAsync("run -c ..\\data\\last.json");
        return new Socks5Server(IPAddress.Loopback.ToString(), this.Socks5LocalPort(), server.Hostname);
    }
}
