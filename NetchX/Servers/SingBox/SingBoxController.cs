using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using NetchX.Controllers;
using NetchX.Interfaces;
using NetchX.Models;

namespace NetchX.Servers;

/// <summary>
///     Local sing-box client runtime for protocols intentionally outside the
///     Xray-owned profile set.
/// </summary>
public sealed class SingBoxController : Guard, IServerController
{
    public SingBoxController() : base("sing-box.exe")
    {
    }

    public override string Name => "sing-box";

    public ushort? Socks5LocalPort { get; set; }

    public string? LocalAddress { get; set; }

    public async Task<Socks5Server> StartAsync(Server server)
    {
        SingBoxConfigUtils.ValidateServer(server);
        var localAddress = this.LocalAddress();
        var localPort = this.Socks5LocalPort();
        var config = await SingBoxConfigUtils.GenerateClientConfigAsync(server, localAddress, localPort);

        await using (var stream = new FileStream(Constants.SingBoxTempConfig, FileMode.Create, FileAccess.Write, FileShare.Read))
        {
            await JsonSerializer.SerializeAsync(stream, config, Global.NewCustomJsonSerializerOptions());
        }

        await CheckConfigurationAsync();
        await StartGuardAsync("run -c ..\\data\\sing-box.json");
        await WaitForSocksListenerAsync(localAddress, localPort);
        return new Socks5Server(IPAddress.Loopback.ToString(), localPort, server.Hostname);
    }

    private async Task CheckConfigurationAsync()
    {
        var result = await RunSingBoxAsync("check -c ..\\data\\sing-box.json");
        if (result.ExitCode != 0)
            throw new MessageException($"sing-box configuration check failed.\n{result.Output}".Trim());
    }

    private async Task WaitForSocksListenerAsync(string address, ushort port)
    {
        Exception? lastError = null;
        for (var attempt = 0; attempt < 100; ++attempt)
        {
            if (Instance.HasExited)
                throw new MessageException($"sing-box exited before its SOCKS listener became ready. See {LogPath}.");

            try
            {
                using var client = new TcpClient();
                using var timeout = new CancellationTokenSource(TimeSpan.FromMilliseconds(150));
                await client.ConnectAsync(address, port, timeout.Token);
                return;
            }
            catch (Exception e) when (e is SocketException or OperationCanceledException)
            {
                lastError = e;
                await Task.Delay(50);
            }
        }

        await StopAsync();
        throw new MessageException($"sing-box did not open its SOCKS listener on {address}:{port}. {lastError?.Message}");
    }

    private static async Task<(int ExitCode, string Output)> RunSingBoxAsync(string arguments)
    {
        var fileName = Path.Combine(Global.NetchXDir, "bin", "sing-box.exe");
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                WorkingDirectory = Path.Combine(Global.NetchXDir, "bin"),
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            }
        };

        process.Start();
        var standardOutput = process.StandardOutput.ReadToEndAsync();
        var standardError = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();
        return (process.ExitCode, (await standardOutput) + (await standardError));
    }
}
