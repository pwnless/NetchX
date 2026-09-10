using System.Diagnostics;
using Microsoft.VisualStudio.Threading;
using NetchX.Interfaces;
using NetchX.Models;
using NetchX.Models.Modes;
using NetchX.Servers;
using NetchX.Services;
using NetchX.Utils;

namespace NetchX.Controllers;

public static class MainController
{
    public static Socks5Server? Socks5Server { get; private set; }

    public static Server? Server { get; private set; }

    public static Mode? Mode { get; private set; }

    public static IServerController? ServerController { get; private set; }

    public static IModeController? ModeController { get; private set; }

    private static readonly AsyncSemaphore Lock = new(1);

    public static async Task StartAsync(Server server, Mode mode)
    {
        using var _ = await Lock.EnterAsync();

        Log.Information("Start MainController: {Server} {Mode}", $"{server.Type}", $"[{(int)mode.Type}]{mode.i18NRemark}");

        try
        {
            if (await DnsUtils.LookupAsync(server.Hostname) == null)
                throw new MessageException(i18N.Translate("Lookup Server hostname failed"));

            // TODO Disable NAT Type Test setting
            // cache STUN Server ip to prevent "Wrong STUN Server"
            DnsUtils.LookupAsync(Global.Settings.STUN_Server).Forget();

            Server = server;
            Mode = mode;

            await Task.WhenAll(Task.Run(NativeMethods.RefreshDNSCache), Task.Run(Firewall.AddNetchXFwRules));

            ModeController = ModeService.GetModeControllerByType(mode.Type, out var modePort, out var portName);

            if (modePort != null)
                TryReleaseTcpPort((ushort)modePort, portName);

            if (Server is Socks5Server socks5 && (!socks5.Auth() || ModeController.Features.HasFlag(ModeFeature.SupportSocks5Auth)))
            {
                Socks5Server = socks5;
            }
            else
            {
                // Start Server Controller to get a local socks5 server
                Log.Debug("Server Information: {Data}", $"{server.Type} {server.MaskedData()}");

                ServerController = CreateServerController(server);
                Global.MainForm.StatusText(i18N.TranslateFormat("Starting {0}", ServerController.Name));

                TryReleaseTcpPort(ServerController.Socks5LocalPort(), "Socks5");
                Socks5Server = await ServerController.StartAsync(server);

                StatusPortInfoText.Socks5Port = Socks5Server.Port;
                StatusPortInfoText.UpdateShareLan();
            }

            // Start Mode Controller
            Global.MainForm.StatusText(i18N.TranslateFormat("Starting {0}", ModeController.Name));

            await ModeController.StartAsync(Socks5Server, mode);
        }
        catch (Exception e)
        {
            // This method already owns Lock.  Releasing it before calling the
            // public StopAsync creates a window in which a second StartAsync
            // can install new controllers that this failed startup then stops.
            await StopCoreAsync();

            switch (e)
            {
                case DllNotFoundException:
                case FileNotFoundException:
                    throw new Exception(e.Message + "\n\n" + i18N.Translate("Missing File or runtime components"));
                case MessageException:
                    throw;
                default:
                    Log.Error(e, "Unhandled Exception When Start MainController");
                    Utils.Utils.Open(Constants.LogFile);
                    throw new MessageException($"{i18N.Translate("Unhandled Exception")}\n{e.Message}");
            }
        }
    }

    public static async Task StopAsync()
    {
        using var _ = await Lock.EnterAsync();
        await StopCoreAsync();
    }

    /// <summary>
    ///     Xray-core is the default runtime. The bundled legacy SagerNet
    ///     binary exists solely for its SSH and ShadowsocksR outbounds.
    /// </summary>
    public static IServerController CreateServerController(Server server)
    {
        return UsesLegacyV2rayFallback(server)
            ? new LegacyV2rayController()
            : new XrayController();
    }

    public static bool UsesLegacyV2rayFallback(Server server)
    {
        return server is SSHServer or ShadowsocksRServer;
    }

    private static async Task StopCoreAsync()
    {
        if (ServerController == null && ModeController == null)
        {
            Socks5Server = null;
            Server = null;
            Mode = null;
            return;
        }

        Log.Information("Stop Main Controller");
        StatusPortInfoText.Reset();

        var tasks = new[]
        {
            ServerController?.StopAsync() ?? Task.CompletedTask,
            ModeController?.StopAsync() ?? Task.CompletedTask
        };

        try
        {
            await Task.WhenAll(tasks);
        }
        catch (Exception e)
        {
            Log.Error(e, "MainController Stop Error");
        }

        finally
        {
            ServerController = null;
            ModeController = null;
            Socks5Server = null;
            Server = null;
            Mode = null;
        }
    }

    public static void PortCheck(ushort port, string portName, PortType portType = PortType.Both)
    {
        try
        {
            PortHelper.CheckPort(port, portType);
        }
        catch (PortInUseException)
        {
            throw new MessageException(i18N.TranslateFormat("The {0} port is in use.", $"{portName} ({port})"));
        }
        catch (PortReservedException)
        {
            throw new MessageException(i18N.TranslateFormat("The {0} port is reserved by system.", $"{portName} ({port})"));
        }
    }

    public static void TryReleaseTcpPort(ushort port, string portName)
    {
        foreach (var p in PortHelper.GetProcessByUsedTcpPort(port))
        {
            var fileName = p.MainModule?.FileName;
            if (fileName == null)
                continue;

            if (IsPathUnderDirectory(fileName, Global.NetchXDir))
            {
                p.Kill();
                p.WaitForExit();
            }
            else
            {
                throw new MessageException(i18N.TranslateFormat("The {0} port is used by {1}.", $"{portName} ({port})", $"({p.Id}){fileName}"));
            }
        }

        PortCheck(port, portName, PortType.TCP);
    }

    private static bool IsPathUnderDirectory(string path, string directory)
    {
        var relativePath = Path.GetRelativePath(Path.GetFullPath(directory), Path.GetFullPath(path));
        return !Path.IsPathRooted(relativePath) &&
               relativePath != ".." &&
               !relativePath.StartsWith($"..{Path.DirectorySeparatorChar}", StringComparison.Ordinal);
    }

    public static Task<NatTypeTestResult> DiscoveryNatTypeAsync(CancellationToken ctx = default)
    {
        Debug.Assert(Socks5Server != null, nameof(Socks5Server) + " != null");
        return Socks5ServerTestUtils.DiscoveryNatTypeAsync(Socks5Server, ctx);
    }

    public static Task<int?> HttpConnectAsync(CancellationToken ctx = default)
    {
        Debug.Assert(Socks5Server != null, nameof(Socks5Server) + " != null");
        try
        {
            return Socks5ServerTestUtils.HttpConnectAsync(Socks5Server, ctx);
        }
        catch (OperationCanceledException)
        {
            // ignored
        }
        catch (Exception e)
        {
            Log.Warning(e, "Unhandled Socks5ServerTestUtils.HttpConnectAsync Exception");
        }

        return Task.FromResult<int?>(null);
    }
}
