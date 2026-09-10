using System.Net;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using NetchX.Interfaces;
using NetchX.Interops;
using NetchX.Models;
using NetchX.Models.Modes;
using NetchX.Models.Modes.TunMode;
using NetchX.Servers;
using NetchX.Utils;

namespace NetchX.Controllers
{
    public class TUNController : IModeController
    {
        private readonly DNSController _aioDnsController = new();

        private TunMode _mode = null!;
        private IPAddress? _serverRemoteAddress;
        private TUNConfig _tunConfig = null!;
        private Process? _tun2SocksProcess;
        private bool _tunRouteContextReady;

        private NetRoute _tun;
        private NetRoute _outbound;

        public string Name => "tun2socks";
        public string interfaceName => "netchx";

        public ModeFeature Features => ModeFeature.SupportSocks5Auth;

        public async Task StartAsync(Socks5Server server, Mode mode)
        {
            if (mode is not TunMode tunMode)
                throw new InvalidOperationException();

            _mode = tunMode;
            _tunConfig = Global.Settings.TUNTAP;

            if (server.RemoteHostname.ValueOrDefault() != null)
                _serverRemoteAddress = await DnsUtils.LookupAsync(server.RemoteHostname!, AddressFamily.InterNetwork);
            else
                _serverRemoteAddress = await DnsUtils.LookupAsync(server.Hostname, AddressFamily.InterNetwork);

            if (_serverRemoteAddress != null && IPAddress.IsLoopback(_serverRemoteAddress))
                _serverRemoteAddress = null;

            _outbound = NetRoute.GetBestRouteTemplate();
            await CheckDriverAsync();

            var serverAddress = await server.AutoResolveHostnameAsync(AddressFamily.InterNetwork);

            try
            {
                #region DNS

                if (!_tunConfig.UseCustomDNS)
                {
                    if (Global.Settings.AioDNS.ListenPort != 53)
                        throw new MessageException("TunMode with tun2socks 2.7 requires AioDNS to listen on port 53.");

                    await _aioDnsController.StartAsync();
                }

                #endregion

                StartTun2Socks(serverAddress, server);
                var tunIndex = await WaitForTunInterfaceIndexAsync(_tun2SocksProcess!);
                _tun = NetRoute.TemplateBuilder(_tunConfig.Gateway, tunIndex);
                _tunRouteContextReady = true;

                if (!RouteHelper.CreateUnicastIP(AddressFamily.InterNetwork,
                        _tunConfig.Address,
                        (byte)Utils.Utils.SubnetToCidr(_tunConfig.Netmask),
                        checked((uint)tunIndex)))
                    throw new MessageException("Failed to assign the TUN IPv4 address.");

                SetupRouteTable();
            }
            catch
            {
                try
                {
                    await StopAsync();
                }
                catch (Exception cleanupException)
                {
                    Log.Error(cleanupException, "TunMode startup cleanup failed");
                }

                throw;
            }
        }

        public async Task StopAsync()
        {
            try
            {
                if (_tunRouteContextReady)
                    ClearRouteTable();
            }
            finally
            {
                _tunRouteContextReady = false;
                await StopTun2SocksAsync();
                await _aioDnsController.StopAsync();
            }
        }

        private async Task CheckDriverAsync()
        {
            string binDriver = Path.Combine(Global.NetchXDir, Constants.WintunDllFile);
            string tun2Socks = Path.Combine(Global.NetchXDir, Constants.Tun2SocksFile);
            if (!File.Exists(binDriver))
                throw new MessageException($"wintun.dll is missing: {binDriver}");

            if (!File.Exists(tun2Socks))
                throw new MessageException($"tun2socks.exe is missing: {tun2Socks}");

            var version = FileVersionInfo.GetVersionInfo(binDriver).FileVersion;
            Log.Information("Using application-local wintun.dll {Version} ({Hash})", version,
                await Utils.Utils.Sha256CheckSumAsync(binDriver));
        }

        private void StartTun2Socks(string serverAddress, Socks5Server server)
        {
            string executable = Path.Combine(Global.NetchXDir, Constants.Tun2SocksFile);
            var startInfo = new ProcessStartInfo(executable)
            {
                WorkingDirectory = Path.GetDirectoryName(executable)!,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            startInfo.ArgumentList.Add("--device");
            startInfo.ArgumentList.Add($"tun://{interfaceName}");
            startInfo.ArgumentList.Add("--proxy");
            startInfo.ArgumentList.Add(BuildSocks5Uri(serverAddress, server));
            startInfo.ArgumentList.Add("--mtu");
            startInfo.ArgumentList.Add("1500");
            startInfo.ArgumentList.Add("--loglevel");
            startInfo.ArgumentList.Add("warn");

            var process = Process.Start(startInfo)
                ?? throw new MessageException("Failed to launch tun2socks.exe.");
            process.OutputDataReceived += (_, e) =>
            {
                if (!string.IsNullOrWhiteSpace(e.Data))
                    Log.Debug("[tun2socks] {Message}", e.Data);
            };
            process.ErrorDataReceived += (_, e) =>
            {
                if (!string.IsNullOrWhiteSpace(e.Data))
                    Log.Warning("[tun2socks] {Message}", e.Data);
            };
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
            _tun2SocksProcess = process;
        }

        private static string BuildSocks5Uri(string serverAddress, Socks5Server server)
        {
            var endpoint = $"{serverAddress}:{server.Port}";
            if (!server.Auth())
                return $"socks5://{endpoint}";

            return $"socks5://{Uri.EscapeDataString(server.Username!)}:{Uri.EscapeDataString(server.Password!)}@{endpoint}";
        }

        private async Task<int> WaitForTunInterfaceIndexAsync(Process process)
        {
            var timeout = Stopwatch.StartNew();
            while (timeout.Elapsed < TimeSpan.FromSeconds(10))
            {
                if (process.HasExited)
                    throw new MessageException($"tun2socks.exe exited during startup (exit code {process.ExitCode}).");

                var networkInterface = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(networkInterface =>
                    string.Equals(networkInterface.Name, interfaceName, StringComparison.OrdinalIgnoreCase));
                if (networkInterface != null)
                    return networkInterface.GetIndex();

                await Task.Delay(100);
            }

            throw new MessageException($"Timed out waiting for the {interfaceName} Wintun adapter.");
        }

        private async Task StopTun2SocksAsync()
        {
            var process = _tun2SocksProcess;
            _tun2SocksProcess = null;
            if (process == null)
                return;

            try
            {
                if (!process.HasExited)
                    process.Kill(entireProcessTree: true);

                await process.WaitForExitAsync();
            }
            finally
            {
                process.Dispose();
            }
        }

        #region Route

        private void SetupRouteTable()
        {
            Global.MainForm.StatusText(i18N.Translate("Setup Route Table Rule"));

            var tunNetworkInterface = NetworkInterfaceUtils.Get(_tun.InterfaceIndex);
            // Server Address
            if (_serverRemoteAddress != null)
                RouteUtils.CreateRoute(_outbound.FillTemplate(_serverRemoteAddress.ToString(), 32));

            // Global Bypass IPs
            RouteUtils.CreateRouteFill(_outbound, _tunConfig.BypassIPs);

            // rule
            RouteUtils.CreateRouteFill(_tun, _mode.Handle);
            RouteUtils.CreateRouteFill(_outbound, _mode.Bypass);

            // dns

            if (_tunConfig.UseCustomDNS)
            {
                if (_tunConfig.ProxyDNS)
                {
                    // NOTICE: DNS metric is network interface metric
                    RouteUtils.CreateRoute(_tun.FillTemplate(_tunConfig.DNS, 32));
                }

                tunNetworkInterface.SetDns(_tunConfig.DNS);
            }
            else
            {
                // tun2socks 2.7 does not provide the legacy tun_dial DNS
                // interceptor. Configure the virtual interface explicitly so
                // Windows sends its DNS requests to the local AioDNS service.
                tunNetworkInterface.SetDns(IPAddress.Loopback.ToString());
                RouteUtils.CreateRoute(_outbound.FillTemplate(Utils.Utils.GetHostFromUri(Global.Settings.AioDNS.ChinaDNS), 32));
                RouteUtils.CreateRoute(_tun.FillTemplate(Utils.Utils.GetHostFromUri(Global.Settings.AioDNS.OtherDNS), 32));
            }

            NetworkInterfaceUtils.SetInterfaceMetric(_tun.InterfaceIndex, 0);
        }

        private void ClearRouteTable()
        {
            if (_serverRemoteAddress != null)
                RouteUtils.DeleteRoute(_outbound.FillTemplate(_serverRemoteAddress.ToString(), 32));

            if (_outbound.Gateway != null)
            {
                RouteUtils.DeleteRouteFill(_outbound, Global.Settings.TUNTAP.BypassIPs);
                RouteUtils.DeleteRoute(_outbound.FillTemplate(Utils.Utils.GetHostFromUri(Global.Settings.AioDNS.ChinaDNS), 32));
                NetworkInterfaceUtils.SetInterfaceMetric(_outbound.InterfaceIndex);
            }

            if (_mode != null)
            {
                RouteUtils.DeleteRouteFill(_tun, _mode.Handle);
                RouteUtils.DeleteRouteFill(_outbound, _mode.Bypass);
            }

            if (_tunConfig != null && _tunConfig.UseCustomDNS && _tunConfig.ProxyDNS)
                RouteUtils.DeleteRoute(_tun.FillTemplate(_tunConfig.DNS, 32));

            if (_tunConfig != null && !_tunConfig.UseCustomDNS)
                RouteUtils.DeleteRoute(_tun.FillTemplate(Utils.Utils.GetHostFromUri(Global.Settings.AioDNS.OtherDNS), 32));
        }

        #endregion
    }
}
