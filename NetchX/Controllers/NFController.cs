using System.Net;
using System.ServiceProcess;
using NetchX.Interfaces;
using NetchX.Models;
using NetchX.Models.Modes;
using NetchX.Models.Modes.ProcessMode;
using NetchX.Servers;
using NetchX.Utils;
using static NetchX.Interops.Redirector;

namespace NetchX.Controllers;

public class NFController : IModeController
{
    private Server? _server;
    private Redirector _mode = null!;
    private RedirectorConfig _rdrConfig = null!;

    private static readonly ServiceController NFService = new("netfilter2");

    private static readonly string SystemDriver = $"{Environment.SystemDirectory}\\drivers\\netfilter2.sys";

    public string Name => "Redirector";

    public ModeFeature Features => ModeFeature.SupportIPv6 | ModeFeature.SupportSocks5Auth;

    public async Task StartAsync(Socks5Server server, Mode mode)
    {
        if (mode is not Redirector processMode)
            throw new InvalidOperationException();

        _server = server;
        _mode = processMode;
        _rdrConfig = Global.Settings.Redirector;

        CheckDriver();

        Dial(NameList.AIO_FILTERLOOPBACK, _mode.FilterLoopback);
        Dial(NameList.AIO_FILTERINTRANET, _mode.FilterIntranet);
        Dial(NameList.AIO_FILTERPARENT, _mode.FilterParent ?? _rdrConfig.FilterParent);
        Dial(NameList.AIO_FILTERICMP, _mode.FilterICMP ?? _rdrConfig.FilterICMP);
        if (_mode.FilterICMP ?? _rdrConfig.FilterICMP)
            Dial(NameList.AIO_ICMPING, (_mode.FilterICMP != null ? _mode.ICMPDelay ?? 10 : _rdrConfig.ICMPDelay).ToString());

        Dial(NameList.AIO_FILTERTCP, _mode.FilterTCP ?? _rdrConfig.FilterTCP);
        Dial(NameList.AIO_FILTERUDP, _mode.FilterUDP ?? _rdrConfig.FilterUDP);

        // DNS
        Dial(NameList.AIO_FILTERDNS, _mode.FilterDNS ?? _rdrConfig.FilterDNS);
        Dial(NameList.AIO_DNSONLY, _mode.HandleOnlyDNS ?? _rdrConfig.HandleOnlyDNS);
        Dial(NameList.AIO_DNSPROX, _mode.DNSProxy ?? _rdrConfig.DNSProxy);
        if (_mode.FilterDNS ?? _rdrConfig.FilterDNS)
        {
            var dnsStr = _mode.FilterDNS != null ? _mode.DNSHost : _rdrConfig.DNSHost;

            dnsStr = dnsStr.ValueOrDefault() ?? $"{Constants.DefaultPrimaryDNS}:53";

            var dns = IPEndPoint.Parse(dnsStr);
            if (dns.Port == 0)
                dns.Port = 53;

            Dial(NameList.AIO_DNSHOST, dns.Address.ToString());
            Dial(NameList.AIO_DNSPORT, dns.Port.ToString());
        }

        // Server
        Dial(NameList.AIO_TGTHOST, await server.AutoResolveHostnameAsync());
        Dial(NameList.AIO_TGTPORT, server.Port.ToString());
        Dial(NameList.AIO_TGTUSER, server.Username ?? string.Empty);
        Dial(NameList.AIO_TGTPASS, server.Password ?? string.Empty);

        // Mode Rule
        DialRule();

        if (!await InitAsync())
            throw new MessageException("Redirector start failed.");
    }

    public Task StopAsync()
    {
        return FreeAsync();
    }

    #region CheckRule

    /// <summary>
    /// </summary>
    /// <param name="r"></param>
    /// <param name="clear"></param>
    /// <returns>No Problem true</returns>
    private static bool CheckCppRegex(string r, bool clear = true)
    {
        try
        {
            if (r.StartsWith("!"))
                return Dial(NameList.AIO_ADDNAME, r.Substring(1));

            return Dial(NameList.AIO_ADDNAME, r);
        }
        finally
        {
            if (clear)
                Dial(NameList.AIO_CLRNAME, "");
        }
    }

    /// <summary>
    /// </summary>
    /// <param name="rules"></param>
    /// <param name="results"></param>
    /// <returns>No Problem true</returns>
    public static bool CheckRules(IEnumerable<string> rules, out IEnumerable<string> results)
    {
        results = rules.Where(r => !CheckCppRegex(r, false));
        Dial(NameList.AIO_CLRNAME, "");
        return !results.Any();
    }

    public static string GenerateInvalidRulesMessage(IEnumerable<string> rules)
    {
        return $"{string.Join("\n", rules)}\n" + i18N.Translate("Above rules does not conform to C++ regular expression syntax");
    }

    #endregion

    private void DialRule()
    {
        Dial(NameList.AIO_CLRNAME, "");
        var invalidList = new List<string>();
        foreach (var s in _mode.Bypass)
        {
            if (!Dial(NameList.AIO_BYPNAME, s))
                invalidList.Add(s);
        }

        foreach (var s in _mode.Handle)
        {
            if (!Dial(NameList.AIO_ADDNAME, s))
                invalidList.Add(s);
        }

        if (invalidList.Any())
            throw new MessageException(GenerateInvalidRulesMessage(invalidList));

        // Bypass Self
        Dial(NameList.AIO_BYPNAME, "^" + Global.NetchXDir.ToRegexString());
    }

    #region DriverUtil

    private static void CheckDriver()
    {
        var binFileVersion = Utils.Utils.GetFileVersion(Constants.NFDriver);
        var systemFileVersion = Utils.Utils.GetFileVersion(SystemDriver);

        Log.Information("Built-in  netfilter2 driver version: {Name}", binFileVersion);
        Log.Information("Installed netfilter2 driver version: {Name}", systemFileVersion);

        if (!File.Exists(SystemDriver))
        {
            // Install
            InstallDriver();
            return;
        }

        var reinstall = false;
        if (Version.TryParse(binFileVersion, out var binResult) && Version.TryParse(systemFileVersion, out var systemResult))
        {
            if (binResult.CompareTo(systemResult) > 0)
                // Update
                reinstall = true;
            else if (systemResult.Major != binResult.Major)
                // Downgrade when Major version different (may have breaking changes)
                reinstall = true;
        }
        else
        {
            // Parse File versionName to Version failed
            if (!systemFileVersion.Equals(binFileVersion))
                // versionNames are different, Reinstall
                reinstall = true;
        }

        if (!reinstall)
            return;

        Log.Information("Update netfilter2 driver");
        UninstallDriver();
        InstallDriver();
    }

    /// <summary>
    ///     Installs the NetFilter driver.
    /// </summary>
    /// <returns>Whether driver installation succeeded.</returns>
    private static void InstallDriver()
    {
        Log.Information("Install netfilter2 driver");
        Global.MainForm.StatusText(i18N.Translate("Installing netfilter2 driver"));

        if (!File.Exists(Constants.NFDriver))
            throw new MessageException(i18N.Translate("builtin driver files missing, can't install NF driver"));

        try
        {
            File.Copy(Constants.NFDriver, SystemDriver);
        }
        catch (Exception e)
        {
            Log.Error(e, "Copy netfilter2.sys failed\n");
            throw new MessageException($"Copy netfilter2.sys failed\n{e.Message}");
        }

        // Register the driver file.
        if (Interops.Redirector.aio_register("netfilter2"))
        {
            Log.Information("Install netfilter2 driver finished");
        }
        else
        {
            Log.Error("Register netfilter2 failed");
        }
    }

    /// <summary>
    ///     Uninstalls the NetFilter driver.
    /// </summary>
    /// <returns>Whether driver removal succeeded.</returns>
    public static bool UninstallDriver()
    {
        Log.Information("Uninstall netfilter2");
        try
        {
            if (NFService.Status == ServiceControllerStatus.Running)
            {
                NFService.Stop();
                NFService.WaitForStatus(ServiceControllerStatus.Stopped);
            }
        }
        catch (Exception)
        {
            // ignored
        }

        if (!File.Exists(SystemDriver))
            return true;

        Interops.Redirector.aio_unregister("netfilter2");
        File.Delete(SystemDriver);

        return true;
    }

    #endregion
}
