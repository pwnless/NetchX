using WindowsFirewallHelper;
using WindowsFirewallHelper.FirewallRules;

namespace NetchX.Utils;

public static class Firewall
{
    private const string NetchX = "NetchX";
    private const string LegacyNetch = "Netch";

    /// <summary>
    ///     Adds firewall rules for executables shipped with NetchX.
    /// </summary>
    public static void AddNetchXFwRules()
    {
        if (!FirewallWAS.IsLocallySupported)
        {
            Log.Warning("Windows Firewall Locally Unsupported");
            return;
        }

        try
        {
            if (!string.Equals(Global.Settings.LocalAddress, "0.0.0.0", StringComparison.Ordinal))
            {
                RemoveNetchXFwRules();
                return;
            }

            RemoveNetchXFwRules();

            foreach (var path in Directory.GetFiles(Global.NetchXDir, "*.exe", SearchOption.AllDirectories))
                AddFwRule(NetchX, path);
        }
        catch (Exception e)
        {
            Log.Warning(e, "Create NetchX Firewall rules error");
        }
    }

    /// <summary>
    ///     Removes firewall rules for executables shipped with NetchX.
    /// </summary>
    public static void RemoveNetchXFwRules()
    {
        if (!FirewallWAS.IsLocallySupported)
            return;

        try
        {
            foreach (var rule in FirewallManager.Instance.Rules.Where(r =>
                         r.Name is NetchX or LegacyNetch ||
                         (r.ApplicationName != null && IsPathUnderDirectory(r.ApplicationName, Global.NetchXDir))))
                FirewallManager.Instance.Rules.Remove(rule);
        }
        catch (Exception e)
        {
            Log.Warning(e, "Remove NetchX Firewall rules error");
        }
    }

    #region Helpers

    private static void AddFwRule(string ruleName, string exeFullPath)
    {
        var rule = new FirewallWASRule(ruleName,
            exeFullPath,
            FirewallAction.Allow,
            FirewallDirection.Inbound,
            FirewallProfiles.Private | FirewallProfiles.Domain);

        FirewallManager.Instance.Rules.Add(rule);
    }

    private static bool IsPathUnderDirectory(string path, string directory)
    {
        var relativePath = Path.GetRelativePath(Path.GetFullPath(directory), Path.GetFullPath(path));
        return !Path.IsPathRooted(relativePath) &&
               relativePath != ".." &&
               !relativePath.StartsWith($"..{Path.DirectorySeparatorChar}", StringComparison.Ordinal);
    }

    #endregion
}
