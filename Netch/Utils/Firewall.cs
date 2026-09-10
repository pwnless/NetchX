using WindowsFirewallHelper;
using WindowsFirewallHelper.FirewallRules;

namespace Netch.Utils;

public static class Firewall
{
    private const string Netch = "Netch";

    /// <summary>
    ///     Adds firewall rules for executables shipped with Netch.
    /// </summary>
    public static void AddNetchFwRules()
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
                RemoveNetchFwRules();
                return;
            }

            RemoveNetchFwRules();

            foreach (var path in Directory.GetFiles(Global.NetchDir, "*.exe", SearchOption.AllDirectories))
                AddFwRule(Netch, path);
        }
        catch (Exception e)
        {
            Log.Warning(e, "Create Netch Firewall rules error");
        }
    }

    /// <summary>
    ///     Removes firewall rules for executables shipped with Netch.
    /// </summary>
    public static void RemoveNetchFwRules()
    {
        if (!FirewallWAS.IsLocallySupported)
            return;

        try
        {
            foreach (var rule in FirewallManager.Instance.Rules.Where(r
                         => r.ApplicationName != null ? IsPathUnderDirectory(r.ApplicationName, Global.NetchDir) : r.Name == Netch))
                FirewallManager.Instance.Rules.Remove(rule);
        }
        catch (Exception e)
        {
            Log.Warning(e, "Remove Netch Firewall rules error");
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
