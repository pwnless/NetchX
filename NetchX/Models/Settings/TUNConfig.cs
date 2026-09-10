namespace NetchX.Models;

/// <summary>
///     TUN/TAP adapter configuration.
/// </summary>
public class TUNConfig
{
    /// <summary>
    ///     Adapter address.
    /// </summary>
    public string Address { get; set; } = "10.0.236.10";

    /// <summary>
    ///     DNS
    /// </summary>
    public string DNS { get; set; } = Constants.DefaultPrimaryDNS;

    /// <summary>
    ///     Gateway address.
    /// </summary>
    public string Gateway { get; set; } = "10.0.236.1";

    /// <summary>
    ///     Network mask.
    /// </summary>
    public string Netmask { get; set; } = "255.255.255.0";

    /// <summary>
    ///     Whether to proxy DNS in mode 2.
    /// </summary>
    public bool ProxyDNS { get; set; } = false;

    /// <summary>
    ///     Whether to use custom DNS settings.
    /// </summary>
    public bool UseCustomDNS { get; set; } = false;

    /// <summary>
    ///     Global bypass IPs
    /// </summary>
    public List<string> BypassIPs { get; set; } = new();
}
