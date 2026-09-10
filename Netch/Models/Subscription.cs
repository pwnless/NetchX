namespace Netch.Models;

public class Subscription
{
    /// <summary>
    ///     Whether this subscription is enabled.
    /// </summary>
    public bool Enable { get; set; } = true;

    /// <summary>
    ///     Subscription URL.
    /// </summary>
    public string Link { get; set; } = string.Empty;

    /// <summary>
    ///     Display remark.
    /// </summary>
    public string Remark { get; set; } = string.Empty;

    /// <summary>
    ///     User Agent
    /// </summary>
    public string UserAgent { get; set; } = string.Empty;
}
