namespace Netch.Servers;

public class V2rayNJObject
{
    /// <summary>
    ///     Link version
    /// </summary>
    public int v { get; set; } = 2;

    /// <summary>
    ///     Remark
    /// </summary>
    public string ps { get; set; } = string.Empty;

    /// <summary>
    ///     Address
    /// </summary>
    public string add { get; set; } = string.Empty;

    /// <summary>
    ///     Port
    /// </summary>
    public ushort port { get; set; }

    /// <summary>
    ///     User ID
    /// </summary>
    public string id { get; set; } = string.Empty;

    /// <summary>
    ///     Alter ID
    /// </summary>
    public int aid { get; set; }

    /// <summary>
    ///     Encryption method (security)
    /// </summary>
    public string scy { get; set; } = "auto";

    /// <summary>
    ///     Transport protocol
    /// </summary>
    public string net { get; set; } = string.Empty;

    /// <summary>
    ///     Camouflage type
    /// </summary>
    public string type { get; set; } = string.Empty;

    /// <summary>
    ///     Camouflage host (HTTP, WS)
    /// </summary>
    public string host { get; set; } = string.Empty;

    /// <summary>
    ///     Camouflage path or service name
    /// </summary>
    public string path { get; set; } = string.Empty;

    /// <summary>
    ///     Whether TLS is enabled
    /// </summary>
    public string tls { get; set; } = string.Empty;

    /// <summary>
    ///     serverName
    /// </summary>
    public string sni { get; set; } = string.Empty;
}
