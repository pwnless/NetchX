#nullable disable
namespace NetchX.Servers;

public class SSDServerJObject
{
    /// <summary>
    ///     Encryption method.
    /// </summary>
    public string encryption;

    /// <summary>
    ///     Password.
    /// </summary>
    public string password;

    /// <summary>
    ///     Plugin.
    /// </summary>
    public string plugin;

    /// <summary>
    ///     Plugin arguments.
    /// </summary>
    public string plugin_options;

    /// <summary>
    ///     Port.
    /// </summary>
    public ushort port;

    /// <summary>
    ///     Remark.
    /// </summary>
    public string remarks;
    /// <summary>
    ///     Server address.
    /// </summary>
    public string server;
}
