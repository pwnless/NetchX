#nullable disable
namespace NetchX.Servers;

public class SSDJObject
{
    /// <summary>
    ///     Provider name.
    /// </summary>
    public string airport;

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
    ///     Server collection.
    /// </summary>
    public List<SSDServerJObject> servers;
}
