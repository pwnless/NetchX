using System.Text.Json;

namespace NetchX.Models;

/// <summary>
///     Application configuration used for reads and writes.
/// </summary>
public class Setting
{
    public RedirectorConfig Redirector { get; set; } = new();

    /// <summary>
    ///     Configured servers.
    /// </summary>
    public List<Server> Server { get; set; } = new();

    public AioDNSConfig AioDNS { get; set; } = new();

    /// <summary>
    ///     Whether to check for beta updates.
    /// </summary>
    public bool CheckBetaUpdate { get; set; } = false;

    /// <summary>
    ///     Whether to check for updates when the application opens.
    /// </summary>
    public bool CheckUpdateWhenOpened { get; set; } = true;

    /// <summary>
    ///     Interval, in seconds, for testing all servers.
    /// </summary>
    public int DetectionTick { get; set; } = 10;

    /// <summary>
    ///     Whether closing the window exits the application.
    /// </summary>
    public bool ExitWhenClosed { get; set; } = false;

    /// <summary>
    ///     Local HTTP port.
    /// </summary>
    public ushort HTTPLocalPort { get; set; } = 2802;

    /// <summary>
    ///     Language setting.
    /// </summary>
    public string Language { get; set; } = "System";

    /// <summary>
    ///     Local HTTP and SOCKS5 proxy address.
    /// </summary>
    public string LocalAddress { get; set; } = "127.0.0.1";

    /// <summary>
    ///     Whether to minimize automatically after startup.
    /// </summary>
    public bool MinimizeWhenStarted { get; set; } = false;

    /// <summary>
    ///     Selected mode index.
    /// </summary>
    public int ModeComboBoxSelectedIndex { get; set; } = -1;

    /// <summary>
    ///     Number of quick profiles.
    /// </summary>
    public int ProfileCount { get; set; } = 4;

    /// <summary>
    ///     Saved quick profiles.
    /// </summary>
    public List<Profile> Profiles { get; set; } = new();

    /// <summary>
    ///     Maximum number of profile columns.
    /// </summary>
    public byte ProfileTableColumnCount { get; set; } = 5;

    /// <summary>
    ///     Web request timeout in milliseconds.
    /// </summary>
    public int RequestTimeout { get; set; } = 10000;

    /// <summary>
    ///     Whether to run at system startup.
    /// </summary>
    public bool RunAtStartup { get; set; } = false;

    /// <summary>
    ///     Selected server index.
    /// </summary>
    public int ServerComboBoxSelectedIndex { get; set; } = -1;

    /// <summary>
    ///     Server test method: false for ICMP ping, true for TCP ping.
    /// </summary>
    public bool ServerTCPing { get; set; } = true;

    /// <summary>
    ///     Local SOCKS5 port.
    /// </summary>
    public ushort Socks5LocalPort { get; set; } = 2801;

    /// <summary>
    ///     Latency test interval after startup, in seconds.
    /// </summary>
    public int StartedPingInterval { get; set; } = -1;

    /// <summary>
    ///     Whether to start proxying when the application opens.
    /// </summary>
    public bool StartWhenOpened { get; set; } = false;

    /// <summary>
    ///     Whether to stop proxying when the application exits.
    /// </summary>
    public bool StopWhenExited { get; set; } = false;

    /// <summary>
    ///     STUN test server.
    /// </summary>
    public string STUN_Server { get; set; } = "stun.syncthing.net";

    /// <summary>
    ///     STUN test server port.
    /// </summary>
    public int STUN_Server_Port { get; set; } = 3478;

    /// <summary>
    ///     Subscription list.
    /// </summary>
    public List<Subscription> Subscription { get; set; } = new();

    /// <summary>
    ///     TUN/TAP adapter configuration.
    /// </summary>
    public TUNConfig TUNTAP { get; set; } = new();

    /// <summary>
    ///     Whether to update subscriptions when the application opens.
    /// </summary>
    public bool UpdateServersWhenOpened { get; set; } = false;

    public V2rayConfig V2RayConfig { get; set; } = new();

    public bool NoSupportDialog { get; set; } = false;

    #region Migration

    [Obsolete]
    public JsonElement SubscribeLink
    {
        set
        {
            if (Subscription == null! || !Subscription.Any())
                Subscription = value.Deserialize<List<Subscription>>()!;
        }
    }

    #endregion

    public Setting ShallowCopy()
    {
        return (Setting)MemberwiseClone();
    }

    public void Set(Setting value)
    {
        foreach (var p in typeof(Setting).GetProperties())
            p.SetValue(this, p.GetValue(value));
    }
}
