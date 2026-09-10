using Netch.Models;

namespace Netch.Servers;

public class TrojanServer : Server
{
    private string _tlsSecureType = TrojanGlobal.TLSSecure[1];

    public override string Type { get; } = "Trojan";

    public override string MaskedData()
    {
        return "";
    }

    /// <summary>
    ///     Password.
    /// </summary>
    public string Password { get; set; } = string.Empty;

    /// <summary>
    ///     Camouflage domain.
    /// </summary>
    public string? Host { get; set; }

    /// <summary>
    ///     TLS transport security.
    /// </summary>
    public string TLSSecureType
    {
        get => _tlsSecureType;
        set
        {
            if (value == "")
                value = TrojanGlobal.TLSSecure[1];

            // Xray removed legacy XTLS and Trojan flow control. Existing
            // profiles continue as ordinary TLS Trojan profiles.
            if (value == "xtls")
                value = "tls";

            _tlsSecureType = value;
        }
    }
}

public static class TrojanGlobal
{
    public static readonly List<string> TLSSecure = new()
    {
        "none",
        "tls"
    };
}
