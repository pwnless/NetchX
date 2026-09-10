using Netch.Models;

namespace Netch.Servers;

public class TrojanServer : Server
{
    private string _tlsSecureType = VLESSGlobal.TLSSecure[1];

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
                value = VLESSGlobal.TLSSecure[1];

            _tlsSecureType = value;
        }
    }
}
