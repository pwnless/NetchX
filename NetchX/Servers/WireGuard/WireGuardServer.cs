using NetchX.Models;

namespace NetchX.Servers;

public class WireGuardServer : Server
{
    public override string Type { get; } = "WireGuard";

    public override string MaskedData()
    {
        return $"{LocalAddresses} + {MTU}";
    }

    /// <summary>
    ///     Local addresses.
    /// </summary>
    public string LocalAddresses { get; set; } = "172.16.0.2";

    /// <summary>
    ///     Peer public key.
    /// </summary>
    public string PeerPublicKey { get; set; } = string.Empty;

    /// <summary>
    ///     Private key.
    /// </summary>
    public string PrivateKey { get; set; }

    /// <summary>
    ///     Peer pre-shared key.
    /// </summary>
    public string? PreSharedKey { get; set; }

    /// <summary>
    ///     MTU
    /// </summary>
    public int MTU { get; set; } = 1420;
}
