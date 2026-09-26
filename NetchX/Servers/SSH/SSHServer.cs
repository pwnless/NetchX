using NetchX.Models;

namespace NetchX.Servers;

public class SSHServer : Server
{
    public override string Type { get; } = "SSH";

    public override string MaskedData()
    {
        return $"{User}";
    }

    /// <summary>
    ///     User name.
    /// </summary>
    public string User { get; set; } = "root";

    /// <summary>
    ///     Password.
    /// </summary>
    public string Password { get; set; } = string.Empty;

    /// <summary>
    ///     Private key.
    /// </summary>
    public string PrivateKey { get; set; }

    /// <summary>
    ///     Host public key.
    /// </summary>
    public string? PublicKey { get; set; }

    /// <summary>
    ///     Private-key passphrase.
    /// </summary>
    public string? PrivateKeyPassphrase { get; set; }

    /// <summary>
    ///     Allowed host-key algorithms, separated by commas.
    /// </summary>
    public string? HostKeyAlgorithms { get; set; }

    /// <summary>
    ///     SSH client identification string.
    /// </summary>
    public string? ClientVersion { get; set; }

    /// <summary>
    ///     Allowed ciphers, separated by commas.
    /// </summary>
    public string? Cipher { get; set; }

    /// <summary>
    ///     Allowed MAC algorithms, separated by commas.
    /// </summary>
    public string? Mac { get; set; }

    /// <summary>
    ///     Allowed key-exchange algorithms, separated by commas.
    /// </summary>
    public string? KexAlgorithms { get; set; }

    [System.Text.Json.Serialization.JsonIgnore]
    public override ServerNetworkCapability NetworkCapabilities => ServerNetworkCapability.Tcp;
}
