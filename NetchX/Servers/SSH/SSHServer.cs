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
}
