using NetchX.Forms;

namespace NetchX.Servers;

[Fody.ConfigureAwait(true)]
public class SSHForm : ServerForm
{
    public SSHForm(SSHServer? server = default)
    {
        server ??= new SSHServer();
        Server = server;
        CreateTextBox("User", "User", value => !string.IsNullOrWhiteSpace(value), value => server.User = value, server.User);
        CreateTextBox("Password", "Password", _ => true, value => server.Password = value, server.Password);
        CreateTextBox("PrivateKey", "Private Key", _ => true, value => server.PrivateKey = value, server.PrivateKey);
        CreateTextBox("PrivateKeyPassphrase", "Key Passphrase", _ => true, value => server.PrivateKeyPassphrase = value, server.PrivateKeyPassphrase ?? string.Empty);
        CreateTextBox("PublicKey", "Host Public Key", _ => true, value => server.PublicKey = value, server.PublicKey ?? string.Empty);
        CreateTextBox("HostKeyAlgorithms", "Host Key Algorithms", _ => true, value => server.HostKeyAlgorithms = value, server.HostKeyAlgorithms ?? string.Empty);
        CreateTextBox("ClientVersion", "Client Version", _ => true, value => server.ClientVersion = value, server.ClientVersion ?? string.Empty);
        CreateTextBox("Cipher", "Ciphers", _ => true, value => server.Cipher = value, server.Cipher ?? string.Empty);
        CreateTextBox("Mac", "MAC Algorithms", _ => true, value => server.Mac = value, server.Mac ?? string.Empty);
        CreateTextBox("KexAlgorithms", "KEX Algorithms", _ => true, value => server.KexAlgorithms = value, server.KexAlgorithms ?? string.Empty);
    }

    protected override string TypeName { get; } = "SSH";
}
