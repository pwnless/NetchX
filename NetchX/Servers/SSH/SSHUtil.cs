using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using NetchX.Interfaces;
using NetchX.Models;
using NetchX.Utils;

namespace NetchX.Servers;

public class SSHUtil : IServerUtil
{
    public ushort Priority { get; } = 4;

    public string TypeName { get; } = "SSH";

    public string FullName { get; } = "SSH";

    public string ShortName { get; } = "SSH";

    public string[] UriScheme { get; } = { "ssh" };

    public Type ServerType { get; } = typeof(SSHServer);

    public void Edit(Server s)
    {
        new SSHForm((SSHServer)s).ShowDialog();
    }

    public void Create()
    {
        new SSHForm().ShowDialog();
    }

    public string GetShareLink(Server s)
    {
        return SingBoxUri.GetShareLink(s);
    }

    public IServerController GetController()
    {
        return new SingBoxController();
    }

    public IEnumerable<Server> ParseUri(string text)
    {
        var server = SingBoxUri.Parse<SSHServer>(text, "ssh");
        var uri = new Uri(text);
        var (user, password) = SingBoxUri.GetUserInfo(uri);
        server.User = user ?? string.Empty;
        server.Password = password ?? string.Empty;
        var query = SingBoxUri.GetQuery(uri);
        server.PublicKey = query["host_key"];
        server.PrivateKey = query["private_key"];
        server.PrivateKeyPassphrase = query["private_key_passphrase"];
        server.HostKeyAlgorithms = query["host_key_algorithms"];
        server.ClientVersion = query["client_version"];
        server.Cipher = query["cipher"];
        server.Mac = query["mac"];
        server.KexAlgorithms = query["kex_algorithm"];
        return new[] { server };
    }

    public bool CheckServer(Server s)
    {
        try
        {
            SingBoxConfigUtils.ValidateServer(s);
            return true;
        }
        catch (MessageException e)
        {
            Log.Error(e, "Invalid SSH server");
            return false;
        }
    }

}
