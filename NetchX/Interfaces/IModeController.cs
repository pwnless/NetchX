using NetchX.Models.Modes;
using NetchX.Servers;

namespace NetchX.Interfaces;

public interface IModeController : IController
{
    public ModeFeature Features { get; }

    public Task StartAsync(Socks5Server server, Mode mode);
}