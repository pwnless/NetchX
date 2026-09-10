namespace Netch.Models.Modes;

public enum ModeType
{
    /// <summary>
    ///     Process-based proxying.
    /// </summary>
    ProcessMode,

    /// <summary>
    ///     Network sharing.
    /// </summary>
    ShareMode,

    /// <summary>
    ///     Virtual network adapter proxying.
    /// </summary>
    TunMode
}
