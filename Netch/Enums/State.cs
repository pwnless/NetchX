namespace Netch.Enums;

/// <summary>
///     Application state.
/// </summary>
public enum State
{
    /// <summary>
    ///     Waiting for a command.
    /// </summary>
    Waiting,

    /// <summary>
    ///     Starting.
    /// </summary>
    Starting,

    /// <summary>
    ///     Started.
    /// </summary>
    Started,

    /// <summary>
    ///     Stopping.
    /// </summary>
    Stopping,

    /// <summary>
    ///     Stopped.
    /// </summary>
    Stopped,

    /// <summary>
    ///     Terminating.
    /// </summary>
    Terminating
}

public static class StateExtension
{
    public static string GetStatusString(State state)
    {
        if (state == State.Waiting)
            return "Waiting for command";

        return state.ToString();
    }
}
