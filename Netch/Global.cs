using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using Netch.Forms;
using Netch.Models;
using Netch.Models.Modes;
using WindowsJobAPI;

namespace Netch;

public static class Global
{
    /// <summary>
    ///     Lazily created main form instance.
    /// </summary>
    private static readonly Lazy<MainForm> LazyMainForm = new(() => new MainForm());

    /// <summary>
    ///     Application settings used for reads and writes.
    /// </summary>
    public static Setting Settings = new();

    public static readonly JobObject Job = new();

    /// <summary>
    ///     Available traffic modes.
    /// </summary>
    public static readonly List<Mode> Modes = new();

    public static readonly string NetchDir;
    public static readonly string NetchExecutable;

    static Global()
    {
        NetchExecutable = Application.ExecutablePath;
        NetchDir = Application.StartupPath;
    }

    /// <summary>
    ///     Gets the lazily created main form instance.
    /// </summary>
    public static MainForm MainForm => LazyMainForm.Value;

    public static JsonSerializerOptions NewCustomJsonSerializerOptions() => new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };
}
