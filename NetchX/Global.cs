using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using NetchX.Forms;
using NetchX.Models;
using NetchX.Models.Modes;
using WindowsJobAPI;

namespace NetchX;

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

    public static readonly string NetchXDir;
    public static readonly string NetchXExecutable;

    static Global()
    {
        NetchXExecutable = Application.ExecutablePath;
        NetchXDir = Application.StartupPath;
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
