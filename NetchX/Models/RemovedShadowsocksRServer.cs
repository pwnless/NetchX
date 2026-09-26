namespace NetchX.Models;

/// <summary>
///     Deserialization-only marker for legacy SSR records. Configuration
///     migration removes these before settings are exposed to the UI.
/// </summary>
internal sealed class RemovedShadowsocksRServer : Server
{
    public override string Type => "SSR";

    public override string MaskedData() => string.Empty;
}
