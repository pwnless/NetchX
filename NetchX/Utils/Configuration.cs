using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.VisualStudio.Threading;
using NetchX.JsonConverter;
using NetchX.Models;

namespace NetchX.Utils;

public static class Configuration
{
    /// <summary>
    ///     Configuration data directory.
    /// </summary>
    public static string DataDirectoryFullName => Path.Combine(Global.NetchXDir, "data");

    public static string FileFullName => Path.Combine(DataDirectoryFullName, FileName);

    private static string BackupFileFullName => Path.Combine(DataDirectoryFullName, BackupFileName);

    private const string FileName = "settings.json";

    private const string BackupFileName = "settings.json.bak";

    private static readonly AsyncReaderWriterLock _lock = new(null);

    private static readonly JsonSerializerOptions JsonSerializerOptions = Global.NewCustomJsonSerializerOptions();

    /// <summary>
    ///     Startup-only notice populated by a successful settings migration.
    /// </summary>
    public static string? PendingMigrationNotice { get; private set; }

    static Configuration()
    {
        JsonSerializerOptions.Converters.Add(new ServerConverterWithTypeDiscriminator());
        JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter());
    }

    public static async Task LoadAsync()
    {
        try
        {
            if (!File.Exists(FileFullName))
            {
                await SaveAsync();
                return;
            }

            var migrated = false;
            var loaded = false;
            await using (var _ = await _lock.ReadLockAsync())
            {
                (loaded, migrated) = await LoadCoreAsync(FileFullName);
                if (!loaded)
                {
                    Log.Information("Load backup configuration \"{FileName}\"", BackupFileFullName);
                    (loaded, migrated) = await LoadCoreAsync(BackupFileFullName);
                }
            }

            if (!loaded)
                throw new InvalidDataException("Neither the primary nor backup settings file could be loaded.");

            if (migrated)
                await SaveAsync();
        }
        catch (Exception e)
        {
            Log.Error(e, "Load configuration failed");
            Environment.Exit(-1);
        }
    }

    private static async ValueTask<(bool Loaded, bool Migrated)> LoadCoreAsync(string filename)
    {
        try
        {
            Setting settings;

            await using (var fs = new FileStream(filename, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, true))
            {
                settings = (await JsonSerializer.DeserializeAsync<Setting>(fs, JsonSerializerOptions))!;
            }

            var migrated = CheckSetting(settings, out var removedSsrCount);
            if (migrated)
            {
                var migrationBackup = Path.Combine(DataDirectoryFullName, $"settings.before-ssr-removal-{DateTime.Now:yyyyMMdd-HHmmssfff}.json");
                File.Copy(filename, migrationBackup, false);
                PendingMigrationNotice = $"Removed {removedSsrCount} obsolete ShadowsocksR profile(s). A backup was saved to {migrationBackup}.";
                Log.Warning("{Notice}", PendingMigrationNotice);
            }

            Global.Settings = settings;
            return (true, migrated);
        }
        catch (Exception e)
        {
            Log.Error(e, "Load configuration file \"{FileName}\" error ", filename);
            return (false, false);
        }
    }

    private static bool CheckSetting(Setting settings, out int removedSsrCount)
    {
        var migrated = MigrateRemovedSsrProfiles(settings, out removedSsrCount);

        settings.Profiles.RemoveAll(p => p.ServerRemark == string.Empty || p.ModeRemark == string.Empty);
        for (var i = 0; i < settings.Profiles.Count; i++)
            settings.Profiles[i].Index = i;

        settings.ServerComboBoxSelectedIndex = settings.Server.Count == 0
            ? -1
            : Math.Clamp(settings.ServerComboBoxSelectedIndex, 0, settings.Server.Count - 1);
        settings.AioDNS.ChinaDNS = DnsUtils.AppendPort(settings.AioDNS.ChinaDNS);
        settings.AioDNS.OtherDNS = DnsUtils.AppendPort(settings.AioDNS.OtherDNS);
        return migrated;
    }

    /// <summary>
    ///     Removes deserialization-only legacy SSR records and quick profiles
    ///     that no longer resolve to a surviving server.
    /// </summary>
    public static bool MigrateRemovedSsrProfiles(Setting settings, out int removedSsrCount)
    {
        var removedRemarks = settings.Server.OfType<RemovedShadowsocksRServer>().Select(server => server.Remark).ToHashSet(StringComparer.Ordinal);
        removedSsrCount = settings.Server.RemoveAll(server => server is RemovedShadowsocksRServer);
        if (removedRemarks.Count > 0)
            settings.Profiles.RemoveAll(profile => removedRemarks.Contains(profile.ServerRemark) && !settings.Server.Any(server => server.Remark.Equals(profile.ServerRemark, StringComparison.Ordinal)));
        return removedSsrCount > 0;
    }

    /// <summary>
    ///     Saves the configuration.
    /// </summary>
    public static async Task SaveAsync()
    {
        if (_lock.IsWriteLockHeld)
            return;

        try
        {
            await using var _ = await _lock.WriteLockAsync();
            Log.Verbose("Save Configuration");

            if (!Directory.Exists(DataDirectoryFullName))
                Directory.CreateDirectory(DataDirectoryFullName);

            var tempFile = Path.Combine(DataDirectoryFullName, FileFullName + ".tmp");
            await using (var fileStream = new FileStream(tempFile, FileMode.Create, FileAccess.Write, FileShare.None, 4096, true))
            {
                await JsonSerializer.SerializeAsync(fileStream, Global.Settings, JsonSerializerOptions);
            }

            await EnsureConfigFileExistsAsync();

            File.Replace(tempFile, FileFullName, BackupFileFullName);
        }
        catch (Exception e)
        {
            Log.Error(e, "Save Configuration error");
        }
    }

    private static async ValueTask EnsureConfigFileExistsAsync()
    {
        if (!File.Exists(FileFullName))
        {
            await using var fs = new FileStream(FileFullName, FileMode.Create, FileAccess.ReadWrite, FileShare.None, 4096, true);
        }
    }
}
