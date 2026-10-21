using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Microsoft.VisualStudio.Threading;

namespace NetchX.Utils;

public static class DnsUtils
{
    private static readonly TimeSpan CacheLifetime = TimeSpan.FromMinutes(5);
    private static readonly ConcurrentDictionary<CacheKey, CacheEntry> Cache = new();
    private static readonly JoinableTaskFactory JoinableTaskFactory = new(new JoinableTaskContext());
    private static readonly ConcurrentDictionary<CacheKey, AsyncLazy<IPAddress?>> InFlight = new();
    private static long _cacheGeneration;

    private readonly record struct CacheKey(string Hostname, AddressFamily AddressFamily);

    private sealed record CacheEntry(IPAddress Address, DateTimeOffset ExpiresAt);

    public static async Task<IPAddress?> LookupAsync(string hostname, AddressFamily inet = AddressFamily.Unspecified, int timeout = 3000)
    {
        if (string.IsNullOrWhiteSpace(hostname) || timeout <= 0)
            return null;

        if (inet is not (AddressFamily.Unspecified or AddressFamily.InterNetwork or AddressFamily.InterNetworkV6))
            throw new ArgumentOutOfRangeException(nameof(inet));

        var key = new CacheKey(hostname, inet);
        if (Cache.TryGetValue(key, out var cached))
        {
            if (cached.ExpiresAt > DateTimeOffset.UtcNow)
                return cached.Address;

            Cache.TryRemove(key, out _);
        }

        var generation = Interlocked.Read(ref _cacheGeneration);
        var lazy = InFlight.GetOrAdd(key, _ => new AsyncLazy<IPAddress?>(
            () => LookupNoCacheAsync(key, timeout, generation),
            JoinableTaskFactory));

        try
        {
            return await lazy.GetValueAsync().ConfigureAwait(false);
        }
        catch (Exception e)
        {
            Log.Verbose(e, "Lookup hostname {Hostname} failed", hostname);
            return null;
        }
        finally
        {
            ((ICollection<KeyValuePair<CacheKey, AsyncLazy<IPAddress?>>>)InFlight)
                .Remove(new KeyValuePair<CacheKey, AsyncLazy<IPAddress?>>(key, lazy));
        }
    }

    private static async Task<IPAddress?> LookupNoCacheAsync(CacheKey key, int timeout, long generation)
    {
        var lookupTask = Dns.GetHostAddressesAsync(key.Hostname);
        IPAddress[] addresses;
        try
        {
            addresses = await lookupTask.WaitAsync(TimeSpan.FromMilliseconds(timeout)).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            _ = lookupTask.ContinueWith(task => _ = task.Exception,
                CancellationToken.None,
                TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);
            return null;
        }

        var result = addresses.FirstOrDefault(address => key.AddressFamily == AddressFamily.Unspecified || address.AddressFamily == key.AddressFamily);
        if (result != null && generation == Interlocked.Read(ref _cacheGeneration))
            Cache[key] = new CacheEntry(result, DateTimeOffset.UtcNow.Add(CacheLifetime));

        return result;
    }

    public static void ClearCache()
    {
        Interlocked.Increment(ref _cacheGeneration);
        Cache.Clear();
        InFlight.Clear();
    }

    /// <summary>
    ///     Normalizes an AioDNS upstream. AioDNS accepts TCP or DNS-over-TLS
    ///     endpoints and requires an explicit port, including for IPv6 literals.
    /// </summary>
    public static string AppendPort(string host, ushort port = 53)
    {
        if (!TryNormalizeDnsEndpoint(host, out var normalized, port))
            throw new ArgumentException("DNS endpoint format invalid", nameof(host));

        return normalized;
    }

    public static bool TryNormalizeDnsEndpoint(string? value, out string normalized, ushort defaultPort = 53)
    {
        normalized = string.Empty;
        if (string.IsNullOrWhiteSpace(value))
            return false;

        value = value.Trim();
        var scheme = "tcp";
        Uri? uri;

        if (value.Contains("://", StringComparison.Ordinal))
        {
            if (!Uri.TryCreate(value, UriKind.Absolute, out uri) ||
                (!uri.Scheme.Equals("tcp", StringComparison.OrdinalIgnoreCase) &&
                 !uri.Scheme.Equals("tls", StringComparison.OrdinalIgnoreCase)) ||
                !string.IsNullOrEmpty(uri.UserInfo) ||
                !string.IsNullOrEmpty(uri.Query) ||
                !string.IsNullOrEmpty(uri.Fragment) ||
                uri.AbsolutePath is not "" and not "/")
                return false;

            scheme = uri.Scheme.ToLowerInvariant();
        }
        else if (IPAddress.TryParse(value, out var address))
        {
            normalized = $"tcp://{FormatHost(address.ToString())}:{defaultPort}";
            return true;
        }
        else if (!Uri.TryCreate("tcp://" + value, UriKind.Absolute, out uri) ||
                 !string.IsNullOrEmpty(uri.UserInfo) ||
                 !string.IsNullOrEmpty(uri.Query) ||
                 !string.IsNullOrEmpty(uri.Fragment) ||
                 uri.AbsolutePath is not "" and not "/")
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(uri.Host) || uri.Port is < -1 or > ushort.MaxValue)
            return false;

        var endpointPort = uri.IsDefaultPort ? defaultPort : uri.Port;
        if (endpointPort == 0)
            return false;

        normalized = $"{scheme}://{FormatHost(uri.Host)}:{endpointPort}";
        return true;
    }

    private static string FormatHost(string host)
    {
        return IPAddress.TryParse(host, out var address) && address.AddressFamily == AddressFamily.InterNetworkV6
            ? $"[{address}]"
            : host;
    }

}
