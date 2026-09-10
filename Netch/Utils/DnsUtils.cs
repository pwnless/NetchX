using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Microsoft.VisualStudio.Threading;

namespace Netch.Utils;

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

    public static string AppendPort(string host, ushort port = 53)
    {
        if (!host.Contains(':'))
            return host + $":{port}";

        return host;
    }
}
