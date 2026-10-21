using System.Net;
using System.Text;

namespace NetchX.Utils;

public static class WebUtil
{
    public const string DefaultUserAgent =
        @"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.61 Safari/537.36 Edg/94.0.992.31";

    private static readonly HttpClient SharedClient = CreateClient();

    private static int DefaultGetTimeout => Global.Settings.RequestTimeout;

    public static async Task<byte[]> DownloadBytesAsync(string address, string? userAgent = null, int? timeout = null)
    {
        using var request = CreateRequest(address, userAgent);
        using var cancellation = CreateTimeoutCancellation(timeout);
        using var response = await SharedClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellation.Token);
        return await response.Content.ReadAsByteArrayAsync(cancellation.Token);
    }

    public static async Task<(HttpStatusCode, string)> DownloadStringAsync(
        string address,
        Encoding? encoding = null,
        string? userAgent = null,
        string? proxyServer = null,
        int? timeout = null)
    {
        using var request = CreateRequest(address, userAgent);
        using var cancellation = CreateTimeoutCancellation(timeout);
        using var client = string.IsNullOrWhiteSpace(proxyServer) ? null : CreateClient(proxyServer);
        using var response = await (client ?? SharedClient).SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellation.Token);
        var bytes = await response.Content.ReadAsByteArrayAsync(cancellation.Token);
        return (response.StatusCode, (encoding ?? Encoding.UTF8).GetString(bytes));
    }

    public static async Task DownloadFileAsync(string address, string fileFullPath, IProgress<int>? progress = null, int? timeout = null)
    {
        using var request = CreateRequest(address, userAgent: null);
        using var cancellation = CreateTimeoutCancellation(timeout);
        using var response = await SharedClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellation.Token);
        response.EnsureSuccessStatusCode();

        var total = response.Content.Headers.ContentLength;
        var buffer = new byte[81920];
        long written = 0;
        var lastProgress = -1;

        await using var input = await response.Content.ReadAsStreamAsync(cancellation.Token);
        await using var output = new FileStream(fileFullPath, FileMode.Create, FileAccess.Write, FileShare.None, buffer.Length, useAsync: true);
        while (true)
        {
            var read = await input.ReadAsync(buffer, cancellation.Token);
            if (read == 0)
                break;

            await output.WriteAsync(buffer.AsMemory(0, read), cancellation.Token);
            written += read;
            if (total is > 0)
            {
                var currentProgress = (int)Math.Min(99, written * 100 / total.Value);
                if (currentProgress != lastProgress)
                {
                    lastProgress = currentProgress;
                    progress?.Report(currentProgress);
                }
            }
        }

        progress?.Report(100);
    }

    private static HttpRequestMessage CreateRequest(string address, string? userAgent)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, address);
        request.Headers.TryAddWithoutValidation("User-Agent", string.IsNullOrWhiteSpace(userAgent) ? DefaultUserAgent : userAgent);
        request.Headers.TryAddWithoutValidation("Accept", "*/*");
        request.Headers.TryAddWithoutValidation("Accept-Charset", "utf-8");
        return request;
    }

    private static CancellationTokenSource CreateTimeoutCancellation(int? timeout)
    {
        var milliseconds = timeout ?? DefaultGetTimeout;
        return milliseconds > 0
            ? new CancellationTokenSource(TimeSpan.FromMilliseconds(milliseconds))
            : new CancellationTokenSource();
    }

    private static HttpClient CreateClient(string? proxyServer = null)
    {
        var handler = new SocketsHttpHandler();
        if (!string.IsNullOrWhiteSpace(proxyServer))
        {
            handler.UseProxy = true;
            handler.Proxy = new WebProxy(proxyServer);
        }

        return new HttpClient(handler, disposeHandler: true);
    }
}
