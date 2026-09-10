using System;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Netch.Controllers;
using Netch.Models.GitHubRelease;
using Netch.Models;
using Netch.Servers;
using Netch.Utils;

namespace Tests;

[TestClass]
public class Global
{
    [TestMethod]
    public void VlessUuid5MatchesReferenceValue()
    {
        var bytes = new byte[16].Concat(Encoding.UTF8.GetBytes("example")).ToArray();
        var hash = SHA1.HashData(bytes).Take(16).ToArray();
        hash[6] = (byte)((hash[6] & 0x0f) | (5 << 4));
        hash[8] = (byte)((hash[8] & 0x3f) | 0x80);

        Assert.AreEqual("3144b5fe-1b30-bb52-a6dd-e1e93e81bb9e", new Guid(hash).ToString());
    }

    [TestMethod]
    public async Task DnsLookupsAreConcurrentAndCacheClearSafeAsync()
    {
        DnsUtils.ClearCache();
        var lookups = Enumerable.Range(0, 16)
            .Select(_ => DnsUtils.LookupAsync("localhost", AddressFamily.InterNetwork, 5000));

        var results = await Task.WhenAll(lookups);
        Assert.IsTrue(results.All(address => address?.AddressFamily == AddressFamily.InterNetwork));

        await Task.WhenAll(
            DnsUtils.LookupAsync("localhost", AddressFamily.InterNetwork, 5000),
            Task.Run(DnsUtils.ClearCache));
    }

    [TestMethod]
    public void NetchLinkRoundTripsDerivedServerFieldsAndNumericPort()
    {
        Server source = new WireGuardServer
        {
            Group = "test",
            Hostname = "wg.example.test",
            Port = 51820,
            Remark = "WireGuard test",
            LocalAddresses = "10.0.0.2/32",
            PeerPublicKey = "peer-key",
            PrivateKey = "private-key",
            PreSharedKey = "psk",
            MTU = 1280
        };

        var link = ShareLink.GetNetchLink(source);
        var parsed = ShareLink.ParseText(link).Single();

        Assert.IsInstanceOfType<WireGuardServer>(parsed);
        var wireGuard = (WireGuardServer)parsed;
        Assert.AreEqual(source.Port, wireGuard.Port);
        Assert.AreEqual("10.0.0.2/32", wireGuard.LocalAddresses);
        Assert.AreEqual("peer-key", wireGuard.PeerPublicKey);
        Assert.AreEqual("private-key", wireGuard.PrivateKey);
        Assert.AreEqual(1280, wireGuard.MTU);
    }

    [TestMethod]
    public void UpdateManifestBindsTheHashToTheMatchingHttpsAsset()
    {
        const string hash = "7f4fd01818936788a7363f4bfd2efac113d42a3e39db7a2aa23bfc6b11e3de19";
        UpdateChecker.LatestRelease = new Release
        {
            body = $"| 文件名 | SHA256 |\n| :- | :- |\n| Netch.7z | {hash} |",
            assets = new[]
            {
                new Asset { name = "other.7z", browser_download_url = "https://example.test/other.7z" },
                new Asset { name = "Netch.7z", browser_download_url = "https://example.test/Netch.7z" }
            }
        };

        var (fileName, actualHash, url) = UpdateChecker.GetLatestUpdateFileNameAndHash();

        Assert.AreEqual("Netch.7z", fileName);
        Assert.AreEqual(hash, actualHash);
        Assert.AreEqual("https://example.test/Netch.7z", url);
    }

    [TestMethod]
    public void ReleaseContentExcludesTheEnglishChecksumSection()
    {
        UpdateChecker.LatestRelease = new Release
        {
            body = "Release preamble\n\n## Changelog\n\nKeep this text.\n\n## Checksums\n\n| File name | SHA256 |"
        };

        var content = UpdateChecker.GetLatestReleaseContent();

        StringAssert.Contains(content, "## Changelog");
        StringAssert.Contains(content, "Keep this text.");
        Assert.IsFalse(content.Contains("## Checksums", StringComparison.Ordinal));
    }

    [TestMethod]
    public void RouteParserRejectsIpv6AndInvalidCidrsForIpv4OnlyTun()
    {
        Assert.IsTrue(RouteUtils.TryParseIPNetwork("10.0.0.0/8", out var address, out var cidr));
        Assert.AreEqual("10.0.0.0", address);
        Assert.AreEqual(8, cidr);
        Assert.IsFalse(RouteUtils.TryParseIPNetwork("2001:db8::/32", out _, out _));
        Assert.IsFalse(RouteUtils.TryParseIPNetwork("10.0.0.0/33", out _, out _));
        Assert.IsFalse(RouteUtils.TryParseIPNetwork("not-an-address/24", out _, out _));
    }
}
