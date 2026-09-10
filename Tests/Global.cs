using System;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using NetchX.Controllers;
using NetchX.Models.GitHubRelease;
using NetchX.Models;
using NetchX.Servers;
using NetchX.Utils;

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
    public void NetchXLinkRoundTripsDerivedServerFieldsAndNumericPort()
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

        var link = ShareLink.GetNetchXLink(source);
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
    public void LegacyNetchShareLinksRemainImportable()
    {
        Server source = new Socks5Server
        {
            Hostname = "legacy.example.test",
            Port = 1080,
            Remark = "Legacy link"
        };

        var currentLink = ShareLink.GetNetchXLink(source);
        var legacyLink = "Netch://" + currentLink["NetchX://".Length..];
        var parsed = ShareLink.ParseText(legacyLink).Single();

        Assert.IsInstanceOfType<Socks5Server>(parsed);
        Assert.AreEqual(source.Hostname, parsed.Hostname);
        Assert.AreEqual(source.Port, parsed.Port);
    }

    [TestMethod]
    public void UpdateManifestBindsTheHashToTheMatchingHttpsAsset()
    {
        const string hash = "7f4fd01818936788a7363f4bfd2efac113d42a3e39db7a2aa23bfc6b11e3de19";
        UpdateChecker.LatestRelease = new Release
        {
            body = $"| 文件名 | SHA256 |\n| :- | :- |\n| NetchX.7z | {hash} |",
            assets = new[]
            {
                new Asset { name = "other.7z", browser_download_url = "https://example.test/other.7z" },
                new Asset { name = "NetchX.7z", browser_download_url = "https://example.test/NetchX.7z" }
            }
        };

        var (fileName, actualHash, url) = UpdateChecker.GetLatestUpdateFileNameAndHash();

        Assert.AreEqual("NetchX.7z", fileName);
        Assert.AreEqual(hash, actualHash);
        Assert.AreEqual("https://example.test/NetchX.7z", url);
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

    [TestMethod]
    public async Task XrayRealityVisionConfigUsesModernTransportFieldsAsync()
    {
        var server = new VLESSServer
        {
            Hostname = "127.0.0.1",
            Port = 443,
            UserID = "b831381d-6324-4d53-ad4f-8cda48b30811",
            TransferProtocol = "raw",
            TLSSecureType = "reality",
            ServerName = "www.example.com",
            Host = "www.example.com",
            Path = "/connect",
            XHttpMode = "stream-one",
            Flow = "xtls-rprx-vision",
            RealityPublicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            RealityShortId = "01234567",
            RealitySpiderX = "/search?q=netch"
        };

        var config = await V2rayConfigUtils.GenerateClientConfigAsync(server);
        var json = JsonSerializer.Serialize(config, NetchX.Global.NewCustomJsonSerializerOptions());
        using var document = JsonDocument.Parse(json);
        var outbound = document.RootElement.GetProperty("outbounds")[0];
        var streamSettings = outbound.GetProperty("streamSettings");
        var realitySettings = streamSettings.GetProperty("realitySettings");

        Assert.AreEqual("raw", streamSettings.GetProperty("method").GetString());
        Assert.AreEqual("reality", streamSettings.GetProperty("security").GetString());
        Assert.IsFalse(streamSettings.TryGetProperty("network", out _));
        Assert.IsTrue(streamSettings.TryGetProperty("rawSettings", out _));
        Assert.AreEqual(server.RealityPublicKey, realitySettings.GetProperty("password").GetString());
        Assert.AreEqual(server.RealityShortId, realitySettings.GetProperty("shortId").GetString());
        Assert.AreEqual(server.Flow, outbound.GetProperty("settings").GetProperty("vnext")[0].GetProperty("users")[0].GetProperty("flow").GetString());
        Assert.IsFalse(outbound.GetProperty("mux").GetProperty("enabled").GetBoolean());
    }

    [TestMethod]
    public void VlessRealityLinkRoundTripsModernTransportFields()
    {
        var source = new VLESSServer
        {
            Hostname = "edge.example.com",
            Port = 443,
            UserID = "b831381d-6324-4d53-ad4f-8cda48b30811",
            TransferProtocol = "xhttp",
            TLSSecureType = "reality",
            ServerName = "www.example.com",
            Host = "www.example.com",
            Path = "/connect",
            XHttpMode = "stream-up",
            Flow = "xtls-rprx-vision",
            RealityPublicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            RealityShortId = "01234567",
            RealityFingerprint = "firefox",
            RealitySpiderX = "/search?q=netch",
            RealityMldsa65Verify = "verify-key"
        };

        var link = V2rayUtils.GetVShareLink(source, "vless");
        var parsedServer = V2rayUtils.ParseVUri(link).Single();
        Assert.IsInstanceOfType<VLESSServer>(parsedServer);
        var parsed = (VLESSServer)parsedServer;

        Assert.AreEqual(source.TransferProtocol, parsed.TransferProtocol);
        Assert.AreEqual(source.TLSSecureType, parsed.TLSSecureType);
        Assert.AreEqual(source.ServerName, parsed.ServerName);
        Assert.AreEqual(source.XHttpMode, parsed.XHttpMode);
        Assert.AreEqual(source.Flow, parsed.Flow);
        Assert.AreEqual(source.RealityPublicKey, parsed.RealityPublicKey);
        Assert.AreEqual(source.RealityShortId, parsed.RealityShortId);
        Assert.AreEqual(source.RealityFingerprint, parsed.RealityFingerprint);
        Assert.AreEqual(source.RealitySpiderX, parsed.RealitySpiderX);
        Assert.AreEqual(source.RealityMldsa65Verify, parsed.RealityMldsa65Verify);
    }

    [TestMethod]
    public async Task XrayXhttpConfigUsesTheConfiguredModeAsync()
    {
        var server = new VLESSServer
        {
            Hostname = "127.0.0.1",
            Port = 443,
            UserID = "b831381d-6324-4d53-ad4f-8cda48b30811",
            TransferProtocol = "xhttp",
            TLSSecureType = "tls",
            ServerName = "www.example.com",
            Host = "www.example.com",
            Path = "/connect",
            XHttpMode = "stream-one"
        };

        var config = await V2rayConfigUtils.GenerateClientConfigAsync(server);
        var json = JsonSerializer.Serialize(config, NetchX.Global.NewCustomJsonSerializerOptions());
        using var document = JsonDocument.Parse(json);
        var streamSettings = document.RootElement.GetProperty("outbounds")[0].GetProperty("streamSettings");

        Assert.AreEqual("xhttp", streamSettings.GetProperty("method").GetString());
        Assert.AreEqual("tls", streamSettings.GetProperty("security").GetString());
        Assert.AreEqual("stream-one", streamSettings.GetProperty("xhttpSettings").GetProperty("mode").GetString());
    }

    [TestMethod]
    public void OnlySshAndShadowsocksRUseTheLegacyRuntime()
    {
        Assert.IsTrue(MainController.UsesLegacyV2rayFallback(new SSHServer()));
        Assert.IsTrue(MainController.UsesLegacyV2rayFallback(new ShadowsocksRServer()));
        Assert.IsFalse(MainController.UsesLegacyV2rayFallback(new VLESSServer()));
        Assert.IsFalse(MainController.UsesLegacyV2rayFallback(new VMessServer()));
        Assert.IsFalse(MainController.UsesLegacyV2rayFallback(new ShadowsocksServer()));
    }

    [TestMethod]
    public async Task LegacySagerNetConfigContainsTheShadowsocksRPluginAsync()
    {
        var server = new ShadowsocksRServer
        {
            Hostname = "127.0.0.1",
            Port = 8388,
            EncryptMethod = "aes-256-cfb",
            Password = "password",
            Protocol = "auth_aes128_sha1",
            ProtocolParam = "user-id:password",
            OBFS = "tls1.2_ticket_auth",
            OBFSParam = "example.com"
        };

        var config = await LegacyV2rayConfigUtils.GenerateClientConfigAsync(server);
        var json = JsonSerializer.Serialize(config, NetchX.Global.NewCustomJsonSerializerOptions());
        using var document = JsonDocument.Parse(json);
        var outbound = document.RootElement.GetProperty("outbounds")[0];
        var settings = outbound.GetProperty("settings");

        Assert.AreEqual("shadowsocks", outbound.GetProperty("protocol").GetString());
        Assert.AreEqual("shadowsocksr", settings.GetProperty("plugin").GetString());
        CollectionAssert.AreEqual(
            new[]
            {
                "--obfs=tls1.2_ticket_auth",
                "--obfs-param=example.com",
                "--protocol=auth_aes128_sha1",
                "--protocol-param=user-id:password"
            },
            settings.GetProperty("pluginArgs").EnumerateArray().Select(argument => argument.GetString()).ToArray());
    }

    [TestMethod]
    public async Task LegacySagerNetConfigContainsTheSshOutboundAsync()
    {
        var server = new SSHServer
        {
            Hostname = "127.0.0.1",
            Port = 22,
            User = "netch",
            Password = "password",
            PrivateKey = "private-key",
            PublicKey = "host-public-key"
        };

        var config = await LegacyV2rayConfigUtils.GenerateClientConfigAsync(server);
        var json = JsonSerializer.Serialize(config, NetchX.Global.NewCustomJsonSerializerOptions());
        using var document = JsonDocument.Parse(json);
        var outbound = document.RootElement.GetProperty("outbounds")[0];
        var settings = outbound.GetProperty("settings");

        Assert.AreEqual("ssh", outbound.GetProperty("protocol").GetString());
        Assert.AreEqual("127.0.0.1", settings.GetProperty("address").GetString());
        Assert.AreEqual(22, settings.GetProperty("port").GetInt32());
        Assert.AreEqual("netch", settings.GetProperty("user").GetString());
        Assert.AreEqual("password", settings.GetProperty("password").GetString());
        Assert.AreEqual("private-key", settings.GetProperty("privateKey").GetString());
        Assert.AreEqual("host-public-key", settings.GetProperty("publicKey").GetString());
    }
}
