using System;
using System.Linq;
using System.Diagnostics;
using System.IO;
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
    public void SingBoxOwnsOnlySingBoxProfiles()
    {
        Assert.IsTrue(MainController.UsesSingBoxRuntime(new SSHServer()));
        Assert.IsTrue(MainController.UsesSingBoxRuntime(new AnyTlsServer()));
        Assert.IsTrue(MainController.UsesSingBoxRuntime(new HysteriaServer()));
        Assert.IsTrue(MainController.UsesSingBoxRuntime(new Hysteria2Server()));
        Assert.IsTrue(MainController.UsesSingBoxRuntime(new TuicServer()));
        Assert.IsTrue(MainController.UsesSingBoxRuntime(new NaiveServer()));
        Assert.IsTrue(MainController.UsesSingBoxRuntime(new ShadowTlsServer()));
        Assert.IsFalse(MainController.UsesSingBoxRuntime(new VLESSServer()));
        Assert.IsFalse(MainController.UsesSingBoxRuntime(new VMessServer()));
        Assert.IsFalse(MainController.UsesSingBoxRuntime(new ShadowsocksServer()));
        Assert.IsFalse(MainController.UsesSingBoxRuntime(new HttpProxyServer()));
    }

    [TestMethod]
    public async Task SingBoxConfigsCarryProtocolFieldsAsync()
    {
        var cases = new Server[]
        {
            new AnyTlsServer { Hostname = "127.0.0.1", Port = 443, Password = "password", ServerName = "localhost" },
            new HysteriaServer { Hostname = "127.0.0.1", Port = 443, UpMbps = 100, DownMbps = 100, Auth = "password" },
            new Hysteria2Server { Hostname = "127.0.0.1", Port = 443, Password = "password", ObfsType = "salamander", ObfsPassword = "obfs" },
            new TuicServer { Hostname = "127.0.0.1", Port = 443, UserID = "bf000d23-0752-40b4-affe-68f7707a9661", Password = "password" },
            new NaiveServer { Hostname = "127.0.0.1", Port = 443, Username = "user", Password = "password", Certificate = "-----BEGIN CERTIFICATE-----\nvalue\n-----END CERTIFICATE-----" },
            new ShadowTlsServer { Hostname = "127.0.0.1", Port = 443, Version = 3, Password = "outer", EncryptMethod = "aes-128-gcm", ShadowsocksPassword = "inner" },
            new SSHServer { Hostname = "127.0.0.1", Port = 22, User = "root", Password = "password", PublicKey = "ssh-ed25519 AAAA" }
        };

        foreach (var source in cases)
        {
            var config = await SingBoxConfigUtils.GenerateClientConfigAsync(source, "127.0.0.1", 2801);
            var json = JsonSerializer.Serialize(config, NetchX.Global.NewCustomJsonSerializerOptions());
            using var document = JsonDocument.Parse(json);
            Assert.AreEqual("socks", document.RootElement.GetProperty("inbounds")[0].GetProperty("type").GetString());
            Assert.IsTrue(document.RootElement.GetProperty("outbounds").GetArrayLength() >= 1);
        }

        var shadowConfig = await SingBoxConfigUtils.GenerateClientConfigAsync((ShadowTlsServer)cases[5], "127.0.0.1", 2801);
        var shadowJson = JsonSerializer.Serialize(shadowConfig, NetchX.Global.NewCustomJsonSerializerOptions());
        using var shadowDocument = JsonDocument.Parse(shadowJson);
        Assert.AreEqual("shadowsocks", shadowDocument.RootElement.GetProperty("outbounds")[0].GetProperty("type").GetString());
        Assert.AreEqual("shadowtls", shadowDocument.RootElement.GetProperty("outbounds")[1].GetProperty("type").GetString());
    }

    [TestMethod]
    public void SingBoxUrisAndNetchXLinksRoundTrip()
    {
        var source = new Hysteria2Server
        {
            Hostname = "hy2.example.test",
            Port = 443,
            Password = "password",
            ServerName = "cdn.example.test",
            ObfsType = "salamander",
            ObfsPassword = "obfs",
            Remark = "HY2"
        };
        var uri = ShareLink.GetShareLink(source);
        var parsed = ShareLink.ParseText(uri).Single();
        Assert.IsInstanceOfType<Hysteria2Server>(parsed);
        Assert.AreEqual(source.Hostname, parsed.Hostname);
        Assert.AreEqual(source.Password, ((Hysteria2Server)parsed).Password);

        Server complex = new ShadowTlsServer
        {
            Hostname = "shadow.example.test",
            Port = 443,
            Password = "outer",
            EncryptMethod = "aes-128-gcm",
            ShadowsocksPassword = "inner",
            Remark = "Shadow"
        };
        var netchXLink = ShareLink.GetNetchXLink(complex);
        var parsedComplex = ShareLink.ParseText(netchXLink).Single();
        Assert.IsInstanceOfType<ShadowTlsServer>(parsedComplex);
        Assert.AreEqual("inner", ((ShadowTlsServer)parsedComplex).ShadowsocksPassword);
    }

    [TestMethod]
    public void PlainShadowsocksRLinkMigratesToShadowsocks()
    {
        var endpoint = "127.0.0.1:8388:origin:aes-256-gcm:plain:" + ShareLink.URLSafeBase64Encode("password") + "/?remarks=" + ShareLink.URLSafeBase64Encode("legacy");
        var parsed = ShareLink.ParseText("ssr://" + ShareLink.URLSafeBase64Encode(endpoint)).Single();
        Assert.IsInstanceOfType<ShadowsocksServer>(parsed);
        Assert.AreEqual("password", ((ShadowsocksServer)parsed).Password);
    }

    [TestMethod]
    public void TcpOnlySingBoxProfilesDeclareNoUdpCapability()
    {
        Assert.IsFalse(new SSHServer().NetworkCapabilities.HasFlag(ServerNetworkCapability.Udp));
        Assert.IsFalse(new ShadowTlsServer().NetworkCapabilities.HasFlag(ServerNetworkCapability.Udp));
        Assert.IsFalse(new NaiveServer().NetworkCapabilities.HasFlag(ServerNetworkCapability.Udp));
        Assert.IsTrue(new NaiveServer { UdpOverTcp = true }.NetworkCapabilities.HasFlag(ServerNetworkCapability.Udp));
        Assert.IsTrue(new AnyTlsServer().NetworkCapabilities.HasFlag(ServerNetworkCapability.Udp));
        Assert.IsTrue(new TuicServer().NetworkCapabilities.HasFlag(ServerNetworkCapability.Udp));
    }

    [TestMethod]
    public async Task XrayHttpProxyConfigUsesHttpOutboundAsync()
    {
        var server = new HttpProxyServer
        {
            Hostname = "127.0.0.1",
            Port = 8080,
            Username = "user",
            Password = "password",
            Headers = "{\"X-Test\":\"value\"}",
            UseTls = true,
            ServerName = "proxy.example.test"
        };
        var config = await V2rayConfigUtils.GenerateClientConfigAsync(server);
        var json = JsonSerializer.Serialize(config, NetchX.Global.NewCustomJsonSerializerOptions());
        using var document = JsonDocument.Parse(json);
        Assert.AreEqual("http", document.RootElement.GetProperty("outbounds")[0].GetProperty("protocol").GetString());
        var stream = document.RootElement.GetProperty("outbounds")[0].GetProperty("streamSettings");
        Assert.IsFalse(stream.TryGetProperty("allowInsecure", out _));
    }

    [TestMethod]
    public async Task SingBoxGeneratedConfigsPassPinnedLocalRuntimeCheckAsync()
    {
        var binary = FindWorkspaceFile("Other", "sing-box", "sing-box.exe");
        if (binary == null)
            return;

        var servers = new Server[]
        {
            new AnyTlsServer { Hostname = "127.0.0.1", Port = 443, Password = "password" },
            new HysteriaServer { Hostname = "127.0.0.1", Port = 443, UpMbps = 100, DownMbps = 100, Auth = "password", ServerPorts = "2000:3000", HopInterval = "30s" },
            new Hysteria2Server { Hostname = "127.0.0.1", Port = 443, Password = "password", ServerPorts = "2000:3000", HopInterval = "30s" },
            new TuicServer { Hostname = "127.0.0.1", Port = 443, UserID = "bf000d23-0752-40b4-affe-68f7707a9661", Password = "password" },
            new NaiveServer { Hostname = "127.0.0.1", Port = 443, Username = "user", Password = "password", Certificate = "-----BEGIN CERTIFICATE-----\nvalue\n-----END CERTIFICATE-----" },
            new ShadowTlsServer { Hostname = "127.0.0.1", Port = 443, Password = "outer", EncryptMethod = "aes-128-gcm", ShadowsocksPassword = "inner" },
            new SSHServer { Hostname = "127.0.0.1", Port = 22, User = "root", Password = "password" }
        };

        foreach (var server in servers)
        {
            var config = await SingBoxConfigUtils.GenerateClientConfigAsync(server, "127.0.0.1", 2801);
            var configPath = Path.Combine(Path.GetTempPath(), $"netchx-sing-box-{Guid.NewGuid():N}.json");
            try
            {
                await File.WriteAllTextAsync(configPath, JsonSerializer.Serialize(config, NetchX.Global.NewCustomJsonSerializerOptions()));
                using var process = Process.Start(new ProcessStartInfo(binary, $"check -c \"{configPath}\"")
                {
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                })!;
                await process.WaitForExitAsync();
                var output = await process.StandardOutput.ReadToEndAsync() + await process.StandardError.ReadToEndAsync();
                Assert.AreEqual(0, process.ExitCode, $"sing-box rejected {server.Type}: {output}");
            }
            finally
            {
                File.Delete(configPath);
            }
        }
    }

    [TestMethod]
    public void SsrSettingsMigrationRemovesOnlyLegacyRecordsAndProfiles()
    {
        var options = NetchX.Global.NewCustomJsonSerializerOptions();
        options.Converters.Add(new NetchX.JsonConverter.ServerConverterWithTypeDiscriminator());
        var settings = JsonSerializer.Deserialize<Setting>("""
            {
              "Server": [
                { "Type": "SSR", "Hostname": "ssr.example.test", "Port": 8388, "Remark": "legacy" },
                { "Type": "SOCKS", "Hostname": "socks.example.test", "Port": 1080, "Remark": "current" }
              ],
              "Profiles": [
                { "Index": 0, "ServerRemark": "legacy", "ModeRemark": "Process", "ProfileName": "legacy profile" },
                { "Index": 1, "ServerRemark": "current", "ModeRemark": "Process", "ProfileName": "current profile" }
              ]
            }
            """, options)!;

        var migrated = Configuration.MigrateRemovedSsrProfiles(settings, out var removed);

        Assert.IsTrue(migrated);
        Assert.AreEqual(1, removed);
        Assert.AreEqual(1, settings.Server.Count);
        Assert.AreEqual("current", settings.Server.Single().Remark);
        Assert.AreEqual(1, settings.Profiles.Count);
        Assert.AreEqual("current", settings.Profiles.Single().ServerRemark);
    }

    private static string FindWorkspaceFile(params string[] pathParts)
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory != null; directory = directory.Parent)
        {
            var candidate = Path.Combine(new[] { directory.FullName }.Concat(pathParts).ToArray());
            if (File.Exists(candidate))
                return candidate;
        }
        return null;
    }

}
