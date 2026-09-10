# NetchX

<p align="center">
  <img src="https://github.com/pwnless/NetchX/blob/main/NetchX/Resources/NetchX.png?raw=true" width="128" alt="NetchX logo" />
</p>

<p align="center">A Windows x64 proxy client with process-based, virtual-adapter, and network-sharing traffic modes.</p>

<p align="center">
  <a href="https://github.com/pwnless/NetchX/releases"><img src="https://img.shields.io/github/v/release/pwnless/NetchX?style=flat-square" alt="GitHub release" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-GPL--3.0-blue?style=flat-square" alt="GPL-3.0 license" /></a>
  <img src="https://img.shields.io/badge/.NET-10.0-512BD4?style=flat-square&logo=dotnet" alt=".NET 10" />
  <img src="https://img.shields.io/badge/platform-Windows%20x64-0078D4?style=flat-square&logo=windows" alt="Windows x64" />
</p>

<p align="center">
  <a href="#quick-start">Quick start</a>
  ·
  <a href="#whats-new-since-197">1.9.7 → 2.0.0</a>
</p>

> The current release line is **2.0.1**. It retains NetchX's core proxy behavior while modernizing the runtime, high-DPI UI, native forwarding reliability, and concurrent data plane.

## What's new since 1.9.7

Version 2.0.0 is more than a version-number refresh. It addresses long-standing lifecycle, concurrency, and Windows network-I/O issues while upgrading the runtime and TUN data-plane dependencies.

| Area | Main changes in 2.0.0 |
| --- | --- |
| Runtime and UI | The main application now targets **.NET 10**. WinForms uses **Per-Monitor V2** DPI awareness and a consistent 96-DPI design baseline for clearer layouts at 125%, 150%, 200%, and across monitors. |
| TCP forwarding | Established ProcessMode TCP flows use shared **IOCP bidirectional pumps**. SOCKS setup uses a bounded worker queue, forwarding buffers are 64 KiB, and partial sends are handled correctly. |
| TCP correctness | TCP half-close is preserved: one direction can send FIN while the other still receives its complete response. The Windows connect context is updated after `WSAConnectByNameW` so `shutdown(SD_SEND)` can propagate FIN reliably. |
| UDP forwarding | UDP sends leave the NetFilter callback through a bounded dispatch queue. UDP replies use shared IOCP `WSARecv` workers instead of one blocking receive thread per endpoint. |
| DNS | Bounded DNS workers reuse their transport. Transaction IDs are replaced and matched so a late response from a timed-out query cannot be delivered to a later query. |
| Reliability and boundaries | Fixed SOCKS5 RFC 1929 credential truncation, SOCKS/UDP short-packet handling, blocking ICMP callbacks, startup-cleanup races, and several shutdown-order defects. |
| TUN and packaging | Updated to application-local **Wintun 0.14.1** and **tun2socks 2.7** without overwriting the system `wintun.dll`. The build validates critical external components and GeoIP download metadata. |
| Xray core | Bundles current **Xray-core** instead of the obsolete SagerNet V2Ray fork. VLESS and VMess profiles support RAW, XHTTP, mKCP, gRPC, WebSocket, HTTPUpgrade, and Hysteria transports; REALITY; and VLESS XTLS Vision. |

### Performance principles

- NetFilter callbacks do not perform SOCKS handshakes, DNS resolution, disk I/O, or long waits.
- Connection setup, UDP, DNS, and delayed ICMP work use bounded queues or context limits to prevent connection storms from becoming unbounded thread or memory growth.
- TCP, UDP, and DNS shutdown paths cancel pending I/O and wait for workers to finish before releasing their state.

The local loopback test suite covers 128 concurrent TCP connections with strict byte validation, SOCKS UDP, and the NetFilter path. Those results validate implementation behavior and local throughput trends only; they are **not** a public-network, long-distance, or encrypted-proxy performance guarantee.

## Features

### Traffic modes

| Mode | Description |
| --- | --- |
| `ProcessMode` | Uses the NetFilter driver to intercept a process's TCP/UDP traffic and forward it through a local SOCKS5 egress. |
| `TunMode` | Creates a Wintun virtual adapter and sends routed system traffic to SOCKS5 through tun2socks. |
| `ShareMode` | Shares traffic from a selected network interface through the Npcap/WinPcap-compatible path and pcap2socks. |

### Supported proxy protocols

- [SOCKS5](https://www.rfc-editor.org/rfc/rfc1928)
- [Shadowsocks](https://shadowsocks.org/)
- [ShadowsocksR](https://github.com/shadowsocksrr/shadowsocksr-libev) (legacy fallback)
- SSH (legacy fallback)
- [WireGuard](https://www.wireguard.com/)
- [Trojan](https://trojan-gfw.github.io/trojan/)
- [VMess](https://www.v2fly.org/)
- [VLESS](https://xtls.github.io/)

Xray-core is the bundled runtime for all Xray-supported profiles. ShadowsocksR and SSH use a separately bundled, legacy SagerNet fallback because current Xray no longer implements those outbounds. That fallback is compatibility-only; it does not provide Xray's modern transports, REALITY, or Vision features.

### Modern Xray transports

VLESS and VMess editors expose Xray's current `raw`, `xhttp`, `mkcp`, `grpc`, `websocket`, `httpupgrade`, and `hysteria` transports. VLESS also exposes the XTLS Vision flows. REALITY profiles require a server name, public key, fingerprint, and optional short ID and SpiderX; Xray permits REALITY only with RAW, XHTTP, or gRPC. Vision requires VLESS over RAW with TLS or REALITY.

Saved profiles using `tcp`, `kcp`, or `ws` are mapped to Xray's current transport names. Legacy HTTP/2, QUIC, and standalone `xtls` security have been removed by Xray-core, so NetchX asks users to migrate those profiles to XHTTP, Hysteria, or TLS/REALITY with Vision as appropriate.

## Quick start

1. Download `NetchX-2.0.1-win-x64.zip` for your system from [Releases](https://github.com/pwnless/NetchX/releases).
2. **Extract the entire archive** to a writable directory. `bin`, `i18n`, and `mode` alongside `NetchX.exe` are required at runtime.
3. Run `NetchX.exe` as an administrator, add or import a server, select a mode, and start it.

`ProcessMode` requires NetFilter driver privileges. `TunMode` creates and configures a virtual adapter and routes. `ShareMode` requires an available Npcap/WinPcap-compatible interface. Save the configuration of other VPN or proxy tools first: running multiple tools that modify routes and DNS simultaneously can produce unexpected results.

## Build

### Prerequisites

- Windows x64
- .NET 10 SDK
- Visual Studio with MSBuild and the C++ x64 toolchain (verified with Visual Studio 2026)
- Go, only when rebuilding optional external components

### Create a complete release package

```powershell
.\build.ps1 -Configuration Release -OutputPath build
```

The script publishes the main application, builds `Redirector` and `RouteHelper`, stages external components, and verifies critical package files. The result is written to `build\`.

The Xray staging script uses the checked-out sibling release at `..\xray-core\release` by default. When that directory is absent—such as on GitHub Actions—it downloads the pinned Xray 26.3.27 Windows archive and verifies both the archive and its extracted runtime files. Set `NETCHX_XRAY_RELEASE` to another extracted, hash-pinned Xray release directory when building elsewhere.

### Run managed regression tests

```powershell
dotnet test .\Tests\Tests.csproj --configuration Release --framework net10.0-windows
```

## Verified scope and limitations

The current work has been validated with .NET 10 Release builds, managed regression tests, core native builds, release-package checks, and local SOCKS5/NetFilter TCP and UDP loopback tests.

Before a production release, validate the following in the target network environment:

- ProcessMode, TunMode, and ShareMode startup, shutdown, and rollback against a real remote SOCKS5 server.
- IPv6, authentication, high RTT, packet loss, and high-concurrency scenarios.
- Layout at 100%, 150%, and 200% DPI, including moves between monitors.
- The SOCKS UDP TCP control/keepalive connection is still per endpoint; moving it to a shared event-driven model remains future performance work.

## License

NetchX is distributed under the [GPL-3.0](LICENSE) license.
