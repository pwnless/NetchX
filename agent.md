# Netch Architecture and Maintenance Guide

This document describes the current codebase and the constraints that apply when changing it. It is intended for maintainers and automation agents. It covers the .NET 10 application, the native forwarding components, the supported runtime payload, and the release process.

## 1. Project profile

Netch is a Windows x64 proxy client. The WinForms application selects a server and a traffic mode. The selected mode forwards traffic to either a directly configured SOCKS5 server or a local SOCKS5 endpoint provided by a protocol controller.

The current release line is `2.0.0`:

- `Netch/Netch.csproj` targets `net10.0-windows` and carries matching package metadata.
- `common.props` defines `net10.0-windows`, `win-x64`, C# `latest`, and nullable-reference support for SDK-style projects.
- `Netch/Controllers/UpdateChecker.cs` contains the displayed and release-comparison version.
- `Netch/Properties/AssemblyInfo.cs` supplies the effective PE assembly, file, and informational versions because `GenerateAssemblyInfo` is disabled.

When changing the version, update all of these values together. The currently published executable reports assembly and file version `2.0.0.0` and product version `2.0.0`.

The main application is Per-Monitor V2 DPI aware. `Program.Main` must call `Application.SetHighDpiMode(HighDpiMode.PerMonitorV2)` before any WinForms object, `Global` member, or form is created. Forms use `AutoScaleMode.Dpi` with a 96-DPI design baseline. Do not restore font-based scaling, DPI-unaware mode, or a conflicting DPI declaration in `App.manifest`.

## 2. Repository layout

| Path | Purpose |
| --- | --- |
| `Netch/` | .NET 10 WinForms application: forms, configuration, models, controllers, protocol support, P/Invoke, and resources. |
| `Tests/` | MSTest managed regression project targeting `net10.0-windows`. |
| `Redirector/` | Native C++20 NetFilter integration and SOCKS5 TCP, UDP, DNS, and ICMP forwarding. It builds `Redirector.bin` and `nfapi.dll`. |
| `Redirector/Tests/` | Standalone native regression sources for Redirector. They are not included by `Redirector.vcxproj`. |
| `RedirectorTester/` | .NET Framework 4.8 x64 end-to-end test utility for the native driver path. |
| `RouteHelper/` | Native C++ Windows IP Helper API wrapper used to configure TUN addresses and routes. It builds `RouteHelper.bin`. |
| `Storage/` | Runtime data copied into a release, including modes, translations, DNS configuration, the NetFilter driver, and the runtime component inventory. |
| `Other/` | Build and staging inputs for AioDNS, pcap2socks, tun2socks, v2ray-sn, Wintun, and compatibility sources. |
| `wintun/` | Local Wintun distribution used by the Wintun staging script. |
| `pcap2socks/` | Local pcap2socks distribution used by the staging script. |
| `tun2socks.exe` | Local tun2socks 2.7 release binary used by the staging script. |
| `build.ps1` | Complete-release build script. It only accepts output paths under `release/`, `artifacts/`, or `build/`. |
| `clean.ps1` | Cleanup script for generated outputs. Pass `-KeepBuild` to preserve a completed release directory. |

The solution contains the main application, managed tests, Redirector, RouteHelper, and RedirectorTester. The native projects are x64 projects and use the Visual C++ toolchain.

## 3. Control plane

```text
WinForms UI
  |
  +-- MainController.StartAsync(server, mode)
        |
        +-- Resolve the server and prepare firewall and port state
        +-- Use a direct Socks5Server or start V2rayController
        +-- Get the selected IModeController from ModeService
        +-- Start the ProcessMode, TunMode, or ShareMode controller
```

`MainController` owns the active server, mode, server controller, mode controller, and SOCKS5 endpoint. An `AsyncSemaphore` serializes startup and shutdown. If startup fails while the semaphore is held, `StartAsync` calls its private `StopCoreAsync` method before releasing the semaphore. Do not replace that with the public `StopAsync` method: releasing the semaphore first can let another startup install controllers that the failed startup then stops.

Startup resolves the server hostname, warms the configured STUN hostname lookup, adds Netch firewall rules, chooses a mode controller, and frees a conflicting application-owned TCP listener if needed. A directly selected SOCKS5 server is used when its authentication requirements are compatible with the selected mode. Other server types start `V2rayController`, which exposes a local SOCKS5 endpoint for the mode.

Shutdown stops the server and mode controllers together, clears the status-port text, and finally clears all active controller references. Mode implementations must not create competing global lifecycle state.

## 4. Traffic modes

### ProcessMode

`NFController` configures and starts `bin/Redirector.bin` through `Netch/Interops/Redirector.cs`. It merges ProcessMode settings with global Redirector settings, configures DNS and SOCKS5 properties, validates native regular expressions, and installs or updates the `netfilter2` driver when necessary.

Process rules are passed to the native component as handle and bypass regular expressions. Netch's own installation directory is always bypassed. The native component also excludes its own process ID, so a realistic ProcessMode test must originate traffic from a separate target process.

The `Redirector.bin` C ABI is:

| Export | Purpose |
| --- | --- |
| `aio_register` and `aio_unregister` | Register or unregister the `netfilter2` driver. Administrative privileges are required. |
| `aio_dial` | Set filtering, DNS, SOCKS5, and regular-expression options. Call it before initialization. |
| `aio_init` | Start Winsock, native workers, and the NetFilter SDK. |
| `aio_free` | Stop workers, drain I/O, and release the SDK. |
| `aio_getUP` and `aio_getDL` | Return Redirector traffic counters. |

The `AIO_TYPE` order must stay synchronized across `Redirector/Based.h`, `Redirector/Redirector.cpp`, and `Netch/Interops/Redirector.cs`.

### TunMode

`TUNController` starts `bin/tun2socks.exe` 2.7 using argument-safe `ProcessStartInfo.ArgumentList` values:

```text
--device tun://netch
--proxy socks5://[credentials@]host:port
--mtu 1500
--loglevel warn
```

It waits for the `netch` Wintun interface, obtains its interface index, assigns its IPv4 address through `RouteHelper.bin`, and installs the necessary route rules. The controller records whether the route context was successfully created, allowing startup cleanup to avoid deleting routes from uninitialized state.

`bin/wintun.dll` is application-local and is loaded by tun2socks. Do not copy it to, overwrite it in, or otherwise depend on `System32`. Wintun 0.14.1 is intentionally paired with tun2socks 2.7; it is not compatible with the obsolete `tun2socks.bin` integration.

When custom DNS is disabled, TUN mode starts AioDNS on `127.0.0.1:53`, configures the virtual interface to use that address, and adds DNS routes. tun2socks 2.7 does not expose the legacy DNS interception behavior, so this explicit interface DNS configuration is required. Stop order is route cleanup, tun2socks termination, then AioDNS shutdown.

### ShareMode

`PcapController` derives from `Guard` and starts `bin/pcap2socks.exe`. It selects the best outbound interface, passes an Npcap-compatible interface path and the SOCKS5 destination, adds credentials when needed, and streams child-process output into `LogForm`. ShareMode requires an Npcap or WinPcap-compatible capture interface.

### DNS service

`DNSController` configures `bin/aiodns.bin` through its P/Invoke interface. TUN mode uses it whenever custom DNS is disabled. Its listener port must be `53` for the tun2socks 2.7 integration.

## 5. Redirector native data plane

```text
Target process traffic
  |
  v
netfilter2.sys callbacks
  |
  +-- TCP: loopback listener -> SOCKS CONNECT -> bidirectional IOCP pumps
  +-- UDP: bounded dispatch queue -> SOCKS UDP Associate -> shared UDP IOCP receive
  +-- DNS: bounded worker queue -> direct UDP or SOCKS UDP DNS transport
  +-- ICMP: bounded deadline queue -> delayed echo-reply injection
```

| Component | Responsibility |
| --- | --- |
| `Redirector.cpp` | Implements the C ABI, initializes NetFilter, and owns the top-level native lifecycle. |
| `Based.*` | Shared configuration, regular-expression rules, common includes, and ABI enums. |
| `EventHandler.*` | NetFilter callbacks, process-rule decisions, UDP context management, dispatch queues, and UDP receive IOCP workers. |
| `TCPHandler.*` | Loopback listener, bounded SOCKS setup workers, TCP session ownership, and bidirectional IOCP forwarding. |
| `DNSHandler.*` | DNS identification, bounded queueing, transaction IDs, direct DNS, SOCKS UDP DNS, and shutdown. |
| `SocksHelper.*` | SOCKS5 negotiation, RFC 1929 authentication, CONNECT, UDP Associate, and UDP encapsulation. |
| `IPEventHandler.*` | Bounded delayed ICMP echo-reply injection. |
| `Utils.*` | Native utility routines. |

### TCP forwarding

The NetFilter TCP callback redirects handled connections to a local listener while preserving the original destination in a TCP context. The listener enqueues accepted sockets to a bounded setup queue. Setup workers establish SOCKS5 CONNECT and create a `TcpSession` with two `TcpPump` instances.

Both directions use a shared I/O completion port. A pump posts receives and continues partial sends until the entire buffer is transmitted. When one direction receives EOF, it calls `shutdown(SD_SEND)` only on its destination. The reverse direction remains live until its own EOF. Do not replace this half-close behavior with session-wide cancellation.

TCP setup and I/O worker pools use `max(2, logical processors * 2)` workers, capped at 16. The setup queue is capped at 1024 sockets, and each pump buffer is 64 KiB.

### UDP forwarding

`udpSend` must only copy callback-owned data and enqueue it. It must not establish a SOCKS association or perform network I/O on the NetFilter callback thread. Dispatch workers initialize the endpoint association, send SOCKS UDP packets, and submit one `WSARecv` operation per active endpoint to a shared completion port.

UDP completion workers decode SOCKS UDP replies, call `nf_udpPostReceive`, and submit the next receive. This event-driven receive model replaces the former one-blocking-receive-thread-per-endpoint design.

Current admission limits are intentional availability safeguards:

- At most 1024 UDP endpoint contexts.
- At most 64 queued packets per endpoint.
- At most 4096 queued packets and 16 MiB queued UDP data globally.
- Oversized packets, closed contexts, or exhausted budgets are dropped.
- When endpoint capacity is exhausted, filtering is disabled for that endpoint so the application can use its direct network path rather than waiting behind unbounded work.

The SOCKS UDP TCP control and keepalive connection remains per association. The receive path is event-driven, but this control path is still a potential linear thread-growth area.

### DNS forwarding

DNS UDP traffic is identified on port 53. If DNS filtering is disabled, Redirector posts the packet directly. Otherwise, the request is copied into the DNS queue. DNS uses 16 persistent workers and a bounded queue of 1024 requests.

Each worker owns either a direct UDP transport or a SOCKS UDP association. Before sending a query, it stores the application's DNS transaction ID and replaces it with a worker-owned ID. It accepts only a matching reply and restores the original ID before calling `nf_udpPostReceive`. This prevents a delayed reply for a timed-out request from being delivered to a later request that reused the socket.

### Delayed ICMP replies

`ipSend` never sleeps on a NetFilter callback. It validates and copies eligible IPv4 ICMP echo requests, then puts them into a bounded priority queue ordered by `steady_clock` deadlines. A worker creates and injects the reply when due. Earlier newly queued deadlines wake and reschedule the worker. On exhaustion, invalid input, or shutdown, the original packet follows the normal send path to preserve connectivity.

## 6. Required lifetime and concurrency rules

### Do not block NetFilter callbacks

NetFilter callbacks may run on SDK or driver threads. The following operations are forbidden in callback paths:

- DNS resolution, SOCKS handshake, SOCKS association, or other blocking network setup.
- Unbounded waits, worker joins, or disk and console activity in hot paths.
- Retaining callback pointers after the callback returns.
- Holding a cross-component lock while calling a NetFilter API.

Copy all required callback data into a bounded work item before scheduling background work.

### Copy UDP options correctly

`target`, payload, and `PNF_UDP_OPTIONS` are callback-owned. The exact byte count of the options object is:

```cpp
offsetof(NF_UDP_OPTIONS, options) + options->optionsLength
```

Validate `optionsLength` before copying. Do not use `sizeof(NF_UDP_OPTIONS)` for its flexible trailing array.

### Drain I/O before releasing ownership

An object that has pending `OVERLAPPED` operations must remain alive until every completion has been consumed. During UDP shutdown, mark contexts closed, cancel or close their sockets, drain completions, then stop receive workers and close the completion port. During TCP shutdown, cancel session I/O while TCP IOCP workers are still active and wait for sessions to leave the active list before closing the completion port.

Normal TCP EOF is not an error: preserve the reverse flow after forwarding FIN. Error handling may abort both pumps.

### Preserve bounded work

Do not replace queues, context maps, deadline queues, or worker pools with unbounded equivalents. The limits are designed to keep a traffic storm from turning into unbounded memory usage, thread creation, or driver callback stalls.

## 7. Build and release

### Prerequisites

- Windows x64.
- .NET 10 SDK.
- Visual Studio with MSBuild and the C++ x64 toolchain. `build.ps1` finds MSBuild through `vswhere` when available.
- Go only when rebuilding applicable external components from source.
- Administrative privileges for driver installation and real ProcessMode tests.

### Complete release build

```powershell
.\build.ps1 -Configuration Release -OutputPath build
```

The script deletes and recreates the selected output directory, so only pass an approved disposable output location. It performs these steps:

1. Creates the release layout and copies `Storage` assets, including `i18n`, `mode`, the driver, DNS files, and `Storage/README.md`.
2. Uses a root `Country.mmdb` when present; otherwise downloads the current GeoIP asset and validates its release metadata.
3. Runs `Other/build.ps1`, which stages the required external binaries.
4. Publishes Netch as a self-contained, single-file `win-x64` executable.
5. Builds Redirector and RouteHelper in Release x64 configuration.
6. Verifies that all required release files are present and removes root-level PDB and XML files for Release output.

The current staging scripts pin the following local external inputs by SHA-256:

| Component | Expected version |
| --- | --- |
| Wintun | 0.14.1 |
| tun2socks | 2.7 |
| pcap2socks | 0.6.2 |

Do not replace one of these binaries without reviewing compatibility, updating its version and digest in the staging script, rebuilding the release, and testing the affected mode.

To create a GitHub Release archive after a successful build:

```powershell
$archive = Join-Path (Get-Location) 'build\Netch-2.0.0-win-x64.zip'
$items = Get-ChildItem -LiteralPath .\build -Force | Where-Object { $_.FullName -ne $archive } | Select-Object -ExpandProperty FullName
Compress-Archive -LiteralPath $items -DestinationPath $archive -CompressionLevel Optimal
Get-FileHash -LiteralPath $archive -Algorithm SHA256
```

## 8. Verification

Run managed tests with:

```powershell
dotnet test .\Tests\Tests.csproj --configuration Release --framework net10.0-windows
```

For a native-only change, build and run the corresponding standalone source in `Redirector/Tests`. The available regressions cover SOCKS parsing, DNS queue behavior, UDP dispatch and shutdown, TCP shutdown, TCP half-close behavior, delayed ICMP scheduling, and ICMP delay configuration. These files are not part of the main `.vcxproj`; compile them with the C++20 x64 environment, `ws2_32.lib`, the NetFilter import library, and an application-local `nfapi.dll` on `PATH`.

`RedirectorTester` is the real-driver test utility. Rebuild it after a Redirector change, then run the stress mode from an elevated terminal only when the NetFilter driver is already installed and healthy:

```powershell
.\RedirectorTester\bin\Release\RedirectorTester.exe --stress 128
```

For each release, also verify the following on a real target network:

- ProcessMode startup, stop, and failure rollback with a remote SOCKS5 server.
- TunMode interface creation, routing, DNS behavior, and complete route cleanup.
- ShareMode startup on a supported capture interface.
- IPv4, IPv6 where the mode supports it, SOCKS authentication, high RTT, packet loss, and concurrent connections.
- Main-window behavior at 100, 150, and 200 percent DPI, including moves between monitors.

Local loopback throughput confirms implementation behavior and byte integrity. It is not evidence of public-network or encrypted-proxy throughput.

## 9. Current limitations and priorities

1. SOCKS UDP control and keepalive connections are still per association. Moving them to a shared cancellable event model is the next significant native scalability opportunity.
2. Process-rule resolution can benefit from a bounded, invalidated, time-limited PID decision cache during short-connection bursts.
3. There is no comprehensive automated baseline for remote latency, loss, IPv6, authenticated servers, or very high concurrency.
4. DNS worker serialization is intentional for correctness. Any parallel DNS redesign needs explicit transaction ownership, timeout cleanup, and late-response isolation.
5. Update distribution has no independent signature, rollback protection, or key-rotation design.
6. Server credentials and private keys may be stored in configuration. Treat configuration files as sensitive.
7. External binaries and downloaded data require continuing provenance, hash, and reproducibility review.

## 10. Maintenance checklist

Before changing code:

1. Identify whether the change affects control-plane lifecycle, ProcessMode, TUN, ShareMode, TCP, UDP, DNS, ICMP, or packaging.
2. Preserve the meaning and lifetime of targets, address families, `ENDPOINT_ID`, credentials, and NetFilter options.
3. Copy driver callback data before deferring work, and keep all queue and context limits bounded.
4. Design cancellation, completion draining, and ownership before adding asynchronous I/O.
5. Do not add per-packet logging, per-connection threads, synchronous network setup, or unbounded queues to a release hot path.
6. Run the managed test suite and every relevant native regression. Use RedirectorTester and manual mode validation when the change crosses a driver or external-process boundary.
7. Record test machine, connection count, data direction, payload validation, and network conditions with any performance result.
8. Keep README files, code comments, and this document in English. Keep localized runtime strings and localization resources unchanged unless their translation is intentionally being changed.
9. Do not recreate deleted planning or change-log files unless explicitly requested. Do not use destructive source-control recovery commands to undo workspace changes.
