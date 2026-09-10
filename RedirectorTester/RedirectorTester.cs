using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace RedirectorTester
{
    public class RedirectorTester
    {
        private const int PayloadSize = 8 * 1024 * 1024;
        // The default exercises enough live connections to prove the bounded
        // setup pool and IOCP forwarding path under sustained load.
        private static int parallelConnections = 64;
        private const int UdpRedirectedPort = 9000;
        private static readonly byte[] UdpProbePayload = { 0x55, 0x44, 0x50, 0x2D, 0x50, 0x52, 0x4F, 0x42, 0x45 };
        private static int socksConnectRequests;
        private static int socksUdpAssociations;

        public enum NameList : int
        {
            AIO_FILTERLOOPBACK,
            AIO_FILTERINTRANET,
            AIO_FILTERPARENT,
            AIO_FILTERICMP,
            AIO_FILTERTCP,
            AIO_FILTERUDP,
            AIO_FILTERDNS,
            AIO_ICMPING,
            AIO_DNSONLY,
            AIO_DNSPROX,
            AIO_DNSHOST,
            AIO_DNSPORT,
            AIO_TGTHOST,
            AIO_TGTPORT,
            AIO_TGTUSER,
            AIO_TGTPASS,
            AIO_CLRNAME,
            AIO_ADDNAME,
            AIO_BYPNAME
        }

        [DllImport("Redirector.bin", CallingConvention = CallingConvention.Cdecl)]
        public static extern bool aio_register([MarshalAs(UnmanagedType.LPWStr)] string value);

        [DllImport("Redirector.bin", CallingConvention = CallingConvention.Cdecl)]
        public static extern bool aio_unregister([MarshalAs(UnmanagedType.LPWStr)] string value);

        [DllImport("Redirector.bin", CallingConvention = CallingConvention.Cdecl)]
        public static extern bool aio_dial(NameList name, [MarshalAs(UnmanagedType.LPWStr)] string value);

        [DllImport("Redirector.bin", CallingConvention = CallingConvention.Cdecl)]
        public static extern bool aio_init();

        [DllImport("Redirector.bin", CallingConvention = CallingConvention.Cdecl)]
        public static extern void aio_free();

        [DllImport("Redirector.bin", CallingConvention = CallingConvention.Cdecl)]
        public static extern ulong aio_getUP();

        [DllImport("Redirector.bin", CallingConvention = CallingConvention.Cdecl)]
        public static extern ulong aio_getDL();

        public static int Main(string[] args)
        {
			if (args.Length == 2 && args[0] == "--stress")
			{
				if (!int.TryParse(args[1], out parallelConnections) || parallelConnections < 1 || parallelConnections > 128)
				{
					Console.Error.WriteLine("--stress requires a connection count from 1 through 128.");
					return 1;
				}
				return Main(new string[0]);
			}
			if (args.Length == 4 && args[0] == "--probe")
				return RunProbe(IPAddress.Parse(args[1]), int.Parse(args[2]), int.Parse(args[3]));
			if (args.Length == 6 && args[0] == "--socks-probe")
				return RunSocksProbe(IPAddress.Parse(args[1]), int.Parse(args[2]), IPAddress.Parse(args[3]), int.Parse(args[4]), int.Parse(args[5]));
			if (args.Length == 4 && args[0] == "--parallel-probe")
				return RunParallelProbe(IPAddress.Parse(args[1]), int.Parse(args[2]), int.Parse(args[3]));
			if (args.Length == 6 && args[0] == "--parallel-socks-probe")
				return RunParallelSocksProbe(IPAddress.Parse(args[1]), int.Parse(args[2]), IPAddress.Parse(args[3]), int.Parse(args[4]), int.Parse(args[5]));
			if (args.Length == 3 && args[0] == "--udp-probe")
				return RunUdpProbe(IPAddress.Parse(args[1]), int.Parse(args[2]));

            TcpListener socksListener = null;
            TcpListener payloadListener = null;
			UdpClient udpRelay = null;
            var redirectorStarted = false;

            try
            {
                var redirectedDestination = IPAddress.Parse("192.0.2.1");
                const int redirectedPort = 9;

                payloadListener = new TcpListener(IPAddress.Loopback, 0);
				payloadListener.Start(parallelConnections * 2);

                socksListener = new TcpListener(IPAddress.Loopback, 0);
				socksListener.Start(parallelConnections * 2 + 1);
				udpRelay = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));

                var socksPort = ((IPEndPoint)socksListener.LocalEndpoint).Port;
                var payloadPort = ((IPEndPoint)payloadListener.LocalEndpoint).Port;

				var payloadTask = Task.Run(() => ServePayloads(payloadListener, parallelConnections * 2));
				var socksTask = Task.Run(() => ServeSocks(socksListener, redirectedDestination, redirectedPort, UdpRedirectedPort, payloadPort, parallelConnections * 2 + 1, udpRelay));

				var directStopwatch = Stopwatch.StartNew();
				var directBytes = RunParallelSocksProbeProcess(socksPort, redirectedDestination, redirectedPort, parallelConnections);
				directStopwatch.Stop();

                ConfigureRedirector(socksPort);
                if (!aio_init())
                    throw new InvalidOperationException("aio_init failed; ensure the netfilter2 driver is installed and running.");

                redirectorStarted = true;
                Console.WriteLine("Redirector initialized. SOCKS5={0}, redirected destination={1}:{2}", socksPort, redirectedDestination, redirectedPort);

                var stopwatch = Stopwatch.StartNew();
				var totalBytes = RunParallelProbeProcess(redirectedDestination, redirectedPort, parallelConnections);
                stopwatch.Stop();
				RunUdpProbeProcess(redirectedDestination, UdpRedirectedPort);

                if (!Task.WaitAll(new[] { payloadTask, socksTask }, TimeSpan.FromSeconds(15)))
                    throw new TimeoutException("Local SOCKS5 or payload server did not complete.");

				if (Volatile.Read(ref socksConnectRequests) != parallelConnections * 2)
                    throw new InvalidOperationException("Traffic did not reach the local SOCKS5 server.");
				if (Volatile.Read(ref socksUdpAssociations) != 1)
					throw new InvalidOperationException("UDP traffic did not reach the local SOCKS5 server.");

				var directMegabitsPerSecond = directBytes * 8d / directStopwatch.Elapsed.TotalSeconds / 1_000_000d;
                var megabitsPerSecond = totalBytes * 8d / stopwatch.Elapsed.TotalSeconds / 1_000_000d;
				Console.WriteLine("Parallel baseline ({0} connections): {1:N2} MiB per direction in {2:N3}s ({3:N2} Mbit/s per direction, {4:N2} Mbit/s aggregate) through local SOCKS5 without Redirector.",
					parallelConnections,
					directBytes / 1024d / 1024d,
					directStopwatch.Elapsed.TotalSeconds,
					directMegabitsPerSecond,
					directMegabitsPerSecond * 2);
				Console.WriteLine("PASS: {0} parallel connections transferred {1:N2} MiB per direction in {2:N3}s ({3:N2} Mbit/s per direction, {4:N2} Mbit/s aggregate); SOCKS CONNECT requests={5}, UDP ASSOCIATE requests={6}; Redirector counters UP={7}, DL={8}",
					parallelConnections,
                    totalBytes / 1024d / 1024d,
                    stopwatch.Elapsed.TotalSeconds,
                    megabitsPerSecond,
					megabitsPerSecond * 2,
                    socksConnectRequests,
					socksUdpAssociations,
                    aio_getUP(),
                    aio_getDL());
                return 0;
            }
            catch (Exception exception)
            {
                Console.Error.WriteLine("FAIL: {0}", exception);
                return 1;
            }
            finally
            {
                if (redirectorStarted)
                    aio_free();

                if (socksListener != null)
                    socksListener.Stop();
                if (payloadListener != null)
                    payloadListener.Stop();
				if (udpRelay != null)
					udpRelay.Close();
            }
        }

		private static int RunProbe(IPAddress destination, int port, int iterations)
		{
			try
			{
				var totalBytes = 0L;
				for (var i = 0; i < iterations; ++i)
					totalBytes += DownloadThroughRedirector(destination, port);

				Console.WriteLine("Probe transferred {0} bytes.", totalBytes);
				return 0;
			}
			catch (Exception exception)
			{
				Console.Error.WriteLine("Probe failed: {0}", exception);
				return 1;
			}
		}

		private static int RunSocksProbe(IPAddress socksAddress, int socksPort, IPAddress destination, int port, int iterations)
		{
			try
			{
				var totalBytes = 0L;
				for (var i = 0; i < iterations; ++i)
					totalBytes += DownloadThroughSocks(socksAddress, socksPort, destination, port);

				Console.WriteLine("Direct SOCKS probe transferred {0} bytes.", totalBytes);
				return 0;
			}
			catch (Exception exception)
			{
				Console.Error.WriteLine("SOCKS probe failed: {0}", exception);
				return -1;
			}
		}

		private static int RunParallelProbe(IPAddress destination, int port, int connections)
		{
			try
			{
				Console.WriteLine("Parallel redirected probe transferred {0} bytes across {1} connections.", RunParallelDownloads(connections, () => DownloadThroughRedirector(destination, port)), connections);
				return 0;
			}
			catch (Exception exception)
			{
				Console.Error.WriteLine("Parallel redirected probe failed: {0}", exception);
				return 1;
			}
		}

		private static int RunParallelSocksProbe(IPAddress socksAddress, int socksPort, IPAddress destination, int port, int connections)
		{
			try
			{
				Console.WriteLine("Parallel direct SOCKS probe transferred {0} bytes across {1} connections.", RunParallelDownloads(connections, () => DownloadThroughSocks(socksAddress, socksPort, destination, port)), connections);
				return 0;
			}
			catch (Exception exception)
			{
				Console.Error.WriteLine("Parallel direct SOCKS probe failed: {0}", exception);
				return 1;
			}
		}

		private static int RunUdpProbe(IPAddress destination, int port)
		{
			try
			{
				using (var client = new UdpClient(AddressFamily.InterNetwork))
				{
					client.Client.ReceiveTimeout = 10000;
					client.Connect(destination, port);
					client.Send(UdpProbePayload, UdpProbePayload.Length);

					var peer = new IPEndPoint(IPAddress.Any, 0);
					var response = client.Receive(ref peer);
					if (!peer.Address.Equals(destination) || peer.Port != port || !ByteArrayEquals(response, UdpProbePayload))
						throw new InvalidDataException("UDP response does not match the intercepted datagram.");
				}

				Console.WriteLine("UDP probe completed through Redirector.");
				return 0;
			}
			catch (Exception exception)
			{
				Console.Error.WriteLine("UDP probe failed: {0}", exception);
				return 1;
			}
		}

		private static long DownloadThroughSocks(IPAddress socksAddress, int socksPort, IPAddress destination, int port)
		{
			using (var client = new TcpClient(AddressFamily.InterNetwork))
			{
				client.ReceiveTimeout = 10000;
				client.SendTimeout = 10000;
				client.Connect(socksAddress, socksPort);
				var stream = client.GetStream();

				stream.Write(new byte[] { 0x05, 0x01, 0x00 }, 0, 3);
				var choice = ReadExact(stream, 2);
				if (choice[0] != 0x05 || choice[1] != 0x00)
					throw new InvalidDataException("Local SOCKS5 server rejected no-authentication.");

				var request = new byte[10];
				request[0] = 0x05;
				request[1] = 0x01;
				request[3] = 0x01;
				Buffer.BlockCopy(destination.GetAddressBytes(), 0, request, 4, 4);
				request[8] = (byte)(port >> 8);
				request[9] = (byte)port;
				stream.Write(request, 0, request.Length);

				var response = ReadExact(stream, 10);
				if (response[0] != 0x05 || response[1] != 0x00)
					throw new InvalidDataException("Local SOCKS5 CONNECT failed.");

				stream.WriteByte(0xA5);
				WritePayload(stream);
				stream.Flush();
				return ReadPayload(stream);
			}
		}

		private static long RunProbeProcess(IPAddress destination, int port, int iterations)
		{
			var executable = Process.GetCurrentProcess().MainModule.FileName;
			using (var probe = Process.Start(new ProcessStartInfo(executable,
				$"--probe {destination} {port} {iterations}")
			{
				UseShellExecute = false
			}))
			{
				if (!probe.WaitForExit(30000))
				{
					probe.Kill();
					throw new TimeoutException("Redirected client probe timed out.");
				}

				if (probe.ExitCode != 0)
					throw new InvalidOperationException("Redirected client probe failed with exit code " + probe.ExitCode);
			}

			return (long)PayloadSize * iterations;
		}

		private static long RunParallelProbeProcess(IPAddress destination, int port, int connections)
		{
			return RunChildProcess($"--parallel-probe {destination} {port} {connections}", 60000, "Parallel redirected client probe");
		}

		private static long RunSocksProbeProcess(int socksPort, IPAddress destination, int port, int iterations)
		{
			var executable = Process.GetCurrentProcess().MainModule.FileName;
			using (var probe = Process.Start(new ProcessStartInfo(executable,
				$"--socks-probe 127.0.0.1 {socksPort} {destination} {port} {iterations}")
			{
				UseShellExecute = false
			}))
			{
				if (!probe.WaitForExit(30000))
				{
					probe.Kill();
					throw new TimeoutException("Direct SOCKS client probe timed out.");
				}

				if (probe.ExitCode != 0)
					throw new InvalidOperationException("Direct SOCKS client probe failed with exit code " + probe.ExitCode);
			}

			return (long)PayloadSize * iterations;
		}

		private static long RunParallelSocksProbeProcess(int socksPort, IPAddress destination, int port, int connections)
		{
			return RunChildProcess($"--parallel-socks-probe 127.0.0.1 {socksPort} {destination} {port} {connections}", 60000, "Parallel direct SOCKS probe");
		}

		private static long RunChildProcess(string arguments, int timeoutMilliseconds, string description)
		{
			var executable = Process.GetCurrentProcess().MainModule.FileName;
			using (var probe = Process.Start(new ProcessStartInfo(executable, arguments)
			{
				UseShellExecute = false
			}))
			{
				if (!probe.WaitForExit(timeoutMilliseconds))
				{
					probe.Kill();
					throw new TimeoutException(description + " timed out.");
				}

				if (probe.ExitCode != 0)
					throw new InvalidOperationException(description + " failed with exit code " + probe.ExitCode);
			}

			var connections = int.Parse(arguments.Substring(arguments.LastIndexOf(' ') + 1));
			return (long)PayloadSize * connections;
		}

		private static void RunUdpProbeProcess(IPAddress destination, int port)
		{
			var executable = Process.GetCurrentProcess().MainModule.FileName;
			using (var probe = Process.Start(new ProcessStartInfo(executable, $"--udp-probe {destination} {port}")
			{
				UseShellExecute = false
			}))
			{
				if (!probe.WaitForExit(15000))
				{
					probe.Kill();
					throw new TimeoutException("Redirected UDP probe timed out.");
				}

				if (probe.ExitCode != 0)
					throw new InvalidOperationException("Redirected UDP probe failed with exit code " + probe.ExitCode);
			}
		}

        private static void ConfigureRedirector(int socksPort)
        {
            Dial(NameList.AIO_FILTERLOOPBACK, "false");
            Dial(NameList.AIO_FILTERINTRANET, "true");
            Dial(NameList.AIO_FILTERPARENT, "false");
            Dial(NameList.AIO_FILTERICMP, "false");
            Dial(NameList.AIO_FILTERTCP, "true");
			Dial(NameList.AIO_FILTERUDP, "true");
            Dial(NameList.AIO_FILTERDNS, "false");
            Dial(NameList.AIO_DNSONLY, "false");
            Dial(NameList.AIO_DNSPROX, "false");
            Dial(NameList.AIO_DNSHOST, "1.1.1.1");
            Dial(NameList.AIO_DNSPORT, "53");
            Dial(NameList.AIO_TGTHOST, "127.0.0.1");
            Dial(NameList.AIO_TGTPORT, socksPort.ToString());
            Dial(NameList.AIO_TGTUSER, string.Empty);
            Dial(NameList.AIO_TGTPASS, string.Empty);
            Dial(NameList.AIO_CLRNAME, string.Empty);
            Dial(NameList.AIO_ADDNAME, "RedirectorTester\\.exe$");
        }

        private static void Dial(NameList name, string value)
        {
            if (!aio_dial(name, value))
                throw new InvalidOperationException("aio_dial failed for " + name);
        }

        private static long DownloadThroughRedirector(IPAddress destination, int port)
        {
            using (var client = new TcpClient(AddressFamily.InterNetwork))
            {
                client.ReceiveTimeout = 10000;
                client.SendTimeout = 10000;
                client.Connect(destination, port);

                var stream = client.GetStream();
                stream.WriteByte(0xA5);
				WritePayload(stream);
                stream.Flush();

				return ReadPayload(stream);
			}
		}

		private static long RunParallelDownloads(int connections, Func<long> download)
		{
			if (connections <= 0)
				throw new ArgumentOutOfRangeException(nameof(connections));

			using (var ready = new CountdownEvent(connections))
			using (var start = new ManualResetEventSlim(false))
			{
				var downloads = new Task<long>[connections];
				for (var i = 0; i < downloads.Length; ++i)
				{
					downloads[i] = Task.Factory.StartNew(() =>
					{
						ready.Signal();
						start.Wait();
						return download();
					}, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
				}

				ready.Wait();
				start.Set();
				Task.WaitAll(downloads);

				var total = 0L;
				for (var i = 0; i < downloads.Length; ++i)
					total += downloads[i].Result;
				return total;
			}
		}

		private static long ReadPayload(Stream stream)
		{
			var buffer = new byte[64 * 1024];
			var remaining = PayloadSize;
			var offset = 0;
			while (remaining > 0)
			{
				var read = stream.Read(buffer, 0, Math.Min(buffer.Length, remaining));
				if (read == 0)
					throw new EndOfStreamException("Payload ended early.");

				ValidatePayload(buffer, read, offset);
				offset += read;
				remaining -= read;
			}

			return PayloadSize;
		}

		private static void WritePayload(Stream stream)
		{
			var buffer = new byte[64 * 1024];
			var remaining = PayloadSize;
			var offset = 0;
			while (remaining > 0)
			{
				var count = Math.Min(buffer.Length, remaining);
				FillPayload(buffer, count, offset);
				stream.Write(buffer, 0, count);
				offset += count;
				remaining -= count;
			}
		}

        private static void ServePayloads(TcpListener listener, int count)
        {
			var sessions = new Task[count];
            for (var i = 0; i < count; ++i)
            {
				var client = listener.AcceptTcpClient();
				sessions[i] = Task.Run(() => ServePayload(client));
            }
			Task.WaitAll(sessions);
        }

		private static void ServePayload(TcpClient client)
		{
			using (client)
			using (var stream = client.GetStream())
			{
				if (stream.ReadByte() != 0xA5)
					throw new InvalidDataException("Payload server received an invalid request.");
				ReadAndValidatePayload(stream);
				WritePayload(stream);
			}
		}

        private static void ServeSocks(TcpListener listener, IPAddress expectedAddress, int expectedTcpPort, int expectedUdpPort, int payloadPort, int count, UdpClient udpRelay)
        {
			var sessions = new Task[count];
            for (var i = 0; i < count; ++i)
            {
				var client = listener.AcceptTcpClient();
				sessions[i] = Task.Run(() => ServeSocksClient(client, expectedAddress, expectedTcpPort, expectedUdpPort, payloadPort, udpRelay));
			}
			Task.WaitAll(sessions);
		}

		private static void ServeSocksClient(TcpClient client, IPAddress expectedAddress, int expectedTcpPort, int expectedUdpPort, int payloadPort, UdpClient udpRelay)
		{
			using (client)
			using (var clientStream = client.GetStream())
			{
                    var greeting = ReadExact(clientStream, 2);
                    if (greeting[0] != 0x05)
                        throw new InvalidDataException("SOCKS client sent an invalid greeting.");

                    ReadExact(clientStream, greeting[1]);
                    clientStream.Write(new byte[] { 0x05, 0x00 }, 0, 2);

                    var request = ReadExact(clientStream, 4);
                    if (request[0] != 0x05 || request[2] != 0x00 || request[3] != 0x01)
                        throw new InvalidDataException("SOCKS client issued an invalid IPv4 request.");

                    var requestAddress = new IPAddress(ReadExact(clientStream, 4));
                    var requestPortBytes = ReadExact(clientStream, 2);
                    var requestPort = (requestPortBytes[0] << 8) | requestPortBytes[1];

					if (request[1] == 0x03)
					{
						if (!requestAddress.Equals(IPAddress.Any) || requestPort != 0)
							throw new InvalidDataException("SOCKS UDP ASSOCIATE request does not use an unspecified address.");
						var relayPort = ((IPEndPoint)udpRelay.Client.LocalEndPoint).Port;
						clientStream.Write(new byte[] {
							0x05, 0x00, 0x00, 0x01,
							0x7F, 0x00, 0x00, 0x01,
							(byte)(relayPort >> 8), (byte)relayPort
						}, 0, 10);
						Interlocked.Increment(ref socksUdpAssociations);
						ServeUdpRelay(udpRelay, expectedAddress, expectedUdpPort);
						client.ReceiveTimeout = 3000;
						try
						{
							clientStream.ReadByte();
						}
						catch (IOException)
						{
							// Closing the intercepted UDP endpoint closes the SOCKS control connection.
						}
						return;
					}
					if (request[1] != 0x01)
						throw new InvalidDataException("SOCKS client issued an unsupported command.");
					if (!requestAddress.Equals(expectedAddress) || requestPort != expectedTcpPort)
						throw new InvalidDataException("SOCKS CONNECT destination does not match the intercepted flow.");

                    using (var upstream = new TcpClient(AddressFamily.InterNetwork))
                    {
                        upstream.Connect(IPAddress.Loopback, payloadPort);
                        clientStream.Write(new byte[] { 0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 0, 10);
                        Interlocked.Increment(ref socksConnectRequests);

                        var upstreamStream = upstream.GetStream();
						if (clientStream.ReadByte() != 0xA5)
							throw new InvalidDataException("SOCKS client sent an invalid payload request.");
						upstreamStream.WriteByte(0xA5);
						RelayAndValidatePayload(clientStream, upstreamStream);
						upstreamStream.Flush();
						RelayAndValidatePayload(upstreamStream, clientStream);
                    }
            }
        }

		private static void ServeUdpRelay(UdpClient relay, IPAddress expectedAddress, int expectedPort)
		{
			var peer = new IPEndPoint(IPAddress.Any, 0);
			var packet = relay.Receive(ref peer);
			if (packet.Length != 10 + UdpProbePayload.Length || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 || packet[3] != 1)
				throw new InvalidDataException("SOCKS UDP relay received an invalid datagram.");

			var destination = new IPAddress(new byte[] { packet[4], packet[5], packet[6], packet[7] });
			var port = (packet[8] << 8) | packet[9];
			var payload = new byte[packet.Length - 10];
			Buffer.BlockCopy(packet, 10, payload, 0, payload.Length);
			if (!destination.Equals(expectedAddress) || port != expectedPort || !ByteArrayEquals(payload, UdpProbePayload))
				throw new InvalidDataException("SOCKS UDP destination or payload does not match the intercepted datagram.");

			var response = new byte[10 + UdpProbePayload.Length];
			response[3] = 1;
			var address = expectedAddress.GetAddressBytes();
			Buffer.BlockCopy(address, 0, response, 4, address.Length);
			response[8] = (byte)(expectedPort >> 8);
			response[9] = (byte)expectedPort;
			Buffer.BlockCopy(UdpProbePayload, 0, response, 10, UdpProbePayload.Length);
			relay.Send(response, response.Length, peer);
		}

        private static byte[] ReadExact(Stream stream, int count)
        {
            var buffer = new byte[count];
            var offset = 0;
            while (offset < count)
            {
                var read = stream.Read(buffer, offset, count - offset);
                if (read == 0)
                    throw new EndOfStreamException("Unexpected end of SOCKS stream.");
                offset += read;
            }
            return buffer;
        }

		private static bool ByteArrayEquals(byte[] left, byte[] right)
		{
			if (left == null || right == null || left.Length != right.Length)
				return false;
			for (var i = 0; i < left.Length; ++i)
				if (left[i] != right[i])
					return false;
			return true;
		}

		private static void ReadAndValidatePayload(Stream stream)
		{
			RelayAndValidatePayload(stream, null);
		}

		private static void RelayAndValidatePayload(Stream source, Stream destination)
		{
			var buffer = new byte[64 * 1024];
			var remaining = PayloadSize;
			var offset = 0;
			while (remaining > 0)
			{
				var read = source.Read(buffer, 0, Math.Min(buffer.Length, remaining));
				if (read == 0)
					throw new EndOfStreamException("Payload ended early.");
				ValidatePayload(buffer, read, offset);
				if (destination != null)
					destination.Write(buffer, 0, read);
				offset += read;
				remaining -= read;
			}
		}

        private static void FillPayload(byte[] buffer, int count, int offset)
        {
            for (var i = 0; i < count; ++i)
                buffer[i] = (byte)((offset + i) % 251);
        }

        private static void ValidatePayload(byte[] buffer, int count, int offset)
        {
            for (var i = 0; i < count; ++i)
            {
                if (buffer[i] != (byte)((offset + i) % 251))
                    throw new InvalidDataException("Redirected payload corruption at byte " + (offset + i));
            }
        }
    }
}
